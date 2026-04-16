#!/usr/bin/env python3
"""
cs_exposure.py — CrowdStrike Exposure Management ↔ NetBox correlation & gap analysis

Fetches external-surface assets from the CrowdStrike Exposure Management API,
attempts to correlate each one with an existing NetBox device (agent-managed or
Discover-identified), persists the match via custom fields, and emits a
structured gap report covering three categories:

  GAP-1  Unmanaged internet exposure
         An external asset was found in the exposure surface but could not be
         correlated to any NetBox device.  This means an internet-facing IP or
         hostname with no known Falcon sensor and no existing NetBox record.
         Risk: unknown/unprotected device exposed to the internet.

  GAP-2  Managed device with public IP absent from the exposure surface
         A device has last_public_ip recorded by the Falcon agent, but that IP
         does not appear in any external asset.  This may indicate a stale IP,
         a shared NAT egress address, or a gap in the external scan coverage.
         Risk: internet exposure may be under-reported.

  GAP-3  High-risk exposure on a managed but unprotected device
         An external asset with critical or high criticality was matched to a
         managed device that has a ZTA score below the threshold or has open
         critical/high Spotlight vulnerabilities.
         Risk: high-value exposed device with known weaknesses.

Correlation attempt order (highest to lowest confidence):
  1. cs_exposure_id custom field already set on the device (idempotent re-run)
  2. last_public_ip matches the external asset IP
  3. IPAM IP address matches the external asset IP
  4. Hostname / FQDN match (exact, then first DNS label)

NetBox custom fields written on matched devices
-----------------------------------------------
  cs_exposure_id           CrowdStrike external asset ID
  cs_exposure_criticality  critical | high | medium | low | unknown
  cs_internet_exposed      True for all matched devices
  cs_exposure_ports        JSON list of open port / protocol pairs
  cs_exposure_first_seen   ISO 8601 timestamp from Exposure Management
  cs_exposure_last_seen    ISO 8601 timestamp from Exposure Management
  cs_exposure_match_method How the device was correlated (see above)

Usage
-----
  python cs_exposure.py                          # full run
  python cs_exposure.py --dry-run                # read-only, report only
  python cs_exposure.py --min-criticality high   # GAP-1 only for high+critical
  python cs_exposure.py --threshold 60           # ZTA threshold for GAP-3
  python cs_exposure.py --create-shadow          # create placeholder devices for GAP-1
  python cs_exposure.py --report-json out.json   # write JSON report file
  python cs_exposure.py --token-file /etc/cs/CS_FEM_TOKEN

Credentials
-----------
  Same CS_FEM_TOKEN JSON file used by cs_sync.py:
  {"client_id": "...", "client_secret": "...", "base_url": "...", "console_url": "..."}

  Required CrowdStrike API scope:  Exposure Management: Read
"""

from __future__ import annotations

import json
import logging
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table

import config
from netbox_client import NetBoxClient

console = Console()
log     = logging.getLogger(__name__)

_DEFAULT_TOKEN_FILE = "CS_FEM_TOKEN"
_DEFAULT_BASE_URL   = "https://api.crowdstrike.com"
_DEFAULT_CONSOLE    = "https://falcon.crowdstrike.com"
_API_DELAY          = 0.05     # seconds between CrowdStrike API calls
_QUERY_LIMIT        = 200      # asset IDs per query page
_DETAIL_BATCH       = 100      # asset IDs per get_external_assets call

# Criticality ranking (higher = more severe)
_CRIT_RANK: dict[str, int] = {
    "critical": 4,
    "high":     3,
    "medium":   2,
    "low":      1,
    "unknown":  0,
}

_SHADOW_ROLE_SLUG = "cs-exposure-unmatched"
_SHADOW_TAG_SLUG  = "cs-internet-exposure"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ExternalAsset:
    asset_id:   str
    asset_type: str               # ip_address | domain | certificate | hostname | …
    ip_address: Optional[str]
    fqdn:       Optional[str]
    hostname:   Optional[str]
    criticality: str              # critical | high | medium | low | unknown
    ports:     list[dict] = field(default_factory=list)
    exposures: list[dict] = field(default_factory=list)
    first_seen: Optional[str]   = None
    last_seen:  Optional[str]   = None
    # Filled in during correlation
    matched_device: Optional[object] = None
    match_method:   Optional[str]    = None


@dataclass
class GapItem:
    gap_type:       str            # GAP-1 | GAP-2 | GAP-3
    severity:       str            # critical | high | medium | low | info
    description:    str
    external_asset: Optional[ExternalAsset] = None
    nb_device_name: Optional[str]           = None
    nb_device_id:   Optional[int]           = None
    detail_lines:   list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Credential loader  (reuses the same CS_FEM_TOKEN format as cs_sync.py)
# ---------------------------------------------------------------------------

def _load_token_file(path: Optional[str]) -> dict:
    token_path = Path(path) if path else Path("CS_FEM_TOKEN")
    if not token_path.exists():
        console.print(f"[red]CS_FEM_TOKEN not found at:[/red] {token_path}")
        sys.exit(1)
    try:
        creds = json.loads(token_path.read_text())
        _ = creds["client_id"], creds["client_secret"]
    except (json.JSONDecodeError, KeyError) as exc:
        console.print(f"[red]CS_FEM_TOKEN error:[/red] {exc}")
        sys.exit(1)
    return creds


# ---------------------------------------------------------------------------
# CrowdStrike Exposure Management client
# ---------------------------------------------------------------------------

class ExposureManagementClient:
    """
    Wraps the FalconPy ExposureManagement service to fetch all external assets.

    External assets represent internet-facing IPs, hostnames, domains, and
    certificates discovered by CrowdStrike scanning from outside the network.
    They are identified separately from agent-managed hosts (Hosts API) and
    from Discover assets (internal visibility).
    """

    def __init__(self, creds: dict) -> None:
        self.console_url = creds.get("console_url", _DEFAULT_CONSOLE).rstrip("/")
        try:
            from falconpy import ExposureManagement
            self._em = ExposureManagement(
                client_id=creds["client_id"],
                client_secret=creds["client_secret"],
                base_url=creds.get("base_url", _DEFAULT_BASE_URL),
            )
        except ImportError:
            console.print(
                "[red]crowdstrike-falconpy is not installed.[/red]\n"
                "Install it with:  pip install crowdstrike-falconpy"
            )
            sys.exit(1)

    def asset_url(self, asset_id: str) -> str:
        return f"{self.console_url}/exposure-management/attack-surface/ip-addresses"

    def scroll_all(self) -> list[ExternalAsset]:
        """
        Page through all external assets and return normalised ExternalAsset objects.
        Returns an empty list if the module is not licensed (HTTP 403).
        """
        all_ids: list[str] = []
        offset = 0

        while True:
            resp   = self._em.query_external_assets(limit=_QUERY_LIMIT, offset=offset)
            status = resp.get("status_code")

            if status == 403:
                log.warning(
                    "ExposureManagement: access denied (HTTP 403) — "
                    "the Exposure Management module may not be licensed for this CID."
                )
                return []
            if status != 200:
                log.error(
                    "ExposureManagement: query_external_assets returned HTTP %s: %s",
                    status,
                    (resp.get("body") or {}).get("errors"),
                )
                break

            body  = resp["body"]
            ids   = body.get("resources") or []
            meta  = (body.get("meta") or {}).get("pagination") or {}
            total = meta.get("total", 0)
            all_ids.extend(ids)
            log.debug("Fetched %d / %d external asset IDs", len(all_ids), total)

            if not ids or len(all_ids) >= total:
                break
            offset += len(ids)
            time.sleep(_API_DELAY)

        if not all_ids:
            log.warning("No external assets returned from Exposure Management API.")
            return []

        return self._fetch_details(all_ids)

    def _fetch_details(self, ids: list[str]) -> list[ExternalAsset]:
        assets: list[ExternalAsset] = []
        for i in range(0, len(ids), _DETAIL_BATCH):
            batch = ids[i : i + _DETAIL_BATCH]
            resp  = self._em.get_external_assets(ids=batch)
            if resp.get("status_code") != 200:
                log.error(
                    "ExposureManagement: get_external_assets HTTP %s for batch %d: %s",
                    resp.get("status_code"),
                    i // _DETAIL_BATCH,
                    (resp.get("body") or {}).get("errors"),
                )
                time.sleep(_API_DELAY)
                continue

            for raw in (resp["body"].get("resources") or []):
                assets.append(self._normalise(raw))
            time.sleep(_API_DELAY)

        log.info("Fetched details for %d external asset(s).", len(assets))
        return assets

    @staticmethod
    def _normalise(raw: dict) -> ExternalAsset:
        """Map a raw API response dict to an ExternalAsset, handling field name variants."""
        # IP address: CrowdStrike uses different keys in different contexts
        ip = (
            raw.get("ip_address")
            or raw.get("inet")
            or (raw.get("ip_addresses") or [None])[0]
        )
        # Normalise ports list: [{port, protocol, service_name}, …]
        ports = []
        for p in (raw.get("ports") or []):
            ports.append({
                "port":     p.get("port"),
                "protocol": (p.get("protocol") or "").lower(),
                "service":  p.get("service_name") or p.get("service") or "",
                "status":   (p.get("status") or "").lower(),
            })

        return ExternalAsset(
            asset_id    = raw["id"],
            asset_type  = raw.get("asset_type", "unknown"),
            ip_address  = ip,
            fqdn        = raw.get("fqdn") or raw.get("domain"),
            hostname    = raw.get("hostname"),
            criticality = (raw.get("criticality") or "unknown").lower(),
            ports       = ports,
            exposures   = raw.get("exposures") or raw.get("external_exposures") or [],
            first_seen  = raw.get("first_seen"),
            last_seen   = raw.get("last_seen"),
        )


# ---------------------------------------------------------------------------
# NetBox lookup maps
# ---------------------------------------------------------------------------

def _build_lookup_maps(nb: NetBoxClient) -> tuple[dict, dict, dict, dict]:
    """
    Build four lookup maps from NetBox device custom fields and IPAM:

      public_ip_map   : last_public_ip value   → device object
      ipam_ip_map     : IPAM IP string         → device object
      hostname_map    : lower-case device name → device object
      exposure_id_map : cs_exposure_id value   → device object
    """
    console.print("Building NetBox device lookup maps…")
    public_ip_map:   dict[str, object] = {}
    hostname_map:    dict[str, object] = {}
    exposure_id_map: dict[str, object] = {}

    for dev in nb.nb.dcim.devices.all():
        cf        = dev.custom_fields or {}
        name_key  = str(dev.name or "").lower().strip()
        if name_key:
            hostname_map[name_key] = dev

        pub_ip = (cf.get("last_public_ip") or "").strip()
        if pub_ip:
            public_ip_map[pub_ip] = dev

        exp_id = (cf.get("cs_exposure_id") or "").strip()
        if exp_id:
            exposure_id_map[exp_id] = dev

    # IPAM IPs → device via interface assignment
    ipam_ip_map: dict[str, object] = {}
    for ip_obj in nb.nb.ipam.ip_addresses.filter(status="active"):
        ip_str = str(ip_obj.address or "").split("/")[0].strip()
        if not ip_str:
            continue
        try:
            ao = getattr(ip_obj, "assigned_object", None)
            if ao and hasattr(ao, "device") and ao.device:
                ipam_ip_map[ip_str] = ao.device
        except Exception as exc:
            log.debug("IPAM IP resolution failed for %s: %s", ip_str, exc)

    log.info(
        "Lookup maps built — public IPs: %d  IPAM IPs: %d  hostnames: %d  "
        "already-linked exposure IDs: %d",
        len(public_ip_map), len(ipam_ip_map), len(hostname_map), len(exposure_id_map),
    )
    return public_ip_map, ipam_ip_map, hostname_map, exposure_id_map


# ---------------------------------------------------------------------------
# Correlation
# ---------------------------------------------------------------------------

def _correlate(
    assets:         list[ExternalAsset],
    public_ip_map:  dict,
    ipam_ip_map:    dict,
    hostname_map:   dict,
    exposure_id_map: dict,
) -> list[ExternalAsset]:
    """
    Attempt to match each external asset to a NetBox device using four strategies
    (highest confidence first).  Sets asset.matched_device and asset.match_method.
    """
    matched = 0

    for asset in assets:

        # ── Priority 1: already linked by cs_exposure_id ──────────────────────
        if asset.asset_id in exposure_id_map:
            asset.matched_device = exposure_id_map[asset.asset_id]
            asset.match_method   = "exposure_id"
            matched += 1
            continue

        # ── Priority 2: last_public_ip match ─────────────────────────────────
        if asset.ip_address and asset.ip_address in public_ip_map:
            asset.matched_device = public_ip_map[asset.ip_address]
            asset.match_method   = "public_ip"
            matched += 1
            continue

        # ── Priority 3: IPAM IP match ─────────────────────────────────────────
        if asset.ip_address and asset.ip_address in ipam_ip_map:
            asset.matched_device = ipam_ip_map[asset.ip_address]
            asset.match_method   = "ipam_ip"
            matched += 1
            continue

        # ── Priority 4: hostname / FQDN match ─────────────────────────────────
        candidates: list[str] = []
        for raw in filter(None, [asset.fqdn, asset.hostname]):
            raw_lower = raw.lower()
            candidates.append(raw_lower)
            candidates.append(raw_lower.split(".")[0])   # first DNS label

        for candidate in candidates:
            if candidate and candidate in hostname_map:
                asset.matched_device = hostname_map[candidate]
                asset.match_method   = "hostname"
                matched += 1
                break

    log.info(
        "Correlation: %d / %d external asset(s) matched to a NetBox device.",
        matched, len(assets),
    )
    return assets


# ---------------------------------------------------------------------------
# NetBox writes
# ---------------------------------------------------------------------------

def _write_exposure_fields(
    asset:     ExternalAsset,
    nb_device: object,
    nb:        NetBoxClient,
    dry_run:   bool,
) -> bool:
    """Write cs_exposure_* custom fields onto a matched device."""
    ports_json = [
        {
            "port":     p.get("port"),
            "protocol": p.get("protocol", ""),
            "service":  p.get("service", ""),
        }
        for p in asset.ports
    ]

    updates = {
        "custom_fields": {
            "cs_exposure_id":           asset.asset_id,
            "cs_exposure_criticality":  asset.criticality,
            "cs_internet_exposed":      True,
            "cs_exposure_ports":        ports_json,
            "cs_exposure_first_seen":   asset.first_seen or "",
            "cs_exposure_last_seen":    asset.last_seen  or "",
            "cs_exposure_match_method": asset.match_method or "",
        }
    }

    prefix = "[yellow]DRY-RUN[/yellow]" if dry_run else "[green]WRITE[/green]"
    console.print(
        f"  {prefix}  {nb_device.name}  "
        f"[dim](match: {asset.match_method}, criticality: {asset.criticality})[/dim]"
    )

    if not dry_run:
        try:
            nb_device.update(updates)
            return True
        except Exception as exc:
            log.warning("Failed to update device %s: %s", nb_device.name, exc)
            return False
    return True


def _create_shadow_device(
    asset:   ExternalAsset,
    nb:      NetBoxClient,
    dry_run: bool,
) -> Optional[object]:
    """
    Create a placeholder ('shadow') NetBox device for an unmatched external asset.
    The device is tagged cs-internet-exposure and assigned the cs-exposure-unmatched
    device role so it is visually distinct from agent-managed inventory.
    """
    label = asset.fqdn or asset.hostname or asset.ip_address or asset.asset_id
    name  = f"[EXPOSED] {label}"

    console.print(
        f"  [{'yellow' if dry_run else 'red'}]"
        f"{'DRY-RUN' if dry_run else 'CREATE SHADOW'}[/{'yellow' if dry_run else 'red'}]  "
        f"{name}  [dim](criticality: {asset.criticality})[/dim]"
    )

    if dry_run:
        return None

    try:
        # Role
        role = nb.nb.dcim.device_roles.get(slug=_SHADOW_ROLE_SLUG)
        if not role:
            role = nb.nb.dcim.device_roles.create(
                name="CS Exposure Unmatched",
                slug=_SHADOW_ROLE_SLUG,
                color="f44336",
                description="Placeholder device created from a CrowdStrike external "
                            "exposure asset that could not be matched to an existing record.",
            )

        # Tag
        tag = nb.nb.extras.tags.get(slug=_SHADOW_TAG_SLUG)
        if not tag:
            tag = nb.nb.extras.tags.create(
                name="cs-internet-exposure",
                slug=_SHADOW_TAG_SLUG,
                color="f44336",
                description="Device with confirmed internet exposure via CrowdStrike "
                            "Exposure Management.",
            )

        # Generic device type — reuse or create an "Unknown" placeholder
        mfr = nb.nb.dcim.manufacturers.get(slug="unknown")
        if not mfr:
            mfr = nb.nb.dcim.manufacturers.create(name="Unknown", slug="unknown")
        dt = nb.nb.dcim.device_types.get(slug="unknown-external")
        if not dt:
            dt = nb.nb.dcim.device_types.create(
                manufacturer=mfr.id,
                model="Unknown External",
                slug="unknown-external",
                u_height=0,
            )

        site = nb.nb.dcim.sites.get(slug=getattr(config, "DEFAULT_SITE_SLUG", "default"))
        if not site:
            site = list(nb.nb.dcim.sites.all())[0]

        dev = nb.nb.dcim.devices.create(
            name        = name,
            site        = site.id,
            role        = role.id,
            device_type = dt.id,
            status      = "active",
            tags        = [{"id": tag.id}],
            custom_fields = {
                "cs_exposure_id":           asset.asset_id,
                "cs_exposure_criticality":  asset.criticality,
                "cs_internet_exposed":      True,
                "cs_exposure_ports":        [
                    {"port": p.get("port"), "protocol": p.get("protocol", "")}
                    for p in asset.ports
                ],
                "cs_exposure_first_seen":   asset.first_seen or "",
                "cs_exposure_last_seen":    asset.last_seen  or "",
                "cs_exposure_match_method": "unmatched",
            },
        )
        log.info("Created shadow device: %s", name)
        return dev

    except Exception as exc:
        log.error("Failed to create shadow device for %s: %s", label, exc)
        return None


# ---------------------------------------------------------------------------
# Gap analysis
# ---------------------------------------------------------------------------

def _analyse_gaps(
    assets:        list[ExternalAsset],
    public_ip_map: dict,
    min_criticality: str,
    zta_threshold:   int,
) -> list[GapItem]:
    """
    Produce gap items for all three gap types.

    Parameters
    ----------
    assets          Correlated external assets.
    public_ip_map   {last_public_ip → device} from all NetBox devices.
    min_criticality Minimum criticality to include in GAP-1 output.
    zta_threshold   ZTA score below which a device is considered at-risk for GAP-3.
    """
    gaps:    list[GapItem]   = []
    min_rank = _CRIT_RANK.get(min_criticality.lower(), 0)

    # Set of IPs present anywhere in the external exposure surface
    exposure_ips = {a.ip_address for a in assets if a.ip_address}

    # ── GAP-1: Unmatched external assets ──────────────────────────────────────
    for asset in assets:
        if _CRIT_RANK.get(asset.criticality, 0) < min_rank:
            continue
        if asset.matched_device is not None:
            continue

        ports_str = (
            ", ".join(
                f"{p['port']}/{p['protocol'] or '?'}"
                + (f" ({p['service']})" if p.get("service") else "")
                for p in asset.ports
            )
            if asset.ports else "none detected"
        )
        label = asset.fqdn or asset.ip_address or asset.asset_id

        gaps.append(GapItem(
            gap_type       = "GAP-1",
            severity       = asset.criticality,
            description    = f"Unmanaged internet-facing asset: {label}",
            external_asset = asset,
            detail_lines   = [
                f"Type:         {asset.asset_type}",
                f"IP:           {asset.ip_address or '—'}",
                f"FQDN:         {asset.fqdn or '—'}",
                f"Criticality:  {asset.criticality}",
                f"Open ports:   {ports_str}",
                f"Last seen:    {asset.last_seen or '—'}",
            ],
        ))

    # ── GAP-2: Managed device with public IP not in exposure surface ──────────
    for pub_ip, dev in public_ip_map.items():
        if pub_ip in exposure_ips:
            continue
        cf = dev.custom_fields or {}
        gaps.append(GapItem(
            gap_type       = "GAP-2",
            severity       = "info",
            description    = (
                f"Managed device '{dev.name}' has last_public_ip {pub_ip} "
                "not found in the exposure surface"
            ),
            nb_device_name = str(dev.name),
            nb_device_id   = dev.id,
            detail_lines   = [
                f"last_public_ip:  {pub_ip}",
                "Interpretation:  IP was not detected by external surface scan — "
                "could be a shared NAT egress, a stale IP record, or a scan blind-spot.",
                f"ZTA score:       {cf.get('cs_zta_score', '—')}",
                f"CS Falcon URL:   {cf.get('cs_falcon_url', '—')}",
            ],
        ))

    # ── GAP-3: High-risk exposure on managed but vulnerable device ────────────
    for asset in assets:
        if asset.matched_device is None:
            continue
        if _CRIT_RANK.get(asset.criticality, 0) < _CRIT_RANK["high"]:
            continue

        cf          = asset.matched_device.custom_fields or {}
        zta         = cf.get("cs_zta_score")
        vuln_json   = cf.get("vulnerabilities") or {}
        vuln_counts = (vuln_json.get("counts") or {}) if isinstance(vuln_json, dict) else {}
        crit_vulns  = (vuln_counts.get("critical") or 0) + (vuln_counts.get("high") or 0)

        risk_reasons: list[str] = []
        if zta is not None and isinstance(zta, (int, float)) and zta < zta_threshold:
            risk_reasons.append(f"ZTA score {zta} < threshold {zta_threshold}")
        if crit_vulns > 0:
            risk_reasons.append(f"{crit_vulns} open critical/high Spotlight vulnerability/ies")

        if not risk_reasons:
            continue

        ports_str = (
            ", ".join(f"{p['port']}/{p['protocol'] or '?'}" for p in asset.ports)
            if asset.ports else "none detected"
        )

        gaps.append(GapItem(
            gap_type       = "GAP-3",
            severity       = asset.criticality,
            description    = (
                f"High-risk external exposure on vulnerable device "
                f"'{asset.matched_device.name}'"
            ),
            external_asset = asset,
            nb_device_name = str(asset.matched_device.name),
            nb_device_id   = asset.matched_device.id,
            detail_lines   = [
                f"External criticality:  {asset.criticality}",
                f"Risk factors:          {';  '.join(risk_reasons)}",
                f"IP:                    {asset.ip_address or '—'}",
                f"Open ports:            {ports_str}",
                f"Match method:          {asset.match_method}",
                f"CS Falcon URL:         {cf.get('cs_falcon_url', '—')}",
            ],
        ))

    return gaps


# ---------------------------------------------------------------------------
# Rich output
# ---------------------------------------------------------------------------

def _print_report(
    gaps:          list[GapItem],
    assets:        list[ExternalAsset],
    public_ip_map: dict,
) -> None:
    """Print the gap report to the terminal using Rich."""
    g1 = [g for g in gaps if g.gap_type == "GAP-1"]
    g2 = [g for g in gaps if g.gap_type == "GAP-2"]
    g3 = [g for g in gaps if g.gap_type == "GAP-3"]

    matched   = sum(1 for a in assets if a.matched_device)
    unmatched = len(assets) - matched

    _SEV_COLOUR = {
        "critical": "bold red",
        "high":     "red",
        "medium":   "yellow",
        "low":      "cyan",
        "unknown":  "dim",
        "info":     "dim",
    }
    _SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4, "info": 5}

    console.rule("[bold]CrowdStrike Exposure Management — Gap Report[/bold]")
    console.print(
        f"Generated: [dim]{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}[/dim]\n"
    )

    # Summary table
    summary = Table(show_header=False, box=None, padding=(0, 2))
    summary.add_column(style="bold")
    summary.add_column()
    summary.add_row("External assets total",     str(len(assets)))
    summary.add_row("  Matched to NetBox device", str(matched))
    summary.add_row("  Unmatched (GAP-1 candidates)", str(unmatched))
    summary.add_row("Managed devices with public IP", str(len(public_ip_map)))
    summary.add_row("  Not in exposure surface (GAP-2)", str(len(g2)))
    summary.add_row("GAP-1  Unmanaged internet exposure",     str(len(g1)))
    summary.add_row("GAP-2  Public IP absent from surface",   str(len(g2)))
    summary.add_row("GAP-3  High-risk on vulnerable device",  str(len(g3)))
    console.print(summary)
    console.print()

    for label, items in [
        ("GAP-1  Unmanaged internet-facing assets  (no Falcon sensor / no NetBox device)", g1),
        ("GAP-2  Managed devices with public IP not found in exposure surface",            g2),
        ("GAP-3  High-risk external exposure on managed but vulnerable device",            g3),
    ]:
        console.rule(f"[bold]{label}[/bold]  ({len(items)})")
        if not items:
            console.print("  [dim](none)[/dim]\n")
            continue

        sorted_items = sorted(items, key=lambda g: _SEV_ORDER.get(g.severity, 9))
        for gap in sorted_items:
            sev_colour = _SEV_COLOUR.get(gap.severity, "")
            console.print(
                f"  [{sev_colour}][{gap.severity.upper():8}][/{sev_colour}]  {gap.description}"
            )
            for line in gap.detail_lines:
                console.print(f"               [dim]{line}[/dim]")
            console.print()


def _write_json_report(
    gaps:          list[GapItem],
    assets:        list[ExternalAsset],
    public_ip_map: dict,
    path:          str,
) -> None:
    """Write a machine-readable JSON version of the gap report."""

    def _serial_asset(a: ExternalAsset) -> dict:
        return {
            "asset_id":    a.asset_id,
            "asset_type":  a.asset_type,
            "ip_address":  a.ip_address,
            "fqdn":        a.fqdn,
            "hostname":    a.hostname,
            "criticality": a.criticality,
            "ports":       a.ports,
            "first_seen":  a.first_seen,
            "last_seen":   a.last_seen,
            "match_method": a.match_method,
            "matched_device_name": (
                str(a.matched_device.name) if a.matched_device else None
            ),
            "matched_device_id": (
                a.matched_device.id if a.matched_device else None
            ),
        }

    report = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "external_assets":            len(assets),
            "matched":                    sum(1 for a in assets if a.matched_device),
            "unmatched":                  sum(1 for a in assets if not a.matched_device),
            "managed_with_public_ip":     len(public_ip_map),
            "gap_1_unmanaged_exposure":   sum(1 for g in gaps if g.gap_type == "GAP-1"),
            "gap_2_ip_outside_surface":   sum(1 for g in gaps if g.gap_type == "GAP-2"),
            "gap_3_risk_on_vulnerable":   sum(1 for g in gaps if g.gap_type == "GAP-3"),
        },
        "gaps": [
            {
                "gap_type":       g.gap_type,
                "severity":       g.severity,
                "description":    g.description,
                "nb_device_name": g.nb_device_name,
                "nb_device_id":   g.nb_device_id,
                "detail":         g.detail_lines,
                "external_asset": _serial_asset(g.external_asset) if g.external_asset else None,
            }
            for g in gaps
        ],
    }

    try:
        with open(path, "w") as fh:
            json.dump(report, fh, indent=2, default=str)
        console.print(f"[green]JSON report written to:[/green] {path}")
    except OSError as exc:
        log.error("Failed to write JSON report to %s: %s", path, exc)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

@click.command()
@click.option("--token-file",        default=None,    metavar="PATH",
              help=f"Path to CS_FEM_TOKEN credential file (default: ./{_DEFAULT_TOKEN_FILE})")
@click.option("--dry-run",           is_flag=True,
              help="Query all sources, print the report, but write nothing to NetBox.")
@click.option("--threshold",         default=70,       metavar="N",     type=int,
              help="ZTA score below which a device is considered at-risk for GAP-3 (default: 70).")
@click.option("--min-criticality",   default="low",
              type=click.Choice(["critical", "high", "medium", "low"], case_sensitive=False),
              help="Minimum criticality for GAP-1 items (default: low = include all).")
@click.option("--create-shadow",     is_flag=True,
              help="Create placeholder NetBox devices for unmatched GAP-1 assets.")
@click.option("--report-json",       default=None,    metavar="PATH",
              help="Write gap report to a JSON file in addition to stdout.")
@click.option("--verbose", "-v",     is_flag=True)
def cli(
    token_file, dry_run, threshold, min_criticality,
    create_shadow, report_json, verbose,
):
    """
    Correlate CrowdStrike Exposure Management assets with NetBox devices and report gaps.

    Fetches all external-surface assets from the Exposure Management API, attempts
    to match them to existing NetBox devices, persists exposure metadata on matched
    devices, and prints a structured gap report.
    """
    logging.basicConfig(
        format  = "%(levelname)-8s %(name)s: %(message)s",
        level   = logging.DEBUG if verbose else logging.INFO,
    )

    if dry_run:
        console.print("[yellow]Dry-run mode — no changes will be written to NetBox.[/yellow]")

    creds = _load_token_file(token_file)
    nb    = NetBoxClient(config.NETBOX_URL, config.NETBOX_TOKEN, dry_run=dry_run)
    em    = ExposureManagementClient(creds)

    # ── 1. Ensure exposure custom fields exist on dcim.device ─────────────────
    nb.ensure_exposure_fields()

    # ── 2. Fetch external assets from Exposure Management API ─────────────────
    console.print("Fetching external assets from CrowdStrike Exposure Management…")
    assets = em.scroll_all()
    if not assets:
        console.print("[yellow]No external assets returned — nothing to correlate.[/yellow]")
        # Still run GAP-2 check (managed devices with recorded public IPs)

    # ── 3. Build NetBox lookup maps ───────────────────────────────────────────
    public_ip_map, ipam_ip_map, hostname_map, exposure_id_map = _build_lookup_maps(nb)

    # ── 4. Correlate assets to devices ───────────────────────────────────────
    if assets:
        assets = _correlate(assets, public_ip_map, ipam_ip_map, hostname_map, exposure_id_map)

    # ── 5. Write exposure fields to matched devices ───────────────────────────
    updated = 0
    if assets:
        console.print("\nWriting exposure fields to matched devices…")
        for asset in assets:
            if asset.matched_device:
                if _write_exposure_fields(asset, asset.matched_device, nb, dry_run):
                    updated += 1

    # ── 6. Optionally create shadow devices for unmatched assets ─────────────
    shadow_created = 0
    if create_shadow and assets:
        console.print("\nCreating shadow devices for unmatched GAP-1 assets…")
        for asset in assets:
            if asset.matched_device is None:
                dev = _create_shadow_device(asset, nb, dry_run)
                if dev:
                    shadow_created += 1

    # ── 7. Gap analysis ───────────────────────────────────────────────────────
    gaps = _analyse_gaps(assets, public_ip_map, min_criticality, threshold)

    # ── 8. Report ─────────────────────────────────────────────────────────────
    console.print()
    _print_report(gaps, assets, public_ip_map)

    if report_json:
        _write_json_report(gaps, assets, public_ip_map, report_json)

    # Summary line
    console.print(
        f"\n[bold]Done.[/bold]  "
        f"[green]{updated} device(s) updated[/green]  "
        + (f"[red]{shadow_created} shadow device(s) created[/red]  " if create_shadow else "")
        + f"[yellow]{sum(1 for g in gaps if g.gap_type == 'GAP-1')} GAP-1[/yellow]  "
        f"[dim]{sum(1 for g in gaps if g.gap_type == 'GAP-2')} GAP-2  "
        f"{sum(1 for g in gaps if g.gap_type == 'GAP-3')} GAP-3[/dim]"
    )

    # Non-zero exit if there are actionable GAP-1 or GAP-3 items
    if any(g.gap_type in ("GAP-1", "GAP-3") for g in gaps):
        sys.exit(1)


if __name__ == "__main__":
    cli()
