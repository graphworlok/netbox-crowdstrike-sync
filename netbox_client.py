"""
Thin pynetbox wrapper for netbox-crowdstrike-sync.

All writes are guarded by a dry_run flag — when True every mutating call
is logged but not sent to NetBox.
"""

from __future__ import annotations

import logging
from typing import Optional

import pynetbox

log = logging.getLogger(__name__)


class NetBoxClient:
    def __init__(self, url: str, token: str, dry_run: bool = False):
        self.nb = pynetbox.api(url, token=token)
        self.nb.http_session.verify = True   # set False if using a self-signed cert
        self.dry_run = dry_run
        self._manufacturer_cache: dict[str, object] = {}
        self._platform_cache:     dict[str, object] = {}
        self._device_type_cache:  dict[str, object] = {}

    # ------------------------------------------------------------------
    # Manufacturers / device types / platforms / sites / roles
    # ------------------------------------------------------------------

    def get_or_create_manufacturer(self, slug: str, name: str) -> object:
        if slug in self._manufacturer_cache:
            return self._manufacturer_cache[slug]
        mfr = self.nb.dcim.manufacturers.get(slug=slug)
        if not mfr:
            log.info("Creating manufacturer: %s", name)
            if not self.dry_run:
                mfr = self.nb.dcim.manufacturers.create({"name": name, "slug": slug})
        self._manufacturer_cache[slug] = mfr
        return mfr

    def get_or_create_device_type(
        self, model: str, manufacturer_slug: str, manufacturer_name: str
    ) -> Optional[object]:
        if not model:
            return None
        key = f"{manufacturer_slug}/{model}"
        if key in self._device_type_cache:
            return self._device_type_cache[key]
        dt = self.nb.dcim.device_types.get(model=model, manufacturer=manufacturer_slug)
        if not dt:
            mfr  = self.get_or_create_manufacturer(manufacturer_slug, manufacturer_name)
            slug = model.lower().replace(" ", "-").replace("/", "-")[:50]
            log.info("Creating device type: %s", model)
            if not self.dry_run:
                dt = self.nb.dcim.device_types.create({
                    "manufacturer": mfr.id if mfr else None,
                    "model":        model,
                    "slug":         slug,
                })
        self._device_type_cache[key] = dt
        return dt

    def get_or_create_platform(self, slug: str, name: str) -> Optional[object]:
        if slug in self._platform_cache:
            return self._platform_cache[slug]
        plat = self.nb.dcim.platforms.get(slug=slug)
        if not plat:
            log.info("Creating platform: %s", slug)
            if not self.dry_run:
                plat = self.nb.dcim.platforms.create({"name": name, "slug": slug})
        self._platform_cache[slug] = plat
        return plat

    def get_or_create_site(self, slug: str) -> Optional[object]:
        site = self.nb.dcim.sites.get(slug=slug)
        if not site:
            log.info("Creating site: %s", slug)
            if not self.dry_run:
                site = self.nb.dcim.sites.create({
                    "name":   slug.replace("-", " ").title(),
                    "slug":   slug,
                    "status": "active",
                })
        return site

    def get_or_create_device_role(self, slug: str) -> Optional[object]:
        role = self.nb.dcim.device_roles.get(slug=slug)
        if not role:
            log.info("Creating device role: %s", slug)
            if not self.dry_run:
                role = self.nb.dcim.device_roles.create({
                    "name":  slug.replace("-", " ").title(),
                    "slug":  slug,
                    "color": "9e9e9e",
                })
        return role

    def site_for_ip(self, ip: str) -> Optional[object]:
        """
        Return the NetBox site associated with the most-specific IPAM prefix
        containing *ip*, or None if no matching prefix has a site assigned.
        """
        try:
            prefixes = list(self.nb.ipam.prefixes.filter(contains=ip))
        except Exception as exc:
            log.debug("IPAM prefix lookup failed for %s: %s", ip, exc)
            return None
        prefixes.sort(key=lambda p: int(str(p.prefix).split("/")[1]), reverse=True)
        for prefix in prefixes:
            site = getattr(prefix, "site", None)
            if site:
                return site
        return None

    # ------------------------------------------------------------------
    # Device lookups
    # ------------------------------------------------------------------

    def get_device_by_name(self, name: str) -> Optional[object]:
        return self.nb.dcim.devices.get(name=name)

    def get_device_by_ip(self, ip: str) -> Optional[object]:
        """Return the device whose interface owns *ip* in IPAM, or None."""
        try:
            ip_obj = self.nb.ipam.ip_addresses.get(address=ip)
            if ip_obj:
                ao = getattr(ip_obj, "assigned_object", None)
                if ao and hasattr(ao, "device"):
                    return ao.device
        except Exception as exc:
            log.debug("IP device lookup failed for %s: %s", ip, exc)
        return None

    def get_device_by_mac(self, mac: str) -> Optional[object]:
        """
        Return the device that owns *mac* (colon-separated) via
        dcim.mac_addresses → assigned interface → device.
        """
        try:
            mac_obj = self.nb.dcim.mac_addresses.get(mac_address=mac)
            if mac_obj:
                ao = getattr(mac_obj, "assigned_object", None)
                if ao and hasattr(ao, "device"):
                    return ao.device
        except Exception as exc:
            log.debug("MAC device lookup failed for %s: %s", mac, exc)
        return None

    def get_device_by_crowdstrike_aid(self, aid: str) -> Optional[object]:
        """Return the device whose crowdstrike_aid custom field matches *aid*."""
        try:
            results = list(self.nb.dcim.devices.filter(**{"cf_crowdstrike_aid": aid}))
            return results[0] if results else None
        except Exception as exc:
            log.debug("AID lookup failed for %s: %s", aid, exc)
            return None

    def get_device_by_any_ip(self, ips: list[str]) -> Optional[object]:
        """Try each IP in *ips* in order; return the first device found."""
        for ip in ips:
            if not ip:
                continue
            try:
                dev = self.get_device_by_ip(ip)
                if dev:
                    return dev
            except Exception as exc:
                log.debug("any-IP lookup failed for %s: %s", ip, exc)
        return None

    def get_device_by_fqdn(self, fqdn: str) -> Optional[object]:
        """
        Try to match a device by its fully-qualified domain name.
        Checks:
          1. Exact name match against the full FQDN
          2. Exact name match against the short hostname (first DNS label)
        """
        if not fqdn:
            return None
        try:
            dev = self.nb.dcim.devices.get(name=fqdn)
            if dev:
                return dev
            if "." in fqdn:
                dev = self.nb.dcim.devices.get(name=fqdn.split(".")[0])
                if dev:
                    return dev
        except Exception as exc:
            log.debug("FQDN device lookup failed for %s: %s", fqdn, exc)
        return None

    def get_device_by_discover_id(self, discover_id: str) -> Optional[object]:
        """Return the device whose cs_discover_id custom field matches *discover_id*."""
        try:
            results = list(self.nb.dcim.devices.filter(**{"cf_cs_discover_id": discover_id}))
            return results[0] if results else None
        except Exception as exc:
            log.debug("Discover ID lookup failed for %s: %s", discover_id, exc)
            return None

    # ------------------------------------------------------------------
    # Interfaces
    # ------------------------------------------------------------------

    def get_interface(self, device_id: int, name: str) -> Optional[object]:
        return self.nb.dcim.interfaces.get(device_id=device_id, name=name)

    # ------------------------------------------------------------------
    # MAC addresses  (NetBox 4.1+ dcim.mac_addresses)
    # ------------------------------------------------------------------

    _STALE_TAG = {"name": "stale", "slug": "stale", "color": "9e9e9e"}

    _MAC_CUSTOM_FIELDS: list[dict] = [
        {
            "name":         "vendor",
            "label":        "Vendor",
            "type":         "text",
            "object_types": ["dcim.macaddress"],
            "description":  "IEEE OUI-derived organisation name for this MAC address.",
            "required":     False,
        },
        {
            "name":         "external_url",
            "label":        "External URL",
            "type":         "url",
            "object_types": ["dcim.macaddress"],
            "description":  "Link to this MAC in an external asset management tool "
                            "(e.g. CrowdStrike Falcon console).",
            "required":     False,
        },
    ]

    def ensure_mac_address_fields(self) -> None:
        """Create the 'stale' tag and MAC address custom fields if absent."""
        if not self.nb.extras.tags.get(slug="stale"):
            log.info("Creating tag: stale")
            if not self.dry_run:
                try:
                    self.nb.extras.tags.create(self._STALE_TAG)
                except Exception as exc:
                    log.error("Could not create stale tag: %s", exc)
        for field in self._MAC_CUSTOM_FIELDS:
            if not self.nb.extras.custom_fields.get(name=field["name"]):
                log.info("Creating custom field: %s on dcim.macaddress", field["name"])
                if not self.dry_run:
                    try:
                        self.nb.extras.custom_fields.create(field)
                    except Exception as exc:
                        log.error("Could not create custom field %s: %s", field["name"], exc)

    def sync_interface_macs(
        self,
        iface_id:   int,
        if_name:    str,
        snmp_macs:  set[str],
        vendor_map: Optional[dict[str, str]] = None,
    ) -> dict[str, int]:
        """
        Reconcile a set of MACs against NetBox dcim.mac_addresses for one interface.

        - Creates entries for MACs not yet in NetBox (populates vendor custom field).
        - Clears the 'stale' tag from MACs that reappear.
        - Applies the 'stale' tag to MACs present in NetBox but absent from the set.

        Returns {"created": N, "refreshed": N, "stale": N, "unchanged": N}.
        """
        counts: dict[str, int] = {"created": 0, "refreshed": 0, "stale": 0, "unchanged": 0}
        vendor_map = vendor_map or {}

        existing = list(self.nb.dcim.mac_addresses.filter(
            assigned_object_type="dcim.interface",
            assigned_object_id=iface_id,
        ))
        existing_by_mac: dict[str, object] = {
            str(obj.mac_address).lower(): obj for obj in existing
        }

        for mac in snmp_macs:
            if mac in existing_by_mac:
                obj       = existing_by_mac[mac]
                tag_slugs = [t.slug for t in (getattr(obj, "tags", None) or [])]
                if "stale" in tag_slugs:
                    log.info("REFRESH mac_address: %s on %s", mac, if_name)
                    if not self.dry_run:
                        obj.update({"tags": [{"slug": s} for s in tag_slugs if s != "stale"]})
                    counts["refreshed"] += 1
                else:
                    counts["unchanged"] += 1
            else:
                vendor = vendor_map.get(mac, "")
                log.info("CREATE mac_address: %s (%s) on interface id=%s (%s)",
                         mac, vendor or "unknown vendor", iface_id, if_name)
                if not self.dry_run:
                    try:
                        self.nb.dcim.mac_addresses.create({
                            "mac_address":          mac,
                            "assigned_object_type": "dcim.interface",
                            "assigned_object_id":   iface_id,
                            "custom_fields":        {"vendor": vendor},
                        })
                    except Exception as exc:
                        log.error("Failed to create MAC %s on %s: %s", mac, if_name, exc)
                        continue
                counts["created"] += 1

        for mac, obj in existing_by_mac.items():
            if mac not in snmp_macs:
                tag_slugs = [t.slug for t in (getattr(obj, "tags", None) or [])]
                if "stale" not in tag_slugs:
                    log.info("STALE mac_address: %s on %s", mac, if_name)
                    if not self.dry_run:
                        obj.update({"tags": [{"slug": s} for s in tag_slugs] + [{"slug": "stale"}]})
                    counts["stale"] += 1

        return counts

    # ------------------------------------------------------------------
    # CrowdStrike custom fields + tag
    # ------------------------------------------------------------------

    _CS_TAG = {"name": "crowdstrike", "slug": "crowdstrike", "color": "e5001c"}

    _CS_DEVICE_FIELDS: list[dict] = [
        {
            "name":         "crowdstrike_aid",
            "label":        "CrowdStrike AID",
            "type":         "text",
            "object_types": ["dcim.device"],
            "description":  "CrowdStrike Falcon agent ID (AID) for this device.",
            "required":     False,
        },
        {
            "name":         "last_public_ip",
            "label":        "Last Public IP",
            "type":         "text",
            "object_types": ["dcim.device"],
            "description":  "Last external/egress IP address seen by CrowdStrike Falcon.",
            "required":     False,
        },
        {
            "name":         "vulnerabilities",
            "label":        "Vulnerabilities",
            "type":         "json",
            "object_types": ["dcim.device"],
            "description":  "Vulnerability findings from CrowdStrike Spotlight. "
                            'Format: {"updated": "...", "counts": {...}, "findings": [...]}',
            "required":     False,
        },
    ]

    _CS_DEVICE_FIELDS_EXTENDED: list[dict] = [
        {
            "name":         "cs_falcon_url",
            "label":        "CS Falcon URL",
            "type":         "url",
            "object_types": ["dcim.device"],
            "description":  "Direct link to this device in the CrowdStrike Falcon console.",
            "required":     False,
        },
        {
            "name":         "cs_first_seen",
            "label":        "CS First Seen",
            "type":         "text",
            "object_types": ["dcim.device"],
            "description":  "Timestamp when the Falcon agent first enrolled on this device (ISO 8601).",
            "required":     False,
        },
        {
            "name":         "cs_last_seen",
            "label":        "CS Last Seen",
            "type":         "text",
            "object_types": ["dcim.device"],
            "description":  "Timestamp of the last Falcon agent check-in (ISO 8601).",
            "required":     False,
        },
        {
            "name":         "cs_sensor_version",
            "label":        "CS Sensor Version",
            "type":         "text",
            "object_types": ["dcim.device"],
            "description":  "CrowdStrike Falcon sensor version installed on this device.",
            "required":     False,
        },
        {
            "name":         "cs_os_version",
            "label":        "CS OS Version",
            "type":         "text",
            "object_types": ["dcim.device"],
            "description":  "Operating system version string from CrowdStrike Falcon.",
            "required":     False,
        },
        {
            "name":         "cs_containment_status",
            "label":        "CS Containment Status",
            "type":         "text",
            "object_types": ["dcim.device"],
            "description":  "Network containment state: normal, contained, "
                            "containment_pending, or lift_containment_pending.",
            "required":     False,
        },
        {
            "name":         "cs_reduced_functionality",
            "label":        "CS Reduced Functionality",
            "type":         "boolean",
            "object_types": ["dcim.device"],
            "description":  "True if the Falcon sensor is running in Reduced Functionality Mode.",
            "required":     False,
        },
        {
            "name":         "cs_prevention_policy",
            "label":        "CS Prevention Policy",
            "type":         "text",
            "object_types": ["dcim.device"],
            "description":  "Name of the CrowdStrike prevention policy applied to this device.",
            "required":     False,
        },
        {
            "name":         "cs_groups",
            "label":        "CS Host Groups",
            "type":         "text",
            "object_types": ["dcim.device"],
            "description":  "Comma-separated list of CrowdStrike host group names.",
            "required":     False,
        },
        {
            "name":         "cs_chassis_type",
            "label":        "CS Chassis Type",
            "type":         "text",
            "object_types": ["dcim.device"],
            "description":  "Chassis type from CrowdStrike "
                            "(Desktop, Laptop, Server, Virtual Machine, Network Device, …).",
            "required":     False,
        },
        {
            "name":         "cs_zta_score",
            "label":        "CS ZTA Score",
            "type":         "integer",
            "object_types": ["dcim.device"],
            "description":  "CrowdStrike Zero Trust Assessment overall score (0–100). "
                            "Requires ZTA to be licensed.",
            "required":     False,
        },
        {
            "name":         "cs_active_detections",
            "label":        "CS Active Detections",
            "type":         "integer",
            "object_types": ["dcim.device"],
            "description":  "Count of open or in-progress CrowdStrike Falcon detections.",
            "required":     False,
        },
        {
            "name":         "cs_discover_id",
            "label":        "CS Discover Asset ID",
            "type":         "text",
            "object_types": ["dcim.device"],
            "description":  "CrowdStrike Discover asset ID for devices without a Falcon sensor "
                            "(unmanaged endpoints, network gear). "
                            "Mutually exclusive with crowdstrike_aid.",
            "required":     False,
        },
    ]

    def ensure_crowdstrike_device_fields(self) -> None:
        """Create the crowdstrike tag and base custom fields on dcim.device if absent."""
        if not self.nb.extras.tags.get(slug="crowdstrike"):
            log.info("Creating tag: crowdstrike")
            if not self.dry_run:
                try:
                    self.nb.extras.tags.create(self._CS_TAG)
                except Exception as exc:
                    log.error("Could not create crowdstrike tag: %s", exc)
        for field in self._CS_DEVICE_FIELDS:
            if not self.nb.extras.custom_fields.get(name=field["name"]):
                log.info("Creating custom field: %s on dcim.device", field["name"])
                if not self.dry_run:
                    try:
                        self.nb.extras.custom_fields.create(field)
                    except Exception as exc:
                        log.error("Could not create custom field %s: %s", field["name"], exc)

    def ensure_crowdstrike_all_fields(self) -> None:
        """Create all CrowdStrike custom fields (base + extended), the tag, and MAC fields."""
        self.ensure_crowdstrike_device_fields()
        self.ensure_mac_address_fields()
        for field in self._CS_DEVICE_FIELDS_EXTENDED:
            if not self.nb.extras.custom_fields.get(name=field["name"]):
                log.info("Creating custom field: %s on dcim.device", field["name"])
                if not self.dry_run:
                    try:
                        self.nb.extras.custom_fields.create(field)
                    except Exception as exc:
                        log.error("Could not create custom field %s: %s", field["name"], exc)

    # Custom fields written by cs_exposure.py (Exposure Management correlation)
    _CS_EXPOSURE_FIELDS: list[dict] = [
        {
            "name":         "cs_exposure_id",
            "label":        "CS Exposure Asset ID",
            "type":         "text",
            "object_types": ["dcim.device"],
            "description":  "CrowdStrike Exposure Management external asset ID. "
                            "Set when this device was correlated with an internet-facing "
                            "external asset discovered by the Exposure Management module.",
            "required":     False,
        },
        {
            "name":         "cs_exposure_criticality",
            "label":        "CS Exposure Criticality",
            "type":         "text",
            "object_types": ["dcim.device"],
            "description":  "Criticality assigned by CrowdStrike Exposure Management: "
                            "critical | high | medium | low | unknown.",
            "required":     False,
        },
        {
            "name":         "cs_internet_exposed",
            "label":        "CS Internet Exposed",
            "type":         "boolean",
            "object_types": ["dcim.device"],
            "description":  "True when the device has been correlated with an entry in the "
                            "CrowdStrike external exposure surface.",
            "required":     False,
        },
        {
            "name":         "cs_exposure_ports",
            "label":        "CS Exposure Ports",
            "type":         "json",
            "object_types": ["dcim.device"],
            "description":  "Open ports detected by CrowdStrike Exposure Management. "
                            'Format: [{"port": 443, "protocol": "tcp", "service": "https"}, …]',
            "required":     False,
        },
        {
            "name":         "cs_exposure_first_seen",
            "label":        "CS Exposure First Seen",
            "type":         "text",
            "object_types": ["dcim.device"],
            "description":  "Timestamp when this device first appeared in the CrowdStrike "
                            "external exposure surface (ISO 8601).",
            "required":     False,
        },
        {
            "name":         "cs_exposure_last_seen",
            "label":        "CS Exposure Last Seen",
            "type":         "text",
            "object_types": ["dcim.device"],
            "description":  "Timestamp of the most recent scan that detected this device "
                            "in the CrowdStrike external exposure surface (ISO 8601).",
            "required":     False,
        },
        {
            "name":         "cs_exposure_match_method",
            "label":        "CS Exposure Match Method",
            "type":         "text",
            "object_types": ["dcim.device"],
            "description":  "How this device was correlated with its external exposure asset: "
                            "exposure_id | public_ip | ipam_ip | hostname.",
            "required":     False,
        },
    ]

    def ensure_exposure_fields(self) -> None:
        """Create the cs_exposure_* custom fields on dcim.device if absent."""
        for field in self._CS_EXPOSURE_FIELDS:
            if not self.nb.extras.custom_fields.get(name=field["name"]):
                log.info("Creating custom field: %s on dcim.device", field["name"])
                if not self.dry_run:
                    try:
                        self.nb.extras.custom_fields.create(field)
                    except Exception as exc:
                        log.error(
                            "Could not create custom field %s: %s", field["name"], exc
                        )
