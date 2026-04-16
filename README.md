# netbox-crowdstrike-sync

Standalone Python scripts that pull host and vulnerability data from CrowdStrike Falcon and push it into NetBox. This is a device inventory tool — it creates and updates NetBox Device records. Vulnerability findings are stored on Device custom fields as a JSON summary; for full per-CVE finding management use [netbox-vuln-manager](https://github.com/graphworlok/netbox-vuln-manager) alongside this tool.

---

## What it does

- **Device sync** (`cs_sync.py`) — creates or updates NetBox `dcim.device` records from CrowdStrike Falcon host inventory, including MAC addresses, interfaces, IP addresses, OS version, sensor metadata, containment status, ZTA score, and active detection counts
- **MAC enrichment** (`cs_enrich.py`) — adds a `crowdstrike_url` field to entries in NetBox interface MAC tables so device records link back to the Falcon console
- **Import helper** (`cs_import.py`) — one-shot import of hosts from a CSV or JSON export

---

## Requirements

- Python 3.10+
- A running NetBox instance (v4.0+) with an API token
- CrowdStrike Falcon API credentials with the following scopes:
  - `Hosts: Read`
  - `Spotlight Vulnerabilities: Read` (required for `--vulns`)
  - `Zero Trust Assessment: Read` (required for `--zta`)
  - `Detections: Read` (required for `--detections`)

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/graphworlok/netbox-crowdstrike-sync.git
cd netbox-crowdstrike-sync
```

### 2. Create a virtual environment and install dependencies

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Dependencies: `pynetbox`, `crowdstrike-falconpy`, `click`, `rich`

### 3. Configure NetBox connection

Edit `config.py`:

```python
NETBOX_URL   = "https://netbox.example.com"
NETBOX_TOKEN = "YOUR_NETBOX_API_TOKEN"
```

Set `DEFAULT_SITE_SLUG` and `DEFAULT_DEVICE_ROLE_SLUG` to slugs that already exist in your NetBox, or the tool will create them automatically on first run.

### 4. Configure CrowdStrike credentials

Create a JSON credential file (default path: `CS_FEM_TOKEN` in the working directory):

```json
{
    "client_id":     "your-client-id",
    "client_secret": "your-client-secret",
    "base_url":      "https://api.crowdstrike.com",
    "console_url":   "https://falcon.crowdstrike.com"
}
```

`base_url` and `console_url` are optional and default to the values above. Store this file outside of source control (add it to `.gitignore`).

### 5. (Optional) Set up OUI vendor lookup

Download the IEEE OUI CSV files and set `OUI_FILES` in `config.py` to their paths. This allows the tool to populate the `vendor` custom field on MAC address records.

```bash
# Download the three IEEE OUI files
curl -o oui-mal.csv    https://standards-oui.ieee.org/oui/oui.csv
curl -o oui-mam.csv    https://standards-oui.ieee.org/oui28/mam.csv
curl -o oui-mas.csv    https://standards-oui.ieee.org/oui36/oui36.csv
```

```python
# config.py
OUI_FILES = ["oui-mal.csv", "oui-mam.csv", "oui-mas.csv"]
```

---

## Usage

### `cs_sync.py` — full device sync

```bash
# Full sync — all data sources
python cs_sync.py

# See what would change without writing anything to NetBox
python cs_sync.py --dry-run

# Limit to a subset of hosts using a CrowdStrike FQL filter
python cs_sync.py --filter "tags:'corp'"

# Skip optional data sources to speed up the run
python cs_sync.py --no-vulns        # skip Spotlight vulnerability counts
python cs_sync.py --no-zta          # skip Zero Trust Assessment scores
python cs_sync.py --no-detections   # skip active detection counts

# Also create IPAM IP address records for each NIC IP
python cs_sync.py --sync-ips

# Use a non-default token file path
python cs_sync.py --token-file /etc/crowdstrike/CS_FEM_TOKEN

# Refresh the external_url field on all MAC address records
python cs_sync.py --overwrite-macs
```

### `cs_enrich.py` — MAC enrichment only

Adds `crowdstrike_url` to entries in the `mac_table` JSON custom field on NetBox interfaces, without doing a full device sync:

```bash
python cs_enrich.py
python cs_enrich.py --dry-run
```

### `cs_import.py` — one-shot CSV/JSON import

```bash
python cs_import.py hosts.csv
python cs_import.py --dry-run hosts.json
```

---

## What gets created in NetBox

### Devices (`dcim.device`)

Matched to existing records in priority order: CrowdStrike AID (via `crowdstrike_aid` custom field) → hostname → MAC address → local IP.

| Field | Source |
|---|---|
| Name | `hostname` from Falcon |
| Device type | `product_type_desc` mapped to a manufacturer/model |
| Device role | Server / Workstation / Virtual Machine based on `product_type_desc` |
| Platform | OS version string |
| Tag | `crowdstrike` tag applied automatically |

### Custom fields on `dcim.device`

All custom fields are created automatically on first run if they do not exist.

| Field | Description |
|---|---|
| `crowdstrike_aid` | CrowdStrike agent ID (used for future matching) |
| `last_public_ip` | Last egress IP seen by Falcon |
| `cs_falcon_url` | Link to the host page in the Falcon console |
| `cs_first_seen` | First Falcon agent enrollment timestamp |
| `cs_last_seen` | Last Falcon agent check-in timestamp |
| `cs_sensor_version` | Installed sensor version |
| `cs_os_version` | OS version string |
| `cs_containment_status` | Network containment state |
| `cs_reduced_functionality` | True if sensor is in Reduced Functionality Mode |
| `cs_prevention_policy` | Applied Falcon prevention policy name |
| `cs_groups` | Falcon host group names (comma-separated) |
| `cs_chassis_type` | Desktop / Laptop / Server / Virtual Machine / … |
| `cs_zta_score` | Zero Trust Assessment overall score (0–100) |
| `cs_active_detections` | Count of open / in-progress Falcon detections |
| `vulnerabilities` | Spotlight findings JSON (summary counts + per-CVE list) |

### Interfaces and MAC addresses (`dcim.interface`, `dcim.mac_address`)

One interface and MAC address record is created per NIC in Falcon's `network_interfaces` list. The MAC address `external_url` field is set to the Falcon console device page for cross-referencing.

---

## Scheduling

Add a cron entry to run the sync regularly:

```
# /etc/cron.d/netbox-crowdstrike-sync

# Full sync every 6 hours
0 */6 * * * svc-netbox cd /opt/netbox-crowdstrike-sync && \
    ./venv/bin/python cs_sync.py >> /var/log/netbox/cs_sync.log 2>&1
```

---

## Project structure

```
netbox-crowdstrike-sync/
├── config.py           NetBox URL/token, default site/role slugs, OUI file paths
├── cs_sync.py          Main sync command (hosts, MACs, interfaces, custom fields)
├── cs_enrich.py        MAC table enrichment only
├── cs_import.py        One-shot import from CSV / JSON export
├── netbox_client.py    pynetbox wrapper: CRUD for devices, interfaces, MACs, custom fields
├── oui.py              IEEE OUI lookup (vendor name from MAC prefix)
└── requirements.txt
```

---

## Notes

- Custom fields on `dcim.device` are created automatically on first run. If NetBox raises a permissions error, ensure the API token has `extras.add_customfield` permission.
- The `vulnerabilities` custom field stores a JSON summary for quick dashboard visibility. For full per-CVE finding tracking with status lifecycle, enrichment, and risk scoring, use [netbox-vuln-manager](https://github.com/graphworlok/netbox-vuln-manager).
- The tool never deletes Device records from NetBox.
- Set `http_session.verify = False` in `netbox_client.py` if your NetBox uses a self-signed TLS certificate.
