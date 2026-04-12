# ---------------------------------------------------------------------------
# netbox-crowdstrike-sync — configuration
# Copy this file and fill in your values before first use.
# ---------------------------------------------------------------------------

# --- NetBox ---
NETBOX_URL   = "https://netbox.example.com"
NETBOX_TOKEN = "YOUR_NETBOX_API_TOKEN"

# --- NetBox defaults for new devices (created from CrowdStrike hosts) ---
# Set these to slugs that already exist in your NetBox instance.
# The sync tool will create them automatically if they are absent.
DEFAULT_SITE_SLUG        = "default"    # e.g. "london-dc1"
DEFAULT_DEVICE_ROLE_SLUG = "endpoint"   # fallback role for unrecognised product types

# Device role slugs for CrowdStrike product_type_desc values.
# Created automatically if absent.
CS_WORKSTATION_ROLE_SLUG = "workstation"
CS_SERVER_ROLE_SLUG      = "server"

# ---------------------------------------------------------------------------
# IEEE OUI vendor lookup (optional)
# ---------------------------------------------------------------------------
# Path to a local copy of the IEEE OUI assignment CSV.  Download from:
#   https://standards-oui.ieee.org/oui/oui.csv   (MA-L, ~37 k entries)
#   https://standards-oui.ieee.org/oui28/mam.csv  (MA-M)
#   https://standards-oui.ieee.org/oui36/oui36.csv (MA-S)
#
# A single path string or a list of paths (all files are merged at load time).
# Leave blank to disable vendor resolution; the 'vendor' field will be empty.
OUI_FILE = ""   # e.g. "/opt/oui/oui.csv" or ["oui.csv", "mam.csv"]
