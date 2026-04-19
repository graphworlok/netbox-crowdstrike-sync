from netbox.plugins import PluginConfig


class CrowdStrikeSyncConfig(PluginConfig):
    name = "netbox_crowdstrike_sync"
    verbose_name = "CrowdStrike Sync"
    description = "Synchronise CrowdStrike Falcon hosts into NetBox"
    version = "0.1.0"
    author = "graphworlok"
    base_url = "crowdstrike"
    min_version = "4.0.0"

    default_settings = {
        # CrowdStrike Falcon API credentials.
        # Can also be stored in a CS_FEM_TOKEN JSON file and referenced via cs_token_file.
        "cs_client_id": "",
        "cs_client_secret": "",
        "cs_base_url": "https://api.crowdstrike.com",
        "cs_console_url": "https://falcon.crowdstrike.com",
        # Path to a JSON token file (alternative to inline credentials above).
        "cs_token_file": "",

        # NetBox defaults for new devices created from CrowdStrike hosts.
        "default_site_slug": "default",
        "default_device_role_slug": "endpoint",
        "cs_workstation_role_slug": "workstation",
        "cs_server_role_slug": "server",

        # Path(s) to IEEE OUI CSV files for vendor lookup. Empty = disabled.
        "oui_file": "",
    }


config = CrowdStrikeSyncConfig
