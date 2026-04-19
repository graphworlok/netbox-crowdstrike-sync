from netbox.plugins.navigation import PluginMenu, PluginMenuButton, PluginMenuItem

menu = PluginMenu(
    label="CrowdStrike Sync",
    groups=(
        (
            "CrowdStrike",
            (
                PluginMenuItem(
                    link="plugins:netbox_crowdstrike_sync:synclog_list",
                    link_text="Sync Logs",
                    buttons=(
                        PluginMenuButton(
                            link="plugins:netbox_crowdstrike_sync:synclog_list",
                            title="View all sync logs",
                            icon_class="mdi mdi-history",
                        ),
                    ),
                ),
            ),
        ),
    ),
    icon_class="mdi mdi-shield-search",
)
