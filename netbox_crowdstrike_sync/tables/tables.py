import django_tables2 as tables
from netbox.tables import NetBoxTable, columns

from ..models import SyncLog


class SyncLogTable(NetBoxTable):
    source       = columns.ChoiceFieldColumn(verbose_name="Source")
    started_at   = tables.DateTimeColumn(verbose_name="Started")
    completed_at = tables.DateTimeColumn(verbose_name="Completed", orderable=True)
    status       = columns.ChoiceFieldColumn(verbose_name="Status")
    hosts_seen    = tables.Column(verbose_name="Seen")
    hosts_created = tables.Column(verbose_name="Created")
    hosts_updated = tables.Column(verbose_name="Updated")
    macs_enriched = tables.Column(verbose_name="MACs")
    ips_synced    = tables.Column(verbose_name="IPs")

    class Meta(NetBoxTable.Meta):
        model = SyncLog
        fields = (
            "pk", "source", "status", "started_at", "completed_at",
            "hosts_seen", "hosts_created", "hosts_updated", "macs_enriched", "ips_synced",
        )
        default_columns = (
            "source", "status", "started_at", "hosts_seen", "hosts_created", "hosts_updated",
        )
