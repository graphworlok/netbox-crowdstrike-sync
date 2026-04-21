from django.db import models
from django.urls import reverse

from ..choices import SyncStatusChoices, SyncSourceChoices
from .querysets import PluginQuerySet


class SyncLog(models.Model):
    objects = PluginQuerySet.as_manager()

    source = models.CharField(
        max_length=20,
        choices=SyncSourceChoices,
        default=SyncSourceChoices.HOSTS,
        db_index=True,
        verbose_name="Sync Source",
    )
    started_at   = models.DateTimeField(auto_now_add=True, db_index=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    status = models.CharField(
        max_length=20,
        choices=SyncStatusChoices,
        default=SyncStatusChoices.PENDING,
        db_index=True,
    )
    message = models.TextField(blank=True)

    # Counters — semantics vary slightly by source type
    hosts_seen    = models.PositiveIntegerField(default=0, verbose_name="Hosts seen")
    hosts_created = models.PositiveIntegerField(default=0, verbose_name="Hosts created")
    hosts_updated = models.PositiveIntegerField(default=0, verbose_name="Hosts updated")
    macs_enriched = models.PositiveIntegerField(default=0, verbose_name="MACs enriched")
    ips_synced    = models.PositiveIntegerField(default=0, verbose_name="IPs synced")

    class Meta:
        ordering = ["-started_at"]
        verbose_name = "Sync Log"
        verbose_name_plural = "Sync Logs"

    def __str__(self) -> str:
        return f"{self.get_source_display()} @ {self.started_at:%Y-%m-%d %H:%M}"

    def get_absolute_url(self) -> str:
        return reverse("plugins:netbox_crowdstrike_sync:synclog", args=[self.pk])

    @property
    def duration(self):
        if self.completed_at and self.started_at:
            return self.completed_at - self.started_at
        return None

    def get_status_color(self) -> str:
        return SyncStatusChoices.colors.get(self.status, "secondary")

    def get_source_color(self) -> str:
        return SyncSourceChoices.colors.get(self.source, "secondary")
