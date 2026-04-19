import django_filters

from .choices import SyncStatusChoices, SyncSourceChoices
from .models import SyncLog


class SyncLogFilterSet(django_filters.FilterSet):
    q      = django_filters.CharFilter(method="search", label="Search")
    status = django_filters.ChoiceFilter(choices=SyncStatusChoices)
    source = django_filters.ChoiceFilter(choices=SyncSourceChoices)

    class Meta:
        model  = SyncLog
        fields = ["source", "status"]

    def search(self, queryset, name, value):
        return queryset.filter(message__icontains=value)
