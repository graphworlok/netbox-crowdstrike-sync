from django import forms

from ..choices import SyncStatusChoices, SyncSourceChoices


class SyncLogFilterForm(forms.Form):
    q = forms.CharField(
        required=False,
        label="Search",
        widget=forms.TextInput(attrs={"placeholder": "Search message…"}),
    )
    status = forms.ChoiceField(
        required=False,
        choices=[("", "Any status")] + list(SyncStatusChoices),
        label="Status",
    )
    source = forms.ChoiceField(
        required=False,
        choices=[("", "Any source")] + list(SyncSourceChoices),
        label="Source",
    )
