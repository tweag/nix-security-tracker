from drf_spectacular.utils import extend_schema_field, extend_schema_serializer
from rest_framework import serializers

from api.unified.matching import evidence_of, mapping_of
from api.unified.serializers import (
    DERIVED_STATE_CHOICES,
    MappingRefSerializer,
    MatchEvidenceSerializer,
)
from api.unified.states import derived_state_map
from shared.cvss import compute_cvss_fields
from shared.logs.batches import (
    FoldedCreationEvent,
    FoldedEventType,
    FoldedMaintainerEvent,
    FoldedPackageEvent,
    FoldedReferenceEvent,
    FoldedStatusEvent,
    batch_events,
)
from shared.logs.events import remove_canceling_events
from shared.logs.fetchers import fetch_suggestion_events
from shared.logs.tracker import TrackerEntry, fetch_tracker_entries
from shared.models.linkage import (
    CVEDerivationClusterProposal,
    SharedValueState,
)
from shared.models.matching import Exposure, TrackerEvent, Verdict


class SuggestionReferenceUpdateSerializer(serializers.Serializer):
    """Request body for ignore/restore reference PATCH operations."""

    reference_url = serializers.URLField(
        max_length=2048,
        help_text="URL of the reference to ignore or restore.",
    )
    ignored = serializers.BooleanField(
        help_text="Set to true to ignore the reference, false to restore it.",
    )


class SuggestionMaintainerUpdateSerializer(serializers.Serializer):
    """Request body for ignore/restore maintainer PATCH operations."""

    github_id = serializers.IntegerField(
        help_text="GitHub ID of the maintainer to ignore or restore.",
    )
    ignored = serializers.BooleanField(
        help_text="Set to true to ignore the maintainer, false to restore it.",
    )


class SuggestionMaintainerAddSerializer(serializers.Serializer):
    """Request body for adding a maintainer that is not part of the original maintainers."""

    github_handle = serializers.CharField(
        max_length=200,
        help_text="GitHub handle of the maintainer to add.",
    )


class SuggestionMaintainerDeleteSerializer(serializers.Serializer):
    """Request body for deleting a manually added maintainer."""

    github_id = serializers.IntegerField(
        help_text="GitHub ID of the manually added maintainer to delete.",
    )


class SuggestionPackageUpdateSerializer(serializers.Serializer):
    """Request body for ignore/restore package PATCH operations."""

    package_attributes = serializers.ListField(
        child=serializers.CharField(max_length=255),
        allow_empty=False,
        help_text="Attribute names to ignore or restore in one go.",
    )
    ignored = serializers.BooleanField(
        help_text="True to ignore, false to restore.",
    )


class SuggestionCommentSerializer(serializers.Serializer):
    """Serializer for reading or updating a suggestion comment."""

    comment = serializers.CharField(
        allow_null=True,
        allow_blank=True,
        required=True,
        max_length=1000,
        help_text="Free-text comment. Set to empty string to clear.",
    )


class SuggestionBundleSerializer(serializers.Serializer):
    """Request/response body for adding or removing a suggestion from the issue draft."""

    in_issue_draft = serializers.BooleanField(
        help_text="Set to true to add the suggestion to the issue draft, false to remove it.",
    )


class BulkResultSerializer(serializers.Serializer):
    """Response body for a successful bulk operation."""

    affected = serializers.IntegerField(
        help_text="Number of suggestions the operation was applied to.",
    )


class BulkErrorSerializer(serializers.Serializer):
    """
    Response body for a bulk operation rejected by at least one selected suggestion.

    Bulk operations are all-or-nothing: when this is returned, nothing was modified.
    """

    detail = serializers.CharField(
        help_text="Human readable summary of the failure.",
    )
    reasons = serializers.DictField(
        child=serializers.DictField(
            child=serializers.ListField(child=serializers.CharField())
        ),
        help_text=(
            "Reasons why the operation was refused, keyed by suggestion id, then by field name."
        ),
    )


class IssueDraftPublishSerializer(serializers.Serializer):
    """Request body for publishing the issue draft (all bundled suggestions) as one issue."""

    title = serializers.CharField(
        max_length=500,
        help_text="Title of the GitHub issue to create from the bundled suggestions.",
    )


class MetricHumanReadableItemSerializer(serializers.Serializer):
    label = serializers.CharField()
    value = serializers.CharField()


class MetricSerializer(serializers.Serializer):
    format = serializers.CharField()
    vector_string = serializers.CharField()
    base_score = serializers.FloatField(allow_null=True)
    base_severity = serializers.CharField(allow_null=True)
    human_readable = MetricHumanReadableItemSerializer(many=True, allow_null=True)


class MaintainerSerializer(serializers.Serializer):
    name = serializers.CharField(allow_null=True)
    email = serializers.CharField(allow_null=True)
    github = serializers.CharField()
    matrix = serializers.CharField(allow_null=True)
    github_id = serializers.IntegerField()


class SuggestionPackageOnBranchSerializer(serializers.Serializer):
    version = serializers.CharField(allow_null=True)
    status = serializers.CharField(allow_null=True)
    updated = serializers.DateTimeField(allow_null=True)
    src_position = serializers.CharField(allow_null=True)


class SuggestionPackageSerializer(serializers.Serializer):
    branches = serializers.DictField(child=SuggestionPackageOnBranchSerializer())
    derivation_ids = serializers.ListField(child=serializers.IntegerField())
    maintainers = MaintainerSerializer(many=True)
    description = serializers.CharField(allow_null=True)


class SuggestionCategorizedPackagesSerializer(serializers.Serializer):
    original = serializers.DictField(child=SuggestionPackageSerializer())
    active = serializers.DictField(child=SuggestionPackageSerializer())
    ignored = serializers.DictField(child=SuggestionPackageSerializer())


class PackageGroupSerializer(serializers.Serializer):
    """Attributes that belong to the same package."""

    package_id = serializers.IntegerField()
    name = serializers.CharField()
    homepage = serializers.CharField(allow_null=True)
    description = serializers.CharField(allow_null=True)
    attributes = serializers.ListField(child=serializers.CharField())


class SuggestionAffectedProductSerializer(serializers.Serializer):
    name = serializers.CharField()
    version_constraints = serializers.ListField(
        child=serializers.ListField(child=serializers.CharField())
    )
    cpes = serializers.ListField(child=serializers.CharField())


class SuggestionUrlReferenceSerializer(serializers.Serializer):
    url = serializers.CharField()
    name = serializers.CharField()
    tags = serializers.ListField(child=serializers.CharField())


class SuggestionCategorizedUrlReferencesSerializer(serializers.Serializer):
    original = SuggestionUrlReferenceSerializer(many=True)
    active = SuggestionUrlReferenceSerializer(many=True)
    ignored = SuggestionUrlReferenceSerializer(many=True)


class SuggestionCategorizedMaintainersSerializer(serializers.Serializer):
    original = MaintainerSerializer(many=True)
    active = MaintainerSerializer(many=True)
    ignored = MaintainerSerializer(many=True)
    added = MaintainerSerializer(many=True)
    orphan = MaintainerSerializer(many=True)


class ActivityLogReferenceSerializer(serializers.Serializer):
    url = serializers.CharField()
    name = serializers.CharField(allow_null=True)


class TrackerChangeSerializer(serializers.Serializer):
    """
    One change the matching model recorded. Which fields are set depends on `kind`:
    match_* carry `matcher`, `score` (and `old_score`, `evidence`); exposure_* carry
    `branch`, versions, statuses and reasons; verdict_* carry `verdict` and `old_verdict`.
    """

    kind = serializers.ChoiceField(choices=TrackerEvent.Kind.choices)
    attrpath = serializers.CharField()
    branch = serializers.CharField(allow_null=True)
    matcher = serializers.CharField(allow_null=True)
    evaluation_commit = serializers.CharField(
        allow_null=True, help_text="Commit of the evaluation that caused the change."
    )
    old_version = serializers.CharField(allow_null=True)
    new_version = serializers.CharField(allow_null=True)
    old_status = serializers.ChoiceField(
        choices=Exposure.Observed.choices, allow_null=True
    )
    new_status = serializers.ChoiceField(
        choices=Exposure.Observed.choices, allow_null=True
    )
    old_reason = serializers.ChoiceField(
        choices=Exposure.Reason.choices, allow_null=True
    )
    new_reason = serializers.ChoiceField(
        choices=Exposure.Reason.choices, allow_null=True
    )
    detail = serializers.CharField(
        allow_null=True, help_text="The classifier's decision, e.g. the deciding range."
    )
    inferred = serializers.BooleanField()
    regression = serializers.BooleanField(
        help_text="Affected again after having been seen fixed."
    )
    fix_candidate = serializers.BooleanField(
        help_text="Became unaffected after affected: now in the possibly-fixed queue."
    )
    score = serializers.FloatField(allow_null=True)
    old_score = serializers.FloatField(allow_null=True)
    evidence = MatchEvidenceSerializer(allow_null=True)
    matcher_truncated = serializers.IntegerField(
        allow_null=True,
        help_text="The matcher dropped this many attributes beyond its limit in that run.",
    )
    verdict = serializers.ChoiceField(choices=Verdict.Kind.choices, allow_null=True)
    old_verdict = serializers.ChoiceField(choices=Verdict.Kind.choices, allow_null=True)
    fix_commit = serializers.CharField(allow_null=True)
    comment = serializers.CharField(allow_null=True, allow_blank=True)
    vetoed_by = MappingRefSerializer(
        allow_null=True,
        help_text="For a retraction: the `not_same` mapping that vetoed the match.",
    )
    via = serializers.CharField(
        allow_null=True,
        help_text="For verdicts: the action they came with (accept, publish, reject). For fix_landed: what was tracked (fix_commit, fixed_evaluation).",
    )
    pull_request = serializers.IntegerField(
        allow_null=True,
        help_text="fix_link_*, exposure_fix_commit_set: the pull request number.",
    )
    repository = serializers.CharField(
        allow_null=True, help_text="fix_link_*: `owner/repository` of the pull request."
    )
    base_ref = serializers.CharField(
        allow_null=True, help_text="fix_link_*: the branch the pull request targets."
    )
    title = serializers.CharField(
        allow_null=True, help_text="fix_link_*: the pull request's title."
    )
    source = serializers.CharField(
        allow_null=True,
        help_text="fix_link_*, exposure_fix_commit_set: how the pull request was linked.",
    )
    method = serializers.CharField(
        allow_null=True,
        help_text="exposure_fix_commit_set: how the pull request was confirmed as the fix.",
    )
    channel = serializers.CharField(
        allow_null=True, help_text="fix_landed: the channel the fix reached."
    )
    commit = serializers.CharField(
        allow_null=True, help_text="fix_landed: the commit of the fix."
    )
    channel_commit = serializers.CharField(
        allow_null=True,
        help_text="fix_landed: the channel commit the fix arrived with.",
    )
    landed_at = serializers.DateTimeField(
        allow_null=True, help_text="fix_landed: when the channel advanced past the fix."
    )


class ActivityLogEntrySerializer(serializers.Serializer):
    action = serializers.CharField(
        help_text="Besides the suggestion's own actions: `tracker.matches`, `tracker.exposures`, `tracker.verdicts`, `tracker.fixes` or `tracker.mixed` for a batch of matching-model changes."
    )
    timestamp = serializers.DateTimeField()
    username = serializers.CharField(allow_null=True)
    status_value = serializers.CharField(allow_null=True, default=None)
    rejection_reason = serializers.CharField(allow_null=True, default=None)
    package_names = serializers.ListField(child=serializers.CharField(), default=list)
    maintainers = MaintainerSerializer(many=True, default=list)
    references = ActivityLogReferenceSerializer(many=True, default=list)
    cause = serializers.ChoiceField(
        choices=TrackerEvent.Cause.choices,
        allow_null=True,
        default=None,
        help_text="For `tracker.*` entries: what triggered the batch.",
    )
    changes = TrackerChangeSerializer(
        many=True,
        default=list,
        help_text="For `tracker.*` entries: the changes of the batch, in order.",
    )


class SuggestionSerializer(serializers.Serializer):
    """Suggestion (proposal linking a CVE to derivations)."""

    id = serializers.IntegerField(source="pk")
    status = serializers.ChoiceField(
        choices=CVEDerivationClusterProposal.Status.choices
    )
    rejection_reason = serializers.ChoiceField(
        choices=CVEDerivationClusterProposal.RejectionReason.choices,
        allow_null=True,
        required=False,
    )
    comment = serializers.CharField(allow_null=True, required=False)
    in_issue_draft = serializers.BooleanField()
    issue_code = serializers.CharField(
        source="nixpkgs_issue.code", allow_null=True, required=False
    )

    # Fields from the cached payload
    cve_id = serializers.SerializerMethodField()
    title = serializers.SerializerMethodField()
    description = serializers.SerializerMethodField()
    affected_products = serializers.SerializerMethodField()
    packages = serializers.SerializerMethodField()
    original_packages = serializers.SerializerMethodField()
    ignored_packages = serializers.SerializerMethodField()
    # for UI grouping.
    attribute_package_groups = serializers.SerializerMethodField()
    metrics = serializers.SerializerMethodField()
    categorized_maintainers = serializers.SerializerMethodField()
    categorized_url_references = serializers.SerializerMethodField()

    # Optional inlined activity log.
    # Null unless requested via the `activity_log` query param.
    # Lets the frontend seed the activity-log query as initial data and avoid a separate request per suggestion.
    activity_log = serializers.SerializerMethodField(allow_null=True)

    # Derived state of the matching model (stored, computed live while stale).
    derived_state = serializers.SerializerMethodField()

    def _payload(self, obj: CVEDerivationClusterProposal) -> dict:
        return obj.cached.payload

    @extend_schema_field(serializers.CharField())
    def get_cve_id(self, obj: CVEDerivationClusterProposal) -> str:
        return self._payload(obj)["cve_id"]

    @extend_schema_field(serializers.CharField())
    def get_title(self, obj: CVEDerivationClusterProposal) -> str:
        return self._payload(obj)["title"]

    @extend_schema_field(serializers.CharField(allow_null=True))
    def get_description(self, obj: CVEDerivationClusterProposal) -> str | None:
        return self._payload(obj)["description"]

    @extend_schema_field(SuggestionAffectedProductSerializer(many=True))
    def get_affected_products(self, obj: CVEDerivationClusterProposal) -> list:
        data = self._payload(obj)["affected_products"]
        return [
            SuggestionAffectedProductSerializer(v | {"name": k}).data
            for k, v in data.items()
        ]

    @extend_schema_field(serializers.DictField(child=SuggestionPackageSerializer()))
    def get_packages(self, obj: CVEDerivationClusterProposal) -> dict:
        data = self._payload(obj)["packages"]
        return {k: SuggestionPackageSerializer(v).data for k, v in data.items()}

    @extend_schema_field(serializers.DictField(child=SuggestionPackageSerializer()))
    def get_original_packages(self, obj: CVEDerivationClusterProposal) -> dict:
        data = self._payload(obj)["original_packages"]
        return {k: SuggestionPackageSerializer(v).data for k, v in data.items()}

    @extend_schema_field(serializers.DictField(child=SuggestionPackageSerializer()))
    def get_ignored_packages(self, obj: CVEDerivationClusterProposal) -> dict:
        original_packages = self._payload(obj)["original_packages"]
        packages = self._payload(obj)["packages"]
        return {
            k: SuggestionPackageSerializer(v).data
            for k, v in original_packages.items()
            if k not in packages
        }

    @extend_schema_field(PackageGroupSerializer(many=True))
    def get_attribute_package_groups(self, obj: CVEDerivationClusterProposal) -> list:
        data = self._payload(obj)["attribute_package_groups"]
        return list(PackageGroupSerializer(data, many=True).data)

    @extend_schema_field(MetricSerializer(many=True))
    def get_metrics(self, obj: CVEDerivationClusterProposal) -> list:
        metrics = self._payload(obj)["metrics"]
        result = []
        for m in metrics:
            fields = compute_cvss_fields(m)
            result.append(
                MetricSerializer(
                    {
                        "format": m.get("format"),
                        "vector_string": m.get("vector_string"),
                        "base_score": fields.base_score,
                        "base_severity": fields.base_severity,
                        "human_readable": fields.human_readable,
                    }
                ).data
            )
        return result

    @extend_schema_field(SuggestionCategorizedMaintainersSerializer())
    def get_categorized_maintainers(self, obj: CVEDerivationClusterProposal) -> dict:
        data = self._payload(obj)["categorized_maintainers"]
        return dict(SuggestionCategorizedMaintainersSerializer(data).data)

    @extend_schema_field(SuggestionCategorizedUrlReferencesSerializer())
    def get_categorized_url_references(self, obj: CVEDerivationClusterProposal) -> dict:
        data = self._payload(obj)["categorized_url_references"]
        return dict(SuggestionCategorizedUrlReferencesSerializer(data).data)

    @extend_schema_field(ActivityLogEntrySerializer(many=True))
    def get_activity_log(self, obj: CVEDerivationClusterProposal) -> list | None:
        if not self.context.get("include_activity_log"):
            return None
        activity_logs = self.context.get("activity_logs")
        if activity_logs is not None and obj.pk in activity_logs:
            data = activity_logs[obj.pk]
        else:
            # Single-object fallback (e.g. retrieve) when no batched map is provided.
            data = build_activity_log_map([obj.pk]).get(obj.pk, [])
        return list(ActivityLogEntrySerializer(data, many=True).data)

    @extend_schema_field(serializers.ChoiceField(choices=DERIVED_STATE_CHOICES))
    def get_derived_state(self, obj: CVEDerivationClusterProposal) -> str:
        states = self.context.get("derived_states")
        if states is None or obj.pk not in states:
            # Single-object fallback: one query, plus a live computation if stale.
            states = derived_state_map([obj])
        return states[obj.pk]

    def to_representation(self, instance: CVEDerivationClusterProposal) -> dict:
        result = super().to_representation(instance)
        if instance.status != CVEDerivationClusterProposal.Status.REJECTED:
            result.pop("rejection_reason", None)
        if instance.status != CVEDerivationClusterProposal.Status.PUBLISHED:
            result.pop("issue_code", None)
        if not instance.comment:
            result.pop("comment", None)
        return result


class SharedPackageSerializer(serializers.Serializer):
    """A package attribute every selected suggestion holds in the same state."""

    state = serializers.ChoiceField(choices=SharedValueState.choices)
    attribute = serializers.CharField(source="value")


class SharedMaintainerSerializer(serializers.Serializer):
    """A maintainer every selected suggestion holds in the same state."""

    state = serializers.ChoiceField(choices=SharedValueState.choices)
    maintainer = MaintainerSerializer(source="value")


class SharedReferenceSerializer(serializers.Serializer):
    """A URL reference every selected suggestion holds in the same state."""

    state = serializers.ChoiceField(choices=SharedValueState.choices)
    reference = SuggestionUrlReferenceSerializer(source="value")


@extend_schema_serializer(component_name="SuggestionSharedState")
class SuggestionSharedStateSerializer(serializers.Serializer):
    """
    What a whole selection of suggestions has in common, source for allowed bulk operations.
    """

    status = serializers.ChoiceField(
        choices=CVEDerivationClusterProposal.Status.choices,
        allow_null=True,
        help_text="The status shared by the whole selection, null when they differ.",
    )
    in_issue_draft = serializers.BooleanField(
        allow_null=True,
        help_text="Whether the whole selection is in the issue draft, or out of it, null when it is mixed.",
    )
    comment = serializers.CharField(
        allow_null=True,
        allow_blank=True,
        help_text="The comment shared by the whole selection, empty when they all hold none, null when they differ.",
    )
    packages = SharedPackageSerializer(many=True)
    maintainers = SharedMaintainerSerializer(many=True)
    references = SharedReferenceSerializer(many=True)


# FIXME(@florentc): Eventually we'll want to:
# - remove cancelling events: at the model level through a proper debouncing implementation
# - batch events: at the frontend level as it's presentation-related
def folded_event_to_dict(event: FoldedEventType) -> dict:
    """Convert a FoldedEventType Pydantic model to a plain dict for serialization."""
    base: dict = {
        "action": event.action,
        "timestamp": event.timestamp,
        "username": event.username,
        "status_value": None,
        "rejection_reason": None,
        "package_names": [],
        "maintainers": [],
        "references": [],
        "cause": None,
        "changes": [],
    }
    if isinstance(event, FoldedCreationEvent):
        base["rejection_reason"] = event.rejection_reason
    elif isinstance(event, FoldedStatusEvent):
        base["status_value"] = event.status_value
        base["rejection_reason"] = event.rejection_reason
    elif isinstance(event, FoldedPackageEvent):
        base["package_names"] = event.package_names
    elif isinstance(event, FoldedMaintainerEvent):
        base["maintainers"] = [dict(m) for m in event.maintainers]
    elif isinstance(event, FoldedReferenceEvent):
        base["references"] = [dict(r) for r in event.references]
    return base


def build_activity_log_map(suggestion_ids: list[int]) -> dict[int, list[dict]]:
    """Build the folded, serializable activity log for several suggestions at once."""
    # FIXME(@florentc): Eventually we'll want to:
    # - remove cancelling events: at the model level through a proper debouncing implementation
    # - batch events: at the frontend level as it's presentation-related
    if not suggestion_ids:
        return {}

    raw_events_by_id = fetch_suggestion_events(suggestion_ids)
    tracker_entries = fetch_tracker_entries(suggestion_ids)
    result: dict[int, list[dict]] = {}
    for suggestion_id, raw_events in raw_events_by_id.items():
        deduplicated = remove_canceling_events(raw_events, sort=True)
        folded = batch_events(deduplicated)
        entries = [folded_event_to_dict(e) for e in folded] + [
            tracker_entry_to_dict(e) for e in tracker_entries.get(suggestion_id, [])
        ]
        result[suggestion_id] = sorted(entries, key=lambda e: e["timestamp"])
    return result


def tracker_entry_to_dict(entry: TrackerEntry) -> dict:
    """A batch of tracker events in the shape of the other activity log entries."""
    return {
        "action": entry["action"],
        "timestamp": entry["timestamp"],
        "username": entry["username"],
        "status_value": None,
        "rejection_reason": None,
        "package_names": [],
        "maintainers": [],
        "references": [],
        "cause": entry["cause"],
        "changes": [
            c
            | {
                "evidence": evidence_of(c["evidence"]) if c["evidence"] else None,
                "vetoed_by": mapping_of(c["vetoed_by"]),
            }
            for c in entry["changes"]
        ],
    }
