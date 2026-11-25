"""Response and request shapes of the unified matching model endpoints."""

import re

from rest_framework import serializers

from shared.derived_state import DerivedState
from shared.models.linkage import CVEDerivationClusterProposal
from shared.models.matching import Exposure, Verdict

SHA1 = re.compile(r"^[0-9a-f]{40}$")

DERIVED_STATE_CHOICES = [(s.value, s.value) for s in DerivedState]
# How an effective status was reached.
EFFECTIVE_SOURCE_CHOICES = [
    ("verdict", "a verdict"),
    ("observed", "the observed exposure"),
    ("none", "nothing known"),
]
EFFECTIVE_STATUS_CHOICES = sorted(
    {*Verdict.Kind.values, *Exposure.Observed.values}, key=str
)


class FixCommitField(serializers.RegexField):
    """A full lowercase 40-character commit sha."""

    def __init__(self, **kwargs: object) -> None:
        super().__init__(SHA1, max_length=40, **kwargs)  # type: ignore[arg-type]
        self.error_messages["invalid"] = (
            "Must be a full lowercase 40-character commit sha."
        )


class MappingRefSerializer(serializers.Serializer):
    """A product mapping as events and evidence record it, readable after it is deleted."""

    id = serializers.IntegerField(allow_null=True)
    product_key = serializers.CharField(
        allow_null=True, help_text="`kind:vendor/product` of the upstream product."
    )
    relation = serializers.CharField(
        allow_null=True, help_text="same, not_same or irrelevant."
    )
    source = serializers.CharField(
        allow_null=True, help_text="nixpkgs_meta, triage, curated or rule_file."
    )
    target = serializers.CharField(
        allow_null=True, help_text="The attribute path or attribute glob it names."
    )


class MatchEvidenceSerializer(serializers.Serializer):
    """
    Why a matcher proposed the attribute: the CVE field and value that matched the
    package field and value. Keys a matcher did not set are null.
    """

    affected_product = serializers.IntegerField(
        allow_null=True,
        help_text="Id of the affected product, a key of `affected_products`; null for matchers that do not read products (known-vuln).",
    )
    container = serializers.CharField(
        allow_null=True, help_text="Container type of the product (cna, adp)."
    )
    cve_field = serializers.CharField(
        allow_null=True,
        help_text="CVE side: which field matched (cpe, product, package_name, repo, ...).",
    )
    cve_value = serializers.CharField(
        allow_null=True,
        help_text="CVE side value; a derived term reads `original -> term`.",
    )
    pkg_field = serializers.CharField(
        allow_null=True,
        help_text="Package side: which field matched (pname, attrpath, cpe, homepage, known_vulnerabilities, ...).",
    )
    pkg_value = serializers.CharField(allow_null=True, help_text="Package side value.")
    similarity = serializers.FloatField(
        allow_null=True, help_text="String similarity for fuzzy matchers."
    )
    branches = serializers.ListField(
        child=serializers.CharField(), help_text="Branches the hit was found on."
    )
    other_hits = serializers.IntegerField(
        help_text="Other distinct reasons the same matcher hit this attribute for."
    )
    mapping = MappingRefSerializer(
        allow_null=True,
        help_text="For `curated` and `rules`: the mapping that produced the match.",
    )
    provenance_flags = serializers.IntegerField(
        allow_null=True,
        help_text="For `legacy-v2`: the provenance flags of the old link it was backfilled from.",
    )
    cve_fields = serializers.ListField(
        child=serializers.CharField(),
        help_text="For `legacy-v2`: every CVE field the old matcher matched on.",
    )


class MatchSerializer(serializers.Serializer):
    vetoed = serializers.BooleanField(
        help_text="Active, but a `not_same` mapping vetoes it; it does not count towards the score."
    )
    matcher = serializers.CharField(help_text="Matcher slug, e.g. name-trigram.")
    matcher_version = serializers.IntegerField()
    score = serializers.FloatField(help_text="Matcher-local confidence in [0, 1].")
    weight = serializers.FloatField(help_text="Base weight of the matcher.")
    contribution = serializers.FloatField(
        help_text="weight x score, the term in the attribute's noisy-OR score."
    )
    retracted = serializers.BooleanField()
    retracted_at = serializers.DateTimeField(allow_null=True)
    first_seen_at = serializers.DateTimeField()
    last_seen_at = serializers.DateTimeField()
    evidence = MatchEvidenceSerializer()


class ExposureDetailSerializer(serializers.Serializer):
    """Why the classifier decided the observed status."""

    detail = serializers.CharField(
        allow_null=True,
        help_text="Human-readable decision of the classifier, e.g. the deciding range.",
    )
    inferred = serializers.BooleanField(
        help_text="Unaffected inferred from being outside every affected range, without a default status."
    )
    range = serializers.CharField(allow_null=True, help_text="The deciding range.")
    range_source = serializers.CharField(allow_null=True)
    affected_product = serializers.IntegerField(
        allow_null=True,
        help_text="Deciding affected product, a key of `affected_products`.",
    )
    last_affected_version = serializers.CharField(allow_null=True)
    last_seen_evaluation = serializers.IntegerField(
        allow_null=True,
        help_text="For absent attributes: the last evaluation that had it.",
    )


class ExposureSerializer(serializers.Serializer):
    present = serializers.BooleanField()
    version = serializers.CharField(allow_null=True)
    observed = serializers.ChoiceField(choices=Exposure.Observed.choices)
    reason = serializers.ChoiceField(choices=Exposure.Reason.choices)
    detail = ExposureDetailSerializer()
    evaluation = serializers.IntegerField(
        allow_null=True,
        help_text="Evaluation that established the current state, a key of `evaluations`.",
    )
    first_affected_evaluation = serializers.IntegerField(allow_null=True)
    last_affected_evaluation = serializers.IntegerField(allow_null=True)
    fixed_evaluation = serializers.IntegerField(
        allow_null=True, help_text="First evaluation seen unaffected after affected."
    )
    fix_commit = serializers.CharField(allow_null=True)
    updated_at = serializers.DateTimeField()


class VerdictSerializer(serializers.Serializer):
    branch = serializers.CharField(
        allow_null=True, help_text="Branch the verdict is about, null for all branches."
    )
    verdict = serializers.ChoiceField(choices=Verdict.Kind.choices)
    fix_commit = serializers.CharField(allow_null=True)
    comment = serializers.CharField(allow_blank=True)
    author = serializers.CharField(
        allow_null=True, help_text="Username, null if set by the tracker or deleted."
    )
    created_at = serializers.DateTimeField()
    updated_at = serializers.DateTimeField()


class EffectiveStatusSerializer(serializers.Serializer):
    status = serializers.ChoiceField(
        choices=[(s, s) for s in EFFECTIVE_STATUS_CHOICES],
        help_text="A verdict kind if a verdict applies, else the observed status.",
    )
    source = serializers.ChoiceField(choices=EFFECTIVE_SOURCE_CHOICES)
    regression = serializers.BooleanField(
        help_text="A fixed verdict, but observed affected again since."
    )
    verdict_branch = serializers.CharField(
        allow_null=True,
        help_text="Branch of the verdict that applied; null if it is the all-branches verdict or none applied.",
    )


class AttributeBranchSerializer(serializers.Serializer):
    branch = serializers.CharField(
        help_text="Tracked branches first, in the order of `branches`, then untracked ones with an exposure or verdict."
    )
    exposure = ExposureSerializer(
        allow_null=True, help_text="Null if the attribute was never seen on the branch."
    )
    effective = EffectiveStatusSerializer(
        allow_null=True, help_text="Null if there is neither an exposure nor a verdict."
    )


class MatchedAttributeSerializer(serializers.Serializer):
    attrpath = serializers.CharField()
    score = serializers.FloatField(
        allow_null=True,
        help_text="Noisy-OR over active matches; null without an active match.",
    )
    rank = serializers.IntegerField(
        allow_null=True,
        help_text="1-based rank by score; null without an active match.",
    )
    has_active_match = serializers.BooleanField()
    retracted = serializers.BooleanField(
        help_text="All its matches are retracted; listed because it carries a verdict."
    )
    matches = MatchSerializer(many=True, help_text="Active first, strongest first.")
    verdicts = VerdictSerializer(many=True)
    vetoed_by = MappingRefSerializer(
        many=True, help_text="Mappings vetoing some of its active matches."
    )
    branches = AttributeBranchSerializer(many=True)


class AttributeBranchKeySerializer(serializers.Serializer):
    attrpath = serializers.CharField()
    branch = serializers.CharField(
        allow_null=True,
        help_text="Null for an attribute with no exposure on any branch.",
    )


class DerivedStateSerializer(serializers.Serializer):
    state = serializers.ChoiceField(choices=DERIVED_STATE_CHOICES)
    needs_triage = AttributeBranchKeySerializer(many=True)
    possibly_fixed = AttributeBranchKeySerializer(many=True)
    regressions = AttributeBranchKeySerializer(many=True)
    affected = AttributeBranchKeySerializer(many=True)


class TrackedBranchSerializer(serializers.Serializer):
    name = serializers.CharField()
    current_evaluation = serializers.IntegerField(allow_null=True)


class EvaluationRefSerializer(serializers.Serializer):
    commit_sha1 = serializers.CharField()
    created_at = serializers.DateTimeField()


class AffectedProductRefSerializer(serializers.Serializer):
    vendor = serializers.CharField(allow_null=True)
    product = serializers.CharField(allow_null=True)
    package_name = serializers.CharField(allow_null=True)
    repo = serializers.CharField(allow_null=True)


class SuggestionMatchingSerializer(serializers.Serializer):
    """The unified model's view of one suggestion."""

    suggestion_id = serializers.IntegerField()
    cve_id = serializers.CharField()
    status = serializers.ChoiceField(
        choices=CVEDerivationClusterProposal.Status.choices
    )
    derived = DerivedStateSerializer()
    branches = TrackedBranchSerializer(many=True)
    attribute_count = serializers.IntegerField(
        help_text="Number of candidate attributes, before `offset` and `limit`."
    )
    attributes = MatchedAttributeSerializer(
        many=True,
        help_text="Candidates ranked by score; attributes without an active match last.",
    )
    evaluations = serializers.DictField(
        child=EvaluationRefSerializer(),
        help_text="Evaluations referenced by id anywhere in this response.",
    )
    affected_products = serializers.DictField(
        child=AffectedProductRefSerializer(),
        help_text="Affected products referenced by id anywhere in this response.",
    )


class MatchingQuerySerializer(serializers.Serializer):
    offset = serializers.IntegerField(
        min_value=0, default=0, help_text="Skip this many ranked attributes."
    )
    limit = serializers.IntegerField(
        min_value=1,
        required=False,
        allow_null=True,
        default=None,
        help_text="Return at most this many ranked attributes (all by default).",
    )


class VerdictUpdateSerializer(serializers.Serializer):
    """Set or remove a verdict on several attributes of a suggestion at once."""

    package_attributes = serializers.ListField(
        child=serializers.CharField(max_length=255),
        allow_empty=False,
        help_text="Attribute names, each with a match or an exposure on this suggestion.",
    )
    branch = serializers.CharField(
        allow_null=True,
        max_length=126,
        help_text="A tracked branch, or null for all branches.",
    )
    verdict = serializers.ChoiceField(
        choices=Verdict.Kind.choices,
        allow_null=True,
        help_text="The decision; null removes the existing verdict.",
    )
    fix_commit = FixCommitField(
        required=False,
        allow_null=True,
        default=None,
        help_text="Only with `fixed`: the full commit sha of the fix.",
    )
    comment = serializers.CharField(
        required=False, allow_blank=True, default="", max_length=1000
    )

    def validate(self, attrs: dict) -> dict:
        if attrs.get("fix_commit") and attrs["verdict"] != Verdict.Kind.FIXED:
            raise serializers.ValidationError(
                {"fix_commit": "Only a `fixed` verdict carries a fix commit."}
            )
        if attrs["verdict"] is None and attrs.get("comment"):
            raise serializers.ValidationError(
                {"comment": "Removing a verdict takes no comment."}
            )
        attrs["package_attributes"] = list(dict.fromkeys(attrs["package_attributes"]))
        return attrs


class PossiblyFixedSerializer(serializers.Serializer):
    """An exposure observed fixed that no verdict answers yet."""

    id = serializers.IntegerField(help_text="Exposure id, used by the row actions.")
    suggestion_id = serializers.IntegerField()
    cve_id = serializers.CharField()
    attrpath = serializers.CharField()
    branch = serializers.CharField()
    old_version = serializers.CharField(
        allow_null=True, help_text="Last version observed affected."
    )
    new_version = serializers.CharField(allow_null=True)
    last_affected_commit = serializers.CharField(allow_null=True)
    last_affected_at = serializers.DateTimeField(allow_null=True)
    fixed_commit = serializers.CharField(
        help_text="Commit of the first evaluation observed unaffected."
    )
    fixed_at = serializers.DateTimeField()
    compare_url = serializers.URLField(allow_null=True)


class PossiblyFixedBranchSerializer(serializers.Serializer):
    name = serializers.CharField()
    count = serializers.IntegerField(help_text="Rows in the queue on this branch.")


class ConfirmFixedSerializer(serializers.Serializer):
    fix_commit = FixCommitField(
        required=False,
        allow_null=True,
        default=None,
        help_text="Full commit sha of the fix, if known.",
    )
    comment = serializers.CharField(
        required=False, allow_blank=True, default="", max_length=1000
    )


class StillAffectedSerializer(serializers.Serializer):
    comment = serializers.CharField(
        required=False, allow_blank=True, default="", max_length=1000
    )
