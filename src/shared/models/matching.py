import pgtrigger
from django.contrib.auth.models import User
from django.contrib.postgres.indexes import GinIndex
from django.db import models
from django.db.models import Q
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from shared.models.linkage import CVEDerivationClusterProposal
from shared.models.nix_evaluation import (
    SHA1_COMMIT_REGEX,
    NixEvaluation,
    NixpkgsBranch,
    TimeStampMixin,
)

DERIVED_STATE_TABLE = "shared_suggestionderivedstate"

FIX_COMMIT_VALID = Q(fix_commit__isnull=True) | Q(fix_commit__regex=SHA1_COMMIT_REGEX)


class ProductKey(models.Model):
    """Normalised upstream product identity, deduplicated across CVEs."""

    class Kind(models.TextChoices):
        CPE = "cpe", _("CPE")
        CNA = "cna", _("CNA vendor/product")
        REPO = "repo", _("repository")
        PURL = "purl", _("package URL")

    kind = models.CharField(max_length=16, choices=Kind.choices)
    # CPE vendor / CNA vendor / repository host and owner / collection URL; "" when unknown.
    vendor = models.CharField(max_length=512, blank=True)
    # CPE product / CNA product or package name / repository name / package name.
    product = models.CharField(max_length=2048)

    class Meta:  # type: ignore[override]
        constraints = [
            models.UniqueConstraint(
                fields=["kind", "vendor", "product"], name="productkey_unique"
            ),
            models.CheckConstraint(
                condition=~Q(product=""), name="productkey_product_not_empty"
            ),
        ]
        indexes = [
            GinIndex(
                fields=["product"],
                opclasses=["gin_trgm_ops"],
                name="productkey_product_trgm",
            ),
        ]

    @staticmethod
    def normalise(value: str | None) -> str:
        """The form `vendor` and `product` are stored in."""
        return (value or "").strip().lower()

    def __str__(self) -> str:
        return f"{self.kind}:{self.vendor}/{self.product}"


class ProductName(models.Model):
    """
    A name term the name matchers derive from an affected product (`matching.view.name_terms`:
    product, packageName, product without its vendor word, tail of a qualified packageName),
    deduplicated. The CVE side of reverse name matching; derived data, not an upstream identity
    (mappings hang off `ProductKey`, never off this).
    """

    term = models.CharField(max_length=255, unique=True)

    class Meta:  # type: ignore[override]
        indexes = [
            GinIndex(
                fields=["term"],
                opclasses=["gin_trgm_ops"],
                name="productname_term_trgm",
            ),
        ]

    def __str__(self) -> str:
        return self.term


class ProductMapping(models.Model):
    """A reusable statement that an upstream product is (or is not) a nixpkgs attribute."""

    class Relation(models.TextChoices):
        SAME = "same", _("same")
        NOT_SAME = "not_same", _("not the same")
        # Nothing in nixpkgs is this product.
        IRRELEVANT = "irrelevant", _("irrelevant")

    class Source(models.TextChoices):
        NIXPKGS_META = "nixpkgs_meta", _("nixpkgs metadata")
        TRIAGE = "triage", _("triage")
        CURATED = "curated", _("curated")
        RULE_FILE = "rule_file", _("rule file")

    # Covered by the unique constraint.
    product_key = models.ForeignKey(
        ProductKey, on_delete=models.CASCADE, related_name="mappings", db_index=False
    )
    attrpath = models.CharField(max_length=255, null=True)
    attr_glob = models.CharField(max_length=255, null=True)
    relation = models.CharField(max_length=16, choices=Relation.choices)
    source = models.CharField(max_length=16, choices=Source.choices)
    auto_accept = models.BooleanField(default=False)
    created_by = models.ForeignKey(User, null=True, on_delete=models.SET_NULL)
    comment = models.TextField(blank=True)
    upstreamed_at = models.DateTimeField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:  # type: ignore[override]
        constraints = [
            models.UniqueConstraint(
                fields=["product_key", "attrpath", "attr_glob", "source"],
                nulls_distinct=False,
                name="productmapping_unique",
            ),
            # Exactly one target, or none for "nothing in nixpkgs".
            models.CheckConstraint(
                condition=Q(attrpath__isnull=False, attr_glob__isnull=True)
                | Q(attrpath__isnull=True, attr_glob__isnull=False)
                | Q(
                    attrpath__isnull=True,
                    attr_glob__isnull=True,
                    relation="irrelevant",
                ),
                name="productmapping_target",
            ),
        ]
        indexes = [
            models.Index(fields=["attrpath"], name="productmapping_attrpath"),
        ]

    def __str__(self) -> str:
        target = self.attrpath or self.attr_glob or "*"
        return f"{self.product_key} {self.relation} {target} ({self.source})"


class MatchQuerySet(models.QuerySet):
    def active(self) -> "MatchQuerySet":
        """Matches that have not been retracted."""
        return self.filter(retracted_at__isnull=True)


class Match(models.Model):
    """Relevance fact: matcher M says attribute A is the product of this CVE."""

    objects = MatchQuerySet.as_manager()

    # Covered by the unique constraint.
    suggestion = models.ForeignKey(
        CVEDerivationClusterProposal,
        on_delete=models.CASCADE,
        related_name="matches",
        db_index=False,
    )
    attrpath = models.CharField(max_length=255)
    # Slug, e.g. "nixpkgs-cpe" or "name-trigram".
    matcher = models.CharField(max_length=64)
    matcher_version = models.IntegerField()
    # Matcher-local confidence.
    score = models.FloatField()
    evidence = models.JSONField(default=dict)
    first_seen_at = models.DateTimeField(auto_now_add=True)
    # Last reconciliation that still produced this match.
    last_seen_at = models.DateTimeField(default=timezone.now)
    # Soft delete: automatic processes never hard-delete matches.
    retracted_at = models.DateTimeField(null=True)

    class Meta:  # type: ignore[override]
        verbose_name_plural = "matches"
        constraints = [
            models.UniqueConstraint(
                fields=["suggestion", "attrpath", "matcher"], name="match_unique"
            ),
            models.CheckConstraint(
                condition=Q(score__gte=0, score__lte=1), name="match_score_range"
            ),
        ]
        indexes = [
            models.Index(
                fields=["suggestion", "retracted_at"], name="match_suggestion_retracted"
            ),
            models.Index(fields=["attrpath"], name="match_attrpath"),
        ]

    def __str__(self) -> str:
        retracted = " (retracted)" if self.retracted_at else ""
        return f"{self.attrpath} via {self.matcher}@{self.matcher_version} ({self.score:.2f}){retracted}"


class Exposure(TimeStampMixin):
    """Affectedness fact: status of attribute A on branch B for this CVE, kept current by diffing."""

    class Observed(models.TextChoices):
        AFFECTED = "affected", _("affected")
        UNAFFECTED = "unaffected", _("unaffected")
        UNKNOWN = "unknown", _("unknown")
        ABSENT = "absent", _("absent")

    class Reason(models.TextChoices):
        VERSION_RANGE = "version_range", _("version range")
        NO_RANGE = "no_range", _("no range")
        UNPARSEABLE = "unparseable", _("unparseable")
        ACKNOWLEDGED = "acknowledged", _("acknowledged in nixpkgs")
        PATCH = "patch", _("patch")
        REMOVED = "removed", _("removed")
        DEFAULT_STATUS = "default_status", _("default status")

    # Covered by the unique constraint.
    suggestion = models.ForeignKey(
        CVEDerivationClusterProposal,
        on_delete=models.CASCADE,
        related_name="exposures",
        db_index=False,
    )
    attrpath = models.CharField(max_length=255)
    # Covered by the index on (branch, attrpath).
    branch = models.ForeignKey(
        NixpkgsBranch, on_delete=models.CASCADE, related_name="+", db_index=False
    )
    present = models.BooleanField(default=True)
    version = models.CharField(max_length=255, null=True)
    observed = models.CharField(max_length=16, choices=Observed.choices)
    reason = models.CharField(max_length=32, choices=Reason.choices)
    # Last evaluation that confirmed this row.
    evaluation = models.ForeignKey(
        NixEvaluation, null=True, on_delete=models.PROTECT, related_name="+"
    )
    first_affected_evaluation = models.ForeignKey(
        NixEvaluation, null=True, on_delete=models.PROTECT, related_name="+"
    )
    last_affected_evaluation = models.ForeignKey(
        NixEvaluation, null=True, on_delete=models.PROTECT, related_name="+"
    )
    # First evaluation observed unaffected after being affected.
    fixed_evaluation = models.ForeignKey(
        NixEvaluation, null=True, on_delete=models.PROTECT, related_name="+"
    )
    fix_commit = models.CharField(max_length=40, null=True)
    # Why the classifier decided `observed` (deciding range, affected product, whether
    # "unaffected" was inferred), and bookkeeping such as the last affected version.
    detail = models.JSONField(default=dict)

    class Meta:  # type: ignore[override]
        constraints = [
            models.UniqueConstraint(
                fields=["suggestion", "attrpath", "branch"], name="exposure_unique"
            ),
            models.CheckConstraint(
                condition=FIX_COMMIT_VALID, name="exposure_fix_commit_valid"
            ),
        ]
        indexes = [
            models.Index(
                fields=["branch", "attrpath"], name="exposure_branch_attrpath"
            ),
        ]

    def __str__(self) -> str:
        return f"{self.attrpath}@{self.branch_id} {self.version or '-'}: {self.observed} ({self.reason})"


class Verdict(TimeStampMixin):
    """Human (or attributed tracker) decision. Never touched by re-matching."""

    class Kind(models.TextChoices):
        IRRELEVANT = "irrelevant", _("irrelevant")
        NOT_AFFECTED = "not_affected", _("not affected")
        AFFECTED = "affected", _("affected")
        FIXED = "fixed", _("fixed")
        WONTFIX = "wontfix", _("won't fix")

    # Covered by the unique constraint.
    suggestion = models.ForeignKey(
        CVEDerivationClusterProposal,
        on_delete=models.CASCADE,
        related_name="verdicts",
        db_index=False,
    )
    attrpath = models.CharField(max_length=255)
    # Null means all branches.
    branch = models.ForeignKey(
        NixpkgsBranch, null=True, on_delete=models.CASCADE, related_name="+"
    )
    verdict = models.CharField(max_length=16, choices=Kind.choices)
    fix_commit = models.CharField(max_length=40, null=True)
    comment = models.TextField(blank=True)
    # Null means set by the tracker.
    author = models.ForeignKey(User, null=True, on_delete=models.SET_NULL)

    class Meta:  # type: ignore[override]
        constraints = [
            models.UniqueConstraint(
                fields=["suggestion", "attrpath", "branch"],
                nulls_distinct=False,
                name="verdict_unique",
            ),
            models.CheckConstraint(
                condition=FIX_COMMIT_VALID, name="verdict_fix_commit_valid"
            ),
        ]

    def __str__(self) -> str:
        return f"{self.attrpath}@{self.branch_id or '*'}: {self.verdict}"


class TrackerEvent(models.Model):
    """
    Append-only log of every change automatic processes and curators make to
    matches, exposures and verdicts.
    """

    class Kind(models.TextChoices):
        MATCH_ADDED = "match_added", _("match added")
        MATCH_RETRACTED = "match_retracted", _("match retracted")
        MATCH_RESTORED = "match_restored", _("match restored")
        MATCH_CHANGED = "match_changed", _("match changed")
        EXPOSURE_APPEARED = "exposure_appeared", _("exposure appeared")
        EXPOSURE_VERSION_CHANGED = (
            "exposure_version_changed",
            _("exposure version changed"),
        )
        EXPOSURE_BECAME_UNAFFECTED = (
            "exposure_became_unaffected",
            _("exposure became unaffected"),
        )
        EXPOSURE_BECAME_AFFECTED = (
            "exposure_became_affected",
            _("exposure became affected"),
        )
        EXPOSURE_STATUS_CHANGED = (
            "exposure_status_changed",
            _("exposure status changed"),
        )
        EXPOSURE_DISAPPEARED = "exposure_disappeared", _("exposure disappeared")
        EXPOSURE_REAPPEARED = "exposure_reappeared", _("exposure reappeared")
        VERDICT_SET = "verdict_set", _("verdict set")
        VERDICT_CHANGED = "verdict_changed", _("verdict changed")
        VERDICT_REMOVED = "verdict_removed", _("verdict removed")

    class Cause(models.TextChoices):
        EVALUATION = "evaluation", _("evaluation")
        CVE_UPDATE = "cve_update", _("CVE update")
        MATCHER = "matcher", _("matcher")
        MAPPING = "mapping", _("product mapping")
        USER = "user", _("user")
        BACKFILL = "backfill", _("backfill")

    # Covered by the index on (suggestion, created_at).
    suggestion = models.ForeignKey(
        CVEDerivationClusterProposal,
        on_delete=models.CASCADE,
        related_name="tracker_events",
        db_index=False,
    )
    kind = models.CharField(max_length=32, choices=Kind.choices)
    attrpath = models.CharField(max_length=255)
    branch = models.ForeignKey(
        NixpkgsBranch, null=True, on_delete=models.SET_NULL, related_name="+"
    )
    matcher = models.CharField(max_length=64, null=True)
    cause = models.CharField(max_length=16, choices=Cause.choices)
    evaluation = models.ForeignKey(
        NixEvaluation, null=True, on_delete=models.SET_NULL, related_name="+"
    )
    # Null means the tracker.
    actor = models.ForeignKey(User, null=True, on_delete=models.SET_NULL)
    data = models.JSONField(default=dict)
    # One id per reconciliation run, to group related events.
    batch = models.UUIDField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:  # type: ignore[override]
        indexes = [
            models.Index(
                fields=["suggestion", "created_at"], name="trackerevent_suggestion"
            ),
            models.Index(fields=["batch"], name="trackerevent_batch"),
        ]
        triggers = [
            # Every change of a match, exposure or verdict has an event (invariant 3), so the
            # events mark which suggestions' derived state must be recomputed.
            pgtrigger.Trigger(
                name="derived_state_stale_on_event",
                level=pgtrigger.Statement,
                when=pgtrigger.After,
                operation=pgtrigger.Insert,
                referencing=pgtrigger.Referencing(new="new_events"),
                func=f"""
                    INSERT INTO {DERIVED_STATE_TABLE} (suggestion_id, state, stale, updated_at)
                    SELECT DISTINCT suggestion_id, '', true, now() FROM new_events
                    ON CONFLICT (suggestion_id) DO UPDATE SET stale = true;
                    RETURN NULL;
                """,
            ),
        ]

    def __str__(self) -> str:
        return f"{self.kind} {self.attrpath} ({self.cause})"


class SuggestionDerivedState(models.Model):
    """
    The derived state of a suggestion (`shared.derived_state.derive_state`), stored so lists can
    filter on it. Database triggers mark a row `stale` whenever its inputs change (a tracker
    event, a status or rejection reason change); `flush_derived_states` recomputes stale rows
    and every writer calls it before committing. `recompute_derived_state` checks for drift.
    """

    suggestion = models.OneToOneField(
        CVEDerivationClusterProposal,
        on_delete=models.CASCADE,
        primary_key=True,
        related_name="derived",
    )
    # A `DerivedState` value; "" until first computed.
    state = models.CharField(max_length=16, blank=True, db_index=True)
    stale = models.BooleanField(default=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:  # type: ignore[override]
        db_table = DERIVED_STATE_TABLE
        indexes = [
            models.Index(
                fields=["stale"],
                condition=Q(stale=True),
                name="derivedstate_stale",
            )
        ]

    def __str__(self) -> str:
        return f"{self.suggestion_id}: {self.state}{' (stale)' if self.stale else ''}"
