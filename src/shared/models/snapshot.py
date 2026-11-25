from django.contrib.postgres import fields
from django.contrib.postgres.indexes import GinIndex
from django.db import models
from django.db.models import Func, Q, Value
from django.db.models.functions import Lower
from django.utils.translation import gettext_lazy as _

from shared.matching.names import (
    ATTR_PARENT_RE,
    LANGUAGE_PREFIX_RE,
    SEPARATORS_RE,
    URL_SCHEME_RE,
    URL_TAIL_RE,
)
from shared.models.nix_evaluation import NixEvaluation, NixpkgsBranch
from shared.models.package import Package


def _regexp_replace(expression: Func | str, pattern: str, flags: str = "") -> Func:
    args = [expression, Value(pattern), Value("")]
    if flags:
        args.append(Value(flags))
    return Func(*args, function="regexp_replace")


def _normalise_name(expression: Func) -> Func:
    """SQL twin of `shared.matching.names.normalise_name` on a lowercased expression."""
    return Func(
        Func(
            expression,
            Value(SEPARATORS_RE),
            Value("-"),
            Value("g"),
            function="regexp_replace",
        ),
        Value("-"),
        function="btrim",
    )


class BranchPackageQuerySet(models.QuerySet):
    def present(self) -> "BranchPackageQuerySet":
        """Attributes that exist in their branch's current evaluation."""
        return self.filter(present=True)


class BranchPackage(models.Model):
    """
    Current state of one attribute on one branch, collapsed over systems.
    One row per (branch, attrpath); maintained by diffing consecutive current evaluations.
    """

    objects = BranchPackageQuerySet.as_manager()

    # Covered by the unique constraint on (branch, attrpath).
    branch = models.ForeignKey(
        NixpkgsBranch,
        on_delete=models.CASCADE,
        related_name="packages",
        db_index=False,
    )
    attrpath = models.CharField(max_length=255)
    # Last evaluation this attribute was seen in.
    evaluation = models.ForeignKey(
        NixEvaluation, on_delete=models.PROTECT, related_name="+"
    )
    # False once the attribute is missing from the branch's current evaluation.
    present = models.BooleanField(default=True)
    # Derivation name, e.g. `python3.12-requests-2.32.3`.
    name = models.CharField(max_length=255)
    pname = models.CharField(max_length=255)
    # May be empty.
    version = models.CharField(max_length=255)
    cpe_vendor = models.CharField(max_length=512, null=True)
    cpe_product = models.CharField(max_length=2048, null=True)
    # Not a URLField: nixpkgs has homepages Django's validator rejects.
    homepage = models.CharField(max_length=2048, null=True)
    description = models.TextField(null=True)
    # Repository-relative, e.g. `pkgs/by-name/he/hello/package.nix:47`.
    position = models.CharField(max_length=1024, null=True)
    known_vulnerabilities = fields.ArrayField(
        models.CharField(max_length=255), default=list
    )
    # Sorted.
    systems = fields.ArrayField(models.CharField(max_length=64), default=list)
    # Hash over (system, derivation path) of all systems: a cheap "anything changed" signal.
    drv_digest = models.CharField(max_length=64)
    # Display grouping only, not identity.
    package = models.ForeignKey(
        Package, null=True, on_delete=models.SET_NULL, related_name="+"
    )
    # Matching keys, computed by the database so that writers need not know about them.
    # See `shared.matching.names` for the Python twins used on the CVE side.
    match_pname = models.GeneratedField(
        expression=_normalise_name(_regexp_replace(Lower("pname"), LANGUAGE_PREFIX_RE)),
        output_field=models.CharField(max_length=255),
        db_persist=True,
    )
    match_attr = models.GeneratedField(
        expression=_normalise_name(Lower(_regexp_replace("attrpath", ATTR_PARENT_RE))),
        output_field=models.CharField(max_length=255),
        db_persist=True,
    )
    match_homepage = models.GeneratedField(
        expression=_regexp_replace(
            _regexp_replace(Lower("homepage"), URL_SCHEME_RE), URL_TAIL_RE
        ),
        output_field=models.CharField(max_length=2048, null=True),
        db_persist=True,
    )

    class Meta:  # type: ignore[override]
        constraints = [
            models.UniqueConstraint(
                fields=["branch", "attrpath"], name="branchpackage_branch_attrpath"
            ),
        ]
        indexes = [
            GinIndex(
                fields=["pname"],
                opclasses=["gin_trgm_ops"],
                name="branchpackage_pname_trgm",
            ),
            GinIndex(
                fields=["attrpath"],
                opclasses=["gin_trgm_ops"],
                name="branchpackage_attrpath_trgm",
            ),
            models.Index(
                Lower("cpe_vendor"),
                Lower("cpe_product"),
                name="branchpackage_cpe_lower",
            ),
            models.Index(
                fields=["branch", "present"], name="branchpackage_branch_present"
            ),
            models.Index(fields=["match_pname"], name="branchpackage_match_pname"),
            GinIndex(
                fields=["match_pname"],
                opclasses=["gin_trgm_ops"],
                name="branchpackage_match_pname_trgm",
            ),
            models.Index(fields=["match_attr"], name="branchpackage_match_attr"),
            models.Index(
                fields=["match_homepage"],
                condition=Q(match_homepage__isnull=False),
                name="branchpackage_match_homepage",
            ),
            # A few hundred rows per branch list known vulnerabilities.
            models.Index(
                fields=["branch"],
                condition=~Q(known_vulnerabilities=[]),
                name="branchpackage_known_vulns",
            ),
        ]

    def __str__(self) -> str:
        absent = "" if self.present else " (absent)"
        return f"{self.branch_id}:{self.attrpath} {self.version}{absent}"


class BranchPackageChange(models.Model):
    """Append-only diff log between consecutive current evaluations of a branch."""

    class Kind(models.TextChoices):
        ADDED = "added", _("added")
        REMOVED = "removed", _("removed")
        VERSION_CHANGED = "version_changed", _("version changed")
        META_CHANGED = "meta_changed", _("metadata changed")
        REBUILT = "rebuilt", _("rebuilt")

    # Covered by the index on (branch, attrpath).
    branch = models.ForeignKey(
        NixpkgsBranch,
        on_delete=models.CASCADE,
        related_name="package_changes",
        db_index=False,
    )
    attrpath = models.CharField(max_length=255)
    kind = models.CharField(max_length=32, choices=Kind.choices)
    old_version = models.CharField(max_length=255, null=True)
    new_version = models.CharField(max_length=255, null=True)
    # For META_CHANGED and VERSION_CHANGED: which metadata fields changed.
    changed_fields = fields.ArrayField(models.CharField(max_length=64), default=list)
    old_evaluation = models.ForeignKey(
        NixEvaluation, null=True, on_delete=models.PROTECT, related_name="+"
    )
    # Covered by the index on (new_evaluation, branch).
    new_evaluation = models.ForeignKey(
        NixEvaluation, on_delete=models.PROTECT, related_name="+", db_index=False
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:  # type: ignore[override]
        indexes = [
            models.Index(
                fields=["new_evaluation", "branch"],
                name="branchpkgchange_eval_branch",
            ),
            models.Index(
                fields=["branch", "attrpath"], name="branchpkgchange_branch_attr"
            ),
        ]

    def __str__(self) -> str:
        return f"{self.branch_id}:{self.attrpath} {self.kind}"
