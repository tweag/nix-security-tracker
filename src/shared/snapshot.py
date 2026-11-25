"""
Per-branch package snapshot: collapse an evaluation's derivations to one row per
attribute, diff against the branch's current rows, and advance the branch's
`current_evaluation` pointer.
"""

import logging
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Literal

import pgpubsub
from django.db import connection, transaction
from django.db.backends.utils import CursorWrapper

from shared.channels import BranchSnapshotChannel
from shared.models.matching import Match
from shared.models.nix_evaluation import (
    NixDerivation,
    NixDerivationMeta,
    NixEvaluation,
    NixpkgsBranch,
)
from shared.models.package import PackageAttrpath
from shared.models.snapshot import BranchPackage, BranchPackageChange

logger = logging.getLogger(__name__)

# The system whose derivation describes an attribute when systems disagree, most preferred first.
# Systems not listed come after these, alphabetically.
SYSTEM_PREFERENCE = [
    "x86_64-linux",
    "aarch64-linux",
    "x86_64-darwin",
    "aarch64-darwin",
]

# Refuse a snapshot that would mark more than this share of the present attributes as removed:
# an evaluation that lost most of the package set is broken, not a mass removal.
MAX_REMOVED_SHARE = 0.5

# Which `REBUILT` changes to record:
# - "all": every attribute whose derivations changed without a version or metadata change;
# - "matched": only attributes some non-retracted `Match` refers to (the only ones anything acts on);
# - "none": none.
RebuiltPolicy = Literal["all", "matched", "none"]
DEFAULT_REBUILT_POLICY: RebuiltPolicy = "matched"


class Outcome(StrEnum):
    # The branch had no snapshot: rows written, no changes recorded.
    INITIALISED = "initialised"
    # Diffed against the previous current evaluation and advanced the pointer.
    ADVANCED = "advanced"
    # The evaluation is already the branch's current one.
    ALREADY_CURRENT = "already_current"
    # A newer evaluation is already current; this one finished late.
    SKIPPED_OLDER = "skipped_older"
    SKIPPED_NOT_COMPLETED = "skipped_not_completed"
    # The evaluation would remove more than `MAX_REMOVED_SHARE` of the branch's attributes.
    SKIPPED_SHRUNK = "skipped_shrunk"


@dataclass
class BranchSnapshotResult:
    branch: str
    outcome: Outcome
    attributes: int = 0
    marked_absent: int = 0
    changes: dict[str, int] = field(default_factory=dict)


@dataclass
class SnapshotResult:
    evaluation: int
    branches: list[BranchSnapshotResult] = field(default_factory=list)


def is_newer(evaluation: NixEvaluation, than: NixEvaluation | None) -> bool:
    """Creation order: `created_at`, then primary key. Never completion time."""
    if than is None:
        return True
    return (evaluation.created_at, evaluation.pk) > (than.created_at, than.pk)


def update_branch_snapshot(
    evaluation: NixEvaluation,
    branches: list[NixpkgsBranch] | None = None,
    rebuilt: RebuiltPolicy = DEFAULT_REBUILT_POLICY,
) -> SnapshotResult:
    """
    Make `evaluation` the current snapshot of each branch it is on (or of `branches`).

    Each branch is one transaction holding a lock on the branch row, so a crash leaves
    either the previous snapshot and pointer or the new ones, and a retry is a no-op.
    After commit, notifies `BranchSnapshotChannel` for every branch whose snapshot changed.
    """
    evaluation = NixEvaluation.objects.get(pk=evaluation.pk)
    result = SnapshotResult(evaluation=evaluation.pk)
    if branches is None:
        branches = list(evaluation.on_branches.all())
    for branch in branches:
        if evaluation.state != NixEvaluation.EvaluationState.COMPLETED:
            result.branches.append(
                BranchSnapshotResult(branch.pk, Outcome.SKIPPED_NOT_COMPLETED)
            )
            continue
        branch_result = _update_branch(evaluation, branch.pk, rebuilt)
        logger.info(
            "Snapshot of %s from evaluation %s: %s, %d attributes, %d marked absent, changes %s",
            branch_result.branch,
            evaluation,
            branch_result.outcome,
            branch_result.attributes,
            branch_result.marked_absent,
            branch_result.changes,
        )
        result.branches.append(branch_result)
    return result


def _update_branch(
    evaluation: NixEvaluation, branch_name: str, rebuilt: RebuiltPolicy
) -> BranchSnapshotResult:
    with transaction.atomic():
        branch = (
            NixpkgsBranch.objects.select_for_update(of=("self",))
            .select_related("current_evaluation")
            .get(pk=branch_name)
        )
        current = branch.current_evaluation
        # The pointer can be set without rows: by the data migration that introduced it, before any snapshot.
        has_rows = BranchPackage.objects.filter(branch=branch).exists()

        if current is not None and current.pk == evaluation.pk and has_rows:
            return BranchSnapshotResult(branch_name, Outcome.ALREADY_CURRENT)
        if current is not None and current.pk != evaluation.pk:
            if not is_newer(evaluation, current):
                return BranchSnapshotResult(branch_name, Outcome.SKIPPED_OLDER)

        with connection.cursor() as cursor:
            attributes = _collect(cursor, evaluation)
            if has_rows:
                present = BranchPackage.objects.filter(
                    branch=branch, present=True
                ).count()
                missing = _count_missing(cursor, branch_name)
                if present and missing > MAX_REMOVED_SHARE * present:
                    logger.error(
                        "Evaluation %s would remove %d of %d attributes of %s, refusing",
                        evaluation,
                        missing,
                        present,
                        branch_name,
                    )
                    transaction.set_rollback(True)
                    return BranchSnapshotResult(
                        branch_name, Outcome.SKIPPED_SHRUNK, attributes=attributes
                    )
                changes = _record_changes(
                    cursor,
                    branch_name,
                    old_evaluation=current.pk if current else None,
                    new_evaluation=evaluation.pk,
                    rebuilt=rebuilt,
                )
            else:
                changes = {}
            _upsert(cursor, branch_name, evaluation.pk)
            marked_absent = _mark_absent(cursor, branch_name)

        NixpkgsBranch.objects.filter(pk=branch_name).update(
            current_evaluation=evaluation
        )
        transaction.on_commit(
            lambda: pgpubsub.notify(
                BranchSnapshotChannel, evaluation_pk=evaluation.pk, branch=branch_name
            )
        )
        return BranchSnapshotResult(
            branch_name,
            Outcome.ADVANCED if has_rows else Outcome.INITIALISED,
            attributes=attributes,
            marked_absent=marked_absent,
            changes=changes,
        )


# Name and version as in `parse_drv_name`: split at the first dash not followed by a letter (and not at the start).
PNAME_SQL = r"regexp_replace(d.name, '(?<=.)-[^a-zA-Z].*$', '')"
# `/tmp/tmpXXXX/pkgs/...:LINE` (the evaluation's worktree) or `/nix/store/...-source/pkgs/...:LINE` to `pkgs/...:LINE`.
POSITION_SQL = r"regexp_replace(m.position, '^/(tmp|nix/store)/[^/]+/', '')"
# Only the file of a position counts as a change, not the line number.
POSITION_FILE_SQL = r"regexp_replace({}, ':[0-9]+$', '')"


def _collect(cursor: CursorWrapper, evaluation: NixEvaluation) -> int:
    """
    Collapse the evaluation's derivations into the temporary table `snapshot_new`, one row per attribute.

    Systems are sorted; `drv_digest` hashes the sorted (system, derivation path) pairs.
    Everything else comes from one representative derivation, chosen deterministically:
    one with metadata over one without, then by `SYSTEM_PREFERENCE`, then by system name and derivation path.
    """
    drv = NixDerivation._meta.db_table
    meta = NixDerivationMeta._meta.db_table
    attrpaths = PackageAttrpath._meta.db_table
    # Several branches can be snapshotted in one transaction, and `ON COMMIT DROP` only fires at its end.
    cursor.execute("DROP TABLE IF EXISTS snapshot_new")
    cursor.execute(
        f"""
        CREATE TEMPORARY TABLE snapshot_new ON COMMIT DROP AS
        WITH per_attribute AS (
            SELECT
                attribute AS attrpath,
                array_agg(DISTINCT system ORDER BY system) AS systems,
                encode(sha256(convert_to(
                    string_agg(system || ' ' || derivation_path, E'\\n' ORDER BY system, derivation_path),
                    'UTF8'
                )), 'hex') AS drv_digest,
                (array_agg(id ORDER BY
                    metadata_id IS NULL,
                    array_position(%s::text[], system::text) NULLS LAST,
                    system,
                    derivation_path,
                    id
                ))[1] AS representative
            FROM {drv}
            WHERE parent_evaluation_id = %s
            GROUP BY attribute
        ),
        named AS (
            SELECT p.attrpath, p.systems, p.drv_digest, d.name, {PNAME_SQL} AS pname,
                m.cpe_vendor, m.cpe_product, m.homepage, m.description,
                {POSITION_SQL} AS position,
                coalesce(m.known_vulnerabilities, '{{}}') AS known_vulnerabilities,
                a.package_id
            FROM per_attribute p
            JOIN {drv} d ON d.id = p.representative
            LEFT JOIN {meta} m ON m.id = d.metadata_id
            LEFT JOIN {attrpaths} a ON a.attrpath = p.attrpath
        )
        SELECT *,
            CASE WHEN pname = name THEN '' ELSE substr(name, char_length(pname) + 2) END AS version
        FROM named
        """,
        [SYSTEM_PREFERENCE, evaluation.pk],
    )
    count = cursor.rowcount
    cursor.execute("ANALYZE snapshot_new")
    return count


def _count_missing(cursor: CursorWrapper, branch: str) -> int:
    cursor.execute(
        f"""
        SELECT count(*) FROM {BranchPackage._meta.db_table} o
        WHERE o.branch_id = %s AND o.present
          AND NOT EXISTS (SELECT 1 FROM snapshot_new n WHERE n.attrpath = o.attrpath)
        """,
        [branch],
    )
    (count,) = cursor.fetchone() or (0,)
    return count


# Metadata whose change is a `META_CHANGED`, as (name, expression over a row alias).
META_FIELDS = [
    ("pname", "{}.pname"),
    ("cpe_vendor", "{}.cpe_vendor"),
    ("cpe_product", "{}.cpe_product"),
    ("known_vulnerabilities", "{}.known_vulnerabilities"),
    ("homepage", "{}.homepage"),
    ("position", POSITION_FILE_SQL.format("{}.position")),
]


def _record_changes(
    cursor: CursorWrapper,
    branch: str,
    old_evaluation: int | None,
    new_evaluation: int,
    rebuilt: RebuiltPolicy,
) -> dict[str, int]:
    """Write at most one `BranchPackageChange` per attribute, by the precedence of `BranchPackageChange.Kind`."""
    changed_fields = ", ".join(
        f"CASE WHEN {expr.format('n')} IS DISTINCT FROM {expr.format('o')} THEN '{name}' END"
        for name, expr in META_FIELDS
    )
    rebuilt_filter = {
        "all": "TRUE",
        "none": "FALSE",
        "matched": f"""EXISTS (
            SELECT 1 FROM {Match._meta.db_table} mt
            WHERE mt.attrpath = c.attrpath AND mt.retracted_at IS NULL
        )""",
    }[rebuilt]
    cursor.execute(
        f"""
        WITH old AS (
            SELECT * FROM {BranchPackage._meta.db_table} WHERE branch_id = %(branch)s
        ),
        compared AS (
            SELECT
                coalesce(n.attrpath, o.attrpath) AS attrpath,
                n.attrpath IS NOT NULL AS in_new,
                o.attrpath IS NOT NULL AND o.present AS in_old,
                o.version AS old_version,
                n.version AS new_version,
                n.drv_digest IS DISTINCT FROM o.drv_digest AS digest_changed,
                array_remove(ARRAY[{changed_fields}]::varchar[], NULL) AS changed_fields
            FROM snapshot_new n FULL JOIN old o ON o.attrpath = n.attrpath
        ),
        classified AS (
            SELECT *,
                CASE
                    WHEN in_new AND NOT in_old THEN '{BranchPackageChange.Kind.ADDED}'
                    WHEN in_old AND NOT in_new THEN '{BranchPackageChange.Kind.REMOVED}'
                    WHEN NOT in_new THEN NULL
                    WHEN new_version IS DISTINCT FROM old_version THEN '{BranchPackageChange.Kind.VERSION_CHANGED}'
                    WHEN cardinality(changed_fields) > 0 THEN '{BranchPackageChange.Kind.META_CHANGED}'
                    WHEN digest_changed THEN '{BranchPackageChange.Kind.REBUILT}'
                END AS kind
            FROM compared
        )
        INSERT INTO {BranchPackageChange._meta.db_table}
            (branch_id, attrpath, kind, old_version, new_version, changed_fields,
             old_evaluation_id, new_evaluation_id, created_at)
        SELECT %(branch)s, c.attrpath, c.kind,
            c.old_version,
            CASE WHEN c.in_new THEN c.new_version END,
            CASE WHEN c.kind IN ('{BranchPackageChange.Kind.VERSION_CHANGED}', '{BranchPackageChange.Kind.META_CHANGED}') THEN c.changed_fields
                 ELSE '{{}}' END,
            %(old)s, %(new)s, now()
        FROM classified c
        WHERE c.kind IS NOT NULL
          AND (c.kind <> '{BranchPackageChange.Kind.REBUILT}' OR {rebuilt_filter})
        RETURNING kind
        """,
        {"branch": branch, "old": old_evaluation, "new": new_evaluation},
    )
    counts: dict[str, int] = {}
    for (kind,) in cursor.fetchall():
        counts[kind] = counts.get(kind, 0) + 1
    return counts


def _upsert(cursor: CursorWrapper, branch: str, evaluation: int) -> None:
    columns = [
        "name",
        "pname",
        "version",
        "cpe_vendor",
        "cpe_product",
        "homepage",
        "description",
        "position",
        "known_vulnerabilities",
        "systems",
        "drv_digest",
    ]
    cursor.execute(
        f"""
        INSERT INTO {BranchPackage._meta.db_table}
            (branch_id, attrpath, evaluation_id, present, package_id, {", ".join(columns)})
        SELECT %s, attrpath, %s, TRUE, package_id, {", ".join(columns)}
        FROM snapshot_new
        ON CONFLICT (branch_id, attrpath) DO UPDATE SET
            evaluation_id = EXCLUDED.evaluation_id,
            present = TRUE,
            package_id = coalesce(EXCLUDED.package_id, {BranchPackage._meta.db_table}.package_id),
            {", ".join(f"{c} = EXCLUDED.{c}" for c in columns)}
        """,
        [branch, evaluation],
    )


def _mark_absent(cursor: CursorWrapper, branch: str) -> int:
    """Keep vanished attributes with their last known data and evaluation."""
    cursor.execute(
        f"""
        UPDATE {BranchPackage._meta.db_table} o SET present = FALSE
        WHERE o.branch_id = %s AND o.present
          AND NOT EXISTS (SELECT 1 FROM snapshot_new n WHERE n.attrpath = o.attrpath)
        """,
        [branch],
    )
    return cursor.rowcount


def fill_package_groups(branches: list[NixpkgsBranch]) -> int:
    """Set the display grouping of snapshot rows that have none yet, after clustering created it."""
    with connection.cursor() as cursor:
        cursor.execute(
            f"""
            UPDATE {BranchPackage._meta.db_table} b SET package_id = a.package_id
            FROM {PackageAttrpath._meta.db_table} a
            WHERE a.attrpath = b.attrpath AND b.package_id IS NULL AND b.branch_id = ANY(%s)
            """,
            [[b.pk for b in branches]],
        )
        return cursor.rowcount
