"""
Version classifier: is a nixpkgs package version affected by a CVE record?

Implements the CVE JSON 5 semantics for the `affected[].versions[]` data of one affected product,
plus the shapes real records use that the schema does not describe (wildcard bounds, placeholder
lower bounds, textual ranges in `version`, git commit ranges). The core has no Django imports;
`classify_affected_products` at the bottom adapts `AffectedProduct` rows.
"""

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Literal

from univers.versions import DebianVersion, InvalidVersion

if TYPE_CHECKING:
    from shared.models.cve import AffectedProduct


class Status(StrEnum):
    AFFECTED = "affected"
    UNAFFECTED = "unaffected"
    UNKNOWN = "unknown"


class Reason(StrEnum):
    """Why a status was decided. Values match `Exposure.Reason`."""

    VERSION_RANGE = "version_range"
    DEFAULT_STATUS = "default_status"
    NO_RANGE = "no_range"
    UNPARSEABLE = "unparseable"


@dataclass(frozen=True)
class Change:
    at: str
    status: Status


@dataclass(frozen=True)
class VersionEntry:
    """One `versions[]` item of a CVE record, as stored in a `Version` row."""

    status: Status
    version: str | None = None
    less_than: str | None = None
    less_equal: str | None = None
    version_type: str | None = None
    changes: tuple[Change, ...] = ()
    id: int | None = None


@dataclass(frozen=True)
class ProductVersions:
    """
    The version data of one affected product.
    `default_status` is None when the record omits `defaultStatus`.
    `key` identifies the product (vendor, product, package name) for combining several products.
    `distribution` marks a distribution's build of a component (Red Hat's per-release rows):
    its versions and statuses describe that build, not upstream releases.
    """

    entries: Sequence[VersionEntry]
    default_status: Status | None = None
    key: str | None = None
    distribution: bool = False
    id: int | None = None


@dataclass(frozen=True)
class Bound:
    text: str
    inclusive: bool

    @property
    def is_wildcard(self) -> bool:
        return _WILDCARD.search(self.text) is not None


@dataclass(frozen=True)
class VersionRange:
    """
    An interval of versions; a missing bound is unbounded.
    `source` is `parsed` when the range was read from a textual expression such as `< 1.2.3`.
    """

    lower: Bound | None
    upper: Bound | None
    source: Literal["structured", "parsed"] = "structured"

    @property
    def is_exact(self) -> bool:
        return (
            self.lower is not None
            and self.upper is not None
            and self.lower == self.upper
            and self.lower.inclusive
        )

    def __str__(self) -> str:
        if self.lower is not None and self.is_exact:
            return f"={self.lower.text}"
        lower = (
            f"{'[' if self.lower.inclusive else '('}{self.lower.text}"
            if self.lower
            else "(*"
        )
        upper = (
            f"{self.upper.text}{']' if self.upper.inclusive else ')'}"
            if self.upper
            else "*)"
        )
        return f"{lower}, {upper}"


@dataclass(frozen=True)
class Classification:
    """
    The answer for one package version.
    `entry`/`range` name the version entry that decided it (or blocked a decision, for
    `unparseable`); `product` is the affected product it belongs to.
    """

    status: Status
    reason: Reason
    product: ProductVersions | None = None
    entry: VersionEntry | None = None
    range: VersionRange | None = None
    detail: str = ""
    silent: bool = False
    """The product has no version data comparable to any package version (git-only, none)."""


# --- Version parsing -------------------------------------------------------------------------

_WILDCARD = re.compile(r"\.[*xX]$")
_HASH = re.compile(r"^(?=[0-9a-f]*[a-f])[0-9a-f]{7,40}$")
# Lower bounds and exact versions that carry no information ("from the beginning").
_PLACEHOLDERS = {
    "",
    "0",
    "0.0",
    "0.0.0",
    "*",
    "-",
    "n/a",
    "na",
    "unspecified",
    "unknown",
    "all",
    "all versions",
}
_PRE_RELEASE = re.compile(r"[-._]?(pre|rc|alpha|beta|dev|canary)(?=[0-9.]|$)")
# nixpkgs snapshot versions: `1.2-unstable-2026-01-02`, `0+unstable20260101`, `0.0.0+rev=abc`, `20260101-git`.
_SNAPSHOT = re.compile(r"^(?P<base>.*?)[-+.]?(?:unstable|git|rev)(?:[-+=._].*|\d.*)?$")
# Trailing nixpkgs decorations of a package version: `1.2.3-envoy`, `140.1.0esr`, `1.2.3+matrix.1`.
_PACKAGE_SUFFIX = re.compile(r"(?:-[A-Za-z][A-Za-z0-9._-]*|(?<=\d)esr|\+.*)$")


@dataclass(frozen=True)
class PackageVersion:
    """
    A parsed nixpkgs package version.
    A snapshot is an unreleased commit strictly after release `base`, at an unknown distance.
    """

    text: str
    base: DebianVersion
    snapshot: bool = False


def _normalise(version: str) -> str:
    cleaned = re.sub(r"^[vV](?=\d)", "", version.strip())
    cleaned = cleaned.replace("_", ".")
    return _PRE_RELEASE.sub(r"~\1", cleaned)


def _debian(version: str) -> DebianVersion | None:
    if not version or not version[0].isdigit() or _HASH.match(version):
        return None
    try:
        # The attrs-generated constructor is invisible to pyright.
        return DebianVersion(version)  # pyright: ignore [reportCallIssue]
    except InvalidVersion:
        return None


def parse_package_version(version: str | None) -> PackageVersion | None:
    """Parse a nixpkgs version (from a derivation name). None if it cannot be compared."""
    if not version or not version.strip() or _HASH.match(version.strip()):
        return None
    text = version.strip()
    snapshot = False
    if m := _SNAPSHOT.match(text):
        text, snapshot = m.group("base").rstrip("-+._") or "0", True
    cleaned = _normalise(text)
    cleaned = _PACKAGE_SUFFIX.sub("", cleaned)
    base = _debian(cleaned)
    if base is None:
        return None
    return PackageVersion(text=version, base=base, snapshot=snapshot)


def parse_bound(text: str) -> DebianVersion | None:
    """Parse a version from a CVE record. Wildcards are handled by `_compare`."""
    cleaned = re.sub(r"\s*\([^()]*\)$", "", _normalise(text))
    # `4.35.5.1 LTS`: a version followed by words without digits.
    if " " in cleaned:
        head, _, tail = cleaned.partition(" ")
        if re.search(r"\d", tail):
            return None
        cleaned = head
    return _debian(cleaned)


def _wildcard_ceiling(text: str) -> DebianVersion | None:
    """`6.1.*` -> the least version above the whole 6.1 series (`6.2~`)."""
    prefix = _WILDCARD.sub("", text.strip())
    m = re.match(r"^(.*?)(\d+)$", _normalise(prefix))
    if not m:
        return None
    return _debian(f"{m.group(1)}{int(m.group(2)) + 1}~")


type Tri = bool | None


def _compare(
    version: PackageVersion, bound: Bound, side: Literal["lower", "upper"]
) -> Tri:
    """
    Whether `version` satisfies `bound` on `side`, or None if that cannot be told.
    A wildcard upper bound covers the whole series (`<= 6.1.*` and `< 6.1.*` both admit 6.1.9).
    """
    if bound.text.strip() == "*":
        return True
    if bound.is_wildcard:
        if side == "upper":
            ceiling = _wildcard_ceiling(bound.text)
            return None if ceiling is None else _lt(version, ceiling)
        target = parse_bound(_WILDCARD.sub("", bound.text.strip()))
        inclusive = True
    else:
        target = parse_bound(bound.text)
        inclusive = bound.inclusive
    if target is None:
        return None
    if side == "lower":
        if version.base > target or (version.base == target and version.snapshot):
            return True
        if version.base == target:
            return inclusive
        return None if version.snapshot else False
    if inclusive:
        return _le(version, target)
    return _lt(version, target)


def _lt(version: PackageVersion, target: DebianVersion) -> Tri:
    if version.base >= target:
        return False
    return None if version.snapshot else True


def _le(version: PackageVersion, target: DebianVersion) -> Tri:
    if version.base > target or (version.base == target and version.snapshot):
        return False
    return None if version.snapshot else True


def _and(a: Tri, b: Tri) -> Tri:
    if a is False or b is False:
        return False
    if a is None or b is None:
        return None
    return True


# --- Interpreting entries --------------------------------------------------------------------

_V = r"v?\d[0-9A-Za-z.+~_-]*?"
_TEXTUAL: list[tuple[re.Pattern[str], str]] = [
    (re.compile(p, re.IGNORECASE), kind)
    for p, kind in [
        # ">= 2.0, < 2.3", ">=2.0 <2.3", "> 1.0 and <= 2.0"
        (
            rf"^(?P<lop>>=?)\s*(?P<lo>{_V})\s*(?:,|and|&&)?\s*(?P<uop><=?|=<)\s*(?P<up>{_V})$",
            "both_ops",
        ),
        (rf"^(?P<uop><=?|=<)\s*(?P<up>{_V})$", "upper_op"),
        (rf"^(?P<lop>>=?)\s*(?P<lo>{_V})$", "lower_op"),
        # "1.0 through 1.4", "1.0 to 1.4", "1.0 - 1.4", "from 1.0 up to and including 1.4"
        (
            rf"^(?:from\s+)?(?P<lo>{_V})\s+(?:through|thru|to|up to(?: and including)?|-)\s+(?P<up>{_V})$",
            "inclusive",
        ),
        # "from 1.0 before 1.4", "1.0 until 1.4"
        (
            rf"^(?:from\s+)?(?P<lo>{_V})\s+(?:before|until|prior to)\s+(?P<up>{_V})$",
            "exclusive",
        ),
        # "before 1.2.3", "All driver versions prior to 595.91.07 (...)", "versions earlier than 2"
        (
            rf"^(?:all\s+)?(?:\w+\s+)?(?:versions?\s+)?(?:before|prior to|earlier than|below|lower than|older than)\s+(?P<up>{_V})(?:[\s,;(].*)?$",
            "before",
        ),
        # "up to and including 1.2", "through 1.2", "all versions up to 1.2"
        (
            rf"^(?:all\s+)?(?:\w+\s+)?(?:versions?\s+)?(?:up to and including|up to|through|until and including)\s+(?P<up>{_V})(?:[\s,;(].*)?$",
            "through",
        ),
        # "1.2 and earlier", "Versions 1.2.3 and earlier", "1.2 or prior", "595.71.05(All versions prior to and including vGPU 20.1)"
        (
            rf"^(?:versions?\s+)?(?P<up>{_V})\s*(?:and|or|&)\s+(?:earlier|prior|below|lower|older|before)(?:\s.*)?$",
            "through",
        ),
        (
            rf"^(?P<up>{_V})\s*\(\s*all versions prior to and including\b.*\)$",
            "through",
        ),
        # "1.2 and later", "2.0+" (only with nothing else after)
        (
            rf"^(?:versions?\s+)?(?P<lo>{_V})\s*(?:and|or)\s+(?:later|above|newer|higher)$",
            "from",
        ),
    ]
]


def parse_textual_range(text: str) -> VersionRange | None:
    """Read a textual range written into `version` (#1449), e.g. `< 1.2.3` or `1.0 through 1.4`."""
    s = " ".join(text.split())
    for pattern, kind in _TEXTUAL:
        m = pattern.match(s)
        if not m:
            continue
        groups = m.groupdict()
        lo, up = groups.get("lo"), groups.get("up")
        if (lo and parse_bound(lo) is None) or (up and parse_bound(up) is None):
            continue
        match kind:
            case "both_ops":
                assert lo and up
                return VersionRange(
                    Bound(lo, groups["lop"] == ">="),
                    Bound(up, groups["uop"] in ("<=", "=<")),
                    "parsed",
                )
            case "upper_op":
                assert up
                return VersionRange(
                    None, Bound(up, groups["uop"] in ("<=", "=<")), "parsed"
                )
            case "lower_op":
                assert lo
                return VersionRange(Bound(lo, groups["lop"] == ">="), None, "parsed")
            case "inclusive":
                assert lo and up
                return VersionRange(Bound(lo, True), Bound(up, True), "parsed")
            case "exclusive":
                assert lo and up
                return VersionRange(Bound(lo, True), Bound(up, False), "parsed")
            case "before":
                assert up
                return VersionRange(None, Bound(up, False), "parsed")
            case "through":
                assert up
                return VersionRange(None, Bound(up, True), "parsed")
            case "from":
                assert lo
                return VersionRange(Bound(lo, True), None, "parsed")
    return None


def _is_placeholder(text: str | None) -> bool:
    return text is None or text.strip().lower() in _PLACEHOLDERS


def is_git_entry(entry: VersionEntry) -> bool:
    """
    Entries whose bounds are commit ids, not comparable to a package version.
    Some CNAs (Zabbix) label release-number ranges `versionType: "git"`; those are compared.
    """
    texts = (entry.version, entry.less_than, entry.less_equal)
    bounds = [
        b.strip() for b in texts if b and not _is_placeholder(b) and b.strip() != "*"
    ]
    if any(_HASH.match(b) for b in bounds):
        return True
    if (entry.version_type or "").lower() == "git":
        return any(parse_bound(_WILDCARD.sub("", b)) is None for b in bounds)
    return False


def interpret(entry: VersionEntry) -> VersionRange | None:
    """
    The range an entry denotes, or None for a placeholder that carries no version information
    (`version: "n/a"` without an upper bound).
    """
    upper_text = entry.less_equal or entry.less_than
    if upper_text is not None and upper_text.strip():
        # Chromium records write `{version: X, lessThan: X}` for "< X", an empty range.
        empty = entry.less_equal is None and entry.version == upper_text
        lower = (
            None
            if _is_placeholder(entry.version) or empty
            else Bound(entry.version or "", True)
        )
        upper = (
            None
            if upper_text.strip() == "*"
            else Bound(upper_text, entry.less_equal is not None)
        )
        return VersionRange(lower, upper)
    version = (entry.version or "").strip()
    if version == "*":
        return VersionRange(None, None)
    if _is_placeholder(version):
        return None
    if _WILDCARD.search(version):
        return VersionRange(
            Bound(_WILDCARD.sub("", version), True), Bound(version, True)
        )
    if parse_bound(version) is None or re.match(r"^[<>=]", version):
        if parsed := parse_textual_range(version):
            return parsed
    return VersionRange(Bound(version, True), Bound(version, True))


def _contains(version: PackageVersion, range_: VersionRange) -> Tri:
    if range_.is_exact and range_.lower is not None:
        target = parse_bound(range_.lower.text)
        if target is None:
            return None
        if version.base == target and not version.snapshot:
            return True
        if version.snapshot and version.base < target:
            return None
        return False
    lower: Tri = (
        True if range_.lower is None else _compare(version, range_.lower, "lower")
    )
    upper: Tri = (
        True if range_.upper is None else _compare(version, range_.upper, "upper")
    )
    return _and(lower, upper)


def _apply_changes(version: PackageVersion, entry: VersionEntry) -> Status | None:
    """The entry's status after its `changes`, or None if a change point is not comparable."""
    status = entry.status
    for change in _sorted_changes(entry.changes):
        reached = _compare(version, Bound(change.at, True), "lower")
        if reached is None:
            return None
        if reached:
            status = change.status
    return status


def _sorted_changes(changes: Iterable[Change]) -> list[Change]:
    keyed = [(parse_bound(c.at), c) for c in changes]
    if any(k is None for k, _ in keyed):
        return list(changes)
    return [c for _, c in sorted(keyed, key=lambda kc: kc[0])]  # pyright: ignore [reportArgumentType, reportCallIssue]


# --- Classification --------------------------------------------------------------------------


def classify_product(
    version: str | None,
    product: ProductVersions,
    missing_default: Status = Status.UNKNOWN,
) -> Classification:
    """
    Classify `version` against one affected product, following the CVE JSON 5 rule:
    the first entry whose range contains the version gives the status (adjusted by its
    `changes`); if none does, `defaultStatus` applies, and `missing_default` if it is absent
    (the schema says "unknown").

    Deviations, all towards "unknown" rather than a false "unaffected":
    - Placeholder entries (`version: "n/a"` and the like, no upper bound) are skipped. A product
      without other entries is `no_range` whatever its `defaultStatus`: in practice such rows
      are Red Hat's per-release statuses, which say nothing about upstream versions.
    - Distribution products are `no_range`.
    - Git entries are another coordinate system for the same ranges. They are ignored when the
      product also has comparable entries, otherwise the product abstains (`unparseable`).
    - An entry that cannot be evaluated (unparseable bound, or a nixpkgs snapshot version that
      may or may not be inside the range) does not stop the scan. The first definite match, or
      the default, is used only if every undecidable entry before it has the same status;
      otherwise the answer is `unknown` with reason `unparseable`, naming that entry.
    """
    if product.distribution:
        return Classification(
            Status.UNKNOWN,
            Reason.NO_RANGE,
            product,
            detail="describes a distribution build",
            silent=True,
        )
    git = [e for e in product.entries if is_git_entry(e)]
    ranged = [
        (e, r)
        for e in product.entries
        if not is_git_entry(e) and (r := interpret(e)) is not None
    ]
    default = product.default_status
    placeholders = [
        e for e in product.entries if not is_git_entry(e) and interpret(e) is None
    ]
    if not ranged:
        if git:
            return Classification(
                Status.UNKNOWN,
                Reason.UNPARSEABLE,
                product,
                git[0],
                detail="only git commit ranges",
                silent=True,
            )
        return Classification(
            Status.UNKNOWN,
            Reason.NO_RANGE,
            product,
            placeholders[0] if placeholders else None,
            detail="no version data",
            silent=True,
        )

    parsed = parse_package_version(version)
    if parsed is None:
        return Classification(
            Status.UNKNOWN,
            Reason.UNPARSEABLE,
            product,
            detail=f"package version {version!r} not comparable",
        )

    undecided: list[tuple[VersionEntry, VersionRange]] = []
    for entry, range_ in ranged:
        contained = _contains(parsed, range_)
        if contained is False:
            continue
        status = _apply_changes(parsed, entry) if contained else None
        if contained is None or status is None:
            undecided.append((entry, range_))
            continue
        if blocker := next(((e, r) for e, r in undecided if e.status != status), None):
            return _undecidable(product, parsed, *blocker)
        return Classification(
            status,
            Reason.VERSION_RANGE,
            product,
            entry,
            range_,
            detail=f"{parsed.text} in {range_}",
        )

    fallback = default if default is not None else missing_default
    if blocker := next(((e, r) for e, r in undecided if e.status != fallback), None):
        return _undecidable(product, parsed, *blocker)
    listed = ", ".join(str(r) for _, r in ranged)
    return Classification(
        fallback,
        Reason.DEFAULT_STATUS,
        product,
        detail=f"{parsed.text} outside {listed}",
    )


def _undecidable(
    product: ProductVersions,
    version: PackageVersion,
    entry: VersionEntry,
    range_: VersionRange,
) -> Classification:
    return Classification(
        Status.UNKNOWN,
        Reason.UNPARSEABLE,
        product,
        entry,
        range_,
        detail=f"cannot tell whether {version.text} is in {range_}",
    )


def classify(
    version: str | None,
    products: Sequence[ProductVersions],
    missing_default: Status = Status.UNKNOWN,
) -> Classification:
    """
    Classify `version` against the affected products a match came from.

    Products that describe the same thing (same `key`, as the Linux kernel's git and semver
    entries do) are merged first: a product whose data is not comparable at all (git-only, no
    versions) gives way to another description of the same product.

    Across different products the match does not say which one the package is, so the result
    is conservative: affected if any product says affected; otherwise unknown if any says
    unknown or abstains; unaffected only if every product says unaffected. The returned
    classification is that of the product that determined the answer.
    """
    if not products:
        return Classification(Status.UNKNOWN, Reason.NO_RANGE, detail="no product")
    groups: dict[str | int, list[Classification]] = {}
    for i, product in enumerate(products):
        groups.setdefault(product.key or i, []).append(
            classify_product(version, product, missing_default)
        )
    results: list[Classification] = []
    for group in groups.values():
        decided = [c for c in group if not c.silent]
        results.extend(decided or group)
    for wanted in (Status.AFFECTED, Status.UNKNOWN):
        if hit := next((c for c in results if c.status == wanted), None):
            return hit
    return results[0]


# --- Adapter for database rows ---------------------------------------------------------------


def product_key(
    vendor: str | None, product: str | None, package_name: str | None
) -> str:
    return "\x1f".join(
        (x or "").strip().lower() for x in (vendor, product, package_name)
    )


def is_distribution_product(
    vendor: str | None, product: str | None, collection_url: str | None
) -> bool:
    """Red Hat records describe RHEL builds (`collectionURL` is its package browser)."""
    return "access.redhat.com" in (collection_url or "") or (
        (vendor or "").lower() == "red hat"
        and (product or "").lower().startswith("red hat")
    )


def products_from_rows(
    affected_products: Iterable["AffectedProduct"],
) -> list[ProductVersions]:
    """
    Build classifier input from `AffectedProduct` rows.
    Entries are taken in insertion order (`Version.pk`), which is the record's order.
    `defaultStatus` absent and "unknown" are indistinguishable after ingestion.
    """
    return [
        ProductVersions(
            entries=[
                VersionEntry(
                    status=Status(v.status),
                    version=v.version,
                    less_than=v.less_than,
                    less_equal=v.less_equal,
                    version_type=v.version_type,
                    id=v.pk,
                )
                for v in sorted(ap.versions.all(), key=lambda v: v.pk)
            ],
            default_status=Status(ap.default_status),
            key=product_key(ap.vendor, ap.product, ap.package_name),
            distribution=is_distribution_product(
                ap.vendor, ap.product, ap.collection_url
            ),
            id=ap.pk,
        )
        for ap in affected_products
    ]


def classify_affected_products(
    version: str | None, affected_products: Iterable["AffectedProduct"]
) -> Classification:
    """Classify a package version against the given `AffectedProduct` rows."""
    return classify(version, products_from_rows(affected_products))
