import pytest

from shared.models.cve import AffectedProduct, Version
from shared.versions import (
    Bound,
    Change,
    ProductVersions,
    Reason,
    Status,
    VersionEntry,
    VersionRange,
    classify,
    classify_affected_products,
    classify_product,
    interpret,
    parse_package_version,
    parse_textual_range,
)

A = Status.AFFECTED
U = Status.UNAFFECTED
K = Status.UNKNOWN


def entry(
    status: Status = A,
    version: str | None = None,
    lt: str | None = None,
    le: str | None = None,
    vt: str | None = None,
    changes: tuple[Change, ...] = (),
) -> VersionEntry:
    return VersionEntry(
        status=status,
        version=version,
        less_than=lt,
        less_equal=le,
        version_type=vt,
        changes=changes,
    )


def product(
    *entries: VersionEntry, default: Status | None = None, key: str | None = None
) -> ProductVersions:
    return ProductVersions(entries=list(entries), default_status=default, key=key)


TWO_RANGES = product(
    entry(A, "2.0", lt="2.0.5"), entry(A, "3.0", lt="3.0.2"), default=U
)

# Shape of a Linux kernel CNA record: one product with git ranges, one with semver ranges.
KERNEL_GIT = product(
    entry(A, "1da177e4c3f4", lt="6d4b0c2d3a6f", vt="git"),
    entry(A, "1da177e4c3f4", lt="9a8b7c6d5e4f", vt="git"),
    default=U,
    key="linux",
)
KERNEL_SEMVER = product(
    entry(A, "6.1"),
    entry(U, "0", lt="6.1", vt="semver"),
    entry(U, "6.1.50", le="6.1.*", vt="semver"),
    entry(U, "6.6", le="*", vt="original_commit_for_fix"),
    default=A,
    key="linux",
)

CASES: list[tuple[str, ProductVersions, str | None, Status, Reason]] = [
    # Plain ranges, lower bound honoured (the report's example).
    ("in first range", TWO_RANGES, "2.0.3", A, Reason.VERSION_RANGE),
    ("in second range", TWO_RANGES, "3.0.1", A, Reason.VERSION_RANGE),
    ("between ranges", TWO_RANGES, "2.1.0", U, Reason.DEFAULT_STATUS),
    ("below all ranges", TWO_RANGES, "1.9", U, Reason.DEFAULT_STATUS),
    ("upper bound exclusive", TWO_RANGES, "2.0.5", U, Reason.DEFAULT_STATUS),
    ("lower bound inclusive", TWO_RANGES, "2.0", A, Reason.VERSION_RANGE),
    (
        "lessThanOrEqual inclusive",
        product(entry(A, "1.0", le="1.4"), default=U),
        "1.4",
        A,
        Reason.VERSION_RANGE,
    ),
    (
        "missing defaultStatus outside affected ranges",
        product(entry(A, "0", lt="1.2")),
        "1.3",
        U,
        Reason.DEFAULT_STATUS,
    ),
    # Lower bounds meaning "from the beginning".
    *[
        (
            f"lower bound {lower!r}",
            product(entry(A, lower, lt="1.2"), default=U),
            "0.5",
            A,
            Reason.VERSION_RANGE,
        )
        for lower in ["0", "0.0.0", "unspecified", "n/a", "*", ""]
    ],
    (
        "lessThan *",
        product(entry(U, "2.570", lt="*"), entry(A, "0", lt="2.570"), default=K),
        "2.600",
        U,
        Reason.VERSION_RANGE,
    ),
    # Exact versions, first match wins.
    (
        "exact version",
        product(entry(A, "1.2.3"), default=U),
        "1.2.3",
        A,
        Reason.VERSION_RANGE,
    ),
    (
        "exact version miss",
        product(entry(A, "1.2.3"), default=U),
        "1.2.4",
        U,
        Reason.DEFAULT_STATUS,
    ),
    (
        "first entry wins",
        product(entry(U, "1.5"), entry(A, "1.0", lt="2.0"), default=U),
        "1.5",
        U,
        Reason.VERSION_RANGE,
    ),
    # Wildcard upper bounds.
    ("kernel stable fixed", KERNEL_SEMVER, "6.1.55", U, Reason.VERSION_RANGE),
    ("kernel stable vulnerable", KERNEL_SEMVER, "6.1.20", A, Reason.DEFAULT_STATUS),
    ("kernel before introduction", KERNEL_SEMVER, "5.15.170", U, Reason.VERSION_RANGE),
    ("kernel mainline fixed", KERNEL_SEMVER, "6.12.3", U, Reason.VERSION_RANGE),
    ("kernel unfixed series", KERNEL_SEMVER, "6.2.1", A, Reason.DEFAULT_STATUS),
    (
        "lessThan wildcard covers the series",
        product(entry(U, "2.568.3", lt="2.568.*"), default=A),
        "2.568.9",
        U,
        Reason.VERSION_RANGE,
    ),
    (
        "wildcard excludes next series pre-release",
        product(entry(U, "6.1.50", le="6.1.*"), default=A),
        "6.2rc1",
        A,
        Reason.DEFAULT_STATUS,
    ),
    (
        "exact wildcard",
        product(entry(A, "4.2.*"), default=U),
        "4.2.7",
        A,
        Reason.VERSION_RANGE,
    ),
    # Git ranges are never a false "unaffected".
    ("git only", KERNEL_GIT, "6.1.20", K, Reason.UNPARSEABLE),
    (
        "unlabelled commit hash bound",
        product(
            entry(A, "0", lt="f72cf46f601efb2a0618c3814cc2f61380b38930"), default=U
        ),
        "1.0",
        K,
        Reason.UNPARSEABLE,
    ),
    (
        "versionType git with release numbers (Zabbix)",
        product(
            entry(A, "6.0.0", le="6.0.47", vt="git", changes=(Change("6.0.48", U),)),
            default=K,
        ),
        "6.0.46",
        A,
        Reason.VERSION_RANGE,
    ),
    (
        "Chromium empty range means below the bound",
        product(entry(A, "155.0.8059.39", lt="155.0.8059.39")),
        "155.0.8059.20",
        A,
        Reason.VERSION_RANGE,
    ),
    (
        "versionless product listed as unaffected",
        product(default=U),
        "1.0",
        K,
        Reason.NO_RANGE,
    ),
    (
        "git entries ignored next to semver ones",
        product(
            entry(A, "abc1234def", lt="def5678abc", vt="git"),
            entry(A, "1.0", lt="1.4", vt="semver"),
            default=U,
        ),
        "1.5",
        U,
        Reason.DEFAULT_STATUS,
    ),
    # Textual ranges in `version` (#1449).
    *[
        (
            f"textual {text!r} {pkg}",
            product(entry(A, text), default=U),
            pkg,
            status,
            reason,
        )
        for text, pkg, status, reason in [
            ("< 1.2.3", "1.2.2", A, Reason.VERSION_RANGE),
            ("< 1.2.3", "1.2.3", U, Reason.DEFAULT_STATUS),
            ("<= 1.2", "1.2", A, Reason.VERSION_RANGE),
            ("before 1.2.3", "1.2.3", U, Reason.DEFAULT_STATUS),
            ("prior to 1.2.3", "1.1", A, Reason.VERSION_RANGE),
            ("1.0 through 1.4", "1.4", A, Reason.VERSION_RANGE),
            ("1.0 through 1.4", "0.9", U, Reason.DEFAULT_STATUS),
            (">= 2.0, < 2.3", "2.2.9", A, Reason.VERSION_RANGE),
            (">= 2.0, < 2.3", "1.9", U, Reason.DEFAULT_STATUS),
            (
                "All driver versions prior to 580.178.04",
                "580.95.05",
                A,
                Reason.VERSION_RANGE,
            ),
            ("Versions 1.2.3 and earlier", "1.2.4", U, Reason.DEFAULT_STATUS),
        ]
    ],
    # Unparseable data.
    (
        "product name as version",
        product(entry(A, "WSA8845H"), default=U),
        "1.0",
        K,
        Reason.UNPARSEABLE,
    ),
    (
        "unparseable entry with the default's status is harmless",
        product(entry(U, "WSA8845H"), entry(A, "0", lt="1.0"), default=U),
        "1.5",
        U,
        Reason.DEFAULT_STATUS,
    ),
    (
        "unparseable package version",
        TWO_RANGES,
        "5aff249fdc119caa1464af9405259799b4f69d8b",
        K,
        Reason.UNPARSEABLE,
    ),
    ("empty package version", TWO_RANGES, "", K, Reason.UNPARSEABLE),
    ("missing package version", TWO_RANGES, None, K, Reason.UNPARSEABLE),
    # No usable version data.
    ("no entries", product(), "1.0", K, Reason.NO_RANGE),
    ("placeholder only", product(entry(A, "n/a")), "1.0", K, Reason.NO_RANGE),
    (
        "defaultStatus only",
        product(default=A),
        "1.0",
        K,
        Reason.NO_RANGE,
    ),
    (
        "distribution build",
        ProductVersions(
            [entry(U, "2.14.3-2.1.hum1", lt="*", vt="rpm")],
            default_status=A,
            distribution=True,
        ),
        "2.14.3",
        K,
        Reason.NO_RANGE,
    ),
    (
        "parenthesised comment in bounds",
        product(
            entry(
                A, "15.64.0 (Legacy Windows 7 & 8)", lt="15.64.8 (Legacy Windows 7 & 8)"
            ),
            default=U,
        ),
        "3.93.0",
        U,
        Reason.DEFAULT_STATUS,
    ),
    (
        "all versions",
        product(entry(A, "*"), default=U),
        "1.0",
        A,
        Reason.VERSION_RANGE,
    ),
    # nixpkgs version shapes.
    (
        "unstable after the fix",
        product(entry(A, "2.0", lt="2.0.5"), default=U),
        "2.0.5-unstable-2026-01-02",
        U,
        Reason.DEFAULT_STATUS,
    ),
    (
        "unstable below a later range is undecidable",
        TWO_RANGES,
        "2.0.5-unstable-2026-01-02",
        K,
        Reason.UNPARSEABLE,
    ),
    (
        "unstable inside a range is undecidable",
        TWO_RANGES,
        "2.0.4-unstable-2026-01-02",
        K,
        Reason.UNPARSEABLE,
    ),
    (
        "unstable from zero is undecidable",
        product(entry(A, "0", lt="1.2"), default=U),
        "0-unstable-2026-01-02",
        K,
        Reason.UNPARSEABLE,
    ),
    (
        "unstable from zero against an open range",
        product(entry(A, "0", lt="*"), default=U),
        "0-unstable-2026-01-02",
        A,
        Reason.VERSION_RANGE,
    ),
    (
        "unstable is past its base release",
        product(entry(A, "1.2.3"), default=U),
        "1.2.3-unstable-2026-01-02",
        U,
        Reason.DEFAULT_STATUS,
    ),
    (
        "tree-sitter style snapshot",
        product(entry(A, "0", lt="0.3.0"), default=U),
        "0.3.0+unstable20260416",
        U,
        Reason.DEFAULT_STATUS,
    ),
    (
        "nixpkgs suffix",
        product(entry(A, "1.0", le="1.16.2"), default=U),
        "1.16.2-envoy",
        A,
        Reason.VERSION_RANGE,
    ),
    (
        "esr suffix",
        product(entry(A, "0", lt="140.17"), default=U),
        "140.17.0esr",
        U,
        Reason.DEFAULT_STATUS,
    ),
    (
        "pre-release before release",
        product(entry(A, "0", lt="2.3"), default=U),
        "2.3rc1",
        A,
        Reason.VERSION_RANGE,
    ),
    # `changes` inside a range.
    (
        "change point reached",
        product(
            entry(A, "1.0", lt="2.0", changes=(Change("1.5", U),)),
            default=U,
        ),
        "1.6",
        U,
        Reason.VERSION_RANGE,
    ),
    (
        "change point not reached",
        product(
            entry(A, "1.0", lt="2.0", changes=(Change("1.5", U),)),
            default=U,
        ),
        "1.4",
        A,
        Reason.VERSION_RANGE,
    ),
]


@pytest.mark.parametrize(
    "prod, version, status, reason",
    [c[1:] for c in CASES],
    ids=[c[0] for c in CASES],
)
def test_classify_product(
    prod: ProductVersions, version: str | None, status: Status, reason: Reason
) -> None:
    result = classify_product(version, prod)
    assert (result.status, result.reason) == (status, reason), result.detail


def test_deciding_entry_is_reported() -> None:
    result = classify_product("2.0.3", TWO_RANGES)
    assert result.entry == TWO_RANGES.entries[0]
    assert str(result.range) == "[2.0, 2.0.5)"
    result = classify_product("2.1.0", TWO_RANGES)
    assert result.entry is None
    assert result.detail == "2.1.0 outside [2.0, 2.0.5), [3.0, 3.0.2)"


def test_textual_range_is_marked_parsed() -> None:
    upper = Bound("1.2.3", inclusive=False)
    assert interpret(entry(A, "< 1.2.3")) == VersionRange(None, upper, "parsed")
    assert interpret(entry(A, "0", lt="1.2.3")) == VersionRange(None, upper)


@pytest.mark.parametrize(
    "text, expected",
    [
        ("< 1.2.3", "(*, 1.2.3)"),
        ("<= 1.2", "(*, 1.2]"),
        ("=< 1.2", "(*, 1.2]"),
        (">= 2.0", "[2.0, *)"),
        ("before 1.2.3", "(*, 1.2.3)"),
        ("prior to 1.2.3", "(*, 1.2.3)"),
        ("1.0 through 1.4", "[1.0, 1.4]"),
        (">= 2.0, < 2.3", "[2.0, 2.3)"),
        (">=2.0 <2.3", "[2.0, 2.3)"),
        (">= 4.0.0-canary.0, < 4.0.0-canary.34", "[4.0.0-canary.0, 4.0.0-canary.34)"),
        (
            "All driver versions prior to 582.78 Only GPUs based on Maxwell",
            "(*, 582.78)",
        ),
        ("595.71.05(All versions prior to and including vGPU 20.1)", "(*, 595.71.05]"),
        ("1.2.3 and earlier", "(*, 1.2.3]"),
        ("1.2 or later", "[1.2, *)"),
        ("WSA8845H", None),
        ("Snapdragon 8 Elite", None),
        ("1.2.3", None),
    ],
)
def test_parse_textual_range(text: str, expected: str | None) -> None:
    parsed = parse_textual_range(text)
    assert (str(parsed) if parsed else None) == expected


@pytest.mark.parametrize(
    "version, base, snapshot",
    [
        ("1.2.3", "1.2.3", False),
        ("0-unstable-2026-01-02", "0", True),
        ("1.2.3-unstable-2026-01-02", "1.2.3", True),
        ("0+unstable20250423", "0", True),
        ("0.0.0+rev=68fd0d8", "0.0.0", True),
        ("1.16.2-envoy", "1.16.2", False),
        ("1.2.3+matrix.1", "1.2.3", False),
        ("v2.0", "2.0", False),
        ("2.3rc1", "2.3~rc1", False),
        ("6.30.223.271-59-5.10.270", "6.30.223.271-59-5.10.270", False),
    ],
)
def test_parse_package_version(version: str, base: str, snapshot: bool) -> None:
    parsed = parse_package_version(version)
    assert parsed is not None
    assert (str(parsed.base), parsed.snapshot) == (base, snapshot)


@pytest.mark.parametrize(
    "version", ["", "5aff249fdc119caa1464af9405259799b4f69d8b", "unknown"]
)
def test_parse_package_version_rejects(version: str) -> None:
    assert parse_package_version(version) is None


def test_ranges_of_other_products_do_not_leak() -> None:
    # The old code pooled all products: `foo-server`'s range marked `foo` 2.0 affected.
    foo = product(entry(A, "0", lt="1.0"), default=U, key="foo")
    server = product(entry(A, "0", lt="3.0"), default=U, key="foo-server")
    assert classify("2.0", [foo]).status == U
    assert classify("2.0", [foo, server]).status == A


@pytest.mark.parametrize(
    "statuses, expected",
    [
        ([U, U], U),
        ([U, A], A),
        ([U, K], K),
        ([K, A], A),
    ],
)
def test_combination_across_products(statuses: list[Status], expected: Status) -> None:
    products = [
        product(entry(s, "1.0"), default=U, key=str(i)) for i, s in enumerate(statuses)
    ]
    assert classify("1.0", products).status == expected


def test_abstention_of_other_product_is_unknown() -> None:
    known = product(entry(A, "0", lt="1.0"), default=U, key="a")
    no_data = product(entry(A, "n/a"), key="b")
    result = classify("2.0", [known, no_data])
    assert (result.status, result.reason) == (K, Reason.NO_RANGE)


def test_same_product_git_and_semver() -> None:
    result = classify("6.1.55", [KERNEL_GIT, KERNEL_SEMVER])
    assert (result.status, result.reason) == (U, Reason.VERSION_RANGE)
    result = classify("6.1.20", [KERNEL_GIT, KERNEL_SEMVER])
    assert (result.status, result.reason) == (A, Reason.DEFAULT_STATUS)


def test_same_key_does_not_hide_undecidable_ranges() -> None:
    # Two version lines under one product name: a snapshot that may be inside one of them
    # must stay unknown even though the other line decides "unaffected".
    line_a = product(entry(A, "0", lt="11.00.00"), default=U, key="eld")
    line_b = product(entry(A, "0", lt="1.1.54"), default=U, key="eld")
    result = classify("2.0-unstable-2025-04-16", [line_a, line_b])
    assert (result.status, result.reason) == (K, Reason.UNPARSEABLE)


def test_no_products() -> None:
    assert classify("1.0", []).reason == Reason.NO_RANGE


def test_absent_default_is_inferred_from_affected_ranges() -> None:
    prod = product(entry(A, "0", lt="1.2"))
    result = classify_product("1.3", prod)
    assert (result.status, result.reason, result.inferred) == (
        U,
        Reason.DEFAULT_STATUS,
        True,
    )
    strict = classify_product("1.3", prod, strict=True)
    assert (strict.status, strict.inferred) == (K, False)


@pytest.mark.parametrize(
    "prod",
    [
        # An explicit defaultStatus is never overridden.
        product(entry(A, "0", lt="1.2"), default=K),
        # Lists of exact versions name tested versions, not the whole affected set.
        product(entry(A, "1.0"), entry(A, "1.1")),
        # An unaffected or unknown entry means the record is not a list of affected ranges.
        product(entry(A, "0", lt="1.2"), entry(K, "2.0", lt="3.0")),
    ],
)
def test_absent_default_not_inferred(prod: ProductVersions) -> None:
    result = classify_product("1.5", prod)
    assert (result.status, result.inferred) == (K, False)


def test_inference_does_not_hide_undecidable_entries() -> None:
    prod = product(entry(A, "2.0", lt="2.0.5"), entry(A, "3.0", lt="3.0.2"))
    result = classify_product("2.0.5-unstable-2026-01-02", prod)
    assert (result.status, result.reason) == (K, Reason.UNPARSEABLE)


@pytest.mark.django_db
def test_classify_affected_product_rows() -> None:
    def make(**fields: str) -> AffectedProduct:
        ap = AffectedProduct.objects.create(
            vendor="acme", product=fields.pop("product"), default_status="unaffected"
        )
        ap.versions.add(Version.objects.create(status="affected", **fields))
        return ap

    a = make(product="a", version="2.0", less_than="2.0.5")
    b = make(product="b", version="3.0", less_than="3.0.2")
    result = classify_affected_products("2.1.0", [a])
    assert (result.status, result.reason) == (U, Reason.DEFAULT_STATUS)
    # Pooled the old way, b's range would make 2.1.0 affected.
    assert classify_affected_products("3.0.1", [a, b]).status == A
    assert classify_affected_products("3.0.1", [a]).status == U


@pytest.mark.django_db
def test_rows_absent_default_and_changes() -> None:
    def make(recorded: bool | None, **fields: object) -> AffectedProduct:
        ap = AffectedProduct.objects.create(
            product="a", default_status="unknown", default_status_recorded=recorded
        )
        ap.versions.add(Version.objects.create(status="affected", **fields))
        return ap

    ranged = {"version": "1.0", "less_than": "2.0"}
    # Absent at ingestion: inferred. Not recorded (older rows): the stored "unknown".
    assert classify_affected_products("2.1", [make(False, **ranged)]).status == U
    assert classify_affected_products("2.1", [make(None, **ranged)]).status == K
    assert classify_affected_products("2.1", [make(True, **ranged)]).status == K
    with_changes = make(
        True, **ranged, changes=[{"at": "1.5", "status": "unaffected"}, {"bad": 1}]
    )
    assert classify_affected_products("1.6", [with_changes]).status == U
    assert classify_affected_products("1.4", [with_changes]).status == A
