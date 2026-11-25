"""
`CveView`: what the matchers see of a CVE, built from all of its containers.
"""

import functools
from collections import defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field, replace
from typing import NamedTuple

from cpe import CPE
from django.db.models import Prefetch, QuerySet

from shared.identity.mappings import NO_MAPPINGS, MappingRule, Mappings, load_mappings
from shared.matching.names import (
    NON_NAMES,
    ecosystem_for,
    ecosystem_package_name,
    go_module_repo,
    normalise_name,
    normalise_repo,
    package_name_tail,
)
from shared.models.cve import (
    AffectedProduct,
    Container,
    CpeApplicability,
    CveRecord,
    Tag,
)
from shared.models.matching import ProductKey

EXCLUSIVELY_HOSTED_SERVICE = "exclusively-hosted-service"


class ParsedCpe(NamedTuple):
    is_hardware: bool
    # (vendor, product) pairs without wildcards, as the `cpe` library returns them.
    pairs: tuple[tuple[str, str], ...]


@functools.lru_cache(maxsize=1 << 16)
def parse_cpe(name: str) -> ParsedCpe:
    """Parse a CPE string once per process; the `cpe` library is slow."""
    parsed = CPE(name)
    pairs = tuple(
        (vendor, product)
        for vendor, product in zip(
            parsed.get_vendor(), parsed.get_product(), strict=False
        )
        if vendor and product and vendor != "*" and product != "*"
    )
    return ParsedCpe(parsed.is_hardware(), pairs)


class KeySpec(NamedTuple):
    """An unsaved `ProductKey`."""

    kind: str
    vendor: str
    product: str

    def capped(self) -> "KeySpec":
        """
        Cut vendor and product to a byte length the unique B-tree index on (kind, vendor,
        product) can hold (an index row is at most about 2.7 kB); real names are far shorter.
        """
        return KeySpec(
            self.kind,
            _cap(self.vendor, KEY_VENDOR_BYTES),
            _cap(self.product, KEY_PRODUCT_BYTES),
        )


KEY_VENDOR_BYTES = 512
KEY_PRODUCT_BYTES = 1024


def _cap(value: str, limit: int) -> str:
    encoded = value.encode()
    if len(encoded) <= limit:
        return value
    return encoded[:limit].decode(errors="ignore").rstrip()


@dataclass(frozen=True)
class ProductFields:
    """The parts of an `AffectedProduct` that identify it, detached from the database."""

    vendor: str | None = None
    product: str | None = None
    package_name: str | None = None
    collection_url: str | None = None
    repo: str | None = None
    cpes: tuple[str, ...] = ()

    @classmethod
    def of(cls, affected: AffectedProduct) -> "ProductFields":
        """Reads `cpes` through the prefetch cache when there is one."""
        return cls(
            vendor=affected.vendor,
            product=affected.product,
            package_name=affected.package_name,
            collection_url=affected.collection_url,
            repo=affected.repo,
            cpes=tuple(sorted(cpe.name for cpe in affected.cpes.all())),
        )


def _usable(value: str | None) -> bool:
    return normalise_name(value) not in NON_NAMES


def product_keys(fields: ProductFields) -> frozenset[KeySpec]:
    """
    Normalised identities of an affected product, in the vocabulary of `ProductKey`:

    - `cpe`: each non-hardware CPE (vendor, product);
    - `cna`: (vendor, product) and, without a known registry, (vendor, packageName);
    - `purl`: (purl type, registry package name) when `collectionURL` names a known registry,
      otherwise (collection URL, packageName);
    - `repo`: (host/owner, name) of `repo`, of a forge `collectionURL`, or of a Go module path.
    """
    norm = ProductKey.normalise
    keys: set[KeySpec] = set()
    for cpe_name in fields.cpes:
        parsed = parse_cpe(cpe_name)
        if not parsed.is_hardware:
            keys |= cpe_pair_keys(parsed.pairs)
    vendor = norm(fields.vendor) if _usable(fields.vendor) else ""
    if _usable(fields.product):
        keys.add(KeySpec(ProductKey.Kind.CNA, vendor, norm(fields.product)))
    if fields.package_name and _usable(fields.package_name):
        ecosystem = ecosystem_for(fields.collection_url)
        if ecosystem is not None:
            name = ecosystem_package_name(ecosystem, fields.package_name)
            keys.add(KeySpec(ProductKey.Kind.PURL, ecosystem.slug, name))
        elif fields.collection_url:
            keys.add(
                KeySpec(
                    ProductKey.Kind.PURL,
                    norm(fields.collection_url).rstrip("/"),
                    norm(fields.package_name),
                )
            )
        else:
            keys.add(KeySpec(ProductKey.Kind.CNA, vendor, norm(fields.package_name)))
    for repo in repositories(fields):
        owner, _, name = repo.rpartition("/")
        if owner and name:
            keys.add(KeySpec(ProductKey.Kind.REPO, owner, name))
    return frozenset(key.capped() for key in keys)


def cpe_pair_keys(pairs: Iterable[tuple[str, str]]) -> frozenset[KeySpec]:
    """
    `cpe` keys of non-hardware CPE (vendor, product) pairs. The one place CPE keys are made:
    pairs from another source (the container-level `cpeApplicability` CPEs) go through here too.
    """
    norm = ProductKey.normalise
    return frozenset(
        KeySpec(ProductKey.Kind.CPE, norm(vendor), norm(product)).capped()
        for vendor, product in pairs
        if vendor and product
    )


def repositories(fields: ProductFields) -> tuple[str, ...]:
    """Normalised repository URLs an affected product names, directly or via its registry coordinates."""
    found: list[str] = []
    candidates = [normalise_repo(fields.repo)]
    if fields.collection_url:
        collection = normalise_repo(fields.collection_url)
        host = fields.collection_url.strip().split("://", 1)[-1].rstrip("/")
        # `collectionURL: https://github.com/owner/repo`, or `https://github.com` + `owner/repo`.
        # With a `packageName` a collection URL with a path is the collection the package is in
        # (`https://access.redhat.com/downloads/content/package-browser`), not its repository.
        if collection and collection.count("/") >= 2 and not fields.package_name:
            candidates.append(collection)
        elif "/" not in host and fields.package_name and "/" in fields.package_name:
            candidates.append(normalise_repo(f"https://{host}/{fields.package_name}"))
    if fields.package_name:
        candidates.append(go_module_repo(fields.package_name))
    for repo in candidates:
        if repo and "/" in repo and repo not in found:
            found.append(repo)
    return tuple(found)


class NameTerm(NamedTuple):
    """A normalised name the name matchers look up, and where it came from."""

    cve_field: str  # "product" | "package_name"
    cve_value: str  # the field's value as published
    term: str  # normalised


def name_terms(fields: ProductFields) -> tuple[NameTerm, ...]:
    """
    Names to look up for an affected product: product and packageName, the last component of
    a qualified packageName (`group:artifact`, `github.com/o/r`, `vendor/name`), and the product
    without a leading vendor word ("Apache Tomcat" by "Apache Software Foundation" -> "tomcat").
    """
    terms: dict[str, NameTerm] = {}

    def add(cve_field: str, cve_value: str, raw: str) -> None:
        term = normalise_name(raw)
        if term not in NON_NAMES and term not in terms:
            terms[term] = NameTerm(cve_field, cve_value, term)

    if fields.product:
        add("product", fields.product, fields.product)
        vendor_word = normalise_name(fields.vendor).split("-", 1)[0]
        product = normalise_name(fields.product)
        if vendor_word and product.startswith(vendor_word + "-"):
            add("product", fields.product, product[len(vendor_word) + 1 :])
    if fields.package_name:
        add("package_name", fields.package_name, fields.package_name)
        if tail := package_name_tail(fields.package_name):
            add("package_name", fields.package_name, tail)
    return tuple(terms.values())


@dataclass(frozen=True)
class ViewProduct:
    """One affected product of a CVE, deduplicated across containers."""

    fields: ProductFields
    # (AffectedProduct pk, container type) of every row merged into this product, CNA first.
    # Pk None: the container-level `cpeApplicability` pairs no affected product claims.
    sources: tuple[tuple[int | None, str], ...]
    cpe_pairs: frozenset[tuple[str, str]]
    # Has CPEs, and all of them are hardware.
    hardware_only: bool
    keys: frozenset[KeySpec]
    names: tuple[NameTerm, ...]
    repos: tuple[str, ...]

    @property
    def affected_product(self) -> int | None:
        return self.sources[0][0]

    @property
    def container(self) -> str:
        return self.sources[0][1]

    @property
    def containers(self) -> tuple[str, ...]:
        return tuple(sorted({kind for _, kind in self.sources}))

    @property
    def affected_products(self) -> list[int]:
        """Every affected product row merged into this one, CNA first."""
        return list(dict.fromkeys(pk for pk, _ in self.sources if pk is not None))

    def evidence(self) -> dict[str, object]:
        # `affected_product` (the first source) stays for existing readers; the version
        # classifier needs all of them (the kernel CNA's git and semver products merge here).
        return {
            "affected_product": self.affected_product,
            "affected_products": self.affected_products,
            "container": self.container,
        }


@dataclass(frozen=True)
class CveView:
    """The union of a CVE's affected products over the CNA and every ADP container."""

    cve_id: str
    products: tuple[ViewProduct, ...]
    # Suggestion-level screens of today's `resolve_linkage_candidates`, not acted on here.
    exclusively_hosted_service: bool = False
    tags: frozenset[str] = field(default_factory=frozenset)
    # `ProductMapping`s on the keys of the products.
    mappings: Mappings = NO_MAPPINGS

    def veto(self, product: ViewProduct | None, attrpath: str) -> MappingRule | None:
        """
        The mapping that removes `attrpath` as a candidate coming from `product`, if any. Only
        the keys of that product count: a CVE naming two products, one vetoed, keeps the other's
        candidates. Candidates from no product (`known-vuln`) are never vetoed.
        """
        if product is None or not self.mappings:
            return None
        return self.mappings.veto(product.keys, attrpath)

    @property
    def hardware_only(self) -> bool:
        """There are affected products, and every one of them has only hardware CPEs."""
        return bool(self.products) and all(p.hardware_only for p in self.products)

    @property
    def matchable(self) -> tuple[ViewProduct, ...]:
        """Products the matchers look at: those not ruled out as hardware."""
        return tuple(p for p in self.products if not p.hardware_only)


def _dedup_key(fields: ProductFields) -> tuple[str, ...]:
    norm = ProductKey.normalise
    return (
        norm(fields.vendor),
        norm(fields.product),
        norm(fields.package_name),
        norm(fields.collection_url).rstrip("/"),
        normalise_repo(fields.repo) or "",
    )


# Operating-system CPEs that name something nixpkgs ships. Every other `o` part (Windows,
# macOS, iOS, Android, router firmware) is the platform of the CVE, never a package.
NIXPKGS_OS_VENDORS = frozenset({"linux"})
_PLACEHOLDERS = frozenset({"", "*", "-"})


def applicability_pairs(rows: Iterable[CpeApplicability]) -> set[tuple[str, str]]:
    """
    The (vendor, product) pairs of a container's `cpeApplicability` that name the vulnerable
    product: vulnerable, not negated, application part (or an operating system nixpkgs ships),
    no placeholder. Platform criteria of "application on platform" configurations are not
    vulnerable and drop out; the application stays.
    """
    return {
        (row.vendor, row.product)
        for row in rows
        if row.vulnerable
        and not row.negated
        and (row.part == "a" or (row.part == "o" and row.vendor in NIXPKGS_OS_VENDORS))
        and row.vendor not in _PLACEHOLDERS
        and row.product not in _PLACEHOLDERS
    }


def attribute_applicability(
    products: Sequence[tuple[int, ProductFields]], pairs: Iterable[tuple[str, str]]
) -> dict[int | None, set[tuple[str, str]]]:
    """
    Which affected product of the container each `cpeApplicability` pair belongs to, so that
    evidence names an affected product and the version classifier scopes to its ranges:
    1. the products whose product or packageName is the CPE product (normalised);
    2. else the container's only affected product without hardware-only CPEs;
    3. else none (key None): a container-level product of its own, scoped to all ranges.
    """
    matchable = [
        (pk, f)
        for pk, f in products
        if not (f.cpes and all(parse_cpe(c).is_hardware for c in f.cpes))
    ]
    result: dict[int | None, set[tuple[str, str]]] = defaultdict(set)
    for vendor, product in pairs:
        name = normalise_name(product)
        named = [
            pk
            for pk, f in matchable
            if name in {normalise_name(f.product), normalise_name(f.package_name)}
        ]
        if named:
            for pk in named:
                result[pk].add((vendor, product))
        elif len(matchable) == 1:
            result[matchable[0][0]].add((vendor, product))
        else:
            result[None].add((vendor, product))
    return dict(result)


def view_from_containers(cve_id: str, containers: Sequence[Container]) -> CveView:
    """
    Build the view from containers whose `affected` (with `cpes`, `product_keys`), `tags` and
    `cpe_applicability` are prefetched. `cpeApplicability` pairs join the affected product
    `attribute_applicability` assigns them to, as CPE pairs and `cpe` keys.
    """
    merged: dict[
        tuple[str, ...], tuple[ProductFields, list[tuple[int | None, str]]]
    ] = {}
    tags: set[str] = set()
    ordered = sorted(
        containers, key=lambda c: (c._type != Container.Type.CNA, c.pk or 0)
    )
    # Persisted keys per merged product; None once a merged row has none, then they are derived.
    persisted: dict[tuple[str, ...], set[KeySpec] | None] = {}
    applicable: dict[tuple[str, ...], set[tuple[str, str]]] = defaultdict(set)
    unclaimed: dict[str, set[tuple[str, str]]] = defaultdict(set)
    for container in ordered:
        tags.update(tag.value for tag in container.tags.all())
        own: list[tuple[int, ProductFields]] = []
        dedup_of: dict[int, tuple[str, ...]] = {}
        for affected in sorted(container.affected.all(), key=lambda a: a.pk):
            fields = ProductFields.of(affected)
            key = _dedup_key(fields)
            if key in merged:
                first, sources = merged[key]
                cpes = tuple(sorted(set(first.cpes) | set(fields.cpes)))
                merged[key] = (replace(first, cpes=cpes), sources)
            else:
                merged[key] = (fields, [])
                persisted[key] = set()
            merged[key][1].append((affected.pk, container._type))
            stored = _stored_keys(affected)
            known = persisted[key]
            persisted[key] = known | stored if known is not None and stored else None
            own.append((affected.pk, fields))
            dedup_of[affected.pk] = key
        pairs = applicability_pairs(container.cpe_applicability.all())
        for pk, assigned in attribute_applicability(own, pairs).items():
            if pk is None:
                unclaimed[container._type] |= assigned
            else:
                applicable[dedup_of[pk]] |= assigned

    products = []
    for dedup, (fields, sources) in merged.items():
        parsed = [parse_cpe(name) for name in fields.cpes]
        keys = persisted[dedup]
        extra = applicable.get(dedup, set())
        products.append(
            ViewProduct(
                fields=fields,
                sources=tuple(dict.fromkeys(sources)),
                cpe_pairs=frozenset(
                    pair for p in parsed if not p.is_hardware for pair in p.pairs
                )
                | extra,
                hardware_only=bool(parsed)
                and all(p.is_hardware for p in parsed)
                and not extra,
                keys=(frozenset(keys) if keys else product_keys(fields))
                | cpe_pair_keys(extra),
                names=name_terms(fields),
                repos=repositories(fields),
            )
        )
    for container_type, pairs in sorted(
        unclaimed.items(), key=lambda kv: kv[0] != Container.Type.CNA
    ):
        products.append(
            ViewProduct(
                fields=ProductFields(),
                sources=((None, container_type),),
                cpe_pairs=frozenset(pairs),
                hardware_only=False,
                keys=cpe_pair_keys(pairs),
                names=(),
                repos=(),
            )
        )
    return CveView(
        cve_id=cve_id,
        products=tuple(products),
        exclusively_hosted_service=EXCLUSIVELY_HOSTED_SERVICE in tags,
        tags=frozenset(tags),
    )


def _stored_keys(affected: AffectedProduct) -> set[KeySpec]:
    """Persisted keys of a row, through the prefetch cache when there is one."""
    return {
        KeySpec(key.kind, key.vendor, key.product)
        for key in affected.product_keys.all()
    }


def _containers_prefetch() -> Prefetch:
    return Prefetch(
        "container",
        queryset=Container.objects.only("id", "_type", "cve_id").prefetch_related(
            Prefetch(
                "affected",
                queryset=AffectedProduct.objects.defer(
                    "search_vector"
                ).prefetch_related("cpes", "product_keys"),
            ),
            Prefetch("tags", queryset=Tag.objects.all()),
            Prefetch("cpe_applicability", queryset=CpeApplicability.objects.all()),
        ),
    )


def build_cve_views(cves: QuerySet[CveRecord] | Iterable[str]) -> dict[str, CveView]:
    """Views of many CVEs, by CVE id, in a constant number of queries (eight)."""
    queryset = (
        cves
        if isinstance(cves, QuerySet)
        else CveRecord.objects.filter(cve_id__in=list(cves))
    )
    records = queryset.only("id", "cve_id").prefetch_related(_containers_prefetch())
    # `cve_id` is not unique: merge the containers of duplicate records.
    containers: dict[str, list[Container]] = {}
    for record in records:
        containers.setdefault(record.cve_id, []).extend(record.container.all())
    views = {
        cve_id: view_from_containers(cve_id, found)
        for cve_id, found in containers.items()
    }
    mappings = load_mappings(
        key for view in views.values() for p in view.products for key in p.keys
    )
    if not mappings:
        return views
    return {cve_id: replace(view, mappings=mappings) for cve_id, view in views.items()}


def build_cve_view(cve: CveRecord | str) -> CveView:
    """View of one CVE, in eight queries."""
    cve_id = cve if isinstance(cve, str) else cve.cve_id
    return build_cve_views([cve_id]).get(cve_id) or CveView(cve_id=cve_id, products=())
