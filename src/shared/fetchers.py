import hashlib
import json
import logging
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

import pgpubsub
import pgtrigger
from cpe import CPE
from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import Exists, OuterRef
from django.utils.timezone import make_aware
from pgpubsub.triggers import Notify
from requests import get

from shared import models
from shared.channels import CvePresentationChannel, CveUpdateChannel
from shared.identity.keys import persist_product_keys

logger = logging.getLogger(__name__)


def make_organization(
    uuid: str | None, short_name: str | None = None
) -> models.Organization | None:
    if uuid is None:
        return None

    org, _ = models.Organization.objects.get_or_create(
        uuid=uuid, defaults={"short_name": short_name}
    )

    return org


def make_date(date: str | None) -> datetime | None:
    if date is None:
        return None

    time = datetime.fromisoformat(date)

    if time.tzinfo is None:
        return make_aware(time)

    return time


def make_media(data: dict[str, str]) -> models.SupportingMedia:
    ctx: dict[str, Any] = dict()
    ctx["_type"] = data["type"]
    ctx["base64"] = data.get("base64", False)
    ctx["value"] = data["value"]

    return models.SupportingMedia.objects.create(**ctx)


def make_description(data: dict[str, Any]) -> models.Description:
    ctx: dict[str, Any] = dict()
    ctx["lang"] = data["lang"]
    ctx["value"] = data["value"]

    obj = models.Description.objects.create(**ctx)
    obj.media.set(map(make_media, data.get("supportingMedia", [])))

    return obj


def make_tag(name: str) -> models.Tag:
    obj, _ = models.Tag.objects.get_or_create(value=name)

    return obj


def make_reference(data: dict[str, Any]) -> models.Reference:
    ctx: dict[str, Any] = dict()
    ctx["url"] = data["url"]
    ctx["name"] = data.get("name", "")

    obj = models.Reference.objects.create(**ctx)
    obj.tags.set(map(make_tag, data.get("tags", [])))

    return obj


def make_problem_type(data: dict[str, Any]) -> models.ProblemType:
    ctx: dict[str, Any] = dict()
    ctx["cwe_id"] = data.get("cweId")
    ctx["_type"] = data.get("type")

    obj = models.ProblemType.objects.create(**ctx)
    obj.description.set(
        [make_description({"lang": data["lang"], "value": data["description"]})]
    )
    obj.references.set(map(make_reference, data.get("references", [])))

    return obj


def to_camel_case(name: str) -> str:
    """
    >>> to_camel_case("abc_def")
    abcDef
    """
    from re import sub

    s = sub(r"(_|-)+", " ", name).title().replace(" ", "")
    return "".join([s[0].lower(), s[1:]])


def make_metrics(data: list[dict[str, Any]]) -> list[models.Metric]:
    metrics = []
    for item in data:
        metric = make_metric(item)
        if metric is not None:
            metrics.append(metric)
    return metrics


def make_metric(data: dict[str, Any]) -> models.Metric | None:
    for fmt in models.Metric.Format.values:
        if fmt in data:
            raw_cvss = data[fmt]
            return models.Metric.objects.create(
                format=fmt,
                vector_string=raw_cvss.get("vectorString", ""),
                # We throw away everything else, it can be recovered from the above.
            )

    return None


def make_event(data: dict[str, Any]) -> models.Event:
    ctx: dict[str, Any] = dict()
    ctx["time"] = make_date(data["time"])
    ctx["description"] = make_description(data)

    return models.Event.objects.create(**ctx)


def make_credit(data: dict[str, Any]) -> models.Credit:
    ctx: dict[str, Any] = dict()
    ctx["_type"] = data.get("type", "finder")
    ctx["user"] = make_organization(uuid=data.get("user"))
    ctx["description"] = make_description(data)

    return models.Credit.objects.create(**ctx)


def make_platform(name: str) -> models.Platform:
    obj, _ = models.Platform.objects.get_or_create(name=name)

    return obj


def make_version(data: dict[str, Any]) -> models.Version:
    ctx: dict[str, Any] = dict()
    ctx["version"] = data.get("version")
    ctx["status"] = data.get("status", models.Version.Status.UNKNOWN)
    ctx["version_type"] = data.get("versionType")
    ctx["less_than"] = data.get("lessThan")
    ctx["less_equal"] = data.get("lessThanOrEqual")
    ctx["changes"] = data.get("changes")

    return models.Version.objects.create(**ctx)


def make_cpe(name: str) -> models.Cpe | None:
    try:
        models.Cpe(name=name).full_clean()
    except ValidationError as e:
        logger.warning("Discarding malformed CPE %r: %s", name, e)
        return None

    obj, _ = models.Cpe.objects.get_or_create(name=name)
    return obj


def make_module(name: str) -> models.Module:
    obj, _ = models.Module.objects.get_or_create(name=name)

    return obj


def make_program_file(name: str) -> models.ProgramFile:
    obj, _ = models.ProgramFile.objects.get_or_create(name=name)

    return obj


def make_program_routine(name: str) -> models.ProgramRoutine:
    obj, _ = models.ProgramRoutine.objects.get_or_create(name=name)

    return obj


def make_affected_product(data: dict[str, Any]) -> models.AffectedProduct:
    ctx: dict[str, Any] = dict()
    ctx["vendor"] = data.get("vendor")
    ctx["product"] = data.get("product")
    ctx["collection_url"] = data.get("collectionURL")
    ctx["package_name"] = data.get("packageName")
    ctx["repo"] = data.get("repo")
    ctx["default_status"] = data.get(
        "defaultStatus", models.AffectedProduct.Status.UNKNOWN
    )
    ctx["default_status_recorded"] = "defaultStatus" in data

    obj = models.AffectedProduct.objects.create(**ctx)
    obj.platforms.set(map(make_platform, data.get("platforms", [])))
    obj.versions.set(map(make_version, data.get("versions", [])))
    obj.cpes.set(
        cpe for name in data.get("cpes", []) if (cpe := make_cpe(name)) is not None
    )
    obj.modules.set(map(make_module, data.get("modules", [])))
    obj.program_files.set(map(make_program_file, data.get("programFiles", [])))
    obj.program_routines.set(map(make_program_routine, data.get("programRoutines", [])))
    persist_product_keys([obj])

    return obj


def make_cve_record(
    data: dict[str, Any], cve: models.CveRecord | None = None
) -> models.CveRecord:
    if cve is None:
        cve = models.CveRecord()

    cve.cve_id = data["cveId"]
    cve.state = data["state"]

    org = make_organization(
        uuid=data["assignerOrgId"], short_name=data.get("assignerShortName")
    )

    assert org is not None, "Organisation cannot be empty"

    cve.assigner = org
    cve.requester = make_organization(uuid=data.get("requesterUserId"))

    cve.date_reserved = make_date(data.get("dateReserved"))
    cve.date_updated = make_date(data.get("dateUpdated"))
    cve.date_published = make_date(data.get("datePublished"))
    cve.serial = data.get("serial", 1)

    return cve


HOSTED_SERVICE_TAG = "exclusively-hosted-service"


def _digest(value: Any) -> str:
    canonical = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def _metric_without_timestamp(metric: dict[str, Any]) -> dict[str, Any]:
    other = metric.get("other")
    if not isinstance(other, dict):
        return metric
    content = other.get("content")
    if not isinstance(content, dict) or "timestamp" not in content:
        return metric
    content = {k: v for k, v in content.items() if k != "timestamp"}
    return {**metric, "other": {**other, "content": content}}


def container_hash(data: dict[str, Any]) -> str:
    """
    Digest of a container without its volatile fields.

    Volatile: `providerMetadata.dateUpdated`, which moves on every republication, and the `timestamp` of
    `other` metrics (CISA's SSVC assessment), which moves when CISA re-assesses with the same outcome.
    """
    stable = dict(data)
    if isinstance(stable.get("providerMetadata"), dict):
        stable["providerMetadata"] = {
            k: v for k, v in stable["providerMetadata"].items() if k != "dateUpdated"
        }
    if isinstance(stable.get("metrics"), list):
        stable["metrics"] = [
            _metric_without_timestamp(m) if isinstance(m, dict) else m
            for m in stable["metrics"]
        ]
    return _digest(stable)


def record_hash(data: dict[str, Any]) -> str:
    """Digest of a whole record without volatile fields: `cveMetadata.dateUpdated` and those of `container_hash`."""
    containers = data["containers"]
    return _digest(
        {
            "cveMetadata": {
                k: v for k, v in data["cveMetadata"].items() if k != "dateUpdated"
            },
            "cna": container_hash(containers["cna"]),
            "adp": [container_hash(adp) for adp in containers.get("adp", [])],
        }
    )


def product_hash(data: dict[str, Any]) -> str:
    return _digest(data)


def _normalise_identity(value: str | None) -> str:
    return (value or "").strip().lower()


def product_identity(data: dict[str, Any]) -> tuple[str, ...]:
    """
    What makes an `affected` entry the same product across updates of a record.

    Vendor, product, package name, collection URL and repository, compared after stripping and lowercasing
    (the normalisation of `ProductKey`). Versions, CPEs, platforms, modules, files, routines and the default
    status are content: a change to them updates the product in place.
    """
    return tuple(
        _normalise_identity(data.get(key))
        for key in ("vendor", "product", "packageName", "collectionURL", "repo")
    )


def _stored_product_identity(obj: models.AffectedProduct) -> tuple[str, ...]:
    return tuple(
        _normalise_identity(value)
        for value in (
            obj.vendor,
            obj.product,
            obj.package_name,
            obj.collection_url,
            obj.repo,
        )
    )


def make_hashed_product(data: dict[str, Any]) -> models.AffectedProduct:
    obj = make_affected_product(data)
    obj.content_hash = product_hash(data)
    obj.save(update_fields=["content_hash"])
    return obj


def find_cve_record(cve_id: str) -> models.CveRecord | None:
    """
    The record an update of `cve_id` applies to.

    `cve_id` is not unique: past bulk ingestions created duplicates. Prefer a record that has a suggestion,
    then the oldest, so that the choice is deterministic and the record users see is the one kept current.
    """
    return (
        models.CveRecord.objects.filter(cve_id=cve_id)
        .annotate(
            has_suggestion=Exists(
                models.CVEDerivationClusterProposal.objects.filter(cve=OuterRef("pk"))
            )
        )
        .order_by("-has_suggestion", "pk")
        .first()
    )


@dataclass
class Reconciliation:
    """What ingesting an update of a known record did."""

    changed: bool = False
    # Something matchers or the version classifier read changed: affected products, their versions or
    # CPEs, CPE applicability, the hosted-service tag, or the record state.
    matching_changed: bool = False
    containers_added: int = 0
    containers_updated: int = 0
    containers_removed: int = 0
    products_added: int = 0
    products_updated: int = 0
    products_removed: int = 0
    products_unchanged: int = 0


CpeCriterion = tuple[
    str, bool, bool, bool, str | None, str | None, str | None, str | None
]


def cpe_applicability_criteria(data: dict[str, Any]) -> list[CpeCriterion]:
    """
    The distinct criteria of a container's `cpeApplicability`, in order of appearance:
    (criteria, vulnerable, negated, conjunctive, start including, start excluding, end including, end excluding).
    """
    seen: dict[CpeCriterion, None] = {}
    for config in data.get("cpeApplicability", []):
        nodes = config.get("nodes", [])
        config_and = config.get("operator") == "AND" and len(nodes) > 1
        for node in nodes:
            matches = node.get("cpeMatch", [])
            negated = bool(node.get("negate", node.get("negated", False)))
            conjunctive = config_and or (
                node.get("operator") == "AND" and len(matches) > 1
            )
            for match in matches:
                criteria = match.get("criteria")
                if not criteria:
                    continue
                key: CpeCriterion = (
                    criteria,
                    bool(match.get("vulnerable", True)),
                    negated,
                    conjunctive,
                    match.get("versionStartIncluding"),
                    match.get("versionStartExcluding"),
                    match.get("versionEndIncluding"),
                    match.get("versionEndExcluding"),
                )
                seen[key] = None
    return list(seen)


def _make_cpe_applicability(
    container: models.Container, criterion: CpeCriterion
) -> models.CpeApplicability | None:
    criteria, vulnerable, negated, conjunctive, vsi, vse, vei, vee = criterion
    try:
        parsed = CPE(criteria)
        part, vendor, product, version = (
            parsed.get_part()[0],
            parsed.get_vendor()[0],
            parsed.get_product()[0],
            parsed.get_version()[0],
        )
    except (NotImplementedError, ValueError, IndexError) as e:
        logger.warning("Discarding malformed CPE criteria %r: %s", criteria, e)
        return None
    return models.CpeApplicability(
        container=container,
        criteria=criteria,
        part=part,
        vendor=vendor,
        product=product,
        version=version,
        vulnerable=vulnerable,
        negated=negated,
        conjunctive=conjunctive,
        version_start_including=vsi,
        version_start_excluding=vse,
        version_end_including=vei,
        version_end_excluding=vee,
    )


def _stored_criterion(obj: models.CpeApplicability) -> CpeCriterion:
    return (
        obj.criteria,
        obj.vulnerable,
        obj.negated,
        obj.conjunctive,
        obj.version_start_including,
        obj.version_start_excluding,
        obj.version_end_including,
        obj.version_end_excluding,
    )


def reconcile_cpe_applicability(
    container: models.Container, data: dict[str, Any]
) -> bool:
    """Bring the stored criteria in line with `data`, keeping rows still present. Returns whether anything changed."""
    stored = {_stored_criterion(obj): obj for obj in container.cpe_applicability.all()}
    incoming = cpe_applicability_criteria(data)
    wanted = set(incoming)
    gone = [obj.pk for key, obj in stored.items() if key not in wanted]
    new = [
        row
        for key in incoming
        if key not in stored
        if (row := _make_cpe_applicability(container, key)) is not None
    ]
    if gone:
        models.CpeApplicability.objects.filter(pk__in=gone).delete()
    if new:
        models.CpeApplicability.objects.bulk_create(new)
    return bool(gone or new)


def _container_notify_triggers() -> list[str]:
    return [
        f"{models.Container._meta.label}:{trigger.name}"
        for model, trigger in pgtrigger.registered()
        if model is models.Container and isinstance(trigger, Notify)
    ]


def _delete_container_content(obj: models.Container) -> None:
    """Delete the presentation children of a container; they are created per container and owned by it."""
    problem_types = list(obj.problem_types.values_list("pk", flat=True))
    description_ids = {
        pk
        for relation in (
            obj.descriptions,
            obj.configurations,
            obj.workarounds,
            obj.solutions,
            obj.exploits,
        )
        for pk in relation.values_list("pk", flat=True)
    }
    description_ids.update(
        models.Description.objects.filter(problemtype__in=problem_types).values_list(
            "pk", flat=True
        )
    )
    description_ids.update(obj.timeline.values_list("description_id", flat=True))
    description_ids.update(obj.credits.values_list("description_id", flat=True))
    reference_ids = set(obj.references.values_list("pk", flat=True))
    reference_ids.update(
        models.Reference.objects.filter(problemtype__in=problem_types).values_list(
            "pk", flat=True
        )
    )
    metric_ids = list(obj.metrics.values_list("pk", flat=True))
    media_ids = list(
        models.SupportingMedia.objects.filter(
            description__in=description_ids
        ).values_list("pk", flat=True)
    )

    models.ProblemType.objects.filter(pk__in=problem_types).delete()
    # Events and credits go with their descriptions.
    models.Description.objects.filter(pk__in=description_ids).delete()
    models.SupportingMedia.objects.filter(pk__in=media_ids).delete()
    models.Reference.objects.filter(pk__in=reference_ids).delete()
    models.Metric.objects.filter(pk__in=metric_ids).delete()


def _product_state(obj: models.AffectedProduct) -> tuple:
    """Everything stored for a product, to tell whether an overwrite changed anything."""
    fields = tuple(
        getattr(obj, f.attname)
        for f in models.AffectedProduct._meta.concrete_fields
        if not f.primary_key and f.name not in ("search_vector", "content_hash")
    )
    relations = []
    for f in models.AffectedProduct._meta.many_to_many:
        related = getattr(obj, f.name).all()
        if f.related_model is models.Version:
            # Versions are owned by their product, so compare their content rather than their keys.
            relations.append(
                sorted(
                    tuple(
                        str(getattr(v, g.attname))
                        for g in models.Version._meta.concrete_fields
                        if not g.primary_key
                    )
                    for v in related
                )
            )
        else:
            # Shared rows (`get_or_create`): equal keys are equal content.
            relations.append(sorted(related.values_list("pk", flat=True)))
    return fields, relations


def _overwrite_product(
    obj: models.AffectedProduct, data: dict[str, Any], digest: str
) -> bool:
    """
    Replace the content of `obj` with `data`, keeping its primary key.

    Builds a fresh row with `make_affected_product` and moves its fields and relations over, so that
    whatever that function stores is updated the same way. Returns whether the stored state changed.
    """
    before = _product_state(obj)
    old_versions = list(obj.versions.values_list("pk", flat=True))
    fresh = make_affected_product(data)
    for f in models.AffectedProduct._meta.concrete_fields:
        if f.primary_key or f.name in ("search_vector", "content_hash"):
            continue
        setattr(obj, f.attname, getattr(fresh, f.attname))
    obj.content_hash = digest
    obj.save()
    for f in models.AffectedProduct._meta.many_to_many:
        getattr(obj, f.name).set(getattr(fresh, f.name).all())
    fresh.delete()
    models.Version.objects.filter(pk__in=old_versions).delete()
    return _product_state(obj) != before


def _delete_product(obj: models.AffectedProduct) -> None:
    versions = list(obj.versions.values_list("pk", flat=True))
    obj.delete()
    models.Version.objects.filter(pk__in=versions).delete()


def _reconcile_products(
    container: models.Container,
    entries: list[dict[str, Any]],
    result: Reconciliation,
) -> None:
    """
    Bring the affected products of `container` in line with `entries`, keeping the primary key of every
    product that is still there (see `product_identity`).

    Several entries with one identity are paired with stored rows first by equal content, then in order
    (stored rows by primary key, which is their original order).
    """
    stored: dict[tuple[str, ...], list[models.AffectedProduct]] = {}
    for obj in container.affected.order_by("pk"):
        stored.setdefault(_stored_product_identity(obj), []).append(obj)
    incoming = [(product_identity(e), product_hash(e), e) for e in entries]
    claimed: set[int] = set()
    assigned: list[models.AffectedProduct | None] = [None] * len(incoming)

    for by_content in (True, False):
        for i, (identity, digest, _) in enumerate(incoming):
            if assigned[i] is not None:
                continue
            for obj in stored.get(identity, []):
                if obj.pk in claimed:
                    continue
                if by_content and obj.content_hash != digest:
                    continue
                assigned[i] = obj
                claimed.add(obj.pk)
                break

    for (_, digest, entry), obj in zip(incoming, assigned, strict=True):
        if obj is None:
            container.affected.add(make_hashed_product(entry))
            result.products_added += 1
            result.matching_changed = True
        elif obj.content_hash == digest:
            result.products_unchanged += 1
        else:
            result.products_updated += 1
            if _overwrite_product(obj, entry, digest):
                result.matching_changed = True

    for objs in stored.values():
        for obj in objs:
            if obj.pk not in claimed:
                _delete_product(obj)
                result.products_removed += 1
                result.matching_changed = True


def _update_container(
    obj: models.Container,
    data: dict[str, Any],
    _type: str,
    result: Reconciliation,
) -> None:
    had_hosted_tag = obj.tags.filter(value=HOSTED_SERVICE_TAG).exists()
    for key, value in _container_fields(data, _type).items():
        setattr(obj, key, value)
    obj.save()
    _delete_container_content(obj)
    _set_container_content(obj, data)
    if had_hosted_tag != (HOSTED_SERVICE_TAG in data.get("tags", [])):
        result.matching_changed = True
    _reconcile_products(obj, data.get("affected", []), result)
    if reconcile_cpe_applicability(obj, data):
        result.matching_changed = True
    result.containers_updated += 1


def _delete_container(obj: models.Container, result: Reconciliation) -> None:
    if obj.affected.exists() or obj.tags.filter(value=HOSTED_SERVICE_TAG).exists():
        result.matching_changed = True
    for product in obj.affected.all():
        _delete_product(product)
    _delete_container_content(obj)
    obj.delete()
    result.containers_removed += 1


def _carries_matching_data(data: dict[str, Any]) -> bool:
    return (
        bool(data.get("affected"))
        or bool(cpe_applicability_criteria(data))
        or HOSTED_SERVICE_TAG in data.get("tags", [])
    )


def _org_key(uuid: str | None) -> str | None:
    return str(UUID(uuid)) if uuid else None


def _reconcile_containers(
    cve: models.CveRecord, containers: dict[str, Any], result: Reconciliation
) -> None:
    """
    Containers are identified by (type, provider). A provider with several containers of one type has
    them paired in order.
    """
    stored: dict[tuple[str, str | None], list[models.Container]] = {}
    for obj in cve.container.order_by("pk"):
        stored.setdefault((obj._type, str(obj.provider_id)), []).append(obj)

    incoming = [(models.Container.Type.CNA.value, containers["cna"])] + [
        (models.Container.Type.ADP.value, adp) for adp in containers.get("adp", [])
    ]
    new: list[tuple[str, dict[str, Any]]] = []
    for _type, data in incoming:
        bucket = stored.get((_type, _org_key(data["providerMetadata"].get("orgId"))))
        if not bucket:
            new.append((_type, data))
            continue
        obj = bucket.pop(0)
        if obj.content_hash != container_hash(data):
            _update_container(obj, data, _type, result)

    for objs in stored.values():
        for obj in objs:
            _delete_container(obj, result)

    # The insert trigger would ask for a fresh suggestion; an update must not create one.
    with pgtrigger.ignore(*_container_notify_triggers()):
        for _type, data in new:
            make_container(data, _type=_type, cve=cve)
            result.containers_added += 1
            if _carries_matching_data(data):
                result.matching_changed = True


def reconcile_cve(
    record: models.CveRecord, data: dict[str, Any], triaged: bool = False
) -> Reconciliation:
    """
    Bring a known CVE record in line with an update of it.

    A record whose digest is unchanged is left alone without further queries. Otherwise every container
    whose digest changed is updated in place, new ones are added without creating a suggestion, and gone
    ones are removed. When something matchers read changed, `CveUpdateChannel` is notified with the
    record's primary key, in the same transaction; otherwise `CvePresentationChannel`.
    """
    result = Reconciliation()
    digest = record_hash(data)
    if record.content_hash == digest:
        return result

    with transaction.atomic():
        cve = models.CveRecord.objects.select_for_update().get(pk=record.pk)
        if cve.content_hash == digest:
            return result
        if (
            models.CveRecord.objects.filter(cve_id=cve.cve_id)
            .exclude(pk=cve.pk)
            .exists()
        ):
            logger.warning(
                "Several records for %s, updating only record %d", cve.cve_id, cve.pk
            )
        old_state = cve.state
        make_cve_record(data["cveMetadata"], cve=cve)
        cve.triaged = triaged
        cve.content_hash = digest
        cve.save()
        result.changed = True
        if cve.state != old_state:
            result.matching_changed = True

        _reconcile_containers(cve, data["containers"], result)

        if result.matching_changed:
            pgpubsub.notify(CveUpdateChannel, pk=cve.pk)
        else:
            pgpubsub.notify(CvePresentationChannel, pk=cve.pk)

    record.refresh_from_db()
    return result


def _container_fields(data: dict[str, Any], _type: str) -> dict[str, Any]:
    ctx: dict[str, Any] = {"_type": _type}
    ctx["provider"] = make_organization(
        uuid=data["providerMetadata"].get("orgId"),
        short_name=data["providerMetadata"].get("shortName"),
    )
    ctx["title"] = data.get("title", "")
    ctx["date_assigned"] = (
        make_date(data.get("dateAssigned"))
        if _type == models.Container.Type.CNA
        else None
    )
    ctx["date_public"] = make_date(data.get("datePublic"))
    ctx["source"] = data.get("source", dict())
    ctx["content_hash"] = container_hash(data)
    return ctx


def _set_container_content(obj: models.Container, data: dict[str, Any]) -> None:
    """Attach the presentation children and tags of a container: everything but `affected`."""
    obj.descriptions.set(map(make_description, data.get("descriptions", [])))
    # Map problem types from the terrible definition to our models
    problems = [
        desc
        for problem in data.get("problemTypes", [])
        for desc in problem.get("descriptions", [])
    ]
    obj.problem_types.set(map(make_problem_type, problems))
    obj.references.set(map(make_reference, data.get("references", [])))
    obj.metrics.set(make_metrics(data.get("metrics", [])))
    obj.configurations.set(map(make_description, data.get("configurations", [])))
    obj.workarounds.set(map(make_description, data.get("workarounds", [])))
    obj.solutions.set(map(make_description, data.get("solutions", [])))
    obj.exploits.set(map(make_description, data.get("exploits", [])))
    obj.timeline.set(map(make_event, data.get("timeline", [])))
    obj.tags.set(map(make_tag, data.get("tags", [])))
    obj.credits.set(map(make_credit, data.get("credits", [])))


def make_container(
    data: dict[str, Any], _type: str, cve: models.CveRecord
) -> models.Container:
    obj = models.Container.objects.create(cve=cve, **_container_fields(data, _type))
    _set_container_content(obj, data)
    obj.affected.set(make_hashed_product(entry) for entry in data.get("affected", []))
    models.CpeApplicability.objects.bulk_create(
        row
        for criterion in cpe_applicability_criteria(data)
        if (row := _make_cpe_applicability(obj, criterion)) is not None
    )
    return obj


def make_cve(
    data: dict[str, Any],
    record: models.CveRecord | None = None,
    triaged: bool = False,
) -> models.CveRecord:
    """
    Ingest a CVE JSON 5 record.

    A record for an unknown CVE id is created; a known one (`record`, or else the one `find_cve_record` picks)
    is reconciled with the incoming data by `reconcile_cve`.
    """
    if record is None:
        record = find_cve_record(data["cveMetadata"]["cveId"])
    if record is not None:
        reconcile_cve(record, data, triaged=triaged)
        return record

    cve = make_cve_record(data["cveMetadata"])
    cve.triaged = triaged
    cve.content_hash = record_hash(data)
    cve.save()

    make_container(data["containers"]["cna"], _type=models.Container.Type.CNA, cve=cve)

    for adp in data["containers"].get("adp", []):
        make_container(adp, _type=models.Container.Type.ADP, cve=cve)

    return cve


def fetch_cve_gh(cve_id: str) -> models.CveRecord | None:
    """Fetch a cve from the cvelistV5 github repository."""

    m = re.fullmatch(
        r"^CVE-(?P<year>[0-9]{4})-(?P<prefix>[0-9]{1,15})[0-9]{3}$", cve_id
    )

    if m is None:
        raise ValueError("Not a correct CVE Id")

    r = get(
        "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/"
        f"{m.group('year')}/{m.group('prefix')}xxx/{cve_id}.json"
    )

    if r.status_code != 200:
        raise RuntimeError(f"Error during GET request: {r.status_code}\n{r.text}")

    data = json.loads(r.text)

    return make_cve(data)
