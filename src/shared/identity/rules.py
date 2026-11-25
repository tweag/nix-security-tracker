"""
Load the checked-in rule file into `ProductMapping(source=rule_file)` rows: create what is new,
update relation and comment in place, delete what was removed from the file.
"""

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from django.db import transaction

from shared.identity.keys import get_or_create_keys
from shared.identity.mappings import validate_glob
from shared.matching.view import KeySpec
from shared.models.matching import ProductKey, ProductMapping

RULE_FILE = Path(__file__).with_name("rules.toml")
Relation = ProductMapping.Relation

RULE_FIELDS = {
    "keys",
    "same",
    "same_glob",
    "not_same",
    "not_same_glob",
    "only",
    "irrelevant",
    "comment",
}


@dataclass(frozen=True)
class RuleRow:
    """One `ProductMapping` the file asks for."""

    key: KeySpec
    relation: str
    attrpath: str | None = None
    attr_glob: str | None = None
    comment: str = ""

    @property
    def target(self) -> tuple[KeySpec, str | None, str | None]:
        """What the unique constraint identifies a rule file row by."""
        return (self.key, self.attrpath, self.attr_glob)


def _key(spec: dict[str, Any]) -> KeySpec:
    if set(spec) != {"kind", "vendor", "product"}:
        raise ValueError(f"a key needs exactly kind, vendor, product: {spec!r}")
    if spec["kind"] not in ProductKey.Kind.values:
        raise ValueError(f"unknown key kind {spec['kind']!r}")
    norm = ProductKey.normalise
    key = KeySpec(spec["kind"], norm(spec["vendor"]), norm(spec["product"])).capped()
    if not key.product:
        raise ValueError(f"empty product in {spec!r}")
    return key


def parse_rules(text: str) -> list[RuleRow]:
    """The rows a rule file asks for; raises `ValueError` on anything malformed or contradictory."""
    rows: dict[tuple[KeySpec, str | None, str | None], RuleRow] = {}
    for i, rule in enumerate(tomllib.loads(text).get("rule", [])):
        unknown = set(rule) - RULE_FIELDS
        if unknown:
            raise ValueError(f"rule {i}: unknown fields {sorted(unknown)}")
        comment = rule.get("comment", "").strip()
        targets: list[tuple[str, str | None, str | None]] = []
        targets += [(Relation.SAME, a, None) for a in rule.get("same", [])]
        targets += [(Relation.SAME, None, g) for g in rule.get("same_glob", [])]
        targets += [(Relation.NOT_SAME, a, None) for a in rule.get("not_same", [])]
        targets += [(Relation.NOT_SAME, None, g) for g in rule.get("not_same_glob", [])]
        if rule.get("only"):
            targets.append((Relation.NOT_SAME, None, "*"))
        if rule.get("irrelevant"):
            if targets:
                raise ValueError(f"rule {i}: irrelevant takes no targets")
            targets.append((Relation.IRRELEVANT, None, None))
        if not targets or not rule.get("keys"):
            raise ValueError(f"rule {i}: needs keys and at least one target")
        for _, _, glob in targets:
            if glob is not None:
                validate_glob(glob)
        for spec in rule["keys"]:
            key = _key(spec)
            for relation, attrpath, glob in targets:
                row = RuleRow(key, relation, attrpath, glob, comment)
                if row.target in rows and rows[row.target].relation != relation:
                    raise ValueError(f"rule {i}: contradicts an earlier rule on {row}")
                rows[row.target] = row
    return list(rows.values())


@dataclass
class SyncResult:
    created: list[ProductMapping] = field(default_factory=list)
    updated: list[ProductMapping] = field(default_factory=list)
    deleted: list[ProductMapping] = field(default_factory=list)
    # Unsaved copies of updated rows as they were, so callers reconcile for old and new relation.
    previous: list[ProductMapping] = field(default_factory=list)
    unchanged: int = 0

    @property
    def changed(self) -> list[ProductMapping]:
        return self.created + self.updated + self.previous + self.deleted


@transaction.atomic
def sync_rule_file(text: str) -> SyncResult:
    """Make the `rule_file` mappings equal to what `text` asks for. Idempotent."""
    wanted = parse_rules(text)
    ids = get_or_create_keys(row.key for row in wanted)
    existing = {
        (KeySpec(m.product_key.kind, m.product_key.vendor, m.product_key.product),
         m.attrpath, m.attr_glob): m
        for m in ProductMapping.objects.filter(
            source=ProductMapping.Source.RULE_FILE
        ).select_related("product_key")
    }  # fmt: skip
    result = SyncResult()
    for row in wanted:
        mapping = existing.pop(row.target, None)
        if mapping is None:
            result.created.append(
                ProductMapping.objects.create(
                    product_key_id=ids[row.key],
                    attrpath=row.attrpath,
                    attr_glob=row.attr_glob,
                    relation=row.relation,
                    source=ProductMapping.Source.RULE_FILE,
                    comment=row.comment,
                )
            )
        elif (mapping.relation, mapping.comment) != (row.relation, row.comment):
            result.previous.append(
                ProductMapping(
                    product_key_id=mapping.product_key_id, relation=mapping.relation
                )
            )
            mapping.relation, mapping.comment = row.relation, row.comment
            mapping.save(update_fields=["relation", "comment"])
            result.updated.append(mapping)
        else:
            result.unchanged += 1
    for mapping in existing.values():
        mapping.delete()
        result.deleted.append(mapping)
    return result
