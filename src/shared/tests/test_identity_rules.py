from collections.abc import Callable
from io import StringIO
from pathlib import Path

import pytest
from django.core.management import call_command

from shared.identity.keys import persist_product_keys
from shared.identity.rules import RULE_FILE, parse_rules, sync_rule_file
from shared.matching.matchers import collect_candidates
from shared.matching.view import build_cve_view
from shared.models.cve import AffectedProduct, Container
from shared.models.linkage import CVEDerivationClusterProposal
from shared.models.matching import Match, ProductMapping
from shared.models.snapshot import BranchPackage

MakePackage = Callable[..., BranchPackage]

RULES = """
[[rule]]
comment = "nvidia"
keys = [{ kind = "cna", vendor = "NVIDIA", product = "GeForce" }]
same_glob = ["linuxPackages*.nvidia_x11*"]
only = true

[[rule]]
keys = [{ kind = "cna", vendor = "google", product = "android" }]
irrelevant = true
"""


def rows() -> set[tuple[str, str | None, str | None, str, str]]:
    return set(
        ProductMapping.objects.values_list(
            "product_key__product", "attrpath", "attr_glob", "relation", "source"
        )
    )


def test_checked_in_rule_file_parses() -> None:
    assert len(parse_rules(RULE_FILE.read_text())) > 10


@pytest.mark.parametrize(
    "text",
    [
        '[[rule]]\nkeys = [{ kind = "cna", vendor = "", product = "x" }]',
        '[[rule]]\nkeys = [{ kind = "bad", vendor = "", product = "x" }]\nirrelevant = true',
        '[[rule]]\nkeys = [{ kind = "cna", product = "x" }]\nirrelevant = true',
        '[[rule]]\nkeys = [{ kind = "cna", vendor = "", product = "x" }]\nsame_glob = ["a[0-9]"]',
        '[[rule]]\nkeys = [{ kind = "cna", vendor = "", product = "x" }]\nirrelevant = true\nsame = ["a"]',
        '[[rule]]\nkeys = [{ kind = "cna", vendor = "", product = "x" }]\nsame = ["a"]\nnot_same = ["a"]',
        '[[rule]]\nkeys = [{ kind = "cna", vendor = "", product = "x" }]\nirrelevant = true\ntypo = 1',
    ],
)
def test_malformed_rules_are_refused(text: str) -> None:
    with pytest.raises(ValueError):
        parse_rules(text)


def test_sync_is_idempotent_and_removes_deleted_rules(db: None) -> None:
    first = sync_rule_file(RULES)
    assert len(first.created) == 3
    assert rows() == {
        ("geforce", None, "linuxPackages*.nvidia_x11*", "same", "rule_file"),
        ("geforce", None, "*", "not_same", "rule_file"),
        ("android", None, None, "irrelevant", "rule_file"),
    }
    pks = set(ProductMapping.objects.values_list("pk", flat=True))

    again = sync_rule_file(RULES)
    assert (again.changed, again.unchanged) == ([], 3)
    assert set(ProductMapping.objects.values_list("pk", flat=True)) == pks

    # Mappings of other sources are never touched.
    curated = ProductMapping.objects.create(
        product_key=ProductMapping.objects.get(attr_glob="*").product_key,
        attrpath="nvidia-settings",
        relation="same",
        source="curated",
    )
    without_android = RULES.split("[[rule]]")
    third = sync_rule_file("[[rule]]".join(without_android[:2]))
    assert [m.relation for m in third.deleted] == ["irrelevant"]
    assert ProductMapping.objects.filter(pk=curated.pk).exists()
    assert ProductMapping.objects.count() == 3


def test_changed_relation_is_updated_in_place(db: None) -> None:
    sync_rule_file(RULES)
    pk = ProductMapping.objects.get(attr_glob="*").pk
    changed = RULES.replace("only = true", 'same = ["x"]\nnot_same_glob = ["*"]')
    result = sync_rule_file(changed)
    assert [m.attrpath for m in result.created] == ["x"]
    assert result.updated == [] and result.deleted == []
    assert ProductMapping.objects.get(attr_glob="*").pk == pk

    flipped = RULES.replace("only = true", 'same_glob = ["*"]').replace(
        'same_glob = ["linuxPackages*.nvidia_x11*"]\n', ""
    )
    result = sync_rule_file(flipped)
    assert [(m.attr_glob, m.relation) for m in result.updated] == [("*", "same")]
    assert [m.relation for m in result.previous] == ["not_same"]
    assert ProductMapping.objects.get(attr_glob="*").pk == pk


def test_command_loads_rules_and_reconciles(
    make_container: Callable[..., Container],
    make_suggestion: Callable[..., CVEDerivationClusterProposal],
    make_branch_package: MakePackage,
    tmp_path: Path,
) -> None:
    container = make_container(package_name=None, product="Tesla")
    AffectedProduct.objects.filter(pk=container.affected.get().pk).update(
        vendor="NVIDIA"
    )
    suggestion = make_suggestion(container=container)
    persist_product_keys(list(AffectedProduct.objects.all()))
    make_branch_package(attrpath="python313Packages.teslajsonpy", pname="teslajsonpy")
    make_branch_package(attrpath="linuxPackages.nvidia_x11", pname="nvidia-x11")
    make_branch_package(
        attrpath="linuxPackages_6_12.nvidia_x11_beta", pname="nvidia-x11"
    )
    view = build_cve_view(container.cve)
    assert [
        c.attrpath for c in collect_candidates(view)["name-substring"].candidates
    ] == ["python313Packages.teslajsonpy"]

    path = tmp_path / "rules.toml"
    path.write_text(RULES.replace('"GeForce"', '"Tesla"'))
    out = StringIO()
    call_command("load_product_rules", "--file", str(path), stdout=out)
    assert "3 created" in out.getvalue()
    active = set(
        Match.objects.active()
        .filter(suggestion=suggestion)
        .values_list("matcher", "attrpath")
    )
    assert active == {
        ("rules", "linuxPackages.nvidia_x11"),
        ("rules", "linuxPackages_6_12.nvidia_x11_beta"),
    }

    out = StringIO()
    call_command("load_product_rules", "--file", str(path), stdout=out)
    assert "0 created, 0 updated, 0 deleted, 3 unchanged" in out.getvalue()
