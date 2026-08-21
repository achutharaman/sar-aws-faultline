"""Mapping data integrity.

Compliance mapping data is the part of this project most likely to rot: it is
hand-written, it is not exercised by normal code paths, and a wrong control
reference is invisible until someone knowledgeable reads the report. These
tests are what make data-driven mapping safe.
"""

from __future__ import annotations

import pytest

from sar_aws_faultline.compliance import MappingDataError, Relationship, load_catalog
from sar_aws_faultline.registry import all_checks


@pytest.fixture(scope="module")
def catalog():
    return load_catalog()


def test_catalog_loads(catalog):
    assert catalog.frameworks and catalog.mappings


def test_no_relationship_claims_compliance():
    """There is deliberately no 'satisfies'. A configuration scanner cannot
    establish that a control is met. If someone adds a third member, this test
    is what stops the tool from starting to lie."""
    assert {r.value for r in Relationship} == {"supports", "partially_supports"}


def test_every_check_is_mapped(catalog):
    """An unmapped check silently vanishes from --framework filtering."""
    unmapped = [c.id for c in all_checks() if not catalog.for_check(c.id)]
    assert not unmapped, f"checks with no control mapping: {unmapped}"


def test_no_mapping_references_a_nonexistent_check(catalog):
    known = {c.id for c in all_checks()}
    orphans = sorted(set(catalog.mappings) - known)
    assert not orphans, f"mappings for checks that do not exist: {orphans}"


def test_every_control_reference_resolves(catalog):
    for check_id, refs in catalog.mappings.items():
        for ref in refs:
            assert ref.framework in catalog.frameworks, f"{check_id}: {ref.framework}"
            fw = catalog.frameworks[ref.framework]
            assert ref.control in fw.control_ids, f"{check_id}: {ref.framework}:{ref.control}"


def test_interpretive_mappings_show_their_working(catalog):
    """A mapping into a principles-based framework must name the objective
    control it was reasoned from, so a reader can audit the inference rather
    than take it on trust."""
    for check_id, refs in catalog.mappings.items():
        for ref in refs:
            if not catalog.frameworks[ref.framework].interpretive:
                continue
            assert ref.derived_from, f"{check_id} -> {ref.framework}:{ref.control}"
            fw_id, _, ctrl = ref.derived_from.partition(":")
            assert fw_id in catalog.frameworks
            assert not catalog.frameworks[fw_id].interpretive, (
                f"{ref.derived_from} is itself interpretive; derived_from must "
                f"point at an objective control"
            )
            assert ctrl in catalog.frameworks[fw_id].control_ids


def test_objective_mappings_do_not_claim_derivation(catalog):
    for check_id, refs in catalog.mappings.items():
        for ref in refs:
            if not catalog.frameworks[ref.framework].interpretive:
                assert not ref.derived_from, f"{check_id}: {ref.framework} is objective"


def test_every_mapping_has_a_substantive_rationale(catalog):
    for check_id, refs in catalog.mappings.items():
        for ref in refs:
            assert len(ref.rationale.split()) >= 15, (
                f"{check_id} -> {ref.framework}:{ref.control} needs a real "
                f"rationale, not a placeholder"
            )


def test_partial_mappings_say_what_is_missing(catalog):
    """'partially_supports' without explaining the gap is worse than no
    mapping: it implies coverage the check does not provide."""
    for check_id, refs in catalog.mappings.items():
        for ref in refs:
            if ref.relationship is Relationship.PARTIALLY_SUPPORTS:
                assert "partial" in ref.rationale.lower(), (
                    f"{check_id} -> {ref.control}: rationale must explain the limit"
                )


def test_every_framework_carries_a_licence_notice(catalog):
    """Both AICPA and CIS material is licensed. Shipping mappings without
    attribution is a legal problem, not a style problem."""
    for fw in catalog.frameworks.values():
        assert len(fw.notice.split()) >= 15, fw.id
        assert fw.url.startswith("https://"), fw.id
        assert fw.version, fw.id
        assert fw.authority, fw.id


def test_framework_filtering(catalog):
    assert "s3-bucket-public-access" in catalog.checks_for_framework("soc2-tsc")
    assert catalog.checks_for_framework("nope") == set()


def test_describe_rejects_unknown_framework(catalog):
    from sar_aws_faultline.compliance import ControlRef

    bad = ControlRef("nope", "1.1", Relationship.SUPPORTS, "x")
    with pytest.raises(MappingDataError):
        catalog.describe(bad)
