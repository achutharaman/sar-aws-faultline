from __future__ import annotations

import pytest

from sar_aws_faultline.models import AuditImpact, Effort, Remediation, Scope, Severity
from sar_aws_faultline.registry import (
    DuplicateCheckError,
    InvalidCheckError,
    all_checks,
    get_check,
    register,
    select_checks,
)

VALID_REMEDIATION = Remediation(
    summary="Do the thing.", effort=Effort.MINUTES, cli_commands=("aws s3 ls",)
)
LONG_RATIONALE = (
    "This matters because an unauthenticated stranger can reach the resource, "
    "which is the kind of thing a customer security questionnaire asks about."
)


def _valid_check_body(**overrides):
    body = {
        "id": "test-check",
        "title": "Test",
        "service": "s3",
        "resource_type": "AWS::S3::Bucket",
        "scope": Scope.GLOBAL,
        "severity": Severity.HIGH,
        "audit_impact": AuditImpact.EXPECTED,
        "rationale": LONG_RATIONALE,
        "remediation": VALID_REMEDIATION,
        "required_actions": frozenset({"s3:ListAllMyBuckets"}),
        "run": lambda self, ctx: iter(()),
    }
    body.update(overrides)
    return body


def test_discovery_finds_the_shipped_check():
    assert "s3-bucket-public-access" in [c.id for c in all_checks()]


def test_every_check_declares_permissions():
    """A check with no declared permissions silently breaks the generated
    least-privilege policy for everyone who uses it."""
    for check in all_checks():
        assert check.required_actions, check.id
        assert all(":" in a for a in check.required_actions), check.id


def test_every_check_has_actionable_remediation():
    for check in all_checks():
        rem = check.remediation
        assert rem.summary.strip()
        assert rem.console_steps or rem.cli_commands


def test_check_ids_are_kebab_case():
    for check in all_checks():
        assert check.id == check.id.lower()
        assert " " not in check.id and "_" not in check.id


def test_register_rejects_missing_metadata():
    with pytest.raises(InvalidCheckError, match="missing required attribute"):
        register(type("Bad", (), {"id": "x"}))


def test_register_rejects_wrong_enum_type():
    with pytest.raises(InvalidCheckError, match="must be a Severity"):
        register(type("Bad", (), _valid_check_body(id="bad-sev", severity="high")))


def test_register_rejects_non_frozenset_actions():
    with pytest.raises(InvalidCheckError, match="frozenset"):
        register(type("Bad", (), _valid_check_body(id="bad-acts", required_actions={"s3:Get"})))


def test_register_rejects_malformed_iam_action():
    with pytest.raises(InvalidCheckError, match="not a valid IAM action"):
        register(
            type("Bad", (), _valid_check_body(id="bad-a", required_actions=frozenset({"nope"})))
        )


def test_register_rejects_a_stub_rationale():
    """The rationale is product copy rendered verbatim in the report, so an
    empty one ships a report that tells the reader nothing."""
    with pytest.raises(InvalidCheckError, match="rationale"):
        register(type("Bad", (), _valid_check_body(id="bad-r", rationale="TODO")))


def test_register_rejects_duplicate_ids():
    register(type("A", (), _valid_check_body(id="dupe-check")))
    with pytest.raises(DuplicateCheckError):
        register(type("B", (), _valid_check_body(id="dupe-check")))


def test_get_check_error_lists_known_ids():
    with pytest.raises(KeyError, match="registered checks"):
        get_check("nope")


def test_select_by_id():
    assert [c.id for c in select_checks(["s3-bucket-public-access"])] == ["s3-bucket-public-access"]


def test_select_skips():
    ids = [c.id for c in select_checks(skip=["s3-bucket-public-access"])]
    assert "s3-bucket-public-access" not in ids


def test_select_by_severity_floor():
    selected = select_checks(min_severity=Severity.CRITICAL)
    assert selected
    assert all(c.severity is Severity.CRITICAL for c in selected)


def test_select_by_impact():
    assert select_checks(impacts=[AuditImpact.BLOCKER])
    # Robust to future checks landing at any impact level: assert the filter
    # actually filters, rather than hardcoding which levels are populated
    # today.
    selected = select_checks(impacts=[AuditImpact.HARDENING])
    expected = [c for c in select_checks() if c.audit_impact is AuditImpact.HARDENING]
    assert selected == expected


def test_select_by_framework():
    ids = [c.id for c in select_checks(framework="cis-aws")]
    assert "s3-bucket-public-access" in ids
    assert select_checks(framework="unknown-framework") == []
