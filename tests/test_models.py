from __future__ import annotations

from datetime import UTC, datetime

import pytest

from sar_aws_faultline.models import (
    AuditImpact,
    CheckError,
    Effort,
    Finding,
    Remediation,
    ScanResult,
    Severity,
)

NOW = datetime(2026, 8, 20, tzinfo=UTC)


def finding(**kw) -> Finding:
    defaults = {
        "check_id": "c",
        "resource_id": "r",
        "resource_type": "AWS::S3::Bucket",
        "region": "global",
        "severity": Severity.HIGH,
        "audit_impact": AuditImpact.EXPECTED,
        "title": "t",
        "detail": "d",
    }
    defaults.update(kw)
    return Finding(**defaults)


def test_severity_ordering_puts_critical_top():
    assert Severity.INFO < Severity.LOW < Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL


def test_findings_are_immutable():
    with pytest.raises(AttributeError):
        finding().resource_id = "other"


def test_sort_key_ranks_audit_impact_above_severity():
    """A low-severity blocker outranks a critical hardening item. That
    inversion is the whole reason the second axis exists."""
    blocker = finding(severity=Severity.LOW, audit_impact=AuditImpact.BLOCKER, resource_id="a")
    hardening = finding(
        severity=Severity.CRITICAL, audit_impact=AuditImpact.HARDENING, resource_id="b"
    )
    assert sorted([hardening, blocker], key=lambda f: f.sort_key)[0] is blocker


def test_remediation_requires_an_action():
    with pytest.raises(ValueError, match="console steps or CLI"):
        Remediation(summary="do the thing", effort=Effort.MINUTES)


def test_remediation_requires_a_summary():
    with pytest.raises(ValueError, match="summary"):
        Remediation(summary="  ", effort=Effort.MINUTES, cli_commands=("x",))


def test_remediation_rejects_negative_cost():
    with pytest.raises(ValueError, match="negative"):
        Remediation(summary="s", effort=Effort.MINUTES, cli_commands=("x",), monthly_cost_usd=-1)


def result(*findings, errors=()) -> ScanResult:
    return ScanResult(
        findings=tuple(findings),
        errors=tuple(errors),
        regions=("global",),
        checks_run=("c",),
        started_at=NOW,
        duration_seconds=1.0,
    )


def test_is_partial_tracks_errors():
    assert not result().is_partial
    assert result(errors=[CheckError("c", "global", "AccessDenied", "m")]).is_partial


def test_blocker_count():
    assert result(finding(audit_impact=AuditImpact.BLOCKER), finding()).blocker_count == 1


def test_by_check_groups_in_report_order():
    grouped = result(
        finding(check_id="b", audit_impact=AuditImpact.HARDENING),
        finding(check_id="a", audit_impact=AuditImpact.BLOCKER),
    ).by_check()
    assert list(grouped) == ["a", "b"]
