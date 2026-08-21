from __future__ import annotations

import pytest

from sar_aws_faultline.config import Config
from sar_aws_faultline.models import (
    AuditImpact,
    Effort,
    Finding,
    Remediation,
    Scope,
    Severity,
)
from sar_aws_faultline.runner import GLOBAL_ENDPOINT_REGION, plan_units, run_scan
from sar_aws_faultline.session import ClientFactory, ReadOnlyViolationError

REM = Remediation(summary="Fix it.", effort=Effort.MINUTES, cli_commands=("aws s3 ls",))


def make_check(check_id, scope=Scope.REGIONAL, raises=None, findings=()):
    class _Check:
        id = check_id
        title = "T"
        service = "s3"
        resource_type = "AWS::S3::Bucket"
        scope = None
        severity = Severity.HIGH
        audit_impact = AuditImpact.EXPECTED
        rationale = "x" * 100
        remediation = REM
        required_actions = frozenset({"s3:ListAllMyBuckets"})

        def run(self, ctx):
            if raises is not None:
                raise raises
            yield from findings

    _Check.scope = scope
    _Check.__name__ = check_id
    return _Check


def finding(check_id="c", region="ap-south-1"):
    return Finding(
        check_id=check_id,
        resource_id="r",
        resource_type="AWS::S3::Bucket",
        region=region,
        severity=Severity.HIGH,
        audit_impact=AuditImpact.EXPECTED,
        title="t",
        detail="d",
    )


def scan(checks, regions=("ap-south-1", "eu-west-1")):
    return run_scan(checks, list(regions), factory=ClientFactory(), config=Config(max_workers=2))


def test_plan_runs_global_checks_once():
    units = plan_units([make_check("g", Scope.GLOBAL)], ["a", "b", "c"])
    assert units == [(units[0][0], GLOBAL_ENDPOINT_REGION)]


def test_plan_expands_regional_checks():
    assert len(plan_units([make_check("r")], ["a", "b", "c"])) == 3


def test_findings_are_collected():
    result = scan([make_check("c", findings=[finding()])])
    assert len(result.findings) == 2  # one per region


def test_global_findings_are_relabelled():
    check = make_check("g", Scope.GLOBAL, findings=[finding(region="us-east-1")])
    assert scan([check]).findings[0].region == "global"


def test_a_failing_check_becomes_an_error_not_a_crash():
    """Losing five checks' findings to one AccessDenied is a bad trade."""
    result = scan([make_check("boom", raises=RuntimeError("nope"))])
    assert not result.findings
    assert result.is_partial
    assert result.errors[0].error_code == "InternalError"


def test_one_broken_check_does_not_stop_the_others():
    result = scan(
        [make_check("ok", findings=[finding()]), make_check("boom", raises=RuntimeError("x"))]
    )
    assert result.findings and result.errors


def test_read_only_violation_propagates():
    """A blocked mutating call is our bug, not the user's environment, so it
    must never be swallowed into a CheckError and hidden in a report."""
    with pytest.raises(ReadOnlyViolationError):
        scan([make_check("bad", raises=ReadOnlyViolationError("PutObject"))])


def test_errors_are_sorted_deterministically():
    result = scan(
        [make_check("z", raises=RuntimeError("x")), make_check("a", raises=RuntimeError("x"))]
    )
    assert [e.check_id for e in result.errors] == sorted(e.check_id for e in result.errors)
