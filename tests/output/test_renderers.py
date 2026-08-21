from __future__ import annotations

import io
import json
from datetime import UTC, datetime

import pytest

from sar_aws_faultline.config import Config, OutputFormat
from sar_aws_faultline.models import (
    AuditImpact,
    CheckError,
    Finding,
    ScanResult,
    Severity,
)
from sar_aws_faultline.output.base import get_renderer

NOW = datetime(2026, 8, 20, 9, 0, tzinfo=UTC)
CHECK = "s3-bucket-public-access"


def result(*findings, errors=()) -> ScanResult:
    return ScanResult(
        findings=tuple(findings),
        errors=tuple(errors),
        regions=("global",),
        checks_run=(CHECK,),
        started_at=NOW,
        duration_seconds=2.5,
        account_id="123456789012",
    )


def finding(resource_id="open-bucket", **kw) -> Finding:
    defaults = {
        "check_id": CHECK,
        "resource_id": resource_id,
        "resource_type": "AWS::S3::Bucket",
        "region": "global",
        "severity": Severity.CRITICAL,
        "audit_impact": AuditImpact.BLOCKER,
        "title": "Publicly accessible S3 bucket",
        "detail": "Readable by anonymous principals via bucket acl",
        "metadata": {"exposure_paths": "acl"},
    }
    defaults.update(kw)
    return Finding(**defaults)


def render(fmt: OutputFormat, res: ScanResult) -> str:
    buf = io.StringIO()
    get_renderer(fmt).render(res, Config(), buf)
    return buf.getvalue()


ALL_FORMATS = [OutputFormat.TABLE, OutputFormat.JSON, OutputFormat.MARKDOWN]


@pytest.mark.parametrize("fmt", ALL_FORMATS)
def test_empty_result_renders(fmt):
    assert render(fmt, result()).strip()


@pytest.mark.parametrize("fmt", ALL_FORMATS)
def test_finding_resource_is_named(fmt):
    assert "open-bucket" in render(fmt, result(finding()))


@pytest.mark.parametrize("fmt", [OutputFormat.TABLE, OutputFormat.MARKDOWN])
def test_scope_limits_are_always_stated(fmt):
    """The likeliest reader is a founder who may forward this to a customer.
    Output that could be mistaken for an attestation is a liability."""
    out = render(fmt, result(finding()))
    assert "SOC 2" in out and "not" in out.lower()


@pytest.mark.parametrize("fmt", ALL_FORMATS)
def test_partial_scan_is_flagged(fmt):
    out = render(fmt, result(errors=[CheckError(CHECK, "global", "AccessDenied", "m")]))
    assert "artial" in out or '"partial": true' in out


# -- json -------------------------------------------------------------------


def test_json_is_valid_and_complete():
    payload = json.loads(render(OutputFormat.JSON, result(finding())))
    assert payload["schema_version"] == "1.0"
    assert payload["summary"] == {"findings": 1, "blockers": 1, "errors": 0}
    entry = payload["findings"][0]
    assert entry["audit_impact"] == "blocker"
    assert entry["remediation"]["effort"] == "minutes"
    assert entry["remediation"]["monthly_cost_usd"] == 0.0
    assert {c["framework"] for c in entry["controls"]} == {"cis-aws", "soc2-tsc"}


def test_json_carries_the_disclaimer():
    payload = json.loads(render(OutputFormat.JSON, result(finding())))
    assert "interpretive" in payload["disclaimer"]


def test_json_records_errors_separately_from_findings():
    payload = json.loads(
        render(OutputFormat.JSON, result(errors=[CheckError(CHECK, "global", "Denied", "m")]))
    )
    assert payload["findings"] == []
    assert payload["errors"][0]["error_code"] == "Denied"
    assert payload["scan"]["partial"] is True


# -- markdown ---------------------------------------------------------------


def test_markdown_leads_with_a_priority_table():
    out = render(OutputFormat.MARKDOWN, result(finding()))
    assert "What to fix, in order" in out
    assert out.index("What to fix") < out.index("How to fix")


def test_markdown_includes_remediation_economics():
    out = render(OutputFormat.MARKDOWN, result(finding()))
    assert "How to fix" in out
    assert "no additional cost" in out
    assert "Before you do this" in out
    assert "aws s3control put-public-access-block" in out


def test_markdown_shows_the_second_hop_of_the_mapping():
    """An interpretive mapping must display what it was reasoned from, or the
    report is asserting a SOC 2 link by fiat."""
    out = render(OutputFormat.MARKDOWN, result(finding()))
    assert "reasoned from cis-aws:2.1.4" in out
    assert "partially_supports" in out


def test_markdown_includes_licence_notices():
    out = render(OutputFormat.MARKDOWN, result(finding()))
    assert "Framework notices" in out and "AICPA" in out


def test_markdown_lists_checks_that_could_not_run():
    out = render(
        OutputFormat.MARKDOWN, result(errors=[CheckError(CHECK, "global", "AccessDenied", "m")])
    )
    assert "could not run" in out
    assert "means nothing" in out


def test_markdown_orders_by_audit_impact_before_severity():
    out = render(
        OutputFormat.MARKDOWN,
        result(
            finding(
                "hardening-bucket", severity=Severity.CRITICAL, audit_impact=AuditImpact.HARDENING
            ),
            finding("blocker-bucket", severity=Severity.LOW, audit_impact=AuditImpact.BLOCKER),
        ),
    )
    assert out.index("blocker-bucket") < out.index("hardening-bucket")
