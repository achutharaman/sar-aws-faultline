from __future__ import annotations

from datetime import UTC, datetime

import pytest

from sar_aws_faultline.config import (
    ExitCode,
    FailOn,
    OutputFormat,
    find_config_file,
    load_config,
    resolve_exit_code,
)
from sar_aws_faultline.models import (
    AuditImpact,
    CheckError,
    Finding,
    ScanResult,
    Severity,
)

NOW = datetime(2026, 8, 20, tzinfo=UTC)

SAMPLE = """
regions = ["ap-south-1", "eu-west-1"]
output = "markdown"
fail_on = "blocker"

[check.s3-bucket-public-access]
ignore_buckets = ["public-assets"]
"""


def test_defaults():
    config = load_config()
    assert config.output is OutputFormat.TABLE
    assert config.fail_on is FailOn.NONE


def test_file_is_read(tmp_path, monkeypatch):
    path = tmp_path / "sar-aws-faultline.toml"
    path.write_text(SAMPLE)
    config = load_config(path)
    assert config.regions == ("ap-south-1", "eu-west-1")
    assert config.output is OutputFormat.MARKDOWN
    assert config.fail_on is FailOn.BLOCKER


def test_per_check_options(tmp_path):
    path = tmp_path / "sar-aws-faultline.toml"
    path.write_text(SAMPLE)
    config = load_config(path)
    assert config.option("s3-bucket-public-access", "ignore_buckets", []) == ["public-assets"]
    assert config.option("other-check", "ignore_buckets", []) == []


def test_env_overrides_file(tmp_path, monkeypatch):
    path = tmp_path / "sar-aws-faultline.toml"
    path.write_text(SAMPLE)
    monkeypatch.setenv("SAR_AWS_FAULTLINE_OUTPUT", "json")
    assert load_config(path).output is OutputFormat.JSON


def test_cli_overrides_env(tmp_path, monkeypatch):
    monkeypatch.setenv("SAR_AWS_FAULTLINE_OUTPUT", "json")
    assert load_config(None, output=OutputFormat.TABLE).output is OutputFormat.TABLE


def test_find_config_walks_up(tmp_path, monkeypatch):
    (tmp_path / "sar-aws-faultline.toml").write_text("")
    nested = tmp_path / "a" / "b"
    nested.mkdir(parents=True)
    monkeypatch.chdir(nested)
    assert find_config_file() == tmp_path / "sar-aws-faultline.toml"


# -- exit codes -------------------------------------------------------------


def finding(severity=Severity.HIGH, impact=AuditImpact.EXPECTED) -> Finding:
    return Finding(
        check_id="c",
        resource_id="r",
        resource_type="t",
        region="global",
        severity=severity,
        audit_impact=impact,
        title="t",
        detail="d",
    )


def result(*findings, errors=()) -> ScanResult:
    return ScanResult(
        findings=tuple(findings),
        errors=tuple(errors),
        regions=("global",),
        checks_run=("c",),
        started_at=NOW,
        duration_seconds=0.1,
    )


def test_clean_scan_is_zero():
    assert resolve_exit_code(result(), load_config(None, fail_on=FailOn.ANY)) == ExitCode.CLEAN


def test_fail_on_none_ignores_findings():
    assert resolve_exit_code(result(finding()), load_config()) == ExitCode.CLEAN


def test_fail_on_any():
    cfg = load_config(None, fail_on=FailOn.ANY)
    assert resolve_exit_code(result(finding()), cfg) == ExitCode.FINDINGS


@pytest.mark.parametrize(
    ("threshold", "severity", "expected"),
    [
        (FailOn.HIGH, Severity.CRITICAL, ExitCode.FINDINGS),
        (FailOn.HIGH, Severity.HIGH, ExitCode.FINDINGS),
        (FailOn.HIGH, Severity.MEDIUM, ExitCode.CLEAN),
        (FailOn.CRITICAL, Severity.HIGH, ExitCode.CLEAN),
    ],
)
def test_severity_threshold(threshold, severity, expected):
    cfg = load_config(None, fail_on=threshold)
    assert resolve_exit_code(result(finding(severity=severity)), cfg) == expected


def test_fail_on_blocker_ignores_severity():
    """The threshold most CI pipelines actually want, and one a
    severity-only tool cannot express."""
    cfg = load_config(None, fail_on=FailOn.BLOCKER)
    low_blocker = finding(severity=Severity.LOW, impact=AuditImpact.BLOCKER)
    crit_hardening = finding(severity=Severity.CRITICAL, impact=AuditImpact.HARDENING)
    assert resolve_exit_code(result(low_blocker), cfg) == ExitCode.FINDINGS
    assert resolve_exit_code(result(crit_hardening), cfg) == ExitCode.CLEAN


def test_errors_outrank_findings():
    """'I could not look at three checks' and 'you have two problems' are
    different messages, and a pipeline must be able to tell them apart."""
    cfg = load_config(None, fail_on=FailOn.ANY)
    r = result(finding(), errors=[CheckError("c", "global", "AccessDenied", "m")])
    assert resolve_exit_code(r, cfg) == ExitCode.ERRORS
