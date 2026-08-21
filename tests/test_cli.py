from __future__ import annotations

import json

from typer.testing import CliRunner

from sar_aws_faultline.cli import app
from sar_aws_faultline.config import ExitCode

runner = CliRunner()


def test_version():
    r = runner.invoke(app, ["--version"])
    assert r.exit_code == 0
    assert "sar-aws-faultline" in r.stdout


def test_checks_table():
    r = runner.invoke(app, ["checks"])
    assert r.exit_code == 0
    assert "s3-bucket-public-access" in r.stdout


def test_checks_json_includes_frameworks():
    r = runner.invoke(app, ["checks", "--output", "json"])
    assert r.exit_code == 0
    entry = json.loads(r.stdout)[0]
    assert entry["frameworks"] == ["cis-aws", "soc2-tsc"]
    assert entry["audit_impact"] == "blocker"


def test_frameworks_labels_mapping_confidence():
    r = runner.invoke(app, ["frameworks"])
    assert r.exit_code == 0
    assert "interpretive" in r.stdout and "objective" in r.stdout


def test_iam_policy_is_generated_from_the_registry():
    r = runner.invoke(app, ["iam-policy"])
    assert r.exit_code == 0
    actions = json.loads(r.stdout)["Statement"][0]["Action"]
    assert "s3:ListAllMyBuckets" in actions
    assert "sts:GetCallerIdentity" in actions


def test_unknown_check_is_a_usage_error():
    r = runner.invoke(app, ["scan", "--check", "no-such-check"])
    assert r.exit_code == ExitCode.USAGE


def test_filters_matching_nothing_are_a_usage_error():
    """Silently scanning zero checks and exiting 0 would be the worst
    possible outcome: a green CI job that checked nothing."""
    r = runner.invoke(app, ["scan", "--impact", "hardening"])
    assert r.exit_code == ExitCode.USAGE
    assert "no checks matched" in r.stderr
