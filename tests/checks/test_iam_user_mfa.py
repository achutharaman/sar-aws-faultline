"""Detection logic for iam-user-no-mfa."""

from __future__ import annotations

import boto3
from moto import mock_aws

from sar_aws_faultline.checks.iam_user_mfa import (
    IamUserState,
    IamUsersWithoutMfa,
    console_user_lacks_mfa,
    parse_users,
)
from sar_aws_faultline.config import Config
from sar_aws_faultline.context import ScanContext
from sar_aws_faultline.session import ClientFactory
from tests.checks.credential_report_fixtures import csv_row, report_bytes
from tests.conftest import FROZEN_NOW, TEST_ACCOUNT


def test_password_and_no_mfa_is_flagged():
    state = IamUserState(user="alice", password_enabled=True, mfa_active=False)
    assert console_user_lacks_mfa(state) is True


def test_password_and_mfa_is_fine():
    state = IamUserState(user="alice", password_enabled=True, mfa_active=True)
    assert console_user_lacks_mfa(state) is False


def test_no_password_is_not_flagged_even_without_mfa():
    """API-only users have no MFA concept to fail; only password sign-in
    needs a second factor."""
    state = IamUserState(user="ci-bot", password_enabled=False, mfa_active=False)
    assert console_user_lacks_mfa(state) is False


def test_parse_users_excludes_root():
    rows = [
        {"user": "<root_account>", "password_enabled": "true", "mfa_active": "false"},
        {"user": "alice", "password_enabled": "true", "mfa_active": "false"},
    ]
    users = parse_users(rows)
    assert [u.user for u in users] == ["alice"]


def _context() -> ScanContext:
    return ScanContext(
        region="us-east-1",
        check_id=IamUsersWithoutMfa.id,
        service="iam",
        config=Config(),
        factory=ClientFactory(),
        now=FROZEN_NOW,
        account_id=TEST_ACCOUNT,
    )


@mock_aws
def test_run_flags_password_users_without_mfa():
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="alice")
    iam.create_login_profile(UserName="alice", Password="Sup3rSecret!!")
    iam.create_user(UserName="bob-api-only")

    findings = list(IamUsersWithoutMfa().run(_context()))

    assert [f.resource_id for f in findings] == ["alice"]


@mock_aws
def test_run_is_quiet_when_mfa_is_enabled(monkeypatch):
    ctx = _context()
    iam = ctx.factory.client("iam", region=ctx.region)
    content = report_bytes(csv_row("alice", password_enabled="true", mfa_active="true"))
    monkeypatch.setattr(iam, "get_credential_report", lambda: {"Content": content})

    assert list(IamUsersWithoutMfa().run(ctx)) == []
