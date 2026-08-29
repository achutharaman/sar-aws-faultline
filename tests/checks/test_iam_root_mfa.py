"""Detection logic for iam-root-account-no-mfa.

moto's fake credential report only ever contains rows for IAM users actually
created in the mock -- it never synthesises the ``<root_account>`` row real
AWS always includes (see moto.iam.models.IAMBackend.get_credential_report).
So _parse() is tested directly against synthetic rows instead of through
moto, and the one full-wiring test below monkeypatches the boto3 client's
response rather than relying on moto to model root at all.
"""

from __future__ import annotations

from moto import mock_aws

from sar_aws_faultline.checks.iam_root_mfa import (
    RootAccountState,
    RootAccountWithoutMfa,
    root_lacks_mfa,
)
from sar_aws_faultline.config import Config
from sar_aws_faultline.context import ScanContext
from sar_aws_faultline.models import AuditImpact, Severity
from sar_aws_faultline.session import ClientFactory
from tests.checks.credential_report_fixtures import csv_row, report_bytes, report_rows
from tests.conftest import FROZEN_NOW, TEST_ACCOUNT


def test_mfa_active_root_is_fine():
    assert root_lacks_mfa(RootAccountState(mfa_active=True)) is False


def test_mfa_missing_root_is_flagged():
    assert root_lacks_mfa(RootAccountState(mfa_active=False)) is True


def test_parse_finds_the_root_row_with_mfa():
    rows = report_rows(csv_row("<root_account>", mfa_active="true"))
    assert RootAccountWithoutMfa._parse(rows) == RootAccountState(mfa_active=True)


def test_parse_finds_the_root_row_without_mfa():
    rows = report_rows(csv_row("<root_account>", mfa_active="false"))
    assert RootAccountWithoutMfa._parse(rows) == RootAccountState(mfa_active=False)


def test_parse_returns_none_when_root_row_is_absent():
    rows = report_rows(csv_row("some-user"))
    assert RootAccountWithoutMfa._parse(rows) is None


def _context() -> ScanContext:
    return ScanContext(
        region="us-east-1",
        check_id=RootAccountWithoutMfa.id,
        service="iam",
        config=Config(),
        factory=ClientFactory(),
        now=FROZEN_NOW,
        account_id=TEST_ACCOUNT,
    )


def test_finding_construction():
    finding = RootAccountWithoutMfa()._evaluate(_context(), RootAccountState(mfa_active=False))
    assert finding is not None
    assert finding.severity is Severity.CRITICAL
    assert finding.audit_impact is AuditImpact.BLOCKER


def test_no_finding_when_mfa_is_active():
    assert RootAccountWithoutMfa()._evaluate(_context(), RootAccountState(mfa_active=True)) is None


@mock_aws
def test_run_on_account_with_no_root_row_yields_nothing():
    """moto's report never includes root, so this is the honest limit of what
    moto alone can exercise here -- see the module docstring."""
    assert list(RootAccountWithoutMfa().run(_context())) == []


@mock_aws
def test_run_flags_root_when_the_report_says_no_mfa(monkeypatch):
    ctx = _context()
    iam = ctx.factory.client("iam", region=ctx.region)
    content = report_bytes(csv_row("<root_account>", mfa_active="false"))
    monkeypatch.setattr(iam, "get_credential_report", lambda: {"Content": content})

    findings = list(RootAccountWithoutMfa().run(ctx))

    assert len(findings) == 1
    assert findings[0].title == "Root account has no MFA"


@mock_aws
def test_run_is_quiet_when_the_report_says_mfa_is_active(monkeypatch):
    ctx = _context()
    iam = ctx.factory.client("iam", region=ctx.region)
    content = report_bytes(csv_row("<root_account>", mfa_active="true"))
    monkeypatch.setattr(iam, "get_credential_report", lambda: {"Content": content})

    assert list(RootAccountWithoutMfa().run(ctx)) == []
