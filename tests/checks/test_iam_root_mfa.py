"""Detection logic for iam-root-account-no-mfa.

moto's fake credential report only ever contains rows for IAM users actually
created in the mock -- it never synthesises the ``<root_account>`` row real
AWS always includes (see moto.iam.models.IAMBackend.get_credential_report).
So _parse() is tested directly against synthetic CSV content instead of
through moto, and the one full-wiring test below monkeypatches the boto3
client's response rather than relying on moto to model root at all.
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
from tests.conftest import FROZEN_NOW, TEST_ACCOUNT

_HEADER = (
    "user,arn,user_creation_time,password_enabled,password_last_used,"
    "password_last_changed,password_next_rotation,mfa_active,"
    "access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,"
    "access_key_1_last_used_region,access_key_1_last_used_service,"
    "access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,"
    "access_key_2_last_used_region,access_key_2_last_used_service,"
    "cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated\n"
)


def _report(root_mfa: str) -> bytes:
    row = (
        "<root_account>,arn:aws:iam::123456789012:root,2020-01-01T00:00:00Z,"
        f"true,N/A,N/A,N/A,{root_mfa},false,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,"
        "N/A,false,N/A,false,N/A\n"
    )
    return (_HEADER + row).encode("utf-8")


def test_mfa_active_root_is_fine():
    assert root_lacks_mfa(RootAccountState(mfa_active=True)) is False


def test_mfa_missing_root_is_flagged():
    assert root_lacks_mfa(RootAccountState(mfa_active=False)) is True


def test_parse_finds_the_root_row_with_mfa():
    state = RootAccountWithoutMfa._parse(_report("true"))
    assert state == RootAccountState(mfa_active=True)


def test_parse_finds_the_root_row_without_mfa():
    state = RootAccountWithoutMfa._parse(_report("false"))
    assert state == RootAccountState(mfa_active=False)


def test_parse_returns_none_when_root_row_is_absent():
    assert RootAccountWithoutMfa._parse(_HEADER.encode("utf-8")) is None


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
    monkeypatch.setattr(iam, "get_credential_report", lambda: {"Content": _report("false")})

    findings = list(RootAccountWithoutMfa().run(ctx))

    assert len(findings) == 1
    assert findings[0].title == "Root account has no MFA"


@mock_aws
def test_run_is_quiet_when_the_report_says_mfa_is_active(monkeypatch):
    ctx = _context()
    iam = ctx.factory.client("iam", region=ctx.region)
    monkeypatch.setattr(iam, "get_credential_report", lambda: {"Content": _report("true")})

    assert list(RootAccountWithoutMfa().run(ctx)) == []
