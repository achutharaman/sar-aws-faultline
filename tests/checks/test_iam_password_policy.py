"""Detection logic for iam-password-policy-weak."""

from __future__ import annotations

import boto3
from moto import mock_aws

from sar_aws_faultline.checks.iam_password_policy import (
    IamPasswordPolicyWeak,
    PasswordPolicyState,
    weaknesses,
)
from sar_aws_faultline.config import Config
from sar_aws_faultline.context import ScanContext
from sar_aws_faultline.session import ClientFactory
from tests.conftest import FROZEN_NOW, TEST_ACCOUNT


def test_strong_policy_has_no_weaknesses():
    state = PasswordPolicyState(configured=True, minimum_length=14, reuse_prevention=24)
    assert weaknesses(state) == []


def test_short_minimum_length_is_a_weakness():
    state = PasswordPolicyState(configured=True, minimum_length=8, reuse_prevention=24)
    assert any("minimum length" in w for w in weaknesses(state))


def test_no_reuse_prevention_is_a_weakness():
    state = PasswordPolicyState(configured=True, minimum_length=14, reuse_prevention=0)
    assert any("reuse" in w for w in weaknesses(state))


def test_unconfigured_policy_is_the_weakest_case():
    state = PasswordPolicyState(configured=False)
    found = weaknesses(state)
    assert any("minimum length" in w for w in found)
    assert any("reuse" in w for w in found)


def _context() -> ScanContext:
    return ScanContext(
        region="us-east-1",
        check_id=IamPasswordPolicyWeak.id,
        service="iam",
        config=Config(),
        factory=ClientFactory(),
        now=FROZEN_NOW,
        account_id=TEST_ACCOUNT,
    )


def test_finding_mentions_no_policy_at_all():
    finding = IamPasswordPolicyWeak()._evaluate(_context(), PasswordPolicyState(configured=False))
    assert finding is not None
    assert "No password policy" in finding.detail


def test_no_finding_for_a_strong_policy():
    state = PasswordPolicyState(configured=True, minimum_length=14, reuse_prevention=24)
    assert IamPasswordPolicyWeak()._evaluate(_context(), state) is None


@mock_aws
def test_run_flags_the_default_no_policy_state():
    findings = list(IamPasswordPolicyWeak().run(_context()))
    assert len(findings) == 1


@mock_aws
def test_run_is_quiet_once_a_strong_policy_is_set():
    iam = boto3.client("iam", region_name="us-east-1")
    iam.update_account_password_policy(MinimumPasswordLength=14, PasswordReusePrevention=24)

    assert list(IamPasswordPolicyWeak().run(_context())) == []
