"""Detection logic for kms-key-rotation-disabled."""

from __future__ import annotations

import boto3
from moto import mock_aws

from sar_aws_faultline.checks.kms_key_rotation import (
    KmsKeyRotationDisabled,
    KmsKeyState,
    rotation_missing,
)
from sar_aws_faultline.config import Config
from sar_aws_faultline.context import ScanContext
from sar_aws_faultline.session import ClientFactory
from tests.conftest import FROZEN_NOW, TEST_ACCOUNT


def _state(**kw) -> KmsKeyState:
    defaults = {
        "key_id": "key-1",
        "key_manager": "CUSTOMER",
        "enabled": True,
        "key_spec": "SYMMETRIC_DEFAULT",
        "rotation_enabled": False,
    }
    defaults.update(kw)
    return KmsKeyState(**defaults)


def test_customer_key_without_rotation_is_flagged():
    assert rotation_missing(_state()) is True


def test_customer_key_with_rotation_is_fine():
    assert rotation_missing(_state(rotation_enabled=True)) is False


def test_aws_managed_key_is_never_flagged():
    """AWS rotates these on its own schedule; the account owner cannot
    toggle it, so flagging it would be noise about nothing actionable."""
    assert rotation_missing(_state(key_manager="AWS")) is False


def test_disabled_key_is_not_flagged():
    assert rotation_missing(_state(enabled=False)) is False


def test_asymmetric_key_is_not_flagged():
    """Automatic rotation isn't supported for these at all."""
    assert rotation_missing(_state(key_spec="RSA_2048")) is False


def _context() -> ScanContext:
    return ScanContext(
        region="us-east-1",
        check_id=KmsKeyRotationDisabled.id,
        service="kms",
        config=Config(),
        factory=ClientFactory(),
        now=FROZEN_NOW,
        account_id=TEST_ACCOUNT,
    )


def test_finding_metadata():
    finding = KmsKeyRotationDisabled()._evaluate(_context(), _state())
    assert finding is not None
    assert finding.metadata["key_manager"] == "CUSTOMER"


def test_no_finding_when_rotation_is_on():
    assert KmsKeyRotationDisabled()._evaluate(_context(), _state(rotation_enabled=True)) is None


@mock_aws
def test_run_flags_only_the_unrotated_customer_key():
    kms = boto3.client("kms", region_name="us-east-1")
    unrotated = kms.create_key(Description="unrotated")["KeyMetadata"]["KeyId"]
    rotated = kms.create_key(Description="rotated")["KeyMetadata"]["KeyId"]
    kms.enable_key_rotation(KeyId=rotated)

    findings = list(KmsKeyRotationDisabled().run(_context()))

    assert [f.resource_id for f in findings] == [unrotated]


@mock_aws
def test_run_on_empty_account_yields_nothing():
    assert list(KmsKeyRotationDisabled().run(_context())) == []
