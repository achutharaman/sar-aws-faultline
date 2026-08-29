"""Detection logic for ebs-volume-unencrypted."""

from __future__ import annotations

import boto3
from moto import mock_aws

from sar_aws_faultline.checks.ebs_encryption import (
    UnencryptedEbsVolumes,
    VolumeState,
    is_unencrypted,
)
from sar_aws_faultline.config import Config
from sar_aws_faultline.context import ScanContext
from sar_aws_faultline.models import AuditImpact, Severity
from sar_aws_faultline.session import ClientFactory
from tests.conftest import FROZEN_NOW, TEST_ACCOUNT


def test_encrypted_volume_is_fine():
    state = VolumeState(volume_id="vol-1", encrypted=True, size_gib=8)
    assert is_unencrypted(state) is False


def test_unencrypted_volume_is_flagged():
    state = VolumeState(volume_id="vol-1", encrypted=False, size_gib=8)
    assert is_unencrypted(state) is True


def _context() -> ScanContext:
    return ScanContext(
        region="us-east-1",
        check_id=UnencryptedEbsVolumes.id,
        service="ec2",
        config=Config(),
        factory=ClientFactory(),
        now=FROZEN_NOW,
        account_id=TEST_ACCOUNT,
    )


def test_finding_metadata():
    ctx = _context()
    state = VolumeState(volume_id="vol-1", encrypted=False, size_gib=100, attachment_state="in-use")
    finding = UnencryptedEbsVolumes()._evaluate(ctx, state)
    assert finding is not None
    assert finding.severity is Severity.MEDIUM
    assert finding.audit_impact is AuditImpact.EXPECTED
    assert finding.metadata["size_gib"] == "100"


@mock_aws
def test_run_flags_only_unencrypted_volumes():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    ec2.create_volume(AvailabilityZone="us-east-1a", Size=8, Encrypted=False)
    ec2.create_volume(AvailabilityZone="us-east-1a", Size=8, Encrypted=True)

    findings = list(UnencryptedEbsVolumes().run(_context()))

    assert len(findings) == 1


@mock_aws
def test_run_on_empty_account_yields_nothing():
    assert list(UnencryptedEbsVolumes().run(_context())) == []
