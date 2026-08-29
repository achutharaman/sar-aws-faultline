"""Detection logic for ebs-snapshot-public."""

from __future__ import annotations

import boto3
from moto import mock_aws

from sar_aws_faultline.checks.ebs_snapshot_public import (
    EbsSnapshotPublic,
    SnapshotState,
    is_public,
)
from sar_aws_faultline.config import Config
from sar_aws_faultline.context import ScanContext
from sar_aws_faultline.session import ClientFactory
from tests.conftest import FROZEN_NOW, TEST_ACCOUNT


def test_private_snapshot_is_fine():
    assert is_public(SnapshotState(snapshot_id="snap-1", public=False)) is False


def test_public_snapshot_is_flagged():
    assert is_public(SnapshotState(snapshot_id="snap-1", public=True)) is True


def _context() -> ScanContext:
    return ScanContext(
        region="us-east-1",
        check_id=EbsSnapshotPublic.id,
        service="ec2",
        config=Config(),
        factory=ClientFactory(),
        now=FROZEN_NOW,
        account_id=TEST_ACCOUNT,
    )


@mock_aws
def test_run_flags_only_the_public_snapshot():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vol = ec2.create_volume(AvailabilityZone="us-east-1a", Size=8)["VolumeId"]
    public_snap = ec2.create_snapshot(VolumeId=vol)["SnapshotId"]
    private_snap = ec2.create_snapshot(VolumeId=vol)["SnapshotId"]
    ec2.modify_snapshot_attribute(
        SnapshotId=public_snap,
        Attribute="createVolumePermission",
        OperationType="add",
        GroupNames=["all"],
    )

    findings = list(EbsSnapshotPublic().run(_context()))

    assert [f.resource_id for f in findings] == [public_snap]
    assert private_snap not in [f.resource_id for f in findings]


@mock_aws
def test_run_on_empty_account_yields_nothing():
    assert list(EbsSnapshotPublic().run(_context())) == []
