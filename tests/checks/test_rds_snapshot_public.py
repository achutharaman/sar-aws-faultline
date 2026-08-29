"""Detection logic for rds-snapshot-public."""

from __future__ import annotations

import boto3
from moto import mock_aws

from sar_aws_faultline.checks.rds_snapshot_public import (
    DbSnapshotState,
    RdsSnapshotPublic,
    is_public,
)
from sar_aws_faultline.config import Config
from sar_aws_faultline.context import ScanContext
from sar_aws_faultline.session import ClientFactory
from tests.conftest import FROZEN_NOW, TEST_ACCOUNT


def test_private_snapshot_is_fine():
    assert is_public(DbSnapshotState(snapshot_id="snap-1", public=False)) is False


def test_public_snapshot_is_flagged():
    assert is_public(DbSnapshotState(snapshot_id="snap-1", public=True)) is True


def _context() -> ScanContext:
    return ScanContext(
        region="us-east-1",
        check_id=RdsSnapshotPublic.id,
        service="rds",
        config=Config(),
        factory=ClientFactory(),
        now=FROZEN_NOW,
        account_id=TEST_ACCOUNT,
    )


@mock_aws
def test_run_flags_only_the_public_snapshot():
    rds = boto3.client("rds", region_name="us-east-1")
    rds.create_db_instance(
        DBInstanceIdentifier="db-1",
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MasterUsername="admin",
        MasterUserPassword="hunter22222",
        AllocatedStorage=20,
    )
    rds.create_db_snapshot(DBInstanceIdentifier="db-1", DBSnapshotIdentifier="public-snap")
    rds.create_db_snapshot(DBInstanceIdentifier="db-1", DBSnapshotIdentifier="private-snap")
    rds.modify_db_snapshot_attribute(
        DBSnapshotIdentifier="public-snap", AttributeName="restore", ValuesToAdd=["all"]
    )

    findings = list(RdsSnapshotPublic().run(_context()))

    assert [f.resource_id for f in findings] == ["public-snap"]


@mock_aws
def test_run_on_empty_account_yields_nothing():
    assert list(RdsSnapshotPublic().run(_context())) == []
