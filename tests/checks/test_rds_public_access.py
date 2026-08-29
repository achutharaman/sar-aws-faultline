"""Detection logic for rds-instance-publicly-accessible."""

from __future__ import annotations

import boto3
from moto import mock_aws

from sar_aws_faultline.checks.rds_public_access import (
    DbPublicAccessState,
    RdsInstancePubliclyAccessible,
    is_publicly_accessible,
)
from sar_aws_faultline.config import Config
from sar_aws_faultline.context import ScanContext
from sar_aws_faultline.session import ClientFactory
from tests.conftest import FROZEN_NOW, TEST_ACCOUNT


def test_private_instance_is_fine():
    state = DbPublicAccessState(identifier="db-1", publicly_accessible=False, engine="postgres")
    assert is_publicly_accessible(state) is False


def test_public_instance_is_flagged():
    state = DbPublicAccessState(identifier="db-1", publicly_accessible=True, engine="postgres")
    assert is_publicly_accessible(state) is True


def _context() -> ScanContext:
    return ScanContext(
        region="us-east-1",
        check_id=RdsInstancePubliclyAccessible.id,
        service="rds",
        config=Config(),
        factory=ClientFactory(),
        now=FROZEN_NOW,
        account_id=TEST_ACCOUNT,
    )


@mock_aws
def test_run_flags_only_the_public_instance():
    rds = boto3.client("rds", region_name="us-east-1")
    rds.create_db_instance(
        DBInstanceIdentifier="public-db",
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MasterUsername="admin",
        MasterUserPassword="hunter22222",
        AllocatedStorage=20,
        PubliclyAccessible=True,
    )
    rds.create_db_instance(
        DBInstanceIdentifier="private-db",
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MasterUsername="admin",
        MasterUserPassword="hunter22222",
        AllocatedStorage=20,
        PubliclyAccessible=False,
    )

    findings = list(RdsInstancePubliclyAccessible().run(_context()))

    assert [f.resource_id for f in findings] == ["public-db"]


@mock_aws
def test_run_on_empty_account_yields_nothing():
    assert list(RdsInstancePubliclyAccessible().run(_context())) == []
