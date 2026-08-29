"""Detection logic for rds-instance-multi-az-disabled."""

from __future__ import annotations

import boto3
from moto import mock_aws

from sar_aws_faultline.checks.rds_multi_az import (
    DbInstanceAzState,
    RdsInstanceMultiAzDisabled,
    is_single_az,
)
from sar_aws_faultline.config import Config
from sar_aws_faultline.context import ScanContext
from sar_aws_faultline.session import ClientFactory
from tests.conftest import FROZEN_NOW, TEST_ACCOUNT


def test_single_az_instance_is_flagged():
    state = DbInstanceAzState(identifier="db-1", multi_az=False, engine="postgres")
    assert is_single_az(state) is True


def test_multi_az_instance_is_fine():
    state = DbInstanceAzState(identifier="db-1", multi_az=True, engine="postgres")
    assert is_single_az(state) is False


def _context() -> ScanContext:
    return ScanContext(
        region="us-east-1",
        check_id=RdsInstanceMultiAzDisabled.id,
        service="rds",
        config=Config(),
        factory=ClientFactory(),
        now=FROZEN_NOW,
        account_id=TEST_ACCOUNT,
    )


@mock_aws
def test_run_flags_only_the_single_az_instance():
    rds = boto3.client("rds", region_name="us-east-1")
    rds.create_db_instance(
        DBInstanceIdentifier="single-az",
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MasterUsername="admin",
        MasterUserPassword="hunter22222",
        AllocatedStorage=20,
        MultiAZ=False,
    )
    rds.create_db_instance(
        DBInstanceIdentifier="multi-az",
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MasterUsername="admin",
        MasterUserPassword="hunter22222",
        AllocatedStorage=20,
        MultiAZ=True,
    )

    findings = list(RdsInstanceMultiAzDisabled().run(_context()))

    assert [f.resource_id for f in findings] == ["single-az"]


@mock_aws
def test_run_on_empty_account_yields_nothing():
    assert list(RdsInstanceMultiAzDisabled().run(_context())) == []
