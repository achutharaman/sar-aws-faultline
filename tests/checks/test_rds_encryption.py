"""Detection logic for rds-instance-unencrypted."""

from __future__ import annotations

import boto3
from moto import mock_aws

from sar_aws_faultline.checks.rds_encryption import (
    DbInstanceState,
    UnencryptedRdsInstances,
    is_unencrypted,
)
from sar_aws_faultline.config import Config
from sar_aws_faultline.context import ScanContext
from sar_aws_faultline.models import AuditImpact, Severity
from sar_aws_faultline.session import ClientFactory
from tests.conftest import FROZEN_NOW, TEST_ACCOUNT


def test_encrypted_instance_is_fine():
    state = DbInstanceState(
        identifier="db-1", engine="postgres", storage_encrypted=True, status="available"
    )
    assert is_unencrypted(state) is False


def test_unencrypted_instance_is_flagged():
    state = DbInstanceState(
        identifier="db-1", engine="postgres", storage_encrypted=False, status="available"
    )
    assert is_unencrypted(state) is True


def _context() -> ScanContext:
    return ScanContext(
        region="us-east-1",
        check_id=UnencryptedRdsInstances.id,
        service="rds",
        config=Config(),
        factory=ClientFactory(),
        now=FROZEN_NOW,
        account_id=TEST_ACCOUNT,
    )


def test_finding_metadata():
    state = DbInstanceState(
        identifier="db-1", engine="mysql", storage_encrypted=False, status="available"
    )
    finding = UnencryptedRdsInstances()._evaluate(_context(), state)
    assert finding is not None
    assert finding.severity is Severity.HIGH
    assert finding.audit_impact is AuditImpact.BLOCKER
    assert finding.metadata["engine"] == "mysql"


@mock_aws
def test_run_flags_only_unencrypted_instances():
    rds = boto3.client("rds", region_name="us-east-1")
    rds.create_db_instance(
        DBInstanceIdentifier="unencrypted-db",
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MasterUsername="admin",
        MasterUserPassword="hunter22222",
        AllocatedStorage=20,
        StorageEncrypted=False,
    )
    rds.create_db_instance(
        DBInstanceIdentifier="encrypted-db",
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MasterUsername="admin",
        MasterUserPassword="hunter22222",
        AllocatedStorage=20,
        StorageEncrypted=True,
    )

    findings = list(UnencryptedRdsInstances().run(_context()))

    assert [f.resource_id for f in findings] == ["unencrypted-db"]


@mock_aws
def test_run_on_empty_account_yields_nothing():
    assert list(UnencryptedRdsInstances().run(_context())) == []
