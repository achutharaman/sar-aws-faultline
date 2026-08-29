"""Detection logic for aws-config-not-enabled."""

from __future__ import annotations

import boto3
from moto import mock_aws

from sar_aws_faultline.checks.config_recorder import (
    AwsConfigNotEnabled,
    RecorderState,
    has_active_recorder,
)
from sar_aws_faultline.config import Config
from sar_aws_faultline.context import ScanContext
from sar_aws_faultline.session import ClientFactory
from tests.conftest import FROZEN_NOW, TEST_ACCOUNT


def test_no_recorders_means_no_coverage():
    assert has_active_recorder([]) is False


def test_recording_recorder_is_coverage():
    assert has_active_recorder([RecorderState(name="default", recording=True)]) is True


def test_stopped_recorder_is_not_coverage():
    assert has_active_recorder([RecorderState(name="default", recording=False)]) is False


def _context() -> ScanContext:
    return ScanContext(
        region="us-east-1",
        check_id=AwsConfigNotEnabled.id,
        service="config",
        config=Config(),
        factory=ClientFactory(),
        now=FROZEN_NOW,
        account_id=TEST_ACCOUNT,
    )


def test_finding_mentions_no_recorder_when_none_exist():
    finding = AwsConfigNotEnabled()._evaluate(_context(), [])
    assert finding is not None
    assert "No AWS Config recorder" in finding.detail


@mock_aws
def test_run_flags_account_with_no_recorder():
    findings = list(AwsConfigNotEnabled().run(_context()))
    assert len(findings) == 1


@mock_aws
def test_run_is_quiet_with_an_active_recorder():
    config = boto3.client("config", region_name="us-east-1")
    config.put_configuration_recorder(
        ConfigurationRecorder={
            "name": "default",
            "roleARN": "arn:aws:iam::123456789012:role/config-role",
        }
    )
    config.put_delivery_channel(
        DeliveryChannel={"name": "default", "s3BucketName": "config-bucket"}
    )
    config.start_configuration_recorder(ConfigurationRecorderName="default")

    assert list(AwsConfigNotEnabled().run(_context())) == []
