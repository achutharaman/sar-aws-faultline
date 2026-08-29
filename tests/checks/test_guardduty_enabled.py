"""Detection logic for guardduty-not-enabled."""

from __future__ import annotations

import boto3
from moto import mock_aws

from sar_aws_faultline.checks.guardduty_enabled import (
    DetectorState,
    GuardDutyNotEnabled,
    has_active_detector,
)
from sar_aws_faultline.config import Config
from sar_aws_faultline.context import ScanContext
from sar_aws_faultline.session import ClientFactory
from tests.conftest import FROZEN_NOW, TEST_ACCOUNT


def test_no_detectors_means_no_coverage():
    assert has_active_detector([]) is False


def test_enabled_detector_is_coverage():
    assert has_active_detector([DetectorState(detector_id="d1", enabled=True)]) is True


def test_disabled_detector_is_not_coverage():
    assert has_active_detector([DetectorState(detector_id="d1", enabled=False)]) is False


def _context() -> ScanContext:
    return ScanContext(
        region="us-east-1",
        check_id=GuardDutyNotEnabled.id,
        service="guardduty",
        config=Config(),
        factory=ClientFactory(),
        now=FROZEN_NOW,
        account_id=TEST_ACCOUNT,
    )


@mock_aws
def test_run_flags_account_with_no_detector():
    findings = list(GuardDutyNotEnabled().run(_context()))
    assert len(findings) == 1


@mock_aws
def test_run_is_quiet_with_an_enabled_detector():
    guardduty = boto3.client("guardduty", region_name="us-east-1")
    guardduty.create_detector(Enable=True)

    assert list(GuardDutyNotEnabled().run(_context())) == []
