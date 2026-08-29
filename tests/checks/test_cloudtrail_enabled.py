"""Detection logic for cloudtrail-not-enabled."""

from __future__ import annotations

import boto3
from moto import mock_aws

from sar_aws_faultline.checks.cloudtrail_enabled import (
    CloudTrailNotEnabled,
    TrailState,
    has_active_multi_region_trail,
)
from sar_aws_faultline.config import Config
from sar_aws_faultline.context import ScanContext
from sar_aws_faultline.session import ClientFactory
from tests.conftest import FROZEN_NOW, TEST_ACCOUNT


def test_no_trails_means_no_coverage():
    assert has_active_multi_region_trail([]) is False


def test_active_multi_region_trail_is_coverage():
    trail = TrailState(name="org-trail", is_multi_region=True, is_logging=True)
    assert has_active_multi_region_trail([trail]) is True


def test_stopped_multi_region_trail_is_not_coverage():
    """Existing but not logging is functionally the same as not existing."""
    trail = TrailState(name="org-trail", is_multi_region=True, is_logging=False)
    assert has_active_multi_region_trail([trail]) is False


def test_single_region_trail_is_not_coverage_even_if_logging():
    trail = TrailState(name="local-trail", is_multi_region=False, is_logging=True)
    assert has_active_multi_region_trail([trail]) is False


def test_one_good_trail_among_bad_ones_is_still_coverage():
    trails = [
        TrailState(name="stopped", is_multi_region=True, is_logging=False),
        TrailState(name="regional", is_multi_region=False, is_logging=True),
        TrailState(name="org-trail", is_multi_region=True, is_logging=True),
    ]
    assert has_active_multi_region_trail(trails) is True


def _context() -> ScanContext:
    return ScanContext(
        region="us-east-1",
        check_id=CloudTrailNotEnabled.id,
        service="cloudtrail",
        config=Config(),
        factory=ClientFactory(),
        now=FROZEN_NOW,
        account_id=TEST_ACCOUNT,
    )


def test_finding_mentions_no_trail_when_account_has_none():
    finding = CloudTrailNotEnabled()._evaluate(_context(), [])
    assert finding is not None
    assert "No CloudTrail trail exists" in finding.detail


def test_finding_lists_existing_but_insufficient_trails():
    trails = [TrailState(name="regional-only", is_multi_region=False, is_logging=True)]
    finding = CloudTrailNotEnabled()._evaluate(_context(), trails)
    assert finding is not None
    assert "regional-only" in finding.detail


def test_no_finding_when_covered():
    trails = [TrailState(name="org-trail", is_multi_region=True, is_logging=True)]
    assert CloudTrailNotEnabled()._evaluate(_context(), trails) is None


@mock_aws
def test_run_flags_account_with_no_trail():
    findings = list(CloudTrailNotEnabled().run(_context()))
    assert len(findings) == 1


@mock_aws
def test_run_is_quiet_with_an_active_multi_region_trail():
    ct = boto3.client("cloudtrail", region_name="us-east-1")
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="trail-logs-bucket")
    s3.put_bucket_policy(
        Bucket="trail-logs-bucket",
        Policy=(
            '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
            '"Principal":{"Service":"cloudtrail.amazonaws.com"},'
            '"Action":"s3:PutObject","Resource":"arn:aws:s3:::trail-logs-bucket/*"}]}'
        ),
    )
    ct.create_trail(Name="org-trail", S3BucketName="trail-logs-bucket", IsMultiRegionTrail=True)
    ct.start_logging(Name="org-trail")

    assert list(CloudTrailNotEnabled().run(_context())) == []
