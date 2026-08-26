"""Detection logic for s3-block-public-access-disabled.

Mirrors test_s3_public_access.py's structure: missing_guardrail() is pure and
tested across its state space directly, moto covers only the wiring, and the
dedup against s3-bucket-public-access (an already-exposed bucket should not
also show up here) gets its own explicit test since it's easy to regress
silently.
"""

from __future__ import annotations

import boto3
from moto import mock_aws

from sar_aws_faultline.checks.s3_block_public_access_disabled import (
    S3BlockPublicAccessDisabled,
    missing_guardrail,
)
from sar_aws_faultline.checks.s3_public_access import ALL_USERS, BlockPublicAccess
from sar_aws_faultline.config import Config
from sar_aws_faultline.context import ScanContext
from sar_aws_faultline.models import AuditImpact, Severity
from sar_aws_faultline.session import ClientFactory
from tests.conftest import FROZEN_NOW, TEST_ACCOUNT


def test_fully_open_bucket_has_no_guardrail(state_factory):
    assert missing_guardrail(state_factory()) is True


def test_ignore_and_restrict_together_is_guarded(state_factory):
    full_guard = BlockPublicAccess(
        ignore_public_acls=True, restrict_public_buckets=True, configured=True
    )
    assert missing_guardrail(state_factory(bucket_bpa=full_guard)) is False


def test_ignore_alone_is_not_enough(state_factory):
    """IgnorePublicAcls only closes the ACL path; the policy path is still open."""
    acl_only = BlockPublicAccess(ignore_public_acls=True, configured=True)
    assert missing_guardrail(state_factory(bucket_bpa=acl_only)) is True


def test_restrict_alone_is_not_enough(state_factory):
    policy_only = BlockPublicAccess(restrict_public_buckets=True, configured=True)
    assert missing_guardrail(state_factory(bucket_bpa=policy_only)) is True


def test_block_public_acls_and_block_public_policy_alone_are_not_enough(state_factory):
    """The 'reject new grants' flags don't neutralise anything already
    present, so they don't count as a guardrail here either."""
    reject_new_only = BlockPublicAccess(
        block_public_acls=True, block_public_policy=True, configured=True
    )
    assert missing_guardrail(state_factory(bucket_bpa=reject_new_only)) is True


def test_guardrail_at_account_level_counts(state_factory):
    full_guard = BlockPublicAccess(
        ignore_public_acls=True, restrict_public_buckets=True, configured=True
    )
    assert missing_guardrail(state_factory(account_bpa=full_guard)) is False


# -- finding construction / dedup --------------------------------------------


def test_unguarded_private_bucket_is_flagged(context, state_factory):
    finding = S3BlockPublicAccessDisabled()._evaluate(context, state_factory())
    assert finding is not None
    assert finding.severity is Severity.MEDIUM
    assert finding.audit_impact is AuditImpact.EXPECTED
    assert finding.metadata["account_bpa_enabled"] == "none"


def test_guarded_bucket_is_not_flagged(context, state_factory):
    full_guard = BlockPublicAccess(
        ignore_public_acls=True, restrict_public_buckets=True, configured=True
    )
    finding = S3BlockPublicAccessDisabled()._evaluate(context, state_factory(bucket_bpa=full_guard))
    assert finding is None


def test_already_exposed_bucket_is_not_double_reported(context, state_factory):
    """s3-bucket-public-access already flags this bucket, and at a higher
    severity/impact -- this check should stay quiet rather than add a second,
    lower-urgency finding for the same root cause."""
    state = state_factory(public_acl_grantees=(ALL_USERS,))
    assert S3BlockPublicAccessDisabled()._evaluate(context, state) is None


# -- collection (moto) -------------------------------------------------------


def _context() -> ScanContext:
    return ScanContext(
        region="us-east-1",
        check_id=S3BlockPublicAccessDisabled.id,
        service="s3",
        config=Config(),
        factory=ClientFactory(),
        now=FROZEN_NOW,
        account_id=TEST_ACCOUNT,
    )


@mock_aws
def test_run_flags_the_unguarded_bucket_only():
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="unguarded-bucket")
    s3.create_bucket(Bucket="guarded-bucket")
    s3.put_public_access_block(
        Bucket="guarded-bucket",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )

    findings = list(S3BlockPublicAccessDisabled().run(_context()))

    assert [f.resource_id for f in findings] == ["unguarded-bucket"]


@mock_aws
def test_run_skips_a_bucket_already_publicly_exposed():
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="open-bucket")
    s3.put_bucket_acl(Bucket="open-bucket", ACL="public-read")

    assert list(S3BlockPublicAccessDisabled().run(_context())) == []


@mock_aws
def test_run_on_empty_account_yields_nothing():
    assert list(S3BlockPublicAccessDisabled().run(_context())) == []
