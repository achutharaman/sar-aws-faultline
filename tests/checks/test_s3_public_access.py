"""Detection logic for s3-bucket-public-access.

Most of this file tests ``exposure_paths``, which is a pure function. That is
the point of keeping it module-level: the decision that matters can be tested
across its whole state space in milliseconds, with no mocking layer standing
between the test and the assertion. moto covers only the wiring.
"""

from __future__ import annotations

import itertools

import boto3
import pytest
from moto import mock_aws
from tests.conftest import FROZEN_NOW, TEST_ACCOUNT

from sar_aws_faultline.checks.s3_public_access import (
    ALL_USERS,
    AUTHENTICATED_USERS,
    PUBLIC_ACL_GRANTEES,
    BlockPublicAccess,
    PublicS3Buckets,
    exposure_paths,
)
from sar_aws_faultline.config import Config
from sar_aws_faultline.context import ScanContext
from sar_aws_faultline.models import AuditImpact, Severity
from sar_aws_faultline.session import ClientFactory


def test_private_bucket_yields_nothing(state_factory):
    assert exposure_paths(state_factory()) == []


def test_public_acl_is_exposure(state_factory):
    assert exposure_paths(state_factory(public_acl_grantees=(ALL_USERS,))) == ["acl"]


def test_public_policy_is_exposure(state_factory):
    assert exposure_paths(state_factory(policy_is_public=True)) == ["policy"]


def test_both_paths_reported(state_factory):
    state = state_factory(public_acl_grantees=(ALL_USERS,), policy_is_public=True)
    assert exposure_paths(state) == ["acl", "policy"]


def test_authenticated_users_counts_as_public():
    """AuthenticatedUsers means any AWS account anywhere, not 'my users'."""
    assert AUTHENTICATED_USERS in PUBLIC_ACL_GRANTEES


# -- the part that distinguishes this from flag-counting --------------------


@pytest.mark.parametrize("level", ["account_bpa", "bucket_bpa"])
def test_ignore_public_acls_neutralises_acl(state_factory, level):
    bpa = BlockPublicAccess(ignore_public_acls=True, configured=True)
    state = state_factory(public_acl_grantees=(ALL_USERS,), **{level: bpa})
    assert exposure_paths(state) == []


@pytest.mark.parametrize("level", ["account_bpa", "bucket_bpa"])
def test_restrict_public_buckets_neutralises_policy(state_factory, level):
    bpa = BlockPublicAccess(restrict_public_buckets=True, configured=True)
    assert exposure_paths(state_factory(policy_is_public=True, **{level: bpa})) == []


def test_block_public_acls_alone_does_not_neutralise_an_existing_acl(state_factory):
    """BlockPublicAcls rejects *new* public ACLs; only IgnorePublicAcls
    neutralises one that already exists. Conflating the two is the most common
    way this check is implemented wrongly."""
    state = state_factory(
        public_acl_grantees=(ALL_USERS,),
        bucket_bpa=BlockPublicAccess(block_public_acls=True, configured=True),
    )
    assert exposure_paths(state) == ["acl"]


def test_block_public_policy_alone_does_not_neutralise_an_existing_policy(state_factory):
    state = state_factory(
        policy_is_public=True,
        bucket_bpa=BlockPublicAccess(block_public_policy=True, configured=True),
    )
    assert exposure_paths(state) == ["policy"]


def test_acl_suppression_does_not_suppress_policy(state_factory):
    state = state_factory(
        public_acl_grantees=(ALL_USERS,),
        policy_is_public=True,
        bucket_bpa=BlockPublicAccess(ignore_public_acls=True, configured=True),
    )
    assert exposure_paths(state) == ["policy"]


@pytest.mark.parametrize("level", ["account_bpa", "bucket_bpa"])
def test_full_bpa_at_either_level_suppresses_everything(state_factory, level):
    full = BlockPublicAccess(True, True, True, True, configured=True)
    state = state_factory(public_acl_grantees=(ALL_USERS,), policy_is_public=True, **{level: full})
    assert exposure_paths(state) == []


def test_exhaustive_flag_matrix(state_factory):
    """Sweep every combination of four flags at both levels. Cheap, because
    the function under test is pure."""
    for acct, bkt in itertools.product(itertools.product([False, True], repeat=4), repeat=2):
        state = state_factory(
            account_bpa=BlockPublicAccess(*acct, configured=True),
            bucket_bpa=BlockPublicAccess(*bkt, configured=True),
            public_acl_grantees=(ALL_USERS,),
            policy_is_public=True,
        )
        paths = exposure_paths(state)
        assert ("acl" in paths) is not (acct[1] or bkt[1])
        assert ("policy" in paths) is not (acct[3] or bkt[3])


# -- finding construction ---------------------------------------------------


def test_finding_metadata_explains_the_verdict(context, state_factory):
    check = PublicS3Buckets()
    finding = check._evaluate(context, state_factory(public_acl_grantees=(ALL_USERS,)))
    assert finding is not None
    assert finding.severity is Severity.CRITICAL
    assert finding.audit_impact is AuditImpact.BLOCKER
    assert finding.metadata["exposure_paths"] == "acl"
    assert finding.metadata["account_bpa_enabled"] == "none"


def test_private_bucket_produces_no_finding(context, state_factory):
    assert PublicS3Buckets()._evaluate(context, state_factory()) is None


def test_authenticated_users_gets_an_explanatory_detail(context, state_factory):
    finding = PublicS3Buckets()._evaluate(
        context, state_factory(public_acl_grantees=(f"{AUTHENTICATED_USERS} (READ)",))
    )
    assert "any AWS account" in finding.detail


# -- collection (moto) ------------------------------------------------------


def _context() -> ScanContext:
    return ScanContext(
        region="us-east-1",
        check_id=PublicS3Buckets.id,
        service="s3",
        config=Config(),
        factory=ClientFactory(),
        now=FROZEN_NOW,
        account_id=TEST_ACCOUNT,
    )


@mock_aws
def test_run_flags_only_the_open_bucket():
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="private-bucket")
    s3.create_bucket(Bucket="open-bucket")
    s3.put_bucket_acl(Bucket="open-bucket", ACL="public-read")

    findings = list(PublicS3Buckets().run(_context()))

    assert [f.resource_id for f in findings] == ["open-bucket"]


@mock_aws
def test_run_on_empty_account_yields_nothing():
    assert list(PublicS3Buckets().run(_context())) == []
