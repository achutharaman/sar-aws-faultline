"""Detection logic for s3-bucket-tls-not-enforced."""

from __future__ import annotations

import json

import boto3
from moto import mock_aws

from sar_aws_faultline.checks.s3_tls_enforcement import (
    S3BucketTlsNotEnforced,
    policy_enforces_tls,
)
from sar_aws_faultline.config import Config
from sar_aws_faultline.context import ScanContext
from sar_aws_faultline.session import ClientFactory
from tests.conftest import FROZEN_NOW, TEST_ACCOUNT

DENY_HTTP_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:*",
            "Resource": "*",
            "Condition": {"Bool": {"aws:SecureTransport": "false"}},
        }
    ],
}


def test_no_policy_does_not_enforce_tls():
    assert policy_enforces_tls({}) is False


def test_policy_with_no_secure_transport_condition_does_not_enforce_tls():
    policy = {
        "Statement": [{"Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": "*"}]
    }
    assert policy_enforces_tls(policy) is False


def test_deny_insecure_transport_statement_enforces_tls():
    assert policy_enforces_tls(DENY_HTTP_POLICY) is True


def test_allow_statement_mentioning_secure_transport_does_not_count():
    """Only a Deny on SecureTransport=false actually blocks HTTP -- an Allow
    conditioned the same way just narrows when access is granted."""
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "*",
                "Condition": {"Bool": {"aws:SecureTransport": "false"}},
            }
        ]
    }
    assert policy_enforces_tls(policy) is False


def _context() -> ScanContext:
    return ScanContext(
        region="us-east-1",
        check_id=S3BucketTlsNotEnforced.id,
        service="s3",
        config=Config(),
        factory=ClientFactory(),
        now=FROZEN_NOW,
        account_id=TEST_ACCOUNT,
    )


@mock_aws
def test_run_flags_only_the_bucket_without_a_tls_policy():
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="no-policy-bucket")
    s3.create_bucket(Bucket="secure-bucket")
    policy = dict(DENY_HTTP_POLICY)
    s3.put_bucket_policy(Bucket="secure-bucket", Policy=json.dumps(policy))

    findings = list(S3BucketTlsNotEnforced().run(_context()))

    assert [f.resource_id for f in findings] == ["no-policy-bucket"]


@mock_aws
def test_run_on_empty_account_yields_nothing():
    assert list(S3BucketTlsNotEnforced().run(_context())) == []
