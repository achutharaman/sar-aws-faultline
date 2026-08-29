"""The read-only guarantee is structural, not a promise in the README."""

from __future__ import annotations

import boto3
import pytest
from moto import mock_aws

from sar_aws_faultline.session import (
    CREDENTIAL_REFRESH_OPERATIONS,
    READ_ONLY_PREFIXES,
    ClientFactory,
    ReadOnlyViolationError,
    _guard_handler,
    install_read_only_guard,
)


class _FakeOperationModel:
    def __init__(self, name: str) -> None:
        self.name = name


def test_credential_refresh_operations_pass_the_guard():
    """botocore calls these internally to refresh SSO tokens or assumed-role
    credentials, through the same guarded session every check's client comes
    from. None of them start with a read-only prefix, and blocking them
    turns an expired token into an unhandled crash instead of the CheckError
    every other credential problem already degrades into."""
    for operation in CREDENTIAL_REFRESH_OPERATIONS:
        _guard_handler(model=_FakeOperationModel(operation))  # must not raise


def test_credential_refresh_exemption_does_not_widen_to_other_calls():
    with pytest.raises(ReadOnlyViolationError):
        _guard_handler(model=_FakeOperationModel("AssumeRolePolicy"))


@mock_aws
def test_read_calls_pass():
    factory = ClientFactory()
    assert factory.client("s3", region="us-east-1").list_buckets()["Buckets"] == []


@mock_aws
def test_mutating_call_is_blocked():
    factory = ClientFactory()
    s3 = factory.client("s3", region="us-east-1")
    with pytest.raises(ReadOnlyViolationError, match="CreateBucket"):
        s3.create_bucket(Bucket="nope")


@mock_aws
def test_delete_is_blocked():
    s3 = ClientFactory().client("s3", region="us-east-1")
    with pytest.raises(ReadOnlyViolationError):
        s3.delete_bucket(Bucket="whatever")


@mock_aws
def test_guard_can_be_disabled_only_explicitly():
    """Tests need to create fixtures. Production paths never set this."""
    s3 = ClientFactory(read_only=False).client("s3", region="us-east-1")
    s3.create_bucket(Bucket="allowed")


def test_prefix_list_is_conservative():
    """Adding a prefix here widens what the tool is permitted to do, so it is
    a design conversation rather than a one-line change."""
    assert set(READ_ONLY_PREFIXES) == {
        "Describe",
        "Get",
        "List",
        "BatchGet",
        "Lookup",
        "Head",
        "Select",
        "Generate",
    }


@mock_aws
def test_guard_installs_on_a_plain_session():
    session = boto3.Session(region_name="us-east-1")
    install_read_only_guard(session)
    with pytest.raises(ReadOnlyViolationError):
        session.client("s3").create_bucket(Bucket="x")
