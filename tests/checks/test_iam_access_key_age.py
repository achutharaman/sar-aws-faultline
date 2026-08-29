"""Detection logic for iam-access-key-stale."""

from __future__ import annotations

import boto3
from moto import mock_aws

from sar_aws_faultline.checks.iam_access_key_age import (
    DEFAULT_MAX_AGE_DAYS,
    AccessKeyState,
    IamAccessKeyStale,
    is_stale,
    parse_access_keys,
)
from sar_aws_faultline.config import Config
from sar_aws_faultline.context import ScanContext
from sar_aws_faultline.session import ClientFactory
from tests.conftest import FROZEN_NOW, TEST_ACCOUNT


def test_fresh_active_key_is_fine():
    state = AccessKeyState(user="alice", key_slot="access_key_1", active=True, age_days=5)
    assert is_stale(state, DEFAULT_MAX_AGE_DAYS) is False


def test_old_active_key_is_stale():
    state = AccessKeyState(user="alice", key_slot="access_key_1", active=True, age_days=200)
    assert is_stale(state, DEFAULT_MAX_AGE_DAYS) is True


def test_old_inactive_key_is_not_flagged():
    """A deactivated key can't be used, however old it is."""
    state = AccessKeyState(user="alice", key_slot="access_key_1", active=False, age_days=999)
    assert is_stale(state, DEFAULT_MAX_AGE_DAYS) is False


def test_no_key_present_is_not_flagged():
    state = AccessKeyState(user="alice", key_slot="access_key_1", active=False, age_days=None)
    assert is_stale(state, DEFAULT_MAX_AGE_DAYS) is False


def test_threshold_is_configurable():
    state = AccessKeyState(user="alice", key_slot="access_key_1", active=True, age_days=45)
    assert is_stale(state, max_age_days=90) is False
    assert is_stale(state, max_age_days=30) is True


def test_parse_access_keys_covers_both_slots_and_excludes_root():
    rows = [
        {
            "user": "<root_account>",
            "access_key_1_active": "true",
            "access_key_1_last_rotated": "2020-01-01T00:00:00+00:00",
            "access_key_2_active": "false",
            "access_key_2_last_rotated": "N/A",
        },
        {
            "user": "alice",
            "access_key_1_active": "true",
            "access_key_1_last_rotated": "2026-08-01T00:00:00+00:00",
            "access_key_2_active": "true",
            "access_key_2_last_rotated": "2020-01-01T00:00:00+00:00",
        },
    ]
    keys = parse_access_keys(rows, FROZEN_NOW)

    assert {k.user for k in keys} == {"alice"}
    by_slot = {k.key_slot: k for k in keys}
    assert by_slot["access_key_1"].age_days < 30
    assert by_slot["access_key_2"].age_days > 2000


def _context() -> ScanContext:
    return ScanContext(
        region="us-east-1",
        check_id=IamAccessKeyStale.id,
        service="iam",
        config=Config(),
        factory=ClientFactory(),
        now=FROZEN_NOW,
        account_id=TEST_ACCOUNT,
    )


@mock_aws
def test_run_on_empty_account_yields_nothing():
    assert list(IamAccessKeyStale().run(_context())) == []


@mock_aws
def test_run_flags_a_freshly_created_key_as_not_stale():
    """Cheap end-to-end wiring check: moto only ever gives us a
    freshly-created key, so this confirms the check runs clean rather than
    erroring, not the age math itself (covered above without moto)."""
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="alice")
    iam.create_access_key(UserName="alice")

    assert list(IamAccessKeyStale().run(_context())) == []
