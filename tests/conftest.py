"""Shared fixtures.

Two things every test here relies on: credentials are always fake (so a
misconfigured test can never reach a real account), and time is always injected
(so age-based assertions do not rot).
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from sar_aws_faultline.checks.s3_public_access import BlockPublicAccess, BucketState
from sar_aws_faultline.config import Config
from sar_aws_faultline.context import ScanContext
from sar_aws_faultline.session import ClientFactory

FROZEN_NOW = datetime(2026, 8, 20, 12, 0, 0, tzinfo=UTC)
TEST_REGION = "ap-south-1"
TEST_ACCOUNT = "123456789012"

BPA_OFF = BlockPublicAccess()
BPA_ALL = BlockPublicAccess(True, True, True, True, configured=True)


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    """Guarantee no test can touch a real account, even by accident."""
    for key, value in {
        "AWS_ACCESS_KEY_ID": "testing",
        "AWS_SECRET_ACCESS_KEY": "testing",
        "AWS_SECURITY_TOKEN": "testing",
        "AWS_SESSION_TOKEN": "testing",
        "AWS_DEFAULT_REGION": TEST_REGION,
    }.items():
        monkeypatch.setenv(key, value)
    for key in (
        "AWS_PROFILE",
        "SAR_AWS_FAULTLINE_PROFILE",
        "SAR_AWS_FAULTLINE_REGIONS",
        "SAR_AWS_FAULTLINE_OUTPUT",
        "SAR_AWS_FAULTLINE_FAIL_ON",
        "SAR_AWS_FAULTLINE_FRAMEWORK",
    ):
        monkeypatch.delenv(key, raising=False)


@pytest.fixture
def now() -> datetime:
    return FROZEN_NOW


@pytest.fixture
def config() -> Config:
    return Config()


@pytest.fixture
def context(config: Config) -> ScanContext:
    return ScanContext(
        region=TEST_REGION,
        check_id="s3-bucket-public-access",
        service="s3",
        config=config,
        factory=ClientFactory(),
        now=FROZEN_NOW,
        account_id=TEST_ACCOUNT,
    )


def make_state(**kw) -> BucketState:
    defaults = {
        "name": "example-bucket",
        "account_bpa": BPA_OFF,
        "bucket_bpa": BPA_OFF,
        "public_acl_grantees": (),
        "policy_is_public": False,
    }
    defaults.update(kw)
    return BucketState(**defaults)


@pytest.fixture
def state_factory():
    return make_state
