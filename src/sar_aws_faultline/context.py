"""The single argument every check receives.

Two things here are deliberate, both inherited from sar-aws-barnacle. ``now`` is
injected rather than read from the clock inside checks, so "is this access key
older than 90 days?" is testable without freezing time globally. And ``client()``
defaults to the check's own declared service, which keeps checks from reaching
for clients they never declared IAM permissions for.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sar_aws_faultline.config import Config
from sar_aws_faultline.session import ClientFactory


@dataclass(frozen=True, slots=True)
class ScanContext:
    region: str
    check_id: str
    service: str
    config: Config
    factory: ClientFactory
    now: datetime
    account_id: str | None = None

    def client(self, service: str | None = None):
        """Client for this check's service in this region."""
        return self.factory.client(service or self.service, region=self.region)

    def option(self, key: str, default: Any) -> Any:
        """Per-check tunable, e.g. ``ctx.option("max_key_age_days", 90)``."""
        return self.config.option(self.check_id, key, default)

    def age_days(self, timestamp: datetime | None) -> int | None:
        """Whole days between ``timestamp`` and the scan's reference time."""
        if timestamp is None:
            return None
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=self.now.tzinfo)
        return max((self.now - timestamp).days, 0)
