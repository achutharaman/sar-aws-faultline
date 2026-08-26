"""Core data types shared by checks, the runner, and the renderers.

Everything here is frozen. Findings are values, not mutable state: once a check
emits one, nothing downstream may edit it. That is what lets the runner fan out
across threads without any locking.

Two additions here are specific to a security tool: ``Severity.CRITICAL`` and
the ``AuditImpact`` axis.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

SCHEMA_VERSION = "1.0"
GLOBAL_REGION = "global"


class Severity(StrEnum):
    """How bad this is if someone exploits it.

    ``CRITICAL`` is the top level here. A cost tool might top out at "you are
    wasting real money"; a security tool needs a level that means "an
    unauthenticated stranger can read your data right now", and collapsing
    that into HIGH loses the distinction that matters most.
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class AuditImpact(StrEnum):
    """The second axis: what this costs you in a SOC 2 readiness conversation.

    Severity and audit impact are not the same question and do not correlate
    cleanly. A missing CloudTrail trail is medium severity -- nothing is
    exposed -- but it is an absolute audit blocker, because without it you
    cannot evidence any monitoring control at all. Conversely a permissive
    security group on an isolated dev VPC is high severity and barely
    registers with an auditor.

    Generic scanners collapse both into one number and leave the reader to
    re-derive the difference. Ordering by this axis first is the entire
    premise of this tool.
    """

    BLOCKER = "blocker"
    """An auditor or an enterprise customer will stop and ask about this."""

    EXPECTED = "expected"
    """Commonly asked about. Absence needs a documented justification."""

    HARDENING = "hardening"
    """Good practice. Rarely audit-determinative on its own."""

    @property
    def rank(self) -> int:
        return _IMPACT_RANK[self]


_IMPACT_RANK: dict[AuditImpact, int] = {
    AuditImpact.BLOCKER: 0,
    AuditImpact.EXPECTED: 1,
    AuditImpact.HARDENING: 2,
}


class Effort(StrEnum):
    """Roughly what fixing this costs the person who has to do it."""

    MINUTES = "minutes"
    HOURS = "hours"
    PLANNED = "planned"
    """Needs a maintenance window, a migration, or change management."""


class Scope(StrEnum):
    """Whether a check runs per-region or exactly once per account.

    Without this, a six-region scan reports the same publicly readable S3
    bucket six times, because S3's ListBuckets is global behind a regional
    endpoint.
    """

    REGIONAL = "regional"
    GLOBAL = "global"


@dataclass(frozen=True, slots=True)
class Remediation:
    """How to fix a finding, and what fixing it costs.

    ``monthly_cost_usd`` is the field that earns this tool its place next to
    Prowler. Several of the highest-value AWS security controls -- GuardDuty,
    a Config recorder, VPC flow logs -- carry a real monthly bill, and a
    three-person team deciding whether to turn them on needs that number in
    the same table as the red X. Zero is a legitimate and common value; it is
    not a placeholder.
    """

    summary: str
    effort: Effort
    console_steps: Sequence[str] = ()
    cli_commands: Sequence[str] = ()
    monthly_cost_usd: float = 0.0
    cost_note: str = ""
    caveats: Sequence[str] = ()
    """What this might break. Be honest; this is what earns a reader's trust
    the second time they run the tool."""

    def __post_init__(self) -> None:
        if not self.summary.strip():
            raise ValueError("remediation needs a summary")
        if not self.console_steps and not self.cli_commands:
            raise ValueError(
                "remediation needs console steps or CLI commands; a finding "
                "the reader cannot act on is just anxiety"
            )
        if self.monthly_cost_usd < 0:
            raise ValueError("monthly_cost_usd cannot be negative")


@dataclass(frozen=True, slots=True)
class Finding:
    """One resource failing one check, in one account."""

    check_id: str
    resource_id: str
    resource_type: str
    region: str
    severity: Severity
    audit_impact: AuditImpact
    title: str
    detail: str
    metadata: Mapping[str, str] = field(default_factory=dict)

    @property
    def sort_key(self) -> tuple[int, int, str]:
        """Audit impact first, then severity, then stable by resource id.

        The ordering is the product. Sorting by severity alone is what every
        other scanner does, and it is why their output needs triage before it
        is useful.
        """
        return (self.audit_impact.rank, -self.severity.rank, self.resource_id)


@dataclass(frozen=True, slots=True)
class CheckError:
    """A check that could not complete, in one region.

    Recorded rather than raised. A missing ``s3:GetBucketPolicyStatus`` should
    degrade one check, not abort a scan that was about to report on five
    others. Kept separate from Finding so that "I could not look" can never be
    rendered as "nothing is wrong".
    """

    check_id: str
    region: str
    error_code: str
    message: str


@dataclass(frozen=True, slots=True)
class ScanResult:
    """Everything one ``sar-aws-faultline scan`` produced."""

    findings: tuple[Finding, ...]
    errors: tuple[CheckError, ...]
    regions: tuple[str, ...]
    checks_run: tuple[str, ...]
    started_at: datetime
    duration_seconds: float
    account_id: str | None = None

    @property
    def is_partial(self) -> bool:
        """True if any check failed, meaning the report understates reality."""
        return bool(self.errors)

    @property
    def blocker_count(self) -> int:
        return sum(1 for f in self.findings if f.audit_impact is AuditImpact.BLOCKER)

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: f.sort_key)

    def by_check(self) -> dict[str, list[Finding]]:
        """Findings grouped by check, in report order."""
        grouped: dict[str, list[Finding]] = {}
        for finding in self.sorted_findings():
            grouped.setdefault(finding.check_id, []).append(finding)
        return grouped
