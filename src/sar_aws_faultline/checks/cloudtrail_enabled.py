"""No active multi-region CloudTrail trail.

The textbook example of the two-axis model: nothing is exposed by a missing
trail, so severity is only MEDIUM, but an auditor cannot evidence any
monitoring control at all without one, so audit_impact is BLOCKER. See
docs/DECISIONS.md section 6.

One finding per account, not per trail: the question this check answers is
"is there at least one trail covering everything," not "grade every trail
individually." A account with three partial trails and zero full-coverage
ones is exactly as blind as an account with none.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from dataclasses import dataclass

from sar_aws_faultline.context import ScanContext
from sar_aws_faultline.models import (
    AuditImpact,
    Effort,
    Finding,
    Remediation,
    Scope,
    Severity,
)
from sar_aws_faultline.registry import register


@dataclass(frozen=True, slots=True)
class TrailState:
    name: str
    is_multi_region: bool
    is_logging: bool


def has_active_multi_region_trail(trails: Sequence[TrailState]) -> bool:
    """Pure. At least one trail must be both multi-region and actually
    logging -- a multi-region trail that has been stopped, or a
    single-region trail that is logging, both leave gaps a stopped-trail or
    other-region API call would fall straight through."""
    return any(t.is_multi_region and t.is_logging for t in trails)


@register
class CloudTrailNotEnabled:
    id = "cloudtrail-not-enabled"
    title = "No active multi-region CloudTrail trail"
    service = "cloudtrail"
    resource_type = "AWS::CloudTrail::Trail"
    scope = Scope.GLOBAL
    severity = Severity.MEDIUM
    audit_impact = AuditImpact.BLOCKER
    rationale = (
        "Without an active, multi-region CloudTrail trail, there is no record "
        "of who did what in this account -- not for an incident "
        "investigation, not for an auditor's evidence request, and not for "
        "noticing a compromise while it is happening. This is not about "
        "exposure; a missing trail does not leak anything by itself. It is "
        "about being unable to answer 'what happened' after the fact, which "
        "is the one thing every SOC 2 audit and every incident response plan "
        "assumes exists."
    )
    remediation = Remediation(
        summary=(
            "Create one multi-region trail that logs to an S3 bucket, and make sure it is logging."
        ),
        effort=Effort.MINUTES,
        console_steps=(
            "CloudTrail console -> Trails -> Create trail.",
            "Enable 'multi-Region trail'. Point it at a new or existing S3 bucket for log storage.",
            "Leave management events enabled (Read and Write) -- this is the "
            "part that actually gives you an audit trail.",
            "Create the trail, then confirm its status shows 'Logging'.",
        ),
        cli_commands=(
            "aws cloudtrail create-trail --name org-trail --s3-bucket-name "
            "<LOG_BUCKET> --is-multi-region-trail",
            "aws cloudtrail start-logging --name org-trail",
        ),
        monthly_cost_usd=2.0,
        cost_note=(
            "The trail itself is free for one copy of management events; "
            "cost is S3 storage for the logs, typically a few dollars a "
            "month for a small account."
        ),
        caveats=(
            "The destination S3 bucket needs a bucket policy granting "
            "CloudTrail write access -- the console does this automatically "
            "when you create a new bucket from within the wizard, but not "
            "when you point it at an existing one.",
        ),
    )
    required_actions = frozenset({"cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus"})

    def run(self, ctx: ScanContext) -> Iterator[Finding]:
        trails = list(self._trails(ctx))
        finding = self._evaluate(ctx, trails)
        if finding is not None:
            yield finding

    @staticmethod
    def _trails(ctx: ScanContext) -> Iterator[TrailState]:
        cloudtrail = ctx.client()
        # includeShadowTrails=True (the default) surfaces multi-region trails
        # created in other regions too, which is the whole point of asking
        # "does anything cover this account" from one endpoint.
        for trail in cloudtrail.describe_trails().get("trailList", []):
            status = cloudtrail.get_trail_status(Name=trail["TrailARN"])
            yield TrailState(
                name=trail.get("Name", trail["TrailARN"]),
                is_multi_region=bool(trail.get("IsMultiRegionTrail", False)),
                is_logging=bool(status.get("IsLogging", False)),
            )

    def _evaluate(self, ctx: ScanContext, trails: list[TrailState]) -> Finding | None:
        if has_active_multi_region_trail(trails):
            return None

        if trails:
            names = ", ".join(t.name for t in trails)
            detail = (
                f"{len(trails)} trail(s) exist ({names}) but none is both "
                f"multi-region and actively logging"
            )
        else:
            detail = "No CloudTrail trail exists in this account"

        return Finding(
            check_id=self.id,
            resource_id=ctx.account_id or "account",
            resource_type=self.resource_type,
            region=ctx.region,
            severity=self.severity,
            audit_impact=self.audit_impact,
            title="No active multi-region CloudTrail trail",
            detail=detail,
            metadata={"trail_count": str(len(trails))},
        )
