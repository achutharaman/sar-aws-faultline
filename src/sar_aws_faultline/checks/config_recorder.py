"""No active AWS Config recorder.

Same two-axis shape as cloudtrail-not-enabled: nothing is exposed by a
missing configuration recorder, but without one there is no record of what
a resource's configuration looked like at any point in the past, which is
exactly the evidence a change-management or configuration-drift question
asks for.
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
class RecorderState:
    name: str
    recording: bool


def has_active_recorder(recorders: Sequence[RecorderState]) -> bool:
    return any(r.recording for r in recorders)


@register
class AwsConfigNotEnabled:
    id = "aws-config-not-enabled"
    title = "No active AWS Config recorder"
    service = "config"
    resource_type = "AWS::Config::ConfigurationRecorder"
    scope = Scope.REGIONAL
    severity = Severity.MEDIUM
    audit_impact = AuditImpact.BLOCKER
    rationale = (
        "AWS Config is the record of what every resource's configuration "
        "looked like over time -- without it, there is no way to answer "
        "'what changed, and when' for anything that isn't also in "
        "CloudTrail's API-call log. This is not about exposure; it is about "
        "being unable to reconstruct configuration history after the fact, "
        "which a change-management control in a SOC 2 audit assumes exists."
    )
    remediation = Remediation(
        summary=(
            "Turn on a Config recorder in this region, recording all resource types, and start it."
        ),
        effort=Effort.MINUTES,
        console_steps=(
            "AWS Config console -> Settings -> set up recording for all "
            "resource types in this region, with an S3 bucket for the "
            "delivery channel.",
            "Confirm the recorder shows as 'Recording' after setup.",
        ),
        cli_commands=(
            "aws configservice put-configuration-recorder --configuration-recorder "
            "name=default,roleARN=<CONFIG_ROLE_ARN>",
            "aws configservice put-delivery-channel --delivery-channel "
            "name=default,s3BucketName=<LOG_BUCKET>",
            "aws configservice start-configuration-recorder --configuration-recorder-name default",
        ),
        monthly_cost_usd=3.0,
        cost_note=(
            "Roughly a few dollars a month for a small account, billed "
            "per configuration item recorded."
        ),
        caveats=(),
    )
    required_actions = frozenset(
        {"config:DescribeConfigurationRecorders", "config:DescribeConfigurationRecorderStatus"}
    )

    def run(self, ctx: ScanContext) -> Iterator[Finding]:
        recorders = list(self._recorders(ctx))
        finding = self._evaluate(ctx, recorders)
        if finding is not None:
            yield finding

    @staticmethod
    def _recorders(ctx: ScanContext) -> Iterator[RecorderState]:
        config = ctx.client()
        names = [
            r["name"]
            for r in config.describe_configuration_recorders().get("ConfigurationRecorders", [])
        ]
        if not names:
            return
        statuses = config.describe_configuration_recorder_status(
            ConfigurationRecorderNames=names
        ).get("ConfigurationRecordersStatus", [])
        for status in statuses:
            yield RecorderState(
                name=status.get("name", "default"),
                recording=bool(status.get("recording", False)),
            )

    def _evaluate(self, ctx: ScanContext, recorders: list[RecorderState]) -> Finding | None:
        if has_active_recorder(recorders):
            return None

        detail = (
            "No AWS Config recorder exists in this region"
            if not recorders
            else f"{len(recorders)} recorder(s) exist but none is recording"
        )

        return Finding(
            check_id=self.id,
            resource_id=ctx.region,
            resource_type=self.resource_type,
            region=ctx.region,
            severity=self.severity,
            audit_impact=self.audit_impact,
            title="No active AWS Config recorder",
            detail=detail,
            metadata={"recorder_count": str(len(recorders))},
        )
