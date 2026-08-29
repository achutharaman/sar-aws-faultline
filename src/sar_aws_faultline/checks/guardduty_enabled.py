"""No active GuardDuty detector.

The detective-control complement to cloudtrail-not-enabled: CloudTrail
records what happened, GuardDuty is what actually looks at that record (plus
VPC flow logs and DNS logs) for signs of compromise. An account with
CloudTrail on and GuardDuty off has the evidence but nobody watching it.
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
class DetectorState:
    detector_id: str
    enabled: bool


def has_active_detector(detectors: Sequence[DetectorState]) -> bool:
    return any(d.enabled for d in detectors)


@register
class GuardDutyNotEnabled:
    id = "guardduty-not-enabled"
    title = "GuardDuty is not enabled"
    service = "guardduty"
    resource_type = "AWS::GuardDuty::Detector"
    scope = Scope.REGIONAL
    severity = Severity.MEDIUM
    audit_impact = AuditImpact.EXPECTED
    rationale = (
        "GuardDuty is the managed threat-detection layer over CloudTrail, "
        "VPC flow logs, and DNS logs -- without it, an account can have "
        "excellent logging and still have nobody and nothing actually "
        "watching for a compromised credential, a crypto-mining instance, or "
        "reconnaissance activity. It is a standard line item on security "
        "questionnaires asking whether the account has active threat "
        "detection, distinct from whether it merely logs activity."
    )
    remediation = Remediation(
        summary="Enable GuardDuty in this region.",
        effort=Effort.MINUTES,
        console_steps=("GuardDuty console -> Get started -> Enable GuardDuty.",),
        cli_commands=("aws guardduty create-detector --enable",),
        monthly_cost_usd=5.0,
        cost_note=(
            "Scales with CloudTrail event volume and VPC traffic; a few "
            "dollars a month is typical for a small account, more with "
            "heavy traffic."
        ),
        caveats=(),
    )
    required_actions = frozenset({"guardduty:ListDetectors", "guardduty:GetDetector"})

    def run(self, ctx: ScanContext) -> Iterator[Finding]:
        detectors = list(self._detectors(ctx))
        finding = self._evaluate(ctx, detectors)
        if finding is not None:
            yield finding

    @staticmethod
    def _detectors(ctx: ScanContext) -> Iterator[DetectorState]:
        guardduty = ctx.client()
        for detector_id in guardduty.list_detectors().get("DetectorIds", []):
            detail = guardduty.get_detector(DetectorId=detector_id)
            yield DetectorState(detector_id=detector_id, enabled=detail.get("Status") == "ENABLED")

    def _evaluate(self, ctx: ScanContext, detectors: list[DetectorState]) -> Finding | None:
        if has_active_detector(detectors):
            return None

        detail = (
            "No GuardDuty detector exists in this region"
            if not detectors
            else f"{len(detectors)} detector(s) exist but none is enabled"
        )

        return Finding(
            check_id=self.id,
            resource_id=ctx.region,
            resource_type=self.resource_type,
            region=ctx.region,
            severity=self.severity,
            audit_impact=self.audit_impact,
            title="GuardDuty is not enabled",
            detail=detail,
            metadata={},
        )
