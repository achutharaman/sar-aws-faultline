"""RDS instances not configured for Multi-AZ.

The one check in this batch mapping to SOC 2's Availability criteria rather
than Security -- see docs/DECISIONS.md for why: this is about surviving an
AZ-level failure, not access control or exposure. Chosen over a backup-
retention check for the same area because Multi-AZ has an actual CIS AWS
Foundations citation (RDS.5); backup retention does not appear as a
numbered recommendation in any version of that benchmark, and forcing a
citation onto it would be exactly the kind of overclaiming this project's
compliance data is built to avoid.
"""

from __future__ import annotations

from collections.abc import Iterator
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
class DbInstanceAzState:
    identifier: str
    multi_az: bool
    engine: str


def is_single_az(state: DbInstanceAzState) -> bool:
    return not state.multi_az


@register
class RdsInstanceMultiAzDisabled:
    id = "rds-instance-multi-az-disabled"
    title = "RDS instance is not configured for Multi-AZ"
    service = "rds"
    resource_type = "AWS::RDS::DBInstance"
    scope = Scope.REGIONAL
    severity = Severity.LOW
    audit_impact = AuditImpact.HARDENING
    rationale = (
        "A single-AZ instance goes down for the duration of any outage in "
        "its Availability Zone, with no automatic failover -- Multi-AZ keeps "
        "a synchronously replicated standby in a second AZ and fails over to "
        "it automatically. This is a business-continuity posture question, "
        "not a security gap: a low-traffic dev database not needing "
        "Multi-AZ is a legitimate, common choice, which is why this sits at "
        "hardening rather than expected."
    )
    remediation = Remediation(
        summary="Enable Multi-AZ deployment for the instance.",
        effort=Effort.MINUTES,
        console_steps=(
            "RDS console -> Databases -> select the instance -> Modify.",
            "Under Availability & durability, set Multi-AZ deployment to "
            "'Yes', then apply during the next maintenance window to avoid "
            "the brief failover-related interruption at busy times.",
        ),
        cli_commands=("aws rds modify-db-instance --db-instance-identifier <DB_ID> --multi-az",),
        monthly_cost_usd=15.0,
        cost_note=(
            "Roughly doubles the instance's compute cost, since it runs a full synchronous standby."
        ),
        caveats=(
            "Enabling this triggers a brief failover-like interruption while "
            "the standby is provisioned and synced -- schedule it outside "
            "peak hours.",
        ),
    )
    required_actions = frozenset({"rds:DescribeDBInstances"})

    def run(self, ctx: ScanContext) -> Iterator[Finding]:
        rds = ctx.client()
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for instance in page.get("DBInstances", []):
                state = DbInstanceAzState(
                    identifier=instance["DBInstanceIdentifier"],
                    multi_az=bool(instance.get("MultiAZ", False)),
                    engine=instance.get("Engine", "unknown"),
                )
                finding = self._evaluate(ctx, state)
                if finding is not None:
                    yield finding

    def _evaluate(self, ctx: ScanContext, state: DbInstanceAzState) -> Finding | None:
        if not is_single_az(state):
            return None

        return Finding(
            check_id=self.id,
            resource_id=state.identifier,
            resource_type=self.resource_type,
            region=ctx.region,
            severity=self.severity,
            audit_impact=self.audit_impact,
            title="RDS instance is not configured for Multi-AZ",
            detail=f"{state.engine} instance has no standby in a second Availability Zone",
            metadata={},
        )
