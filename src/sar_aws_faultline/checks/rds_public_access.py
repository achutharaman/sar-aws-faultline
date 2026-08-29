"""RDS instances that are publicly accessible.

The network-exposure counterpart to rds-instance-unencrypted: this is about
whether the database has a public endpoint at all, independent of whether
its storage is encrypted. A publicly accessible instance is reachable from
the internet at the network layer; anyone still needs valid credentials to
actually connect, but the attack surface -- credential stuffing, exploiting
an unpatched engine vulnerability -- is exposed to the whole internet
instead of only to the VPC.
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
class DbPublicAccessState:
    identifier: str
    publicly_accessible: bool
    engine: str


def is_publicly_accessible(state: DbPublicAccessState) -> bool:
    return state.publicly_accessible


@register
class RdsInstancePubliclyAccessible:
    id = "rds-instance-publicly-accessible"
    title = "RDS instance is publicly accessible"
    service = "rds"
    resource_type = "AWS::RDS::DBInstance"
    scope = Scope.REGIONAL
    severity = Severity.HIGH
    audit_impact = AuditImpact.BLOCKER
    rationale = (
        "A publicly accessible RDS instance has a network path from the "
        "entire internet, not just from inside the VPC -- every unpatched "
        "engine vulnerability and every credential-stuffing attempt against "
        "it is reachable by anyone, not just by something already on your "
        "network. Databases are rarely meant to be reached directly from the "
        "internet; application servers inside the VPC are the intended "
        "path, which makes this both high severity and something an auditor "
        "or customer questionnaire asks about directly."
    )
    remediation = Remediation(
        summary=(
            "Turn off public accessibility and connect to the database from inside the VPC instead."
        ),
        effort=Effort.MINUTES,
        console_steps=(
            "RDS console -> Databases -> select the instance -> Modify.",
            "Under Connectivity, set 'Public access' to 'No', then apply "
            "immediately or during the next maintenance window.",
        ),
        cli_commands=(
            "aws rds modify-db-instance --db-instance-identifier <DB_ID> "
            "--no-publicly-accessible --apply-immediately",
        ),
        monthly_cost_usd=0.0,
        cost_note="Free.",
        caveats=(
            "Anything currently connecting from outside the VPC (a local "
            "dev machine, an external service) will lose connectivity -- "
            "route it through a bastion, VPN, or an application layer "
            "inside the VPC first.",
        ),
    )
    required_actions = frozenset({"rds:DescribeDBInstances"})

    def run(self, ctx: ScanContext) -> Iterator[Finding]:
        rds = ctx.client()
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for instance in page.get("DBInstances", []):
                state = DbPublicAccessState(
                    identifier=instance["DBInstanceIdentifier"],
                    publicly_accessible=bool(instance.get("PubliclyAccessible", False)),
                    engine=instance.get("Engine", "unknown"),
                )
                finding = self._evaluate(ctx, state)
                if finding is not None:
                    yield finding

    def _evaluate(self, ctx: ScanContext, state: DbPublicAccessState) -> Finding | None:
        if not is_publicly_accessible(state):
            return None

        return Finding(
            check_id=self.id,
            resource_id=state.identifier,
            resource_type=self.resource_type,
            region=ctx.region,
            severity=self.severity,
            audit_impact=self.audit_impact,
            title="RDS instance is publicly accessible",
            detail=f"{state.engine} instance has a public network endpoint",
            metadata={},
        )
