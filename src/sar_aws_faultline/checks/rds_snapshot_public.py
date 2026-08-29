"""Publicly shared RDS snapshots.

The database counterpart of ebs-snapshot-public -- same exposure shape
(shared with 'all', invisible outside the snapshot's own permissions page),
kept as a separate check because it's a different service (rds vs ec2) with
its own IAM actions, matching how every other check in this project maps
one service to one check.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

from botocore.exceptions import ClientError

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
class DbSnapshotState:
    snapshot_id: str
    public: bool


def is_public(state: DbSnapshotState) -> bool:
    return state.public


@register
class RdsSnapshotPublic:
    id = "rds-snapshot-public"
    title = "Publicly shared RDS snapshot"
    service = "rds"
    resource_type = "AWS::RDS::DBSnapshot"
    scope = Scope.REGIONAL
    severity = Severity.CRITICAL
    audit_impact = AuditImpact.BLOCKER
    rationale = (
        "A database snapshot shared with 'all' lets anyone restore a full "
        "copy of the database -- every table, every row, at the point the "
        "snapshot was taken -- with no authentication against your account "
        "at all. This is one of the most severe exposure modes available in "
        "AWS: the entire dataset, not just one bucket or one bug."
    )
    remediation = Remediation(
        summary=(
            "Remove the public share permission from the snapshot, and "
            "re-share only with specific account IDs if sharing was "
            "intentional."
        ),
        effort=Effort.MINUTES,
        console_steps=(
            "RDS console -> Snapshots -> select the snapshot -> Actions -> Share snapshot.",
            "Change from 'Public' to 'Private', and add specific AWS account "
            "IDs only if sharing was genuinely intended.",
        ),
        cli_commands=(
            "aws rds modify-db-snapshot-attribute --db-snapshot-identifier "
            "<SNAPSHOT_ID> --attribute-name restore --values-to-remove all",
        ),
        monthly_cost_usd=0.0,
        cost_note="Free.",
        caveats=(
            "Confirm nothing legitimate depends on public access before "
            "revoking it -- this is rarely intentional, but it does happen "
            "for shared sample datasets.",
        ),
    )
    required_actions = frozenset({"rds:DescribeDBSnapshots", "rds:DescribeDBSnapshotAttributes"})

    def run(self, ctx: ScanContext) -> Iterator[Finding]:
        rds = ctx.client()
        paginator = rds.get_paginator("describe_db_snapshots")
        for page in paginator.paginate():
            for snapshot in page.get("DBSnapshots", []):
                state = self._state(rds, snapshot["DBSnapshotIdentifier"])
                finding = self._evaluate(ctx, state)
                if finding is not None:
                    yield finding

    @staticmethod
    def _state(rds, snapshot_id: str) -> DbSnapshotState:
        try:
            attrs = rds.describe_db_snapshot_attributes(DBSnapshotIdentifier=snapshot_id)
        except ClientError:
            return DbSnapshotState(snapshot_id=snapshot_id, public=False)
        result = attrs.get("DBSnapshotAttributesResult", {})
        public = any(
            attr.get("AttributeName") == "restore" and "all" in attr.get("AttributeValues", [])
            for attr in result.get("DBSnapshotAttributes", [])
        )
        return DbSnapshotState(snapshot_id=snapshot_id, public=public)

    def _evaluate(self, ctx: ScanContext, state: DbSnapshotState) -> Finding | None:
        if not is_public(state):
            return None

        return Finding(
            check_id=self.id,
            resource_id=state.snapshot_id,
            resource_type=self.resource_type,
            region=ctx.region,
            severity=self.severity,
            audit_impact=self.audit_impact,
            title="Publicly shared RDS snapshot",
            detail="Snapshot can be restored by any AWS account",
            metadata={},
        )
