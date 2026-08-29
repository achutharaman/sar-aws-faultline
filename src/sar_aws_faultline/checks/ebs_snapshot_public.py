"""Publicly shared EBS snapshots.

A public snapshot is a public data exposure exactly like a public S3 bucket,
just less visible: anyone can create a volume from it and read the raw block
data, but it never shows up in the resource lists people actually look at
day to day.
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
class SnapshotState:
    snapshot_id: str
    public: bool


def is_public(state: SnapshotState) -> bool:
    return state.public


@register
class EbsSnapshotPublic:
    id = "ebs-snapshot-public"
    title = "Publicly shared EBS snapshot"
    service = "ec2"
    resource_type = "AWS::EC2::Snapshot"
    scope = Scope.REGIONAL
    severity = Severity.CRITICAL
    audit_impact = AuditImpact.BLOCKER
    rationale = (
        "A snapshot shared with 'all' AWS accounts lets anyone create a "
        "volume from it and read every byte of its raw block data -- "
        "application data, credentials embedded in config files, temporary "
        "files nobody meant to keep. Unlike a public bucket, a public "
        "snapshot doesn't show up in the console page anyone checks "
        "routinely, so this tends to go unnoticed far longer than public S3 "
        "exposure does."
    )
    remediation = Remediation(
        summary=(
            "Remove the public share permission from the snapshot, and "
            "re-share only with specific account IDs if sharing was "
            "intentional."
        ),
        effort=Effort.MINUTES,
        console_steps=(
            "EC2 console -> Snapshots -> select the snapshot -> Actions -> Modify permissions.",
            "Remove 'Public' access. If specific accounts genuinely need it, "
            "add their account IDs individually instead.",
        ),
        cli_commands=(
            "aws ec2 modify-snapshot-attribute --snapshot-id <SNAPSHOT_ID> "
            "--attribute createVolumePermission --operation-type remove "
            "--group-names all",
        ),
        monthly_cost_usd=0.0,
        cost_note="Free.",
        caveats=(
            "If this snapshot is intentionally public (e.g. distributing a "
            "shared AMI's underlying volume), removing public access will "
            "break that distribution -- confirm intent before revoking.",
        ),
    )
    required_actions = frozenset({"ec2:DescribeSnapshots", "ec2:DescribeSnapshotAttribute"})

    def run(self, ctx: ScanContext) -> Iterator[Finding]:
        ec2 = ctx.client()
        paginator = ec2.get_paginator("describe_snapshots")
        for page in paginator.paginate(OwnerIds=["self"]):
            for snapshot in page.get("Snapshots", []):
                state = self._state(ec2, snapshot["SnapshotId"])
                finding = self._evaluate(ctx, state)
                if finding is not None:
                    yield finding

    @staticmethod
    def _state(ec2, snapshot_id: str) -> SnapshotState:
        try:
            attrs = ec2.describe_snapshot_attribute(
                SnapshotId=snapshot_id, Attribute="createVolumePermission"
            )
        except ClientError:
            return SnapshotState(snapshot_id=snapshot_id, public=False)
        public = any(
            perm.get("Group") == "all" for perm in attrs.get("CreateVolumePermissions", [])
        )
        return SnapshotState(snapshot_id=snapshot_id, public=public)

    def _evaluate(self, ctx: ScanContext, state: SnapshotState) -> Finding | None:
        if not is_public(state):
            return None

        return Finding(
            check_id=self.id,
            resource_id=state.snapshot_id,
            resource_type=self.resource_type,
            region=ctx.region,
            severity=self.severity,
            audit_impact=self.audit_impact,
            title="Publicly shared EBS snapshot",
            detail="Snapshot can be used to create a volume by any AWS account",
            metadata={},
        )
