"""Unencrypted EBS volumes.

Scope decision: volumes and snapshots are two different resources with two
different exposure windows (a volume is encrypted or it is not, for its whole
life; a snapshot inherits its source volume's encryption state at the moment
it was taken, so an old snapshot can be unencrypted even if the volume that
made it was later encrypted). This check covers volumes only. Snapshots and
the account-level "encrypt new volumes by default" setting are separate,
narrower findings and are not conflated with this one -- see
docs/DECISIONS.md's note on the sibling cost tool's ebs-unattached, which
this check deliberately does not fold into.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field

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
class VolumeState:
    volume_id: str
    encrypted: bool
    size_gib: int
    attachment_state: str = "available"
    tags: dict[str, str] = field(default_factory=dict)


def is_unencrypted(state: VolumeState) -> bool:
    """Pure. Kept as its own function, trivial as it is, so the decision is
    testable without AWS and so a future refinement (e.g. distinguishing
    AWS-managed from customer-managed key encryption) has one place to land.
    """
    return not state.encrypted


@register
class UnencryptedEbsVolumes:
    id = "ebs-volume-unencrypted"
    title = "EBS volumes without encryption at rest"
    service = "ec2"
    resource_type = "AWS::EC2::Volume"
    scope = Scope.REGIONAL
    severity = Severity.MEDIUM
    audit_impact = AuditImpact.EXPECTED
    rationale = (
        "An unencrypted EBS volume means the raw block data -- and anything "
        "recovered from a snapshot, a detached volume, or the underlying "
        "storage -- is readable without going through IAM at all. Encryption "
        "at rest is one of the first things a SOC 2 auditor or an enterprise "
        "security questionnaire asks about, and turning it on for new volumes "
        "costs nothing and has no performance impact."
    )
    remediation = Remediation(
        summary=(
            "Turn on EBS encryption by default for the region, then re-create "
            "existing unencrypted volumes from an encrypted snapshot."
        ),
        effort=Effort.HOURS,
        console_steps=(
            "EC2 console -> Settings -> Data protection and security -> Enable "
            "'Always encrypt new EBS volumes'. This only affects volumes "
            "created after this point.",
            "For each existing unencrypted volume: create a snapshot, copy it "
            "with encryption enabled, create a new volume from the encrypted "
            "copy, then swap it in place of the original (stop the instance "
            "first if the volume is attached).",
        ),
        cli_commands=(
            "aws ec2 enable-ebs-encryption-by-default --region <REGION>",
            "aws ec2 create-snapshot --volume-id <VOLUME_ID>",
            "aws ec2 copy-snapshot --source-snapshot-id <SNAPSHOT_ID> "
            "--source-region <REGION> --encrypted",
        ),
        monthly_cost_usd=0.0,
        cost_note="EBS encryption is free; it changes no pricing tier.",
        caveats=(
            "Swapping a volume on a running instance needs a stop/start, which "
            "is downtime for anything not fault-tolerant across an instance "
            "replacement.",
            "'Encrypt by default' only applies going forward -- it does not "
            "retroactively encrypt volumes that already exist.",
        ),
    )
    required_actions = frozenset({"ec2:DescribeVolumes"})

    def run(self, ctx: ScanContext) -> Iterator[Finding]:
        ec2 = ctx.client()
        paginator = ec2.get_paginator("describe_volumes")
        for page in paginator.paginate():
            for volume in page.get("Volumes", []):
                state = self._state(volume)
                finding = self._evaluate(ctx, state)
                if finding is not None:
                    yield finding

    @staticmethod
    def _state(volume: dict) -> VolumeState:
        attachments = volume.get("Attachments") or []
        attachment_state = attachments[0]["State"] if attachments else "available"
        tags = {t["Key"]: t["Value"] for t in volume.get("Tags", []) if "Key" in t}
        return VolumeState(
            volume_id=volume["VolumeId"],
            encrypted=bool(volume.get("Encrypted", False)),
            size_gib=int(volume.get("Size", 0)),
            attachment_state=attachment_state,
            tags=tags,
        )

    def _evaluate(self, ctx: ScanContext, state: VolumeState) -> Finding | None:
        if not is_unencrypted(state):
            return None

        metadata = {
            "size_gib": str(state.size_gib),
            "attachment_state": state.attachment_state,
        }
        if name := state.tags.get("Name"):
            metadata["name"] = name

        return Finding(
            check_id=self.id,
            resource_id=state.volume_id,
            resource_type=self.resource_type,
            region=ctx.region,
            severity=self.severity,
            audit_impact=self.audit_impact,
            title="EBS volume without encryption at rest",
            detail=(f"{state.size_gib} GiB volume is not encrypted ({state.attachment_state})"),
            metadata=metadata,
        )
