"""RDS instances without encryption at rest.

This is the worked example CONTRIBUTING.md uses to illustrate the check
contract -- id, severity/audit_impact set independently, a Remediation with
console and CLI paths. Implemented here for real rather than left as
documentation-only.
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
class DbInstanceState:
    identifier: str
    engine: str
    storage_encrypted: bool
    status: str
    tags: dict[str, str] = field(default_factory=dict)


def is_unencrypted(state: DbInstanceState) -> bool:
    return not state.storage_encrypted


@register
class UnencryptedRdsInstances:
    id = "rds-instance-unencrypted"
    title = "RDS instances without encryption at rest"
    service = "rds"
    resource_type = "AWS::RDS::DBInstance"
    scope = Scope.REGIONAL
    severity = Severity.HIGH
    audit_impact = AuditImpact.BLOCKER
    rationale = (
        "An unencrypted database instance means its storage, automated "
        "backups, read replicas, and snapshots are all unencrypted too -- "
        "encryption at rest cannot be turned on after the fact for an "
        "existing instance. Customer or application data usually lives in "
        "RDS, which makes this one of the first things an enterprise "
        "customer's security questionnaire or a SOC 2 auditor asks about "
        "directly, and one of the most disruptive to fix late."
    )
    remediation = Remediation(
        summary=(
            "Encryption at rest cannot be enabled in place. Snapshot the "
            "instance, copy the snapshot with encryption enabled, then "
            "restore a new encrypted instance from that copy."
        ),
        effort=Effort.PLANNED,
        console_steps=(
            "RDS console -> Databases -> select the instance -> Actions -> Take snapshot.",
            "Open the new snapshot -> Actions -> Copy snapshot, and enable encryption on the copy.",
            "Open the encrypted copy -> Actions -> Restore snapshot to create "
            "a new, encrypted instance.",
            "Cut applications over to the new instance's endpoint, verify, "
            "then decommission the original.",
        ),
        cli_commands=(
            "aws rds create-db-snapshot --db-instance-identifier <DB_ID> "
            "--db-snapshot-identifier <SNAPSHOT_ID>",
            "aws rds copy-db-snapshot --source-db-snapshot-identifier "
            "<SNAPSHOT_ID> --target-db-snapshot-identifier <ENCRYPTED_ID> "
            "--kms-key-id <KMS_KEY_ID>",
            "aws rds restore-db-instance-from-db-snapshot "
            "--db-instance-identifier <NEW_DB_ID> --db-snapshot-identifier "
            "<ENCRYPTED_ID>",
        ),
        monthly_cost_usd=0.0,
        cost_note="Encryption itself is free; the migration needs a maintenance window.",
        caveats=(
            "This requires a new instance with a new endpoint -- every "
            "connected application needs its connection string updated, and "
            "there is a cutover window with either downtime or a replication "
            "step in between.",
            "Read replicas of an unencrypted instance are also unencrypted "
            "and need the same treatment.",
        ),
    )
    required_actions = frozenset({"rds:DescribeDBInstances"})

    def run(self, ctx: ScanContext) -> Iterator[Finding]:
        rds = ctx.client()
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for instance in page.get("DBInstances", []):
                state = self._state(instance)
                finding = self._evaluate(ctx, state)
                if finding is not None:
                    yield finding

    @staticmethod
    def _state(instance: dict) -> DbInstanceState:
        tags = {t["Key"]: t["Value"] for t in instance.get("TagList", []) if "Key" in t}
        return DbInstanceState(
            identifier=instance["DBInstanceIdentifier"],
            engine=instance.get("Engine", "unknown"),
            storage_encrypted=bool(instance.get("StorageEncrypted", False)),
            status=instance.get("DBInstanceStatus", "unknown"),
            tags=tags,
        )

    def _evaluate(self, ctx: ScanContext, state: DbInstanceState) -> Finding | None:
        if not is_unencrypted(state):
            return None

        return Finding(
            check_id=self.id,
            resource_id=state.identifier,
            resource_type=self.resource_type,
            region=ctx.region,
            severity=self.severity,
            audit_impact=self.audit_impact,
            title="RDS instance without encryption at rest",
            detail=f"{state.engine} instance is not encrypted ({state.status})",
            metadata={"engine": state.engine, "status": state.status},
        )
