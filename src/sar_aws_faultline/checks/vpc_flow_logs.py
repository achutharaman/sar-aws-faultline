"""VPCs with no active flow log.

One finding per unlogged VPC, not one per account -- unlike CloudTrail and
GuardDuty, flow log coverage is genuinely per-VPC: a five-VPC account with
flow logs on four of them has one real gap, not zero and not five.
"""

from __future__ import annotations

from collections.abc import Iterator

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


def vpcs_without_flow_logs(vpc_ids: set[str], logged_resource_ids: set[str]) -> list[str]:
    """Pure. logged_resource_ids is whatever a flow log's ResourceId points
    at -- only entries that are themselves a VPC (not a subnet or ENI flow
    log, which don't cover the whole VPC) count as coverage here."""
    return sorted(vpc_ids - logged_resource_ids)


@register
class VpcFlowLogsDisabled:
    id = "vpc-flow-logs-disabled"
    title = "VPC has no active flow log"
    service = "ec2"
    resource_type = "AWS::EC2::VPC"
    scope = Scope.REGIONAL
    severity = Severity.LOW
    audit_impact = AuditImpact.HARDENING
    rationale = (
        "Flow logs record which IP addresses and ports actually talked to "
        "each other inside the VPC -- network-layer evidence CloudTrail "
        "cannot provide, since CloudTrail only sees AWS API calls, not the "
        "traffic those resources send each other. Without flow logs, an "
        "incident investigation has no way to answer what a compromised "
        "instance actually connected to."
    )
    remediation = Remediation(
        summary="Turn on flow logs for the VPC, delivering to CloudWatch Logs or S3.",
        effort=Effort.MINUTES,
        console_steps=(
            "VPC console -> Your VPCs -> select the VPC -> Flow logs tab -> Create flow log.",
            "Filter: All. Destination: CloudWatch Logs or S3, whichever the "
            "team already uses for log aggregation.",
        ),
        cli_commands=(
            "aws ec2 create-flow-logs --resource-type VPC --resource-ids "
            "<VPC_ID> --traffic-type ALL --log-destination-type "
            "cloud-watch-logs --log-group-name /vpc/flowlogs "
            "--deliver-logs-permission-arn <ROLE_ARN>",
        ),
        monthly_cost_usd=2.0,
        cost_note=(
            "CloudWatch Logs ingestion and storage cost, typically a few "
            "dollars a month for a small VPC."
        ),
        caveats=(),
    )
    required_actions = frozenset({"ec2:DescribeVpcs", "ec2:DescribeFlowLogs"})

    def run(self, ctx: ScanContext) -> Iterator[Finding]:
        ec2 = ctx.client()
        vpc_ids = {v["VpcId"] for v in ec2.describe_vpcs().get("Vpcs", [])}
        if not vpc_ids:
            return

        logged = {
            fl["ResourceId"]
            for fl in ec2.describe_flow_logs().get("FlowLogs", [])
            if fl.get("FlowLogStatus") == "ACTIVE" and fl.get("ResourceId", "").startswith("vpc-")
        }

        for vpc_id in vpcs_without_flow_logs(vpc_ids, logged):
            yield Finding(
                check_id=self.id,
                resource_id=vpc_id,
                resource_type=self.resource_type,
                region=ctx.region,
                severity=self.severity,
                audit_impact=self.audit_impact,
                title="VPC has no active flow log",
                detail=f"{vpc_id} has no active flow log recording its traffic",
                metadata={},
            )
