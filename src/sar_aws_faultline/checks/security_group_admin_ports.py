"""Security groups open to the world on an admin port.

Deliberately narrower than a general "any 0.0.0.0/0 ingress" check: wide-open
ingress to an application port is often intentional (a public web server),
but wide-open SSH or RDP is very rarely intentional and is one of the most
common paths to compromise. Security groups, not NACLs -- see
docs/DECISIONS.md's "Cut from v1" table for why NACL evaluation is out of
scope (ordered rule processing, high false-positive rate).
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

ADMIN_PORTS: dict[int, str] = {22: "SSH", 3389: "RDP"}
PUBLIC_CIDRS = frozenset({"0.0.0.0/0", "::/0"})


@dataclass(frozen=True, slots=True)
class SecurityGroupState:
    group_id: str
    group_name: str
    open_ports: tuple[int, ...]


def open_admin_ports(from_port: int | None, to_port: int | None, cidrs: set[str]) -> list[int]:
    """Pure. Which admin ports, if any, a single ingress rule opens to the
    world. A rule with no port range (from_port/to_port both None) means
    "all ports" -- IpProtocol '-1' -- which opens everything, admin ports
    included."""
    if not cidrs & PUBLIC_CIDRS:
        return []
    if from_port is None or to_port is None:
        return sorted(ADMIN_PORTS)
    return [port for port in ADMIN_PORTS if from_port <= port <= to_port]


@register
class SecurityGroupOpenAdminPorts:
    id = "security-group-open-admin-ports"
    title = "Security group allows SSH or RDP from the internet"
    service = "ec2"
    resource_type = "AWS::EC2::SecurityGroup"
    scope = Scope.REGIONAL
    severity = Severity.CRITICAL
    audit_impact = AuditImpact.BLOCKER
    rationale = (
        "SSH and RDP are the two ports credential-stuffing and brute-force "
        "scanners probe first and most often -- opening either to the whole "
        "internet turns every password guess and every unpatched "
        "vulnerability in the listening service into a reachable attack "
        "surface with no network-level barrier at all. This is one of the "
        "single most common causes of AWS account compromise, and it is "
        "almost never the intended configuration."
    )
    remediation = Remediation(
        summary=(
            "Restrict SSH/RDP ingress to specific known IP ranges, or "
            "route through a bastion / SSM Session Manager instead."
        ),
        effort=Effort.MINUTES,
        console_steps=(
            "EC2 console -> Security Groups -> select the group -> Inbound "
            "rules -> Edit inbound rules.",
            "Change the source of the SSH/RDP rule from Anywhere (0.0.0.0/0 "
            "or ::/0) to your office or VPN CIDR range.",
            "Where possible, remove the rule entirely and use AWS Systems "
            "Manager Session Manager instead, which needs no open inbound "
            "port at all.",
        ),
        cli_commands=(
            "aws ec2 revoke-security-group-ingress --group-id <SG_ID> "
            "--protocol tcp --port 22 --cidr 0.0.0.0/0",
            "aws ec2 authorize-security-group-ingress --group-id <SG_ID> "
            "--protocol tcp --port 22 --cidr <YOUR_IP_RANGE>/32",
        ),
        monthly_cost_usd=0.0,
        cost_note="Free. SSM Session Manager has no additional charge beyond the instance itself.",
        caveats=(
            "If this is how the team currently accesses these instances, "
            "narrowing it without first setting up an alternative (VPN, "
            "bastion, SSM) will lock everyone out.",
        ),
    )
    required_actions = frozenset({"ec2:DescribeSecurityGroups"})

    def run(self, ctx: ScanContext) -> Iterator[Finding]:
        ec2 = ctx.client()
        paginator = ec2.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            for group in page.get("SecurityGroups", []):
                state = self._state(group)
                finding = self._evaluate(ctx, state)
                if finding is not None:
                    yield finding

    @staticmethod
    def _state(group: dict) -> SecurityGroupState:
        open_ports: set[int] = set()
        for rule in group.get("IpPermissions", []):
            cidrs = {r["CidrIp"] for r in rule.get("IpRanges", [])}
            cidrs |= {r["CidrIpv6"] for r in rule.get("Ipv6Ranges", [])}
            open_ports.update(open_admin_ports(rule.get("FromPort"), rule.get("ToPort"), cidrs))
        return SecurityGroupState(
            group_id=group["GroupId"],
            group_name=group.get("GroupName", group["GroupId"]),
            open_ports=tuple(sorted(open_ports)),
        )

    def _evaluate(self, ctx: ScanContext, state: SecurityGroupState) -> Finding | None:
        if not state.open_ports:
            return None

        names = ", ".join(f"{ADMIN_PORTS[p]} ({p})" for p in state.open_ports)
        return Finding(
            check_id=self.id,
            resource_id=state.group_id,
            resource_type=self.resource_type,
            region=ctx.region,
            severity=self.severity,
            audit_impact=self.audit_impact,
            title="Security group allows SSH or RDP from the internet",
            detail=f"Group {state.group_name!r} allows {names} from 0.0.0.0/0 or ::/0",
            metadata={"open_ports": ",".join(str(p) for p in state.open_ports)},
        )
