"""Detection logic for security-group-open-admin-ports."""

from __future__ import annotations

import boto3
from moto import mock_aws

from sar_aws_faultline.checks.security_group_admin_ports import (
    SecurityGroupOpenAdminPorts,
    SecurityGroupState,
    open_admin_ports,
)
from sar_aws_faultline.config import Config
from sar_aws_faultline.context import ScanContext
from sar_aws_faultline.session import ClientFactory
from tests.conftest import FROZEN_NOW, TEST_ACCOUNT


def test_ssh_open_to_the_world_is_flagged():
    assert open_admin_ports(22, 22, {"0.0.0.0/0"}) == [22]


def test_ssh_open_to_a_specific_ip_is_not_flagged():
    assert open_admin_ports(22, 22, {"203.0.113.4/32"}) == []


def test_rdp_open_via_ipv6_is_flagged():
    assert open_admin_ports(3389, 3389, {"::/0"}) == [3389]


def test_app_port_open_to_the_world_is_not_an_admin_port():
    assert open_admin_ports(8080, 8080, {"0.0.0.0/0"}) == []


def test_wide_port_range_covering_ssh_is_flagged():
    assert open_admin_ports(0, 65535, {"0.0.0.0/0"}) == [22, 3389]


def test_all_ports_rule_with_no_port_range_is_flagged():
    """IpProtocol '-1' rules have no FromPort/ToPort at all -- that means
    every port, admin ports included."""
    assert open_admin_ports(None, None, {"0.0.0.0/0"}) == [22, 3389]


def _context() -> ScanContext:
    return ScanContext(
        region="us-east-1",
        check_id=SecurityGroupOpenAdminPorts.id,
        service="ec2",
        config=Config(),
        factory=ClientFactory(),
        now=FROZEN_NOW,
        account_id=TEST_ACCOUNT,
    )


def test_finding_names_the_open_ports():
    state = SecurityGroupState(group_id="sg-1", group_name="web", open_ports=(22,))
    finding = SecurityGroupOpenAdminPorts()._evaluate(_context(), state)
    assert finding is not None
    assert "SSH" in finding.detail


def test_no_finding_when_nothing_is_open():
    state = SecurityGroupState(group_id="sg-1", group_name="web", open_ports=())
    assert SecurityGroupOpenAdminPorts()._evaluate(_context(), state) is None


@mock_aws
def test_run_flags_only_the_open_group():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    open_sg = ec2.create_security_group(GroupName="open", Description="d", VpcId=vpc)["GroupId"]
    closed_sg = ec2.create_security_group(GroupName="closed", Description="d", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=open_sg,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )
    ec2.authorize_security_group_ingress(
        GroupId=closed_sg,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 443,
                "ToPort": 443,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )

    findings = list(SecurityGroupOpenAdminPorts().run(_context()))

    assert [f.resource_id for f in findings] == [open_sg]


@mock_aws
def test_run_on_default_only_account_yields_nothing():
    assert list(SecurityGroupOpenAdminPorts().run(_context())) == []
