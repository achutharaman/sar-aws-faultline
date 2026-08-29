"""Detection logic for vpc-flow-logs-disabled."""

from __future__ import annotations

import boto3
from moto import mock_aws

from sar_aws_faultline.checks.vpc_flow_logs import VpcFlowLogsDisabled, vpcs_without_flow_logs
from sar_aws_faultline.config import Config
from sar_aws_faultline.context import ScanContext
from sar_aws_faultline.session import ClientFactory
from tests.conftest import FROZEN_NOW, TEST_ACCOUNT


def test_vpc_with_no_flow_log_is_flagged():
    assert vpcs_without_flow_logs({"vpc-1"}, set()) == ["vpc-1"]


def test_vpc_with_a_flow_log_is_not_flagged():
    assert vpcs_without_flow_logs({"vpc-1"}, {"vpc-1"}) == []


def test_only_the_unlogged_vpc_is_reported():
    assert vpcs_without_flow_logs({"vpc-1", "vpc-2"}, {"vpc-1"}) == ["vpc-2"]


def _context() -> ScanContext:
    return ScanContext(
        region="us-east-1",
        check_id=VpcFlowLogsDisabled.id,
        service="ec2",
        config=Config(),
        factory=ClientFactory(),
        now=FROZEN_NOW,
        account_id=TEST_ACCOUNT,
    )


@mock_aws
def test_run_flags_only_the_unlogged_vpc():
    """A fresh moto region already carries a default VPC, which also has no
    flow log and is correctly flagged too -- so this asserts membership, not
    an exact list, since the true-positive count from the default VPC is
    itself a valid finding, not test noise."""
    ec2 = boto3.client("ec2", region_name="us-east-1")
    logged_vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    ec2.create_flow_logs(
        ResourceIds=[logged_vpc],
        ResourceType="VPC",
        TrafficType="ALL",
        LogDestinationType="cloud-watch-logs",
        LogGroupName="/vpc/flowlogs",
        DeliverLogsPermissionArn="arn:aws:iam::123456789012:role/x",
    )
    unlogged_vpc = ec2.create_vpc(CidrBlock="10.1.0.0/16")["Vpc"]["VpcId"]

    resource_ids = [f.resource_id for f in VpcFlowLogsDisabled().run(_context())]

    assert unlogged_vpc in resource_ids
    assert logged_vpc not in resource_ids
