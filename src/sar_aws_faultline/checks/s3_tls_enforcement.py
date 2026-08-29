"""S3 buckets that don't require TLS.

The in-transit complement to s3-bucket-public-access's at-rest angle: a
private bucket can still let a client connect over plain HTTP, where the
request (and any pre-signed URL, session token, or object content) travels
unencrypted. Detected the same way AWS's own guidance checks it: a
bucket-policy statement that explicitly denies requests where
aws:SecureTransport is false.
"""

from __future__ import annotations

import json
from collections.abc import Iterator

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


def policy_enforces_tls(policy: dict) -> bool:
    """Pure. True if any Deny statement conditions on aws:SecureTransport
    being false -- the standard, AWS-documented pattern for requiring TLS.
    A bucket with no policy at all, or a policy that never mentions
    SecureTransport, does not enforce anything: HTTP is accepted by
    default."""
    for stmt in policy.get("Statement", []):
        if stmt.get("Effect") != "Deny":
            continue
        condition = stmt.get("Condition", {})
        for operator in ("Bool", "BoolIfExists"):
            values = condition.get(operator, {})
            if str(values.get("aws:SecureTransport", "")).lower() == "false":
                return True
    return False


@register
class S3BucketTlsNotEnforced:
    id = "s3-bucket-tls-not-enforced"
    title = "S3 bucket does not require TLS"
    service = "s3"
    resource_type = "AWS::S3::Bucket"
    scope = Scope.GLOBAL
    severity = Severity.MEDIUM
    audit_impact = AuditImpact.EXPECTED
    rationale = (
        "Without a policy denying non-TLS requests, S3 accepts plain HTTP by "
        "default -- anyone positioned to observe the network path (a shared "
        "network, a misconfigured proxy, a compromised intermediate host) "
        "can read requests and responses in the clear, credentials included "
        "if any are passed via a pre-signed URL. Requiring TLS costs nothing "
        "and breaks nothing that wasn't already using HTTPS."
    )
    remediation = Remediation(
        summary=(
            "Add a bucket policy statement denying any request where aws:SecureTransport is false."
        ),
        effort=Effort.MINUTES,
        console_steps=(
            "S3 console -> select the bucket -> Permissions -> Bucket policy -> Edit.",
            "Add a Deny statement for Principal '*' on all S3 actions, "
            'conditioned on Bool { "aws:SecureTransport": "false" }.',
        ),
        cli_commands=(
            "aws s3api put-bucket-policy --bucket <BUCKET> --policy "
            '\'{"Version":"2012-10-17","Statement":[{"Sid":"DenyInsecureTransport",'
            '"Effect":"Deny","Principal":"*","Action":"s3:*",'
            '"Resource":["arn:aws:s3:::<BUCKET>","arn:aws:s3:::<BUCKET>/*"],'
            '"Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}\'',
        ),
        monthly_cost_usd=0.0,
        cost_note="Free.",
        caveats=(
            "Merge this statement into any existing bucket policy rather "
            "than replacing it -- put-bucket-policy overwrites the whole "
            "policy document.",
        ),
    )
    required_actions = frozenset({"s3:ListAllMyBuckets", "s3:GetBucketPolicy"})

    def run(self, ctx: ScanContext) -> Iterator[Finding]:
        s3 = ctx.client()
        for bucket in s3.list_buckets().get("Buckets", []):
            name = bucket["Name"]
            policy = self._policy(s3, name)
            finding = self._evaluate(ctx, name, policy)
            if finding is not None:
                yield finding

    @staticmethod
    def _policy(s3, name: str) -> dict:
        try:
            raw = s3.get_bucket_policy(Bucket=name)["Policy"]
        except ClientError:
            return {}
        try:
            return json.loads(raw)
        except (TypeError, ValueError):
            return {}

    def _evaluate(self, ctx: ScanContext, name: str, policy: dict) -> Finding | None:
        if policy_enforces_tls(policy):
            return None

        return Finding(
            check_id=self.id,
            resource_id=name,
            resource_type=self.resource_type,
            region=ctx.region,
            severity=self.severity,
            audit_impact=self.audit_impact,
            title="S3 bucket does not require TLS",
            detail="No bucket policy statement denies non-TLS requests",
            metadata={},
        )
