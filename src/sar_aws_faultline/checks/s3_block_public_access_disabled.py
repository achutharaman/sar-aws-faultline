"""S3 buckets with no Block Public Access guardrail.

Deliberately a separate check from s3-bucket-public-access rather than a third
exposure_paths() branch. That check's own remediation caveat already flags the
gap this fills: "This reports effective exposure, not whether all four BPA
flags are set. A bucket can pass here and still have incomplete BPA settings
that would let a future change expose it." A bucket that *could* become public
is not as urgent as one that *is* public right now, and the two-axis model
(severity, audit_impact) exists precisely so the two get ranked differently
instead of both landing at CRITICAL/BLOCKER.

A bucket is considered guarded here only if IgnorePublicAcls and
RestrictPublicBuckets are both in effect (account- or bucket-level) -- the two
flags that neutralise a grant regardless of when it was made, matching
exposure_paths()'s own acls_neutralised/policy_neutralised logic.
BlockPublicAcls/BlockPublicPolicy only reject *new* grants made through that
specific API call and are not sufficient on their own.
"""

from __future__ import annotations

from collections.abc import Iterator

from sar_aws_faultline.checks.s3_public_access import (
    BucketState,
    collect_bucket_state,
    exposure_paths,
    fetch_account_bpa,
)
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


def missing_guardrail(state: BucketState) -> bool:
    """Pure. True if a future ACL or policy change could expose this bucket.

    Kept module-level and dependency-free for the same reason as
    exposure_paths(): the whole decision surface should be testable without
    AWS, without moto, and without a mocking layer in between.
    """
    acls_neutralised = state.account_bpa.ignore_public_acls or state.bucket_bpa.ignore_public_acls
    policy_neutralised = (
        state.account_bpa.restrict_public_buckets or state.bucket_bpa.restrict_public_buckets
    )
    return not (acls_neutralised and policy_neutralised)


@register
class S3BlockPublicAccessDisabled:
    id = "s3-block-public-access-disabled"
    title = "S3 buckets without full Block Public Access protection"
    service = "s3"
    resource_type = "AWS::S3::Bucket"
    scope = Scope.GLOBAL
    severity = Severity.MEDIUM
    audit_impact = AuditImpact.EXPECTED
    rationale = (
        "Block Public Access is the guardrail that stops a future ACL change or "
        "bucket policy edit from silently making a bucket public. Without it, "
        "one mistaken policy statement or ACL grant -- from a teammate, a "
        "script, or a copy-pasted Terraform module -- takes effect immediately "
        "with no safety net. This bucket is not necessarily public right now, "
        "but nothing would stop it from becoming public the next time someone "
        "touches its permissions."
    )
    remediation = Remediation(
        summary=(
            "Turn on Block Public Access at the account level so every bucket "
            "is protected by default, rather than relying on each bucket's own "
            "settings."
        ),
        effort=Effort.MINUTES,
        console_steps=(
            "Open the S3 console and choose 'Block Public Access settings for "
            "this account' in the left navigation.",
            "Choose Edit, tick 'Block all public access', and save.",
        ),
        cli_commands=(
            "aws s3control put-public-access-block --account-id <ACCOUNT_ID> "
            "--public-access-block-configuration "
            "BlockPublicAcls=true,IgnorePublicAcls=true,"
            "BlockPublicPolicy=true,RestrictPublicBuckets=true",
        ),
        monthly_cost_usd=0.0,
        cost_note="Block Public Access is free.",
        caveats=(
            "Account-level Block Public Access applies to every bucket at "
            "once. If any bucket genuinely serves public content directly, "
            "this will break it -- put that content behind CloudFront with an "
            "Origin Access Control first, or scope the exception to that "
            "bucket alone instead of applying it account-wide.",
        ),
    )
    required_actions = frozenset(
        {
            "s3:GetAccountPublicAccessBlock",
            "s3:GetBucketAcl",
            "s3:GetBucketPolicy",
            "s3:GetBucketPolicyStatus",
            "s3:GetBucketPublicAccessBlock",
            "s3:GetBucketTagging",
            "s3:ListAllMyBuckets",
        }
    )

    def run(self, ctx: ScanContext) -> Iterator[Finding]:
        s3 = ctx.client()
        account_bpa = fetch_account_bpa(ctx)

        for bucket in s3.list_buckets().get("Buckets", []):
            name = bucket["Name"]
            state = collect_bucket_state(s3, name, account_bpa)
            finding = self._evaluate(ctx, state)
            if finding is not None:
                yield finding

    def _evaluate(self, ctx: ScanContext, state: BucketState) -> Finding | None:
        # Already flagged as actually public by s3-bucket-public-access --
        # reporting both here would be two findings for one root cause, at two
        # different severities. That check is the more urgent of the two.
        if exposure_paths(state):
            return None
        if not missing_guardrail(state):
            return None

        metadata = {
            "account_bpa_enabled": state.account_bpa.as_flags(),
            "bucket_bpa_enabled": state.bucket_bpa.as_flags(),
            "bucket_bpa_configured": str(state.bucket_bpa.configured).lower(),
        }
        if name := state.tags.get("Name"):
            metadata["name"] = name

        return Finding(
            check_id=self.id,
            resource_id=state.name,
            resource_type=self.resource_type,
            region=ctx.region,
            severity=self.severity,
            audit_impact=self.audit_impact,
            title="S3 bucket without full Block Public Access protection",
            detail=(
                "Neither this bucket nor the account has Block Public Access "
                "fully enabled, so a future ACL grant or bucket policy change "
                "could expose it with no guardrail in place"
            ),
            metadata=metadata,
        )
