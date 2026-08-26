"""Publicly accessible S3 buckets.

Why this models *effective* exposure rather than "are all four Block Public
Access flags on"
-------------------------------------------------------------------------
The four BPA settings are not interchangeable, and they suppress different
sources of public access:

    BlockPublicAcls        rejects *new* public ACLs
    IgnorePublicAcls       neutralises *existing* public ACLs
    BlockPublicPolicy      rejects *new* public bucket policies
    RestrictPublicBuckets  neutralises *existing* public bucket policies

So a bucket carrying a public ACL is not actually exposed if IgnorePublicAcls
is set, and one with a public policy is not exposed if RestrictPublicBuckets is
set. Account-level BPA applies on top of bucket-level; either can suppress.

Flagging "not all four flags are true" -- which is the easy implementation --
produces false positives on buckets that are genuinely private. False positives
are the specific failure mode this tool exists to avoid, so the check computes
the outcome and reports which path is open.

Deliberately not covered here
-----------------------------
"Bucket has no BPA configuration at all" is a hardening finding, not an
exposure finding, and belongs in its own check so its severity and audit impact
can differ. Cross-account policy grants to named principals are authorised
sharing, not public access, and are out of scope.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass, field

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

ALL_USERS = "http://acs.amazonaws.com/groups/global/AllUsers"
AUTHENTICATED_USERS = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"

# AuthenticatedUsers means *any* AWS account anywhere, not "users of my
# account". Reading it as internal is a classic and expensive mistake.
PUBLIC_ACL_GRANTEES = frozenset({ALL_USERS, AUTHENTICATED_USERS})

_MISSING_BPA_CODES = frozenset(
    {"NoSuchPublicAccessBlockConfiguration", "NoSuchBucketPolicy", "AccessDenied"}
)


@dataclass(frozen=True, slots=True)
class BlockPublicAccess:
    """The four BPA flags.

    Absent configuration is modelled as all-false, matching AWS behaviour: no
    BPA means nothing is suppressed.
    """

    block_public_acls: bool = False
    ignore_public_acls: bool = False
    block_public_policy: bool = False
    restrict_public_buckets: bool = False
    configured: bool = False

    @classmethod
    def from_api(cls, payload: dict | None) -> BlockPublicAccess:
        if not payload:
            return cls()
        cfg = payload.get("PublicAccessBlockConfiguration", payload)
        return cls(
            block_public_acls=bool(cfg.get("BlockPublicAcls", False)),
            ignore_public_acls=bool(cfg.get("IgnorePublicAcls", False)),
            block_public_policy=bool(cfg.get("BlockPublicPolicy", False)),
            restrict_public_buckets=bool(cfg.get("RestrictPublicBuckets", False)),
            configured=True,
        )

    def as_flags(self) -> str:
        on = [
            name
            for name, value in (
                ("BlockPublicAcls", self.block_public_acls),
                ("IgnorePublicAcls", self.ignore_public_acls),
                ("BlockPublicPolicy", self.block_public_policy),
                ("RestrictPublicBuckets", self.restrict_public_buckets),
            )
            if value
        ]
        return ",".join(on) if on else "none"


@dataclass(frozen=True, slots=True)
class BucketState:
    """Everything the verdict depends on, collected once."""

    name: str
    account_bpa: BlockPublicAccess = BlockPublicAccess()
    bucket_bpa: BlockPublicAccess = BlockPublicAccess()
    public_acl_grantees: tuple[str, ...] = ()
    policy_is_public: bool = False
    tags: dict[str, str] = field(default_factory=dict)


def exposure_paths(state: BucketState) -> list[str]:
    """Pure. Which routes to public access are actually open.

    Kept module-level and dependency-free so the whole decision surface can be
    tested exhaustively without AWS, without moto, and without a mocking layer
    standing between the test and the assertion.
    """
    acls_neutralised = state.account_bpa.ignore_public_acls or state.bucket_bpa.ignore_public_acls
    policy_neutralised = (
        state.account_bpa.restrict_public_buckets or state.bucket_bpa.restrict_public_buckets
    )

    paths: list[str] = []
    if state.public_acl_grantees and not acls_neutralised:
        paths.append("acl")
    if state.policy_is_public and not policy_neutralised:
        paths.append("policy")
    return paths


# -- collection (boto3 wiring) -----------------------------------------------
#
# Module-level rather than methods on PublicS3Buckets so a sibling check
# (s3-block-public-access-disabled) can collect the same BucketState without
# reaching into another check's private methods.


def fetch_account_bpa(ctx: ScanContext) -> BlockPublicAccess:
    if not ctx.account_id:
        return BlockPublicAccess()
    try:
        client = ctx.client("s3control")
        return BlockPublicAccess.from_api(client.get_public_access_block(AccountId=ctx.account_id))
    except Exception:  # noqa: BLE001 - unset account BPA is the common case
        return BlockPublicAccess()


def fetch_bucket_bpa(s3, name: str) -> BlockPublicAccess:
    try:
        return BlockPublicAccess.from_api(s3.get_public_access_block(Bucket=name))
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") in _MISSING_BPA_CODES:
            return BlockPublicAccess()
        raise
    except Exception:  # noqa: BLE001
        return BlockPublicAccess()


def fetch_public_acl_grantees(s3, name: str) -> tuple[str, ...]:
    try:
        acl = s3.get_bucket_acl(Bucket=name)
    except ClientError:
        return ()
    return tuple(
        f"{uri} ({grant.get('Permission')})"
        for grant in acl.get("Grants", [])
        if (uri := grant.get("Grantee", {}).get("URI")) in PUBLIC_ACL_GRANTEES
    )


def fetch_policy_is_public(s3, name: str) -> bool:
    try:
        return bool(s3.get_bucket_policy_status(Bucket=name)["PolicyStatus"]["IsPublic"])
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NoSuchBucketPolicy":
            return False
        return _policy_looks_public(s3, name)
    except Exception:  # noqa: BLE001 - not every mock layer implements this
        return _policy_looks_public(s3, name)


def _policy_looks_public(s3, name: str) -> bool:
    """Fallback when GetBucketPolicyStatus is unavailable.

    Deliberately conservative: it only recognises the unambiguous wildcard
    principal. AWS's own IsPublic evaluation also accounts for Condition keys
    that narrow a wildcard, so this fallback can over-report where the real
    API would not -- which is why it is a fallback and not the primary path.
    """
    try:
        doc = json.loads(s3.get_bucket_policy(Bucket=name)["Policy"])
    except Exception:  # noqa: BLE001
        return False
    for stmt in doc.get("Statement", []):
        if stmt.get("Effect") != "Allow" or stmt.get("Condition"):
            continue
        principal = stmt.get("Principal")
        if principal == "*" or (
            isinstance(principal, dict) and principal.get("AWS") in ("*", ["*"])
        ):
            return True
    return False


def fetch_bucket_tags(s3, name: str) -> dict[str, str]:
    try:
        tagging = s3.get_bucket_tagging(Bucket=name)
    except Exception:  # noqa: BLE001 - untagged buckets raise NoSuchTagSet
        return {}
    return {t["Key"]: t["Value"] for t in tagging.get("TagSet", []) if "Key" in t}


def collect_bucket_state(s3, name: str, account_bpa: BlockPublicAccess) -> BucketState:
    """Gather everything a verdict about this bucket depends on, in one call."""
    return BucketState(
        name=name,
        account_bpa=account_bpa,
        bucket_bpa=fetch_bucket_bpa(s3, name),
        public_acl_grantees=fetch_public_acl_grantees(s3, name),
        policy_is_public=fetch_policy_is_public(s3, name),
        tags=fetch_bucket_tags(s3, name),
    )


@register
class PublicS3Buckets:
    id = "s3-bucket-public-access"
    title = "Publicly accessible S3 buckets"
    service = "s3"
    resource_type = "AWS::S3::Bucket"
    scope = Scope.GLOBAL
    severity = Severity.CRITICAL
    audit_impact = AuditImpact.BLOCKER
    rationale = (
        "Anyone on the internet can list or read the contents of this bucket. "
        "Publicly exposed object storage is among the most common causes of "
        "data breaches in cloud environments, and an enterprise customer's "
        "security questionnaire will ask about it directly. Serving public "
        "content from S3 is a legitimate thing to do -- but it should be a "
        "deliberate, documented decision about a specific bucket, rather than "
        "a default nobody has revisited since the account was created."
    )
    remediation = Remediation(
        summary=(
            "Turn on Block Public Access at the account level, then grant "
            "exceptions per bucket only where public content is genuinely "
            "intended."
        ),
        effort=Effort.MINUTES,
        console_steps=(
            "Open the S3 console and choose 'Block Public Access settings for "
            "this account' in the left navigation.",
            "Choose Edit, tick 'Block all public access', and save.",
            "For any bucket that genuinely serves public content, move that "
            "content to a dedicated bucket and re-enable public access there "
            "alone.",
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
            "once. If you serve a static site or public assets directly from "
            "S3 this will break it -- put that content behind CloudFront with "
            "an Origin Access Control first.",
            "This reports effective exposure, not whether all four BPA flags "
            "are set. A bucket can pass here and still have incomplete BPA "
            "settings that would let a future change expose it.",
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
        paths = exposure_paths(state)
        if not paths:
            return None

        via = " and ".join(paths)
        detail = f"Readable by anonymous or any-AWS principals via bucket {via}"
        if AUTHENTICATED_USERS in " ".join(state.public_acl_grantees):
            detail += "; the AuthenticatedUsers grant means any AWS account, not just yours"

        metadata = {
            "exposure_paths": ",".join(paths),
            "account_bpa_enabled": state.account_bpa.as_flags(),
            "bucket_bpa_enabled": state.bucket_bpa.as_flags(),
            "bucket_bpa_configured": str(state.bucket_bpa.configured).lower(),
            "public_acl_grantees": "; ".join(state.public_acl_grantees) or "none",
            "policy_is_public": str(state.policy_is_public).lower(),
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
            title="Publicly accessible S3 bucket",
            detail=detail,
            metadata=metadata,
        )
