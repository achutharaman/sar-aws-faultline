"""Weak or absent IAM password policy.

No password policy configured at all is modelled as the weakest possible
policy (0 minimum length, no reuse prevention), matching how a fresh account
actually behaves -- IAM's GetAccountPasswordPolicy raises NoSuchEntity when
nothing has ever been set, which is not "this check doesn't apply," it's
"there is no floor on password strength at all."
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

MIN_LENGTH_FLOOR = 14


@dataclass(frozen=True, slots=True)
class PasswordPolicyState:
    configured: bool
    minimum_length: int = 0
    reuse_prevention: int = 0


def weaknesses(state: PasswordPolicyState) -> list[str]:
    """Pure. Each independent gap is reported by name rather than collapsed
    into one boolean, since "too short" and "reuse allowed" call for the
    same fix (edit the policy) but are different facts about it."""
    found = []
    if state.minimum_length < MIN_LENGTH_FLOOR:
        found.append(f"minimum length is {state.minimum_length}, below {MIN_LENGTH_FLOOR}")
    if state.reuse_prevention < 1:
        found.append("password reuse is not prevented")
    return found


@register
class IamPasswordPolicyWeak:
    id = "iam-password-policy-weak"
    title = "Weak or missing IAM password policy"
    service = "iam"
    resource_type = "AWS::IAM::AccountPasswordPolicy"
    scope = Scope.GLOBAL
    severity = Severity.LOW
    audit_impact = AuditImpact.EXPECTED
    rationale = (
        "The account password policy is the floor every IAM user's password "
        "has to clear, and it applies retroactively to nobody -- existing "
        "weak passwords stay weak until their owner changes them. A short or "
        "reusable password policy is a low-severity finding on its own since "
        "MFA is the real backstop, but it is a standard line item on a "
        "security questionnaire and costs nothing to tighten."
    )
    remediation = Remediation(
        summary=(
            f"Set a password policy requiring at least {MIN_LENGTH_FLOOR} "
            "characters and preventing reuse."
        ),
        effort=Effort.MINUTES,
        console_steps=(
            "IAM console -> Account settings -> Password policy -> Edit.",
            f"Set minimum length to {MIN_LENGTH_FLOOR} or more, and set "
            "'Prevent password reuse' to remember at least one prior password.",
        ),
        cli_commands=(
            "aws iam update-account-password-policy --minimum-password-length "
            f"{MIN_LENGTH_FLOOR} --password-reuse-prevention 24",
        ),
        monthly_cost_usd=0.0,
        cost_note="Free.",
        caveats=(
            "This only affects passwords set or changed after the policy is "
            "tightened -- it does not force an immediate reset of existing "
            "passwords unless combined with a maximum password age.",
        ),
    )
    required_actions = frozenset({"iam:GetAccountPasswordPolicy"})

    def run(self, ctx: ScanContext) -> Iterator[Finding]:
        iam = ctx.client()
        state = self._state(iam)
        finding = self._evaluate(ctx, state)
        if finding is not None:
            yield finding

    @staticmethod
    def _state(iam) -> PasswordPolicyState:
        try:
            policy = iam.get_account_password_policy()["PasswordPolicy"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
                return PasswordPolicyState(configured=False)
            raise
        return PasswordPolicyState(
            configured=True,
            minimum_length=int(policy.get("MinimumPasswordLength", 0)),
            reuse_prevention=int(policy.get("PasswordReusePrevention", 0)),
        )

    def _evaluate(self, ctx: ScanContext, state: PasswordPolicyState) -> Finding | None:
        found = weaknesses(state)
        if not found:
            return None

        detail = (
            "No password policy is configured at all" if not state.configured else "; ".join(found)
        )

        return Finding(
            check_id=self.id,
            resource_id=ctx.account_id or "account",
            resource_type=self.resource_type,
            region=ctx.region,
            severity=self.severity,
            audit_impact=self.audit_impact,
            title="Weak or missing IAM password policy",
            detail=detail,
            metadata={"configured": str(state.configured).lower()},
        )
