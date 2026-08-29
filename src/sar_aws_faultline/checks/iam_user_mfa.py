"""IAM users with a console password but no MFA.

Direct sibling of iam-root-account-no-mfa: same credential report, filtered
to a different set of rows. Users without a console password (API-only,
access-key-only users) are excluded -- MFA protects a password sign-in; an
access key has no MFA concept at all, so flagging one would be a finding
about a control that doesn't apply to that principal.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

from sar_aws_faultline.checks.iam_credential_report import ROOT_ROW_USER, fetch_report_rows
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
class IamUserState:
    user: str
    password_enabled: bool
    mfa_active: bool


def console_user_lacks_mfa(state: IamUserState) -> bool:
    return state.password_enabled and not state.mfa_active


def parse_users(rows: list[dict[str, str]]) -> list[IamUserState]:
    """Pure. Root is excluded here -- it has its own check with its own
    severity, since a compromised root credential is categorically worse
    than a compromised IAM user."""
    users = []
    for row in rows:
        user = row.get("user", "")
        if not user or user == ROOT_ROW_USER:
            continue
        users.append(
            IamUserState(
                user=user,
                password_enabled=row.get("password_enabled", "false") == "true",
                mfa_active=row.get("mfa_active", "false") == "true",
            )
        )
    return users


@register
class IamUsersWithoutMfa:
    id = "iam-user-no-mfa"
    title = "IAM users with a console password but no MFA"
    service = "iam"
    resource_type = "AWS::IAM::User"
    scope = Scope.GLOBAL
    severity = Severity.HIGH
    audit_impact = AuditImpact.EXPECTED
    rationale = (
        "A console password with no MFA means account takeover is one leaked "
        "or guessed password away, with no second factor to stop it. This is "
        "one of the most consistently checked items across security "
        "questionnaires and audit frameworks, and enabling MFA costs the user "
        "a few minutes and nothing else."
    )
    remediation = Remediation(
        summary="Have each affected user enable MFA on their own IAM account.",
        effort=Effort.MINUTES,
        console_steps=(
            "IAM console -> Users -> select the user -> Security credentials "
            "tab -> Assign MFA device.",
            "For a fleet-wide fix, attach a policy that denies all actions "
            "except MFA setup until the user has configured a device.",
        ),
        cli_commands=(),
        monthly_cost_usd=0.0,
        cost_note="MFA is free.",
        caveats=(
            "This can only be completed by the user themselves -- an admin "
            "can require it but cannot enable it on someone else's behalf.",
        ),
    )
    required_actions = frozenset({"iam:GenerateCredentialReport", "iam:GetCredentialReport"})

    def run(self, ctx: ScanContext) -> Iterator[Finding]:
        iam = ctx.client()
        rows = fetch_report_rows(iam)
        if rows is None:
            return
        for state in parse_users(rows):
            finding = self._evaluate(ctx, state)
            if finding is not None:
                yield finding

    def _evaluate(self, ctx: ScanContext, state: IamUserState) -> Finding | None:
        if not console_user_lacks_mfa(state):
            return None

        return Finding(
            check_id=self.id,
            resource_id=state.user,
            resource_type=self.resource_type,
            region=ctx.region,
            severity=self.severity,
            audit_impact=self.audit_impact,
            title="IAM user has a console password but no MFA",
            detail=f"User {state.user!r} can sign in with a password and no second factor",
            metadata={},
        )
