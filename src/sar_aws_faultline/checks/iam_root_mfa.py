"""Root account without MFA.

Uses the IAM credential report rather than a dedicated root-user API call --
there isn't one. The report is a single account-wide CSV covering every IAM
user plus a synthetic ``<root_account>`` row, generated asynchronously on
AWS's side. This is the efficiency approach docs/DECISIONS.md's IAM section
calls for generally (MFA status, key age, rotation, root usage and password
age all come from one pull instead of N per-user calls); this check is the
first to actually pull it, scoped to just the root row for now.
"""

from __future__ import annotations

import csv
import io
import time
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

ROOT_ROW_USER = "<root_account>"

# The report is generated asynchronously; GetCredentialReport 404s with
# ReportInProgress until it's ready. A handful of short retries covers the
# common case (seconds) without turning a slow account into a stalled scan.
_REPORT_POLL_ATTEMPTS = 5
_REPORT_POLL_SECONDS = 1.0


@dataclass(frozen=True, slots=True)
class RootAccountState:
    mfa_active: bool


def root_lacks_mfa(state: RootAccountState) -> bool:
    return not state.mfa_active


@register
class RootAccountWithoutMfa:
    id = "iam-root-account-no-mfa"
    title = "Root account without MFA"
    service = "iam"
    resource_type = "AWS::IAM::User"
    scope = Scope.GLOBAL
    severity = Severity.CRITICAL
    audit_impact = AuditImpact.BLOCKER
    rationale = (
        "The root user cannot be restricted by any IAM policy and has "
        "unconditional access to every resource and every setting in the "
        "account, including billing. A compromised root credential with no "
        "MFA is a total account takeover from a single leaked password, and "
        "root MFA is one of the first and most universal items on any AWS "
        "security checklist -- a SOC 2 auditor or security questionnaire "
        "will ask about it by name."
    )
    remediation = Remediation(
        summary="Sign in as root and enable MFA on the root user.",
        effort=Effort.MINUTES,
        console_steps=(
            "Sign in to the AWS console as the root user (not an IAM role or "
            "user -- this must be done as root).",
            "Open the IAM console -> Dashboard -> 'Add MFA' next to the root "
            "user security status, or account name (top right) -> Security "
            "credentials -> Assign MFA device.",
            "A hardware security key or authenticator app is preferable to "
            "virtual MFA on the same device used to sign in.",
        ),
        cli_commands=(),
        monthly_cost_usd=0.0,
        cost_note="MFA is free. A hardware key is a one-time device cost, not a monthly one.",
        caveats=(
            "This can only be done by whoever holds the root password -- it "
            "is not delegable through IAM, so track down who that is before "
            "promising a same-day fix.",
            "Store the MFA device or recovery codes somewhere the team can "
            "reach in an emergency; a root account locked out of its own MFA "
            "is its own incident.",
        ),
    )
    required_actions = frozenset({"iam:GenerateCredentialReport", "iam:GetCredentialReport"})

    def run(self, ctx: ScanContext) -> Iterator[Finding]:
        iam = ctx.client()
        state = self._root_state(iam)
        if state is None:
            return
        finding = self._evaluate(ctx, state)
        if finding is not None:
            yield finding

    @staticmethod
    def _root_state(iam) -> RootAccountState | None:
        for _ in range(_REPORT_POLL_ATTEMPTS):
            iam.generate_credential_report()
            try:
                report = iam.get_credential_report()
            except (
                iam.exceptions.CredentialReportNotPresentException,
                iam.exceptions.CredentialReportNotReadyException,
            ):
                time.sleep(_REPORT_POLL_SECONDS)
                continue
            except iam.exceptions.CredentialReportExpiredException:
                continue
            return RootAccountWithoutMfa._parse(report["Content"])
        return None

    @staticmethod
    def _parse(content: bytes) -> RootAccountState | None:
        rows = csv.DictReader(io.StringIO(content.decode("utf-8")))
        for row in rows:
            if row.get("user") == ROOT_ROW_USER:
                return RootAccountState(mfa_active=row.get("mfa_active", "false") == "true")
        return None

    def _evaluate(self, ctx: ScanContext, state: RootAccountState) -> Finding | None:
        if not root_lacks_mfa(state):
            return None

        return Finding(
            check_id=self.id,
            resource_id=ctx.account_id or "root",
            resource_type=self.resource_type,
            region=ctx.region,
            severity=self.severity,
            audit_impact=self.audit_impact,
            title="Root account has no MFA",
            detail="The root user has no MFA device assigned",
            metadata={},
        )
