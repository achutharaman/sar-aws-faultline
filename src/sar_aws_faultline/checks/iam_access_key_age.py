"""IAM access keys not rotated in 90+ days.

Both key slots on a user are checked independently -- an unused, ancient
first key sitting alongside a fresh second key is exactly the case a
naive "does this user have an old key" check would miss if it only looked
at whichever key happened to be listed first.

The 90-day threshold is a per-check tunable via ctx.option(), not hardcoded,
so it can be adjusted in sar-aws-faultline.toml without a code change.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime

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

DEFAULT_MAX_AGE_DAYS = 90


@dataclass(frozen=True, slots=True)
class AccessKeyState:
    user: str
    key_slot: str
    active: bool
    age_days: int | None


def is_stale(state: AccessKeyState, max_age_days: int) -> bool:
    if not state.active or state.age_days is None:
        return False
    return state.age_days > max_age_days


def _parse_timestamp(value: str) -> datetime | None:
    if not value or value in ("N/A", "not_supported"):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def parse_access_keys(rows: list[dict[str, str]], now: datetime) -> list[AccessKeyState]:
    """Pure given the report rows and a reference time -- age_days is
    computed here, not read from the clock, for the same testability reason
    ScanContext.now exists at all."""
    keys: list[AccessKeyState] = []
    for row in rows:
        user = row.get("user", "")
        if not user or user == ROOT_ROW_USER:
            continue
        for slot in ("access_key_1", "access_key_2"):
            active = row.get(f"{slot}_active", "false") == "true"
            rotated = _parse_timestamp(row.get(f"{slot}_last_rotated", ""))
            if rotated is not None and rotated.tzinfo is None:
                rotated = rotated.replace(tzinfo=now.tzinfo)
            age_days = max((now - rotated).days, 0) if rotated else None
            keys.append(AccessKeyState(user=user, key_slot=slot, active=active, age_days=age_days))
    return keys


@register
class IamAccessKeyStale:
    id = "iam-access-key-stale"
    title = "IAM access keys not rotated recently"
    service = "iam"
    resource_type = "AWS::IAM::AccessKey"
    scope = Scope.GLOBAL
    severity = Severity.MEDIUM
    audit_impact = AuditImpact.EXPECTED
    rationale = (
        "An access key is a long-lived credential with no built-in "
        "expiration -- if it leaks into a script, a log, or a public "
        "repository, it stays valid until someone notices and rotates it. "
        "Regular rotation bounds how long a single leaked key stays useful, "
        "and it is one of the standard items on a security questionnaire's "
        "credential-hygiene section."
    )
    remediation = Remediation(
        summary=(
            "Create a new access key, update whatever uses the old one, "
            "then deactivate and delete the old key."
        ),
        effort=Effort.HOURS,
        console_steps=(
            "IAM console -> Users -> select the user -> Security credentials "
            "tab -> Create access key.",
            "Update every application, script, or CI job that used the old key with the new one.",
            "Once nothing fails using the new key, deactivate the old key "
            "first (reversible), then delete it after a safety window.",
        ),
        cli_commands=(
            "aws iam create-access-key --user-name <USER>",
            "aws iam update-access-key --user-name <USER> --access-key-id "
            "<OLD_KEY_ID> --status Inactive",
            "aws iam delete-access-key --user-name <USER> --access-key-id <OLD_KEY_ID>",
        ),
        monthly_cost_usd=0.0,
        cost_note="Rotation is free.",
        caveats=(
            "Deactivating before confirming the new key works everywhere "
            "avoids an outage; deleting is the irreversible step, so leave a "
            "gap between the two.",
        ),
    )
    required_actions = frozenset({"iam:GenerateCredentialReport", "iam:GetCredentialReport"})

    def run(self, ctx: ScanContext) -> Iterator[Finding]:
        iam = ctx.client()
        rows = fetch_report_rows(iam)
        if rows is None:
            return
        max_age_days = ctx.option("max_key_age_days", DEFAULT_MAX_AGE_DAYS)
        for state in parse_access_keys(rows, ctx.now):
            finding = self._evaluate(ctx, state, max_age_days)
            if finding is not None:
                yield finding

    def _evaluate(
        self, ctx: ScanContext, state: AccessKeyState, max_age_days: int
    ) -> Finding | None:
        if not is_stale(state, max_age_days):
            return None

        return Finding(
            check_id=self.id,
            resource_id=f"{state.user}/{state.key_slot}",
            resource_type=self.resource_type,
            region=ctx.region,
            severity=self.severity,
            audit_impact=self.audit_impact,
            title="IAM access key not rotated recently",
            detail=(
                f"{state.key_slot} for user {state.user!r} is {state.age_days} "
                f"days old (threshold: {max_age_days})"
            ),
            metadata={"age_days": str(state.age_days)},
        )
