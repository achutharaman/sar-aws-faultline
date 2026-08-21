"""Generate the least-privilege IAM policy from the registry.

The policy is derived from ``Check.required_actions``, never hand-written. CI
asserts the committed ``docs/iam-policy.json`` still matches what the code
calls, so the policy in the README cannot drift away from reality -- and a new
check that forgets to declare its permissions fails the build.

A second test asserts the generated policy contains no mutating action. The
read-only promise is enforced twice: once at runtime by the botocore guard in
session.py, and once here at the permission boundary, so a user who follows the
README cannot grant this tool write access even by mistake.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from sar_aws_faultline.registry import Check, all_checks

POLICY_VERSION = "2012-10-17"
SID = "SarAwsFaultlineReadOnlyScan"

# Needed by the runner itself rather than by any single check: account id for
# the report header, and enabled-region discovery for --all-regions.
BASELINE_ACTIONS = frozenset({"sts:GetCallerIdentity", "ec2:DescribeRegions"})

# Verbs that can change state. Used to assert the generated policy stays read
# only; see tests/test_iam_policy.py.
MUTATING_VERBS = (
    "Create",
    "Delete",
    "Put",
    "Update",
    "Modify",
    "Attach",
    "Detach",
    "Remove",
    "Add",
    "Set",
    "Enable",
    "Disable",
    "Start",
    "Stop",
    "Terminate",
    "Reboot",
    "Run",
    "Associate",
    "Disassociate",
    "Tag",
    "Untag",
    "Revoke",
    "Authorize",
    "Copy",
    "Restore",
    "Cancel",
    "Accept",
    "Reject",
    "Replace",
    "Register",
    "Deregister",
    "Import",
    "Upload",
)


def collect_actions(checks: Sequence[type[Check]] | None = None) -> list[str]:
    selected = list(checks) if checks is not None else all_checks()
    actions = set(BASELINE_ACTIONS)
    for check in selected:
        actions |= set(check.required_actions)
    return sorted(actions)


def build_policy(checks: Sequence[type[Check]] | None = None) -> dict[str, Any]:
    return {
        "Version": POLICY_VERSION,
        "Statement": [
            {
                "Sid": SID,
                "Effect": "Allow",
                "Action": collect_actions(checks),
                "Resource": "*",
            }
        ],
    }


def mutating_actions(actions: Sequence[str]) -> list[str]:
    """Any action whose verb could change state. Should always be empty."""
    found = []
    for action in actions:
        _, _, verb = action.partition(":")
        if verb.startswith(MUTATING_VERBS):
            found.append(action)
    return found
