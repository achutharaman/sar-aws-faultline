from __future__ import annotations

import json
from pathlib import Path

from sar_aws_faultline.iam import (
    BASELINE_ACTIONS,
    SID,
    build_policy,
    collect_actions,
    mutating_actions,
)
from sar_aws_faultline.registry import all_checks

COMMITTED = Path(__file__).resolve().parents[1] / "docs" / "iam-policy.json"


def test_policy_shape():
    policy = build_policy()
    assert policy["Version"] == "2012-10-17"
    assert policy["Statement"][0]["Sid"] == SID
    assert policy["Statement"][0]["Effect"] == "Allow"


def test_actions_are_sorted_and_deduped():
    actions = collect_actions()
    assert actions == sorted(set(actions))


def test_baseline_actions_are_always_present():
    assert set(collect_actions()) >= BASELINE_ACTIONS


def test_policy_covers_every_check():
    actions = set(collect_actions())
    for check in all_checks():
        assert check.required_actions <= actions, check.id


def test_generated_policy_contains_no_mutating_action():
    """The read-only promise enforced a second time, at the permission
    boundary. A user who follows the README cannot grant this tool write
    access even by accident."""
    assert mutating_actions(collect_actions()) == []


def test_committed_policy_is_current():
    """CI runs the generator and diffs. This gives the same failure locally,
    with a clearer message."""
    assert COMMITTED.is_file(), "docs/iam-policy.json is missing"
    committed = json.loads(COMMITTED.read_text())
    assert committed == build_policy(), (
        "docs/iam-policy.json is stale — run scripts/generate_iam_policy.py"
    )
