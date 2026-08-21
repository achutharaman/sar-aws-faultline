#!/usr/bin/env python3
"""Regenerate docs/iam-policy.json from the check registry.

Run after adding or changing a check. CI diffs the result, so a check that
declares a new IAM action but never regenerates the policy fails the build --
which is what keeps the README's policy from advertising permissions that do
not actually work.
"""

from __future__ import annotations

import json
from pathlib import Path

from sar_aws_faultline.iam import build_policy, collect_actions, mutating_actions

OUTPUT = Path(__file__).resolve().parents[1] / "docs" / "iam-policy.json"


def main() -> int:
    actions = collect_actions()
    if offenders := mutating_actions(actions):
        raise SystemExit(
            f"refusing to generate a policy containing mutating actions: {offenders}. "
            f"sar-aws-faultline is read-only."
        )
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(build_policy(), indent=2) + "\n", encoding="utf-8")
    print(f"wrote {OUTPUT} ({len(actions)} actions)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
