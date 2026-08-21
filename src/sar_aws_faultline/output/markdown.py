"""Markdown gap report.

The format meant to be read by a person deciding what to do on Monday morning:
grouped by check, ordered by audit impact, with fix steps, effort, monthly cost
and caveats inline.

The scope note at the top is output, not decoration. A report that could be
mistaken for a compliance attestation is a liability for whoever runs it -- and
the likeliest reader here is a founder who will forward it to a customer.
"""

from __future__ import annotations

from typing import TextIO

from sar_aws_faultline import __version__
from sar_aws_faultline.compliance import load_catalog
from sar_aws_faultline.config import Config
from sar_aws_faultline.models import ScanResult
from sar_aws_faultline.registry import get_check

SCOPE_NOTE = """\
> **What this is.** An automated review of AWS configuration against a curated
> set of security checks, ordered by what to fix first, with each finding mapped
> to control references for context.
>
> **What it is not.** A SOC 2 assessment. AWS configuration is one input to a
> SOC 2 audit; access reviews, onboarding and offboarding, change management,
> vendor management, incident response and written policy are not evaluated here
> and are not visible to any scanner. The control mappings below are one
> practitioner's interpretation, offered as context. They do not assert that any
> control is satisfied.
"""


def _cost(value: float) -> str:
    return "no additional cost" if value == 0 else f"~${value:,.2f}/month"


class MarkdownRenderer:
    name = "markdown"

    def render(self, result: ScanResult, config: Config, stream: TextIO) -> None:
        stream.write(self.document(result))

    def document(self, result: ScanResult) -> str:
        catalog = load_catalog()
        out: list[str] = []

        out.append("# AWS security gap report\n")
        out.append(
            f"- **Account:** `{result.account_id or 'unknown'}`\n"
            f"- **Scanned:** {result.started_at.isoformat(timespec='seconds')}\n"
            f"- **Regions:** {', '.join(result.regions) or 'n/a'}\n"
            f"- **Checks run:** {len(result.checks_run)}\n"
            f"- **Tool:** sar-aws-faultline {__version__}\n"
        )
        out.append(SCOPE_NOTE)

        if result.is_partial:
            out.append(
                f"> **Partial scan.** {len(result.errors)} check(s) could not "
                f"complete. Treat the absence of a finding in those areas as "
                f"unknown, not as a pass.\n"
            )

        grouped = result.by_check()
        if not grouped:
            out.append("## Result\n\nNo gaps found in the checks that ran.\n")
            out.append(self._errors(result))
            out.append(self._notices(result))
            return "\n".join(p for p in out if p)

        out.append(self._summary_table(grouped))

        for i, (check_id, findings) in enumerate(grouped.items(), start=1):
            out.append(self._section(i, check_id, findings, catalog))

        out.append(self._errors(result))
        out.append(self._notices(result))
        return "\n".join(p for p in out if p)

    def _summary_table(self, grouped: dict) -> str:
        rows = [
            "## What to fix, in order\n",
            "| # | Finding | Affected | Severity | Audit impact | Effort | Cost |",
            "|---|---|---|---|---|---|---|",
        ]
        for i, (check_id, findings) in enumerate(grouped.items(), start=1):
            check = get_check(check_id)
            rem = check.remediation
            cost = "$0" if rem.monthly_cost_usd == 0 else f"~${rem.monthly_cost_usd:,.0f}/mo"
            rows.append(
                f"| {i} | {check.title} | {len(findings)} | "
                f"{findings[0].severity.value} | {findings[0].audit_impact.value} | "
                f"{rem.effort.value} | {cost} |"
            )
        return "\n".join(rows) + "\n\n---\n"

    def _section(self, index: int, check_id: str, findings: list, catalog) -> str:
        check = get_check(check_id)
        rem = check.remediation
        out = [
            f"## {index}. {check.title}\n",
            f"`{check.id}` · **{findings[0].severity.value}** severity · "
            f"**{findings[0].audit_impact.value}** for audit purposes\n",
            f"{check.rationale}\n",
            "### Affected resources\n",
        ]
        for f in findings:
            out.append(f"- `{f.resource_id}` _({f.region})_ — {f.detail}")
        out.append("")

        out.append("### How to fix\n")
        out.append(f"{rem.summary}\n")
        cost_line = (
            f"**Effort:** {rem.effort.value} · **Cost of fixing:** {_cost(rem.monthly_cost_usd)}"
        )
        if rem.cost_note:
            cost_line += f" ({rem.cost_note})"
        out.append(cost_line + "\n")

        if rem.console_steps:
            out.append("**Console**\n")
            out.extend(f"{n}. {step}" for n, step in enumerate(rem.console_steps, 1))
            out.append("")
        if rem.cli_commands:
            out.append("**CLI**\n")
            out.append("```bash\n" + "\n".join(rem.cli_commands) + "\n```\n")
        if rem.caveats:
            out.append("**Before you do this**\n")
            out.extend(f"- {c}" for c in rem.caveats)
            out.append("")

        refs = catalog.for_check(check_id)
        if refs:
            out.append("### Control references\n")
            for ref in refs:
                fw, control = catalog.describe(ref)
                via = f" _(reasoned from {ref.derived_from})_" if ref.derived_from else ""
                out.append(
                    f"- **{fw.name} {fw.version} — {ref.control}**: {control.title}\n"
                    f"  - Relationship: `{ref.relationship.value}`{via}\n"
                    f"  - {' '.join(ref.rationale.split())}"
                )
            out.append("")

        out.append("---\n")
        return "\n".join(out)

    def _errors(self, result: ScanResult) -> str:
        if not result.errors:
            return ""
        rows = [
            "## Checks that could not run\n",
            "These areas were not evaluated. Absence of a finding here means nothing.\n",
            "| Check | Region | Error |",
            "|---|---|---|",
        ]
        rows.extend(f"| `{e.check_id}` | {e.region} | {e.error_code} |" for e in result.errors)
        return "\n".join(rows) + "\n"

    def _notices(self, result: ScanResult) -> str:
        catalog = load_catalog()
        used = sorted(
            {ref.framework for f in result.findings for ref in catalog.for_check(f.check_id)}
        )
        if not used:
            return ""
        lines = ["## Framework notices\n"]
        for fid in used:
            fw = catalog.frameworks[fid]
            lines.append(f"- **{fw.name}** — {' '.join(fw.notice.split())} <{fw.url}>")
        return "\n".join(lines) + "\n"
