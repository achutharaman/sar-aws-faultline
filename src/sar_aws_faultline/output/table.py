"""Default terminal output.

Ordered by audit impact first, then severity. The ordering is the product: a
generic scanner sorts by severity and leaves triage to the reader, and that is
precisely the step a three-person team does not have time for.
"""

from __future__ import annotations

from typing import TextIO

from rich.console import Console
from rich.table import Table

from sar_aws_faultline.config import Config
from sar_aws_faultline.models import ScanResult
from sar_aws_faultline.registry import get_check

SEVERITY_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}

IMPACT_STYLE = {
    "blocker": "bold red",
    "expected": "yellow",
    "hardening": "dim",
}

SCOPE_NOTE = (
    "Checks AWS configuration only, which is one part of a SOC 2 audit. "
    "Not a compliance assessment."
)


class TableRenderer:
    name = "table"

    def render(self, result: ScanResult, config: Config, stream: TextIO) -> None:
        console = Console(file=stream, width=120)

        console.print(f"sar-aws-faultline — account {result.account_id or 'unknown'}\n")
        console.print(self._status_table(result))
        console.print()

        if result.findings:
            console.print(self._table(result))
        else:
            console.print("[green]No gaps found in the checks that ran.[/green]")

        self._summary(console, result)

    def _status_table(self, result: ScanResult) -> Table:
        """One row per check that ran, regardless of outcome.

        The findings table below only lists rows for gaps, which leaves a
        clean check indistinguishable from one nobody looked at. This is
        what answers "did every check actually run, and how did it go" --
        ok, issue, error, or partial (some regions errored, others didn't).
        """
        table = Table(title="Checks run", title_justify="left", header_style="bold")
        table.add_column("Check")
        table.add_column("Status", width=9)
        table.add_column("Detail", overflow="fold")

        findings_by_check = result.by_check()
        errors_by_check: dict[str, list] = {}
        for e in result.errors:
            errors_by_check.setdefault(e.check_id, []).append(e)

        for check_id in sorted(result.checks_run):
            findings = findings_by_check.get(check_id, [])
            errors = errors_by_check.get(check_id, [])

            detail_parts = []
            if findings:
                detail_parts.append(f"{len(findings)} finding(s)")
            if errors:
                regions = ", ".join(e.region for e in errors)
                detail_parts.append(f"could not check: {regions}")
            detail = "; ".join(detail_parts) or "clean"

            if errors and findings:
                status, style = "partial", "yellow"
            elif errors:
                status, style = "error", "bold red"
            elif findings:
                worst = min(findings, key=lambda f: f.sort_key).audit_impact.value
                status, style = "issue", IMPACT_STYLE.get(worst, "yellow")
            else:
                status, style = "ok", "green"

            table.add_row(check_id, f"[{style}]{status}[/{style}]", detail)

        return table

    def _table(self, result: ScanResult) -> Table:
        table = Table(
            title="Findings, in order",
            title_justify="left",
            header_style="bold",
        )
        table.add_column("#", justify="right", width=3)
        table.add_column("Impact", width=9)
        table.add_column("Severity", width=8)
        table.add_column("Region", width=12)
        table.add_column("Resource", overflow="fold")
        table.add_column("Finding", overflow="fold")
        table.add_column("Fix", width=8)

        for i, f in enumerate(result.sorted_findings(), start=1):
            rem = get_check(f.check_id).remediation
            table.add_row(
                str(i),
                f"[{IMPACT_STYLE.get(f.audit_impact.value, 'dim')}]{f.audit_impact.value}[/]",
                f"[{SEVERITY_STYLE.get(f.severity.value, 'dim')}]{f.severity.value}[/]",
                f.region,
                f.resource_id,
                f"{f.title}\n[dim]{f.detail}[/dim]",
                rem.effort.value,
            )
        return table

    def _summary(self, console: Console, result: ScanResult) -> None:
        console.print(
            f"\n[dim]{len(result.checks_run)} check(s) across "
            f"{len(result.regions)} region(s) in {result.duration_seconds:.1f}s — "
            f"{len(result.findings)} gap(s), {result.blocker_count} blocker(s).[/dim]"
        )

        if result.is_partial:
            console.print(
                f"\n[bold yellow]Partial scan:[/bold yellow] "
                f"{len(result.errors)} check(s) could not run. This is not a "
                f"clean bill of health — it means we could not look."
            )
            for e in result.errors[:5]:
                console.print(f"  [dim]{e.check_id} ({e.region}): {e.error_code}[/dim]")

        if result.findings:
            console.print(
                "[dim]Run with --output markdown for fix steps, effort and monthly cost.[/dim]"
            )

        console.print(f"\n[dim]{SCOPE_NOTE}[/dim]")
