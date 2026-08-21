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

        if result.findings:
            console.print(self._table(result))
        else:
            console.print("[green]No gaps found in the checks that ran.[/green]")

        self._summary(console, result)

    def _table(self, result: ScanResult) -> Table:
        table = Table(
            title=f"sar-aws-faultline — account {result.account_id or 'unknown'}",
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
