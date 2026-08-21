"""Command-line interface.

Deliberately thin. Every command here parses flags, builds a Config, calls into
the library, and renders. No detection logic lives in this file, which is what
lets the package be imported and driven from a Lambda or a notebook without
Typer being involved at all.
"""

from __future__ import annotations

import json as _json
import logging
import sys
from pathlib import Path
from typing import Annotated

import typer

from sar_aws_faultline import __version__
from sar_aws_faultline.compliance import load_catalog
from sar_aws_faultline.config import (
    Config,
    ExitCode,
    FailOn,
    OutputFormat,
    load_config,
    resolve_exit_code,
)
from sar_aws_faultline.iam import build_policy
from sar_aws_faultline.models import AuditImpact, Severity
from sar_aws_faultline.output.base import get_renderer
from sar_aws_faultline.registry import all_checks, select_checks
from sar_aws_faultline.runner import run_scan
from sar_aws_faultline.session import ClientFactory

app = typer.Typer(
    name="sar-aws-faultline",
    help=(
        "Find the security gaps in your AWS account, ranked by what to fix "
        "first. Read-only: reports, never changes anything."
    ),
    no_args_is_help=True,
    add_completion=False,
)


def _configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )


def _resolve_regions(config: Config, factory: ClientFactory) -> list[str]:
    if config.all_regions:
        return factory.available_regions()
    if config.regions:
        return list(config.regions)
    if default := factory.default_region():
        return [default]
    raise typer.BadParameter(
        "no region specified and no default found. Pass --region, or --all-regions, "
        "or set AWS_REGION / a region in your AWS profile."
    )


@app.command()
def scan(
    region: Annotated[
        list[str] | None, typer.Option("--region", "-r", help="Region to scan. Repeatable.")
    ] = None,
    all_regions: Annotated[
        bool, typer.Option("--all-regions", help="Scan every region enabled on the account.")
    ] = False,
    profile: Annotated[str | None, typer.Option("--profile", help="AWS profile name.")] = None,
    check: Annotated[
        list[str] | None,
        typer.Option("--check", "-c", help="Run only these check ids. Repeatable."),
    ] = None,
    skip: Annotated[
        list[str] | None, typer.Option("--skip", help="Skip these check ids. Repeatable.")
    ] = None,
    severity: Annotated[
        Severity | None,
        typer.Option("--severity", help="Only run checks at or above this severity."),
    ] = None,
    impact: Annotated[
        list[AuditImpact] | None,
        typer.Option("--impact", help="Only run checks with this audit impact. Repeatable."),
    ] = None,
    framework: Annotated[
        str | None,
        typer.Option("--framework", help="Only run checks mapped to this framework."),
    ] = None,
    output: Annotated[
        OutputFormat | None,
        typer.Option("--output", "-o", help="Output format. [default: table]"),
    ] = None,
    fail_on: Annotated[
        FailOn | None,
        typer.Option("--fail-on", help="What makes this exit 1. [default: none]"),
    ] = None,
    config_file: Annotated[
        Path | None, typer.Option("--config", help="Path to sar-aws-faultline.toml.")
    ] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Debug logging.")] = False,
) -> None:
    """Scan an AWS account for security gaps. Makes no changes."""
    _configure_logging(verbose)

    config = load_config(
        config_file,
        regions=tuple(region or ()),
        all_regions=all_regions or None,
        profile=profile,
        output=output,
        fail_on=fail_on,
        checks=tuple(check or ()),
        skip=tuple(skip or ()),
        min_severity=severity,
        impacts=tuple(impact or ()),
        framework=framework,
    )

    try:
        selected = select_checks(
            config.checks,
            skip=config.skip,
            min_severity=config.min_severity,
            impacts=config.impacts,
            framework=config.framework,
        )
    except KeyError as exc:
        typer.echo(str(exc).strip("'"), err=True)
        raise typer.Exit(ExitCode.USAGE) from None

    if not selected:
        typer.echo("no checks matched the given filters", err=True)
        raise typer.Exit(ExitCode.USAGE)

    factory = ClientFactory(profile=config.profile)
    regions = _resolve_regions(config, factory)

    result = run_scan(
        selected,
        regions,
        factory=factory,
        config=config,
        account_id=factory.account_id(),
    )

    get_renderer(config.output).render(result, config, sys.stdout)
    raise typer.Exit(resolve_exit_code(result, config))


@app.command(name="checks")
def list_checks(
    output: Annotated[
        OutputFormat | None, typer.Option("--output", "-o", help="table or json.")
    ] = None,
) -> None:
    """List available checks and what they map to."""
    catalog = load_catalog()
    checks = all_checks()

    if output is OutputFormat.JSON:
        typer.echo(
            _json.dumps(
                [
                    {
                        "id": c.id,
                        "title": c.title,
                        "service": c.service,
                        "resource_type": c.resource_type,
                        "scope": c.scope.value,
                        "severity": c.severity.value,
                        "audit_impact": c.audit_impact.value,
                        "effort": c.remediation.effort.value,
                        "monthly_cost_usd": c.remediation.monthly_cost_usd,
                        "required_actions": sorted(c.required_actions),
                        "frameworks": catalog.frameworks_for_check(c.id),
                    }
                    for c in checks
                ],
                indent=2,
            )
        )
        return

    from rich.console import Console
    from rich.table import Table

    # Fixed width: check ids are public API and must never be truncated by a
    # narrow terminal, which is exactly what a bare Console() would do in CI.
    console = Console(width=140)
    table = Table(header_style="bold")
    for col in ("ID", "Service", "Severity", "Impact", "Effort", "Cost/mo", "Title"):
        table.add_column(col)
    for c in checks:
        rem = c.remediation
        table.add_row(
            c.id,
            c.service,
            c.severity.value,
            c.audit_impact.value,
            rem.effort.value,
            "$0" if rem.monthly_cost_usd == 0 else f"${rem.monthly_cost_usd:,.0f}",
            c.title,
        )
    console.print(table)
    console.print(f"\n[dim]{len(checks)} check(s).[/dim]")


@app.command()
def frameworks() -> None:
    """List the compliance frameworks findings can be mapped to."""
    from rich.console import Console

    catalog = load_catalog()
    console = Console(width=140)
    for fw in catalog.frameworks.values():
        kind = "interpretive" if fw.interpretive else "objective"
        mapped = len(catalog.checks_for_framework(fw.id))
        console.print(f"[bold]{fw.id}[/bold]  {fw.name} {fw.version}")
        console.print(f"  mapping type: {kind} · checks mapped: {mapped} · {fw.url}")
        console.print(f"  [dim]{' '.join(fw.notice.split())}[/dim]\n")


@app.command(name="iam-policy")
def iam_policy() -> None:
    """Print the least-privilege IAM policy this tool needs.

    Generated from the check registry, so it cannot drift from the API calls
    the code actually makes.
    """
    typer.echo(_json.dumps(build_policy(), indent=2))


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"sar-aws-faultline {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool, typer.Option("--version", callback=_version_callback, is_eager=True)
    ] = False,
) -> None:
    pass
