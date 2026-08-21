"""Configuration resolution.

Precedence, highest wins: CLI flags > environment (``SAR_AWS_FAULTLINE_*``) >
config file > defaults. Per-check settings live in a nested table keyed by check
id, so a new check can add tunables without this module changing.

TOML via stdlib ``tomllib`` (3.11+), which is why there is no YAML dependency --
the same reasoning that keeps the compliance mapping data in TOML.
"""

from __future__ import annotations

import os
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from enum import StrEnum
from pathlib import Path
from typing import Any

from sar_aws_faultline.models import AuditImpact, Severity

CONFIG_FILENAMES = ("sar-aws-faultline.toml", ".sar-aws-faultline.toml")
ENV_PREFIX = "SAR_AWS_FAULTLINE_"


class OutputFormat(StrEnum):
    TABLE = "table"
    JSON = "json"
    MARKDOWN = "markdown"


class FailOn(StrEnum):
    """What makes ``sar-aws-faultline scan`` exit non-zero."""

    NONE = "none"
    """Only infrastructure errors fail. Findings are informational."""

    ANY = "any"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    BLOCKER = "blocker"
    """Fail on anything an auditor would stop at, regardless of severity.

    This is the threshold most CI pipelines actually want, and it has no
    equivalent in a severity-only tool."""


class ExitCode:
    """Exit codes are an interface. Changing them is a breaking change."""

    CLEAN = 0
    FINDINGS = 1
    ERRORS = 2
    USAGE = 3


def _default_cache_dir() -> Path:
    base = os.environ.get("XDG_CACHE_HOME")
    root = Path(base) if base else Path.home() / ".cache"
    return root / "sar-aws-faultline"


@dataclass(frozen=True, slots=True)
class Config:
    regions: tuple[str, ...] = ()
    all_regions: bool = False
    profile: str | None = None
    output: OutputFormat = OutputFormat.TABLE
    fail_on: FailOn = FailOn.NONE
    max_workers: int = 8
    cache_dir: Path = field(default_factory=_default_cache_dir)
    checks: tuple[str, ...] = ()
    skip: tuple[str, ...] = ()
    min_severity: Severity | None = None
    impacts: tuple[AuditImpact, ...] = ()
    framework: str | None = None
    options: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)

    def option(self, check_id: str, key: str, default: Any) -> Any:
        """Per-check tunable with a fallback.

        Checks call this instead of reading config attributes directly, which is
        what keeps ``Config`` from growing a field for every new check.
        """
        value = self.options.get(check_id, {}).get(key, default)
        if isinstance(default, int) and not isinstance(default, bool) and value is not None:
            return int(value)
        return value


def find_config_file(start: Path | None = None) -> Path | None:
    """Nearest config file, walking up from the working directory."""
    current = (start or Path.cwd()).resolve()
    for directory in (current, *current.parents):
        for name in CONFIG_FILENAMES:
            candidate = directory / name
            if candidate.is_file():
                return candidate
    return None


def _from_file(path: Path) -> dict[str, Any]:
    with path.open("rb") as handle:
        raw = tomllib.load(handle)
    data: dict[str, Any] = {}
    if regions := raw.get("regions"):
        data["regions"] = tuple(regions)
    for key in ("all_regions", "profile", "max_workers", "framework"):
        if key in raw:
            data[key] = raw[key]
    if "output" in raw:
        data["output"] = OutputFormat(raw["output"])
    if "fail_on" in raw:
        data["fail_on"] = FailOn(raw["fail_on"])
    if "min_severity" in raw:
        data["min_severity"] = Severity(raw["min_severity"])
    if checks := raw.get("checks"):
        data["checks"] = tuple(checks)
    if skip := raw.get("skip"):
        data["skip"] = tuple(skip)
    if impacts := raw.get("impacts"):
        data["impacts"] = tuple(AuditImpact(i) for i in impacts)
    if options := raw.get("check"):
        data["options"] = options
    return data


def _from_env() -> dict[str, Any]:
    data: dict[str, Any] = {}
    if profile := os.environ.get(f"{ENV_PREFIX}PROFILE"):
        data["profile"] = profile
    if regions := os.environ.get(f"{ENV_PREFIX}REGIONS"):
        data["regions"] = tuple(r.strip() for r in regions.split(",") if r.strip())
    if output := os.environ.get(f"{ENV_PREFIX}OUTPUT"):
        data["output"] = OutputFormat(output)
    if fail_on := os.environ.get(f"{ENV_PREFIX}FAIL_ON"):
        data["fail_on"] = FailOn(fail_on)
    if framework := os.environ.get(f"{ENV_PREFIX}FRAMEWORK"):
        data["framework"] = framework
    return data


def load_config(path: Path | None = None, **overrides: Any) -> Config:
    """Resolve defaults, file, environment and explicit overrides in order."""
    config = Config()

    resolved = path or find_config_file()
    if resolved is not None:
        config = replace(config, **_from_file(resolved))

    config = replace(config, **_from_env())

    explicit = {k: v for k, v in overrides.items() if v is not None and v != () and v != ""}
    return replace(config, **explicit) if explicit else config


def resolve_exit_code(result, config: Config) -> int:
    """Map a scan result onto a process exit code.

    Errors outrank findings deliberately. "I could not look at three of your
    checks" and "you have two problems" are different messages, and a pipeline
    that treats a permissions failure as a clean pass is worse than no scan.
    """
    from sar_aws_faultline.models import AuditImpact as _Impact

    if result.errors:
        return ExitCode.ERRORS
    if config.fail_on is FailOn.NONE or not result.findings:
        return ExitCode.CLEAN
    if config.fail_on is FailOn.ANY:
        return ExitCode.FINDINGS
    if config.fail_on is FailOn.BLOCKER:
        return (
            ExitCode.FINDINGS
            if any(f.audit_impact is _Impact.BLOCKER for f in result.findings)
            else ExitCode.CLEAN
        )

    threshold = Severity(config.fail_on.value)
    if any(f.severity.rank >= threshold.rank for f in result.findings):
        return ExitCode.FINDINGS
    return ExitCode.CLEAN
