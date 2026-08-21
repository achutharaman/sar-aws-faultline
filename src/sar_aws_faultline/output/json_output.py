"""Machine-readable output.

Deliberately not ASFF or OCSF in v1. Both are aggregation formats designed for
ingestion into Security Hub or a SIEM, and neither carries the remediation cost
and audit-impact fields that are the point of this tool. An ASFF exporter is a
reasonable later addition as a second renderer -- which is exactly why the
renderer seam exists.
"""

from __future__ import annotations

import json
from typing import Any, TextIO

from sar_aws_faultline import __version__
from sar_aws_faultline.compliance import load_catalog
from sar_aws_faultline.config import Config
from sar_aws_faultline.models import SCHEMA_VERSION, ScanResult
from sar_aws_faultline.registry import get_check


class JsonRenderer:
    name = "json"

    def render(self, result: ScanResult, config: Config, stream: TextIO) -> None:
        json.dump(self.payload(result), stream, indent=2, default=str)
        stream.write("\n")

    def payload(self, result: ScanResult) -> dict[str, Any]:
        catalog = load_catalog()
        return {
            "schema_version": SCHEMA_VERSION,
            "tool": {"name": "sar-aws-faultline", "version": __version__},
            "scan": {
                "account_id": result.account_id,
                "regions": list(result.regions),
                "checks_run": list(result.checks_run),
                "started_at": result.started_at.isoformat(),
                "duration_seconds": result.duration_seconds,
                "partial": result.is_partial,
            },
            "summary": {
                "findings": len(result.findings),
                "blockers": result.blocker_count,
                "errors": len(result.errors),
            },
            "findings": [
                {
                    "check_id": f.check_id,
                    "resource_id": f.resource_id,
                    "resource_type": f.resource_type,
                    "region": f.region,
                    "severity": f.severity.value,
                    "audit_impact": f.audit_impact.value,
                    "title": f.title,
                    "detail": f.detail,
                    "metadata": dict(f.metadata),
                    "remediation": self._remediation(f.check_id),
                    "controls": [
                        {
                            "framework": r.framework,
                            "control": r.control,
                            "relationship": r.relationship.value,
                            "derived_from": r.derived_from or None,
                            "rationale": " ".join(r.rationale.split()),
                        }
                        for r in catalog.for_check(f.check_id)
                    ],
                }
                for f in result.sorted_findings()
            ],
            "errors": [
                {
                    "check_id": e.check_id,
                    "region": e.region,
                    "error_code": e.error_code,
                    "message": e.message,
                }
                for e in result.errors
            ],
            "disclaimer": (
                "This tool inspects AWS configuration only, which is one input "
                "to a SOC 2 audit. Control mappings are interpretive and do not "
                "assert that any control is satisfied."
            ),
        }

    @staticmethod
    def _remediation(check_id: str) -> dict[str, Any]:
        rem = get_check(check_id).remediation
        return {
            "summary": rem.summary,
            "effort": rem.effort.value,
            "monthly_cost_usd": rem.monthly_cost_usd,
            "cost_note": rem.cost_note,
            "console_steps": list(rem.console_steps),
            "cli_commands": list(rem.cli_commands),
            "caveats": list(rem.caveats),
        }
