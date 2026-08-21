"""Renderer protocol and lookup.

Renderers receive a finished ScanResult and a stream. They never talk to AWS and
never decide what is a finding, which is what makes adding a new output format
(csv, sarif, html, ASFF) a matter of adding one class here.
"""

from __future__ import annotations

from typing import Protocol, TextIO, runtime_checkable

from sar_aws_faultline.config import Config, OutputFormat
from sar_aws_faultline.models import ScanResult


@runtime_checkable
class Renderer(Protocol):
    name: str

    def render(self, result: ScanResult, config: Config, stream: TextIO) -> None: ...


def get_renderer(fmt: OutputFormat) -> Renderer:
    from sar_aws_faultline.output.json_output import JsonRenderer
    from sar_aws_faultline.output.markdown import MarkdownRenderer
    from sar_aws_faultline.output.table import TableRenderer

    if fmt is OutputFormat.JSON:
        return JsonRenderer()
    if fmt is OutputFormat.MARKDOWN:
        return MarkdownRenderer()
    return TableRenderer()
