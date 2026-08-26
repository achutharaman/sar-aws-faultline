"""Compliance framework catalogues and check-to-control mappings.

Design notes
------------

*Data, not code.* Mappings live in TOML under ``data/``. Adding a framework is
adding a file. The data is reviewable by someone who reads controls but does
not read Python, and diffs are legible in review. TOML rather than YAML because
``tomllib`` is stdlib on 3.11+, which keeps the runtime dependency set to just
boto3, typer and rich -- nothing else.

*Two hops, with different confidence.* Mapping a check to a CIS AWS Foundations
recommendation is objective: the recommendation is numbered, prescriptive and
testable. Mapping that to a SOC 2 Trust Services Criterion is interpretive --
the TSC are principles-based and there is no authoritative
AWS-configuration-to-TSC mapping. Frameworks declare which they are via
``interpretive``, and an interpretive mapping must record ``derived_from`` so a
reader can audit the inference instead of taking it on trust.

*No "satisfies".* ``Relationship`` has exactly two members and neither claims
compliance. This is the overclaiming problem solved by the type system rather
than by a disclaimer nobody reads.

*No licensed text.* AICPA Trust Services Criteria text is copyrighted, and CIS
publishes its benchmarks under a restrictive licence. This repository stores
control identifiers and short paraphrased titles only.
"""

from __future__ import annotations

import tomllib
from collections.abc import Iterator
from dataclasses import dataclass, field
from enum import StrEnum
from functools import lru_cache
from importlib import resources

FRAMEWORK_DIR = "data/frameworks"
MAPPING_DIR = "data/mappings"


class Relationship(StrEnum):
    """How a check relates to a control. Note what is absent.

    There is deliberately no ``SATISFIES``. A configuration scanner cannot
    establish that a control is met -- it can only produce one input to that
    judgement. Adding a third member here would be a product decision, not a
    refactor, and ``test_compliance.py`` fails if anyone tries.
    """

    SUPPORTS = "supports"
    """Evidence directly relevant to the control."""

    PARTIALLY_SUPPORTS = "partially_supports"
    """Evidence relevant to one aspect; the control requires more."""


class MappingDataError(ValueError):
    """The shipped mapping data is malformed or internally inconsistent."""


@dataclass(frozen=True, slots=True)
class Control:
    id: str
    title: str
    """Short paraphrase. Never the verbatim text of a licensed standard."""


@dataclass(frozen=True, slots=True)
class Framework:
    id: str
    name: str
    version: str
    authority: str
    url: str
    interpretive: bool
    """False when mapping to this framework is objective -- numbered, testable
    recommendations. True when it requires judgement."""

    notice: str
    """Copyright and licence notice, surfaced in any report citing it."""

    controls: tuple[Control, ...]

    @property
    def control_ids(self) -> frozenset[str]:
        return frozenset(c.id for c in self.controls)

    def control(self, control_id: str) -> Control:
        for c in self.controls:
            if c.id == control_id:
                return c
        raise KeyError(f"{self.id} has no control {control_id!r}")


@dataclass(frozen=True, slots=True)
class ControlRef:
    framework: str
    control: str
    relationship: Relationship
    rationale: str
    """Why this check bears on this control. Required -- an unexplained mapping
    is an assertion, not evidence."""

    derived_from: str = ""
    """For interpretive frameworks, the objective control this was reasoned
    from, as ``<framework>:<control>``. Makes the second hop inspectable."""


@dataclass(frozen=True, slots=True)
class Catalog:
    frameworks: dict[str, Framework] = field(default_factory=dict)
    mappings: dict[str, tuple[ControlRef, ...]] = field(default_factory=dict)

    def for_check(self, check_id: str) -> tuple[ControlRef, ...]:
        return self.mappings.get(check_id, ())

    def checks_for_framework(self, framework_id: str) -> set[str]:
        return {
            check_id
            for check_id, refs in self.mappings.items()
            if any(r.framework == framework_id for r in refs)
        }

    def frameworks_for_check(self, check_id: str) -> list[str]:
        return sorted({r.framework for r in self.for_check(check_id)})

    def describe(self, ref: ControlRef) -> tuple[Framework, Control]:
        try:
            fw = self.frameworks[ref.framework]
        except KeyError:
            raise MappingDataError(f"unknown framework {ref.framework!r}") from None
        return fw, fw.control(ref.control)


def _read_toml_dir(subdir: str) -> Iterator[dict]:
    root = resources.files("sar_aws_faultline").joinpath(subdir)
    for entry in sorted(root.iterdir(), key=lambda p: p.name):
        if entry.name.endswith(".toml"):
            yield tomllib.loads(entry.read_text(encoding="utf-8"))


def _parse_framework(raw: dict) -> Framework:
    try:
        return Framework(
            id=raw["id"],
            name=raw["name"],
            version=str(raw["version"]),
            authority=raw["authority"],
            url=raw["url"],
            interpretive=bool(raw["interpretive"]),
            notice=raw["notice"],
            controls=tuple(
                Control(id=str(c["id"]), title=c["title"]) for c in raw.get("controls", [])
            ),
        )
    except KeyError as exc:
        raise MappingDataError(f"framework file missing field {exc}") from None


def _parse_refs(raw: dict) -> tuple[str, tuple[ControlRef, ...]]:
    try:
        check_id = raw["check"]
        refs = tuple(
            ControlRef(
                framework=c["framework"],
                control=str(c["control"]),
                relationship=Relationship(c["relationship"]),
                rationale=c["rationale"],
                derived_from=c.get("derived_from", ""),
            )
            for c in raw.get("controls", [])
        )
    except KeyError as exc:
        raise MappingDataError(f"mapping entry missing field {exc}") from None
    except ValueError as exc:
        raise MappingDataError(f"mapping entry has an invalid relationship: {exc}") from None
    return check_id, refs


@lru_cache(maxsize=1)
def load_catalog() -> Catalog:
    """Load and cross-validate the shipped mapping data.

    Validation is here rather than only in tests because a malformed mapping
    file shipped in a wheel should fail loudly on first use, not render a
    report with a silently missing control reference.
    """
    frameworks: dict[str, Framework] = {}
    for raw in _read_toml_dir(FRAMEWORK_DIR):
        fw = _parse_framework(raw)
        if fw.id in frameworks:
            raise MappingDataError(f"duplicate framework id {fw.id!r}")
        frameworks[fw.id] = fw

    mappings: dict[str, tuple[ControlRef, ...]] = {}
    for raw in _read_toml_dir(MAPPING_DIR):
        for entry in raw.get("mappings", []):
            check_id, refs = _parse_refs(entry)
            if check_id in mappings:
                raise MappingDataError(f"duplicate mapping for check {check_id!r}")
            for ref in refs:
                if ref.framework not in frameworks:
                    raise MappingDataError(
                        f"{check_id} references unknown framework {ref.framework!r}"
                    )
                if ref.control not in frameworks[ref.framework].control_ids:
                    raise MappingDataError(
                        f"{check_id} references {ref.framework}:{ref.control}, "
                        f"which is not in that framework's catalogue"
                    )
                if frameworks[ref.framework].interpretive and not ref.derived_from:
                    raise MappingDataError(
                        f"{check_id} -> {ref.framework}:{ref.control} is an "
                        f"interpretive mapping and must declare derived_from"
                    )
            mappings[check_id] = refs

    return Catalog(frameworks=frameworks, mappings=mappings)
