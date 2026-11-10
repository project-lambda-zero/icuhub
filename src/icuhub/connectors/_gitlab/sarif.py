"""Build and parse the SARIF payload published to GitLab security report artifacts."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from icuhub.connectors._gitlab.models import VendorResult
from icuhub.kit.errors import VendorContractError
from icuhub_schemas.ocsf import VulnerabilityFinding
from icuhub_schemas.sarif import (
    Run,
    SarifLog,
    Tool,
    ToolComponent,
    dump_sarif,
    findings_to_sarif,
    parse_sarif,
)

__all__ = ["build_publish_sarif", "parse_publish_sarif"]

_TOOL_NAME = "ICUHUB GitLab"


def build_publish_sarif(
    findings: Sequence[VulnerabilityFinding],
    *,
    tool_version: str | None,
    max_results: int,
) -> VendorResult:
    """Build the SARIF document for a set of mapped findings.

    Findings without a code location produce no SARIF result and are reported in ``dropped``;
    the result is then ``partial``.

    Raises:
        VendorContractError: the document would exceed ``max_results`` results. Results are never
            truncated silently.
    """

    conversion = findings_to_sarif(list(findings), tool_name=_TOOL_NAME, tool_version=tool_version)
    results = [result for run in conversion.log.runs for result in run.results or []]
    if len(results) > max_results:
        raise VendorContractError(f"SARIF document has {len(results)} results; the limit is {max_results}")
    log = SarifLog(
        runs=[Run(tool=Tool(driver=ToolComponent(name=_TOOL_NAME, version=tool_version)), results=results)]
    )
    dropped = [
        {"uid": finding.finding_info.uid, "reason": "no code location"} for finding in conversion.skipped
    ]
    return VendorResult(
        data=dump_sarif(log),
        coverage="partial" if dropped else "complete",
        dropped=dropped,
    )


def parse_publish_sarif(
    data: bytes | str | Mapping[str, Any],
    *,
    max_bytes: int,
    max_runs: int,
    max_results_per_run: int,
) -> VendorResult:
    """Parse and validate a SARIF artifact, retaining results that carry a ``ruleId`` and a ``physicalLocation``.

    Results without a ``ruleId`` or without a ``physicalLocation`` cannot be published as located findings and are
    reported in ``dropped``; the result is then ``partial``.

    Over-limit artifacts are refused rather than truncated. GitLab truncates runs and results beyond its caps and
    emits a warning; this connector fails closed on the same breach so a publication never silently covers a subset
    of the scan.

    Raises:
        VendorContractError: the artifact exceeds ``max_bytes``, or has more than ``max_runs`` runs
            or more than ``max_results_per_run`` results in one run.
        SarifValidationError: the document violates the SARIF 2.1.0 schema.
    """

    if isinstance(data, (bytes, str)):
        size = len(data) if isinstance(data, bytes) else len(data.encode("utf-8"))
        if size > max_bytes:
            raise VendorContractError(f"SARIF artifact is {size} bytes; the limit is {max_bytes}")
    log = parse_sarif(data)
    if len(log.runs) > max_runs:
        raise VendorContractError(f"SARIF artifact has {len(log.runs)} runs; the limit is {max_runs}")
    runs: list[Run] = []
    dropped: list[dict[str, Any]] = []
    for run in log.runs:
        results = run.results or []
        if len(results) > max_results_per_run:
            raise VendorContractError(
                f"SARIF run has {len(results)} results; the limit is {max_results_per_run}"
            )
        kept = []
        for result in results:
            if result.rule_id is None:
                dropped.append(
                    {
                        "reason": "missing ruleId",
                        "message": result.message.text,
                        "uri": _first_uri(result),
                    }
                )
            elif not _has_physical_location(result):
                dropped.append(
                    {
                        "reason": "missing physicalLocation",
                        "message": result.message.text,
                        "uri": None,
                    }
                )
            else:
                kept.append(result)
        runs.append(run.model_copy(update={"results": kept}))
    document = dump_sarif(log.model_copy(update={"runs": runs}))
    return VendorResult(
        data=document,
        coverage="partial" if dropped else "complete",
        dropped=dropped,
    )


def _has_physical_location(result: Any) -> bool:
    return any(location.physical_location is not None for location in result.locations or [])


def _first_uri(result: Any) -> str | None:
    for location in result.locations or []:
        physical = location.physical_location
        if physical is not None and physical.artifact_location is not None:
            return physical.artifact_location.uri
    return None
