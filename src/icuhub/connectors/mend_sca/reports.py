"""Offline Mend SCA report parser (GAP-MEND-03).

Validates one uploaded Mend JSON report (unified agent, manual vulnerability export,
platform components, or platform 3.0 response) and normalizes each vulnerability row
into a record keyed by vendor identity. Pure function; performs no network access.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Literal

from icuhub.connectors.mend_sca.models import MendSCAConfig, ParsedMendReport, ReportIdentity
from icuhub.kit.errors import VendorContractError

__all__ = ["parse_report"]

Schema = Literal["unified_agent_libraries", "manual_vulnerabilities", "platform_components", "platform_3_response"]

_SCHEMA_KEYS: dict[str, Schema] = {
    "libraries": "unified_agent_libraries",
    "vulnerabilities": "manual_vulnerabilities",
    "components": "platform_components",
    "response": "platform_3_response",
}
_SUPPRESSED_FINDING_STATUS = "SUPPRESSED"
_IGNORED_STATUS = "IGNORED"


def parse_report(data: bytes, *, config: MendSCAConfig, project_snapshot: str) -> ParsedMendReport:
    """Parse one offline Mend report into its identity and normalized records."""
    if len(data) > config.max_report_bytes:
        raise VendorContractError("report exceeds max_report_bytes")
    digest = hashlib.sha256(data).hexdigest()
    document = _decode(data, config)
    schema, body = _detect(document)
    rows = _extract(schema, body)
    if len(rows) > config.max_report_items:
        raise VendorContractError("report exceeds max_report_items")

    incomplete: list[str] = []
    records: list[dict[str, Any]] = []
    for fields in rows:
        if fields["library_name"] is None and fields["vulnerability_id"] is None:
            incomplete.append("skipped_record_missing_identity")
            continue
        records.append(_record(schema, fields))

    identity = ReportIdentity(
        parser_version=1,
        report_schema=schema,
        report_sha256=digest,
        project_snapshot=project_snapshot,
        snapshot_id=digest,
        project_uuid=None,
        project_name=next((f["project_name"] for f in rows if f["project_name"] is not None), None),
        application_uuid=None,
        application_name=None,
        last_scan=None,
        complete=not incomplete,
        incomplete_reasons=list(dict.fromkeys(incomplete)),
    )
    return ParsedMendReport(identity=identity, records=records)


def _decode(data: bytes, config: MendSCAConfig) -> dict[str, Any]:
    try:
        document = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise VendorContractError("report is not UTF-8 JSON") from exc
    if not isinstance(document, dict):
        raise VendorContractError("report top level must be a JSON object")
    _check_structure(document, config)
    return document


def _check_structure(root: dict[str, Any], config: MendSCAConfig) -> None:
    """Walk the parsed document iteratively, enforcing nesting depth and string bounds."""
    pending: list[tuple[Any, int]] = [(root, 1)]
    while pending:
        node, depth = pending.pop()
        if isinstance(node, dict | list) and depth > config.max_report_depth:
            raise VendorContractError("report nesting exceeds max_report_depth")
        if isinstance(node, dict):
            for key, child in node.items():
                _check_string(key, config)
                pending.append((child, depth + 1))
        elif isinstance(node, list):
            pending.extend((child, depth + 1) for child in node)
        elif isinstance(node, str):
            _check_string(node, config)


def _check_string(value: str, config: MendSCAConfig) -> None:
    if len(value) > config.max_report_string_chars:
        raise VendorContractError("report string exceeds max_report_string_chars")


def _detect(document: dict[str, Any]) -> tuple[Schema, list[Any]]:
    present = [key for key in _SCHEMA_KEYS if key in document]
    if len(present) != 1:
        raise VendorContractError(
            "report must contain exactly one of libraries, vulnerabilities, components, response"
        )
    key = present[0]
    body = document[key]
    if not isinstance(body, list):
        raise VendorContractError(f"report key {key!r} must be a JSON array")
    return _SCHEMA_KEYS[key], body


def _extract(schema: Schema, body: Any) -> list[dict[str, Any]]:
    if schema == "unified_agent_libraries":
        return _unified(body)
    if schema == "manual_vulnerabilities":
        return _manual(body)
    if schema == "platform_components":
        return _components(body)
    return _platform(body)


def _unified(libraries: list[Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for lib in libraries:
        library = _obj(lib)
        for vuln in _list(library.get("vulnerabilities")):
            rows.append(_row(_obj(vuln), library, None, None))
    return rows


def _manual(vulns: list[Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for vuln in vulns:
        node = _obj(vuln)
        rows.append(_row(node, _obj(node.get("library")), None, _opt_str(node.get("project"))))
    return rows


def _components(components: list[Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for comp in components:
        component = _obj(comp)
        name = _opt_str(component.get("name"))
        for entry in _list(component.get("response")):
            node = _obj(entry)
            rows.append(_row(node, _obj(node.get("component")), name, None))
    return rows


def _platform(findings: list[Any]) -> list[dict[str, Any]]:
    return [_row(node, _obj(node.get("component")), None, None) for node in map(_obj, findings)]


def _row(
    node: dict[str, Any],
    library: dict[str, Any],
    fallback_name: str | None,
    project_name: str | None,
) -> dict[str, Any]:
    nested = _obj(node.get("vulnerability"))
    top_fix = _obj(node.get("topFix"))
    finding_info = _obj(node.get("findingInfo"))
    # Only the vendor's suppressing states hide a finding. UNREVIEWED, IN_REVIEW, and other open
    # states stay active. The row is kept either way; suppression is a flag, not a drop.
    finding_status = _opt_str(finding_info.get("findingStatus"))
    status = _opt_str(finding_info.get("status"))
    suppression_reason: str | None = None
    if finding_status == _SUPPRESSED_FINDING_STATUS:
        suppression_reason = finding_status
    elif status == _IGNORED_STATUS:
        suppression_reason = status
    suppressed = suppression_reason is not None
    paths = [
        *(_opt_str(_obj(item).get("localPath")) for item in _list(node.get("sourceFiles"))),
        *(_opt_str(_obj(item).get("path")) for item in _list(node.get("locations"))),
        _opt_str(library.get("path")),
    ]
    score = _number(nested.get("score"))
    if score is None:
        score = _number(node.get("cvss3_score"))
    return {
        "vulnerability_id": _opt_str(node.get("name")),
        "severity": _opt_str(node.get("cvss3_severity"))
        or _opt_str(nested.get("severity"))
        or _opt_str(node.get("severity")),
        "cvss_score": score,
        "cvss_vector": _opt_str(node.get("scoreMetadataVector")),
        "description": _opt_str(nested.get("description")) or _opt_str(node.get("description")),
        "published_at": _opt_str(nested.get("publishDate")),
        "modified_at": None,
        "library_name": _opt_str(library.get("name")) or fallback_name,
        "library_version": _opt_str(library.get("version")),
        "library_purl": None,
        "library_sha1": None,
        "project_name": project_name,
        "dependency_path": [],
        "suppressed": suppressed,
        "suppression_reason": suppression_reason,
        "fix_resolution": _opt_str(top_fix.get("fixResolution")),
        "source_file": ", ".join(path for path in paths if path) or None,
    }


def _record(schema: Schema, fields: dict[str, Any]) -> dict[str, Any]:
    key = (
        f"{schema}:{fields['vulnerability_id'] or ''}:{fields['library_name'] or ''}:"
        f"{fields['library_version'] or ''}:{'/'.join(fields['dependency_path'])}"
    )
    return {"schema": schema, "key": key, "fields": fields}


def _obj(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    raise VendorContractError("report field must be a JSON object")


def _list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    raise VendorContractError("report field must be a JSON array")


def _opt_str(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None
