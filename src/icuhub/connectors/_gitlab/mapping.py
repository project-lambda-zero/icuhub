"""Pure GitLab native vulnerability finding to OCSF mapping."""

from __future__ import annotations

import json
import posixpath
import re
from collections.abc import Mapping
from datetime import datetime
from typing import Any

from icuhub.connectors._gitlab.models import VendorResult
from icuhub.kit.errors import VendorContractError
from icuhub.kit.mapping import EnumTable, epoch_ms, severity_id_from_label
from icuhub.kit.types import MapContext
from icuhub_schemas.ocsf import (
    AffectedCode,
    Cloud,
    Cve,
    Cwe,
    File,
    FindingInfo,
    Metadata,
    Product,
    Vulnerability,
    VulnerabilityFinding,
)

__all__ = ["NoIdentifierError", "map_native_finding", "map_native_findings", "parse_time"]

_GITLAB_PRODUCT = "GitLab"
_GITLAB_VENDOR = "GitLab Inc."
_CLOUD_PROVIDER = "gitlab"
# OCSF activity 1 (Create): each native GitLab finding is an observed finding.
_ACTIVITY_CREATE = 1
_FILE_TYPE_REGULAR = 1
# OCSF finding status: 1 New, 2 In Progress, 3 Suppressed, 4 Resolved. Unlisted states map to 0 (Unknown).
_STATUS = EnumTable(mapping={"detected": 1, "confirmed": 2, "dismissed": 3, "resolved": 4}, default=0)
# Labels not listed here map to OCSF severity 0 (Unknown); no severity is invented.
_SEVERITY = EnumTable(mapping={"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1}, default=0)
_RAW_MAX_BYTES = 32 * 1024
_TRUNCATION_SUFFIX = "...[truncated]"
_CVE_VALUE = re.compile(r"^CVE-\d{4}-\d+$")
_CWE_VALUE = re.compile(r"^\d+$")


def parse_time(value: object, field: str) -> datetime:
    """Parse a GitLab ISO 8601 timestamp; a missing or offset-less value is a vendor contract break."""
    if not isinstance(value, str):
        raise VendorContractError(f"{field} must be an ISO 8601 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise VendorContractError(f"{field} is not an ISO 8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise VendorContractError(f"{field} must carry a UTC offset")
    return parsed


class NoIdentifierError(ValueError):
    """A native finding has neither a CVE nor a CWE identifier, which OCSF vulnerabilities require."""

    def __init__(self, native_id: int) -> None:
        super().__init__(f"GitLab finding {native_id} has no CVE or CWE identifier")
        self.native_id = native_id


def map_native_findings(payload: Mapping[str, Any], ctx: MapContext) -> VendorResult:
    """Map a native GitLab findings page.

    ``coverage`` reflects the source page: ``complete`` only when the page reports ``complete``
    true. Findings that cannot be mapped (no CVE or CWE identifier) are listed in ``dropped``.

    Raises:
        VendorContractError: the page or a finding is malformed.
    """

    items = payload.get("items")
    complete = payload.get("complete")
    if not isinstance(items, list) or not isinstance(complete, bool):
        raise VendorContractError("GitLab native findings require a boolean complete and a list of items")
    findings: list[VulnerabilityFinding] = []
    dropped: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, Mapping):
            raise VendorContractError("GitLab native finding must be an object")
        try:
            findings.append(map_native_finding(item, ctx))
        except NoIdentifierError as exc:
            dropped.append({"id": exc.native_id, "reason": "no CVE or CWE identifier"})
    return VendorResult(data=findings, coverage="complete" if complete else "partial", dropped=dropped)


def map_native_finding(raw: Mapping[str, Any], ctx: MapContext) -> VulnerabilityFinding:
    """Map one native GitLab finding to an OCSF vulnerability finding.

    Raises:
        NoIdentifierError: the finding carries neither a CVE nor a CWE identifier.
        VendorContractError: a required field is missing or malformed.
    """

    native_id = _positive_int(raw.get("id"), "id")
    uuid = _required_str(raw, "uuid")
    report_type = _optional_str(raw, "report_type")
    state = _optional_str(raw, "state")
    severity_label = _optional_str(raw, "severity")
    identifiers = _identifiers(raw.get("identifiers"))
    affected_code = _affected_code(raw.get("location"))
    observed = epoch_ms(ctx.received_at.isoformat())
    if observed is None:
        raise VendorContractError("GitLab observation time is unavailable")
    vulnerability = _vulnerability(native_id, identifiers, report_type, affected_code)
    return VulnerabilityFinding(
        time=observed,
        severity_id=severity_id_from_label(severity_label, _SEVERITY),
        severity=severity_label,
        activity_id=_ACTIVITY_CREATE,
        status_id=_STATUS.lookup(state),
        status=state,
        finding_info=FindingInfo(
            uid=uuid,
            uid_alt=str(native_id),
            title=_optional_str(raw, "name"),
            desc=_optional_str(raw, "description"),
        ),
        vulnerabilities=[vulnerability],
        metadata=Metadata(product=Product(name=_GITLAB_PRODUCT, vendor_name=_GITLAB_VENDOR)),
        cloud=Cloud(provider=_CLOUD_PROVIDER),
        osint=[],
        unmapped={
            "gitlab": {
                "id": native_id,
                "report_type": report_type,
                "state": state,
                "identifiers": identifiers,
            }
        },
        raw_data=_raw_evidence(raw),
    )


def _vulnerability(
    native_id: int,
    identifiers: list[dict[str, str]],
    report_type: str | None,
    affected_code: list[AffectedCode] | None,
) -> Vulnerability:
    """Build the vulnerability carrying the first CVE, else the first CWE.

    OCSF allows exactly one of ``cve`` or ``cwe``. When a CVE is present, the first CWE is nested on
    the CVE object so the classification is not lost.

    Raises:
        NoIdentifierError: neither a CVE nor a CWE identifier is present.
        VendorContractError: an identifier value is malformed.
    """

    cwe = None
    cwe_values = [entry["value"] for entry in identifiers if entry["type"] == "cwe"]
    if cwe_values:
        if not _CWE_VALUE.match(cwe_values[0]):
            raise VendorContractError(f"GitLab cwe identifier is not numeric: {cwe_values[0]!r}")
        cwe = Cwe(uid=f"CWE-{cwe_values[0]}")
    cve_values = [entry["value"] for entry in identifiers if entry["type"] == "cve"]
    if cve_values:
        if not _CVE_VALUE.match(cve_values[0]):
            raise VendorContractError(f"GitLab cve identifier is malformed: {cve_values[0]!r}")
        return Vulnerability(
            category=report_type,
            cve=Cve(uid=cve_values[0], cwe=cwe),
            affected_code=affected_code,
        )
    if cwe is None:
        raise NoIdentifierError(native_id)
    return Vulnerability(category=report_type, cwe=cwe, affected_code=affected_code)


def _affected_code(value: Any) -> list[AffectedCode] | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise VendorContractError("GitLab finding location must be an object")
    path = value.get("file")
    if not isinstance(path, str) or not path.strip():
        raise VendorContractError("GitLab finding location.file must be a non-empty string")
    return [
        AffectedCode(
            file=File(name=_basename(path), type_id=_FILE_TYPE_REGULAR, path=path),
            start_line=_optional_int(value.get("start_line"), "location.start_line"),
            end_line=_optional_int(value.get("end_line"), "location.end_line"),
        )
    ]


def _identifiers(value: Any) -> list[dict[str, str]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise VendorContractError("GitLab finding identifiers must be a list")
    identifiers: list[dict[str, str]] = []
    for entry in value:
        if not isinstance(entry, Mapping):
            raise VendorContractError("GitLab finding identifier must be an object")
        kind = entry.get("type")
        identifier = entry.get("value")
        if not isinstance(kind, str) or not isinstance(identifier, str):
            raise VendorContractError("GitLab finding identifier requires string type and value")
        identifiers.append({"type": kind, "value": identifier})
    return identifiers


def _raw_evidence(raw: Mapping[str, Any]) -> str:
    """Serialize the native record to JSON, bounded to ``_RAW_MAX_BYTES`` UTF-8 bytes."""

    text = json.dumps(dict(raw), ensure_ascii=False, default=str)
    encoded = text.encode("utf-8")
    if len(encoded) <= _RAW_MAX_BYTES:
        return text
    budget = _RAW_MAX_BYTES - len(_TRUNCATION_SUFFIX.encode("utf-8"))
    return encoded[:budget].decode("utf-8", errors="ignore") + _TRUNCATION_SUFFIX


def _basename(path: str) -> str:
    return posixpath.basename(path.replace("\\", "/")) or path


def _required_str(raw: Mapping[str, Any], key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value:
        raise VendorContractError(f"GitLab finding {key} must be a non-empty string")
    return value


def _optional_str(raw: Mapping[str, Any], key: str) -> str | None:
    value = raw.get(key)
    if value is None or isinstance(value, str):
        return value
    raise VendorContractError(f"GitLab finding {key} must be a string when present")


def _positive_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise VendorContractError(f"GitLab finding {field} must be a positive integer")
    return value


def _optional_int(value: Any, field: str) -> int | None:
    if value is None:
        return None
    return _positive_int(value, field)
