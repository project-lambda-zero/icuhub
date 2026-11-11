"""GitHub stream mappers: OCSF findings for security alerts, an ACTIVITY record for audit events,
a ticket for pull requests, and kit source records for every other stream."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping
from datetime import datetime
from typing import Any, Literal, TypeVar

from pydantic import BaseModel

from icuhub.connectors._github.base import GitHubBase
from icuhub.kit.errors import ConfigError, VendorContractError
from icuhub.kit.mapping import bounded_raw, epoch_ms, product
from icuhub.kit.types import MapContext, SourceRecord, TicketRecord
from icuhub_schemas.ocsf import (
    Actor,
    AffectedCode,
    AffectedPackage,
    Api,
    ApiActivity,
    Cloud,
    Compliance,
    ComplianceFinding,
    Cve,
    Cwe,
    DetectionFinding,
    File,
    FindingInfo,
    FindingStatusId,
    Metadata,
    NetworkEndpoint,
    Product,
    ResourceDetails,
    SeverityId,
    User,
    Vulnerability,
    VulnerabilityFinding,
    validate_ocsf,
)

_M = TypeVar("_M", bound=BaseModel)
Handler = Callable[[GitHubBase, dict[str, Any], MapContext], list[BaseModel]]

_PROVIDER = "GitHub"
# OCSF "Base Event" (class_uid 0): the documented carrier for GitHub objects with no OCSF class.
_NON_OCSF_CLASS_UID = 0
_REDACTED = "[redacted]"
_SECRET_KEY = re.compile(r"(^|_)(secret|token|password|credential|private_key|api_key)$", re.IGNORECASE)
_CWE_TAG = re.compile(r"^external/cwe/cwe-(\d+)$")
_KEY_FIELDS = ("_document_id", "_branch", "id", "number", "sha", "path", "login", "name", "key")
# Exposed-secret alerts carry no vendor severity; an exposed credential is treated as High.
_SECRET_EXPOSED_SEVERITY: SeverityId = 4
_ACTIVITY_FINDING: Literal[1] = 1
_ACTIVITY_OTHER: Literal[99] = 99
_FILE_REGULAR: Literal[1] = 1
_CHECK_PASS: Literal[1] = 1
_CHECK_FAIL: Literal[2] = 2

_SECURITY_SEVERITY: dict[str, SeverityId] = {"critical": 5, "high": 4, "medium": 3, "low": 2}
_RULE_SEVERITY: dict[str, SeverityId] = {"error": 4, "warning": 3, "note": 2, "none": 1}
_ALERT_STATUS: dict[str, FindingStatusId] = {"open": 1, "dismissed": 3, "auto_dismissed": 3, "fixed": 4}
_SECRET_STATUS: dict[str, FindingStatusId] = {"open": 1, "resolved": 4}
_PULL_STATUS_CATEGORY: dict[str, Literal["open", "in_progress", "done", "unknown"]] = {
    "open": "open",
    "closed": "done",
}


def _redact(value: Any) -> Any:
    """Recursively replace every value under a secret-named key; keys are kept for debugging."""
    if isinstance(value, dict):
        return {
            key: _REDACTED if isinstance(key, str) and _SECRET_KEY.search(key) else _redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def _evidence(raw: Mapping[str, Any]) -> str:
    return bounded_raw(_redact(dict(raw)))


def _text(mapping: Mapping[str, Any], key: str) -> str | None:
    value = mapping.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise VendorContractError(f"GitHub field {key!r} must be a string")
    return value


def _required_text(mapping: Mapping[str, Any], key: str) -> str:
    value = _text(mapping, key)
    if not value:
        raise VendorContractError(f"GitHub record is missing required field {key!r}")
    return value


def _optional_int(mapping: Mapping[str, Any], key: str) -> int | None:
    value = mapping.get(key)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise VendorContractError(f"GitHub field {key!r} must be an integer")
    return value


def _required_int(mapping: Mapping[str, Any], key: str) -> int:
    value = _optional_int(mapping, key)
    if value is None:
        raise VendorContractError(f"GitHub record is missing required field {key!r}")
    return value


def _mapping(mapping: Mapping[str, Any], key: str) -> dict[str, Any]:
    value = mapping.get(key)
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise VendorContractError(f"GitHub field {key!r} must be an object")
    return value


def _strings(mapping: Mapping[str, Any], key: str) -> list[str]:
    value = mapping.get(key)
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise VendorContractError(f"GitHub field {key!r} must be a list of strings")
    return list(value)


def _objects(mapping: Mapping[str, Any], key: str) -> list[dict[str, Any]]:
    value = mapping.get(key)
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise VendorContractError(f"GitHub field {key!r} must be a list of objects")
    return list(value)


def _optional_ms(value: Any) -> int | None:
    return epoch_ms(value) if value is not None else None


def _time_ms(value: Any, ctx: MapContext) -> int:
    resolved = _optional_ms(value)
    return resolved if resolved is not None else int(ctx.received_at.timestamp() * 1000)


def _parse_time(value: Any, field: str) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise VendorContractError(f"GitHub field {field!r} must be an ISO timestamp string")
    try:
        return datetime.fromisoformat(value)
    except ValueError as exc:
        raise VendorContractError(f"GitHub field {field!r} is not an ISO timestamp") from exc


def _checked(model: _M) -> _M:
    """Validate against the pinned OCSF schema; a violation is a mapper bug and must surface."""
    validate_ocsf(model.model_dump(mode="json", exclude_none=True))
    return model


def _repository_id(raw: Mapping[str, Any]) -> int:
    return _required_int(raw, "_repository_id")


def _resource(connector: GitHubBase, raw: Mapping[str, Any]) -> ResourceDetails:
    return ResourceDetails(
        uid=connector.repo_uid(_repository_id(raw)),
        name=_text(raw, "_repository_full_name"),
        type="Repository",
        provider=_PROVIDER,
    )


def _metadata(uid: str | None = None) -> Metadata:
    return Metadata(product=Product(**product("GitHub", _PROVIDER)), uid=uid)


def _cloud() -> Cloud:
    return Cloud(provider=_PROVIDER)


def _status(state: str | None, table: Mapping[str, FindingStatusId]) -> tuple[FindingStatusId, dict[str, Any] | None]:
    if state is not None and state in table:
        return table[state], None
    return 0, {"state": state}


def _alert_severity(security_level: str | None, rule_severity: str | None) -> SeverityId:
    if security_level is not None and security_level in _SECURITY_SEVERITY:
        return _SECURITY_SEVERITY[security_level]
    if rule_severity is not None and rule_severity in _RULE_SEVERITY:
        return _RULE_SEVERITY[rule_severity]
    return 0


def _scope(raw: Mapping[str, Any]) -> str:
    if raw.get("_repository_id") is not None:
        parts = [f"repository:{raw['_repository_id']}"]
    elif raw.get("_enterprise") is not None:
        parts = [f"enterprise:{raw['_enterprise']}"]
    elif raw.get("_organization") is not None:
        parts = [f"organization:{raw['_organization']}"]
    else:
        parts = ["account"]
    for key, label in (("_team_id", "team"), ("_pull_request_number", "pull"), ("_workflow_run_id", "run")):
        if raw.get(key) is not None:
            parts.append(f"{label}:{raw[key]}")
    return "/".join(parts)


def _record_key(raw: Mapping[str, Any]) -> str:
    for field in _KEY_FIELDS:
        value = raw.get(field)
        if isinstance(value, (str, int)) and not isinstance(value, bool):
            return str(value)
    return hashlib.sha256(_canonical(_redact(dict(raw))).encode("utf-8")).hexdigest()


def _source_uid(connector: GitHubBase, stream_name: str, raw: Mapping[str, Any]) -> str:
    return f"github_{stream_name}:{connector.installation_id()}/{_scope(raw)}/{_record_key(raw)}"


def _revision(raw: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical(_redact(dict(raw))).encode("utf-8")).hexdigest()


def _links(raw: Mapping[str, Any]) -> dict[str, str]:
    links: dict[str, str] = {}
    if isinstance(raw.get("html_url"), str):
        links["html"] = str(raw["html_url"])
    if isinstance(raw.get("url"), str):
        links["api"] = str(raw["url"])
    return links


def _source_data(stream_name: str, raw: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "class_uid": _NON_OCSF_CLASS_UID,
        "stream": stream_name,
        "record_kind": raw.get("_record_kind"),
        "partial_coverage": raw.get("_partial_coverage") is True,
        "coverage": _redact(raw.get("_coverage")),
        "stream_error": _redact(raw.get("_stream_error")),
        "raw": _evidence(raw),
    }


_COMMENT_STREAMS = frozenset({"reviews", "review_comments"})


def _source_record(connector: GitHubBase, stream_name: str, raw: Mapping[str, Any]) -> SourceRecord:
    return SourceRecord(
        record_type="comment" if stream_name in _COMMENT_STREAMS else stream_name,
        uid=_source_uid(connector, stream_name, raw),
        revision=_revision(raw),
        data=_source_data(stream_name, raw),
        links=_links(raw),
    )


def _first_cwe(tags: list[str]) -> str | None:
    for tag in tags:
        match = _CWE_TAG.match(tag)
        if match is not None:
            return f"CWE-{int(match.group(1))}"
    return None


def _affected_code(location: Mapping[str, Any]) -> list[AffectedCode] | None:
    path = _text(location, "path")
    if path is None:
        return None
    return [
        AffectedCode(
            file=File(name=path.rsplit("/", 1)[-1], type_id=_FILE_REGULAR, path=path),
            start_line=_optional_int(location, "start_line"),
            end_line=_optional_int(location, "end_line"),
            start_column=_optional_int(location, "start_column"),
            end_column=_optional_int(location, "end_column"),
        )
    ]


def _code_scanning_alert(connector: GitHubBase, raw: dict[str, Any], ctx: MapContext) -> list[BaseModel]:
    repository_id = _repository_id(raw)
    number = _required_int(raw, "number")
    rule = _mapping(raw, "rule")
    tool = _mapping(raw, "tool")
    location = _mapping(_mapping(raw, "most_recent_instance"), "location")
    rule_id = _text(rule, "id")
    description = _text(rule, "description") or _text(rule, "name")
    status, unmapped = _status(_text(raw, "state"), _ALERT_STATUS)
    severity = _alert_severity(_text(rule, "security_severity_level"), _text(rule, "severity"))
    cwe = _first_cwe(_strings(rule, "tags"))
    time = _time_ms(raw.get("updated_at") or raw.get("created_at"), ctx)
    info = FindingInfo(
        uid=connector.repo_uid(repository_id, number),
        title=description,
        src_url=_text(raw, "html_url"),
        types=[rule_id] if rule_id is not None else None,
        created_time=_optional_ms(raw.get("created_at")),
        modified_time=_optional_ms(raw.get("updated_at")),
        product=Product(**product(_text(tool, "name") or "GitHub Code Scanning", _PROVIDER, _text(tool, "version"))),
    )
    if cwe is None:
        return [
            _checked(
                DetectionFinding(
                    type_uid=DetectionFinding.CLASS_UID * 100 + _ACTIVITY_FINDING,
                    activity_id=_ACTIVITY_FINDING,
                    status_id=status,
                    severity_id=severity,
                    time=time,
                    metadata=_metadata(),
                    cloud=_cloud(),
                    osint=[],
                    finding_info=info,
                    resources=[_resource(connector, raw)],
                    raw_data=_evidence(raw),
                    unmapped=unmapped,
                )
            )
        ]
    vulnerability = Vulnerability(
        desc=description,
        cwe=Cwe(uid=cwe),
        affected_code=_affected_code(location),
    )
    return [
        _checked(
            VulnerabilityFinding(
                type_uid=VulnerabilityFinding.CLASS_UID * 100 + _ACTIVITY_FINDING,
                activity_id=_ACTIVITY_FINDING,
                status_id=status,
                severity_id=severity,
                time=time,
                metadata=_metadata(),
                cloud=_cloud(),
                osint=[],
                finding_info=info,
                vulnerabilities=[vulnerability],
                resources=[_resource(connector, raw)],
                raw_data=_evidence(raw),
                unmapped=unmapped,
            )
        )
    ]


def _dependabot_alert(connector: GitHubBase, raw: dict[str, Any], ctx: MapContext) -> list[BaseModel]:
    repository_id = _repository_id(raw)
    number = _required_int(raw, "number")
    advisory = _mapping(raw, "security_advisory")
    dependency = _mapping(raw, "dependency")
    package = _mapping(dependency, "package")
    vulnerable = _mapping(raw, "security_vulnerability")
    fixed = _mapping(vulnerable, "first_patched_version")
    summary = _text(advisory, "summary")
    cve_id = _text(advisory, "cve_id")
    cwes = _objects(advisory, "cwes")
    cwe_id = _text(cwes[0], "cwe_id") if cwes else None
    status, unmapped = _status(_text(raw, "state"), _ALERT_STATUS)
    severity = _alert_severity(_text(advisory, "severity"), None)
    package_name = _text(package, "name")
    version_range = _text(vulnerable, "vulnerable_version_range")
    affected_packages = (
        [
            AffectedPackage(
                name=package_name,
                version=version_range,
                fixed_in_version=_text(fixed, "identifier"),
                package_manager=_text(package, "ecosystem"),
                path=_text(dependency, "manifest_path"),
            )
        ]
        if package_name is not None and version_range is not None
        else None
    )
    info = FindingInfo(
        uid=f"{connector.repo_uid(repository_id)}:dependabot:{number}",
        title=summary,
        src_url=_text(raw, "html_url"),
        types=[cve_id] if cve_id is not None else None,
        created_time=_optional_ms(raw.get("created_at")),
        modified_time=_optional_ms(raw.get("updated_at")),
        product=Product(**product("GitHub Dependabot", _PROVIDER)),
    )
    time = _time_ms(raw.get("updated_at") or raw.get("created_at"), ctx)
    if cve_id is not None:
        vulnerability: Vulnerability | None = Vulnerability(
            desc=_text(advisory, "description"),
            cve=Cve(uid=cve_id, title=summary, desc=_text(advisory, "description")),
            affected_packages=affected_packages,
        )
    elif cwe_id is not None:
        vulnerability = Vulnerability(
            desc=_text(advisory, "description"),
            cwe=Cwe(uid=cwe_id, caption=_text(cwes[0], "name")),
            affected_packages=affected_packages,
        )
    else:
        vulnerability = None
    if vulnerability is None:
        return [
            _checked(
                DetectionFinding(
                    type_uid=DetectionFinding.CLASS_UID * 100 + _ACTIVITY_FINDING,
                    activity_id=_ACTIVITY_FINDING,
                    status_id=status,
                    severity_id=severity,
                    time=time,
                    metadata=_metadata(),
                    cloud=_cloud(),
                    osint=[],
                    finding_info=info,
                    resources=[_resource(connector, raw)],
                    raw_data=_evidence(raw),
                    unmapped=unmapped,
                )
            )
        ]
    return [
        _checked(
            VulnerabilityFinding(
                type_uid=VulnerabilityFinding.CLASS_UID * 100 + _ACTIVITY_FINDING,
                activity_id=_ACTIVITY_FINDING,
                status_id=status,
                severity_id=severity,
                time=time,
                metadata=_metadata(),
                cloud=_cloud(),
                osint=[],
                finding_info=info,
                vulnerabilities=[vulnerability],
                resources=[_resource(connector, raw)],
                raw_data=_evidence(raw),
                unmapped=unmapped,
            )
        )
    ]


def _secret_scanning_alert(connector: GitHubBase, raw: dict[str, Any], ctx: MapContext) -> list[BaseModel]:
    repository_id = _repository_id(raw)
    number = _required_int(raw, "number")
    secret_type = _required_text(raw, "secret_type")
    display = _text(raw, "secret_type_display_name") or secret_type
    status, unmapped = _status(_text(raw, "state"), _SECRET_STATUS)
    info = FindingInfo(
        uid=f"{connector.repo_uid(repository_id)}:secret_scanning:{number}",
        title=f"Exposed {display}",
        src_url=_text(raw, "html_url"),
        types=[secret_type],
        created_time=_optional_ms(raw.get("created_at")),
        modified_time=_optional_ms(raw.get("updated_at")),
        product=Product(**product("GitHub Secret Scanning", _PROVIDER)),
    )
    return [
        _checked(
            DetectionFinding(
                type_uid=DetectionFinding.CLASS_UID * 100 + _ACTIVITY_FINDING,
                activity_id=_ACTIVITY_FINDING,
                status_id=status,
                severity_id=_SECRET_EXPOSED_SEVERITY,
                time=_time_ms(raw.get("updated_at") or raw.get("created_at"), ctx),
                metadata=_metadata(),
                cloud=_cloud(),
                osint=[],
                finding_info=info,
                resources=[_resource(connector, raw)],
                raw_data=_evidence(raw),
                unmapped=unmapped,
            )
        )
    ]


def _branch_protection(connector: GitHubBase, raw: dict[str, Any], ctx: MapContext) -> list[BaseModel]:
    repository_id = _repository_id(raw)
    branch = _required_text(raw, "_branch")
    reviews_required = isinstance(raw.get("required_pull_request_reviews"), dict)
    admins = _mapping(raw, "enforce_admins")
    admins_enforced = admins.get("enabled") is True
    passed = reviews_required and admins_enforced
    compliance = Compliance(
        control="Branch protection",
        status="Pass" if passed else "Fail",
        status_id=_CHECK_PASS if passed else _CHECK_FAIL,
        desc=(
            f"Branch {branch}: pull request reviews required={reviews_required}; "
            f"administrators enforced={admins_enforced}"
        ),
    )
    finding = ComplianceFinding(
        type_uid=ComplianceFinding.CLASS_UID * 100 + _ACTIVITY_FINDING,
        activity_id=_ACTIVITY_FINDING,
        severity_id=0,
        time=_time_ms(None, ctx),
        metadata=_metadata(),
        cloud=_cloud(),
        osint=[],
        finding_info=FindingInfo(
            uid=f"{connector.repo_uid(repository_id)}:branch_protection:{branch}",
            title=f"Branch protection for {branch}",
            product=Product(**product("GitHub Branch Protection", _PROVIDER)),
        ),
        compliance=compliance,
        resources=[_resource(connector, raw)],
        raw_data=_evidence(raw),
    )
    return [_checked(finding), _source_record(connector, "branch_protection", raw)]


def _pull_request(connector: GitHubBase, raw: dict[str, Any], _ctx: MapContext) -> list[BaseModel]:
    repository_id = _repository_id(raw)
    number = _required_int(raw, "number")
    state = _required_text(raw, "state")
    merged = raw.get("merged_at") is not None
    if merged:
        resolution: str | None = "merged"
    elif state == "closed":
        resolution = "closed"
    else:
        resolution = None
    labels = []
    for label in _objects(raw, "labels"):
        labels.append(_required_text(label, "name"))
    return [
        TicketRecord(
            uid=f"{connector.repo_uid(repository_id)}:pull_request:{number}",
            revision=_revision(raw),
            key=f"#{number}",
            status=state,
            status_category=_PULL_STATUS_CATEGORY.get(state, "unknown"),
            resolution=resolution,
            url=_text(raw, "html_url"),
            updated_at=_parse_time(raw.get("updated_at"), "updated_at"),
            labels=labels,
            fingerprint_links=[],
            links=_links(raw),
            data=_source_data("pull_requests", raw),
        )
    ]


def _audit_api_activity(
    connector: GitHubBase, stream_name: str, raw: dict[str, Any], ctx: MapContext
) -> list[BaseModel]:
    actor_name = _text(raw, "actor")
    operation = _text(raw, "action")
    endpoint_ip = _text(raw, "actor_ip")
    endpoint_name = _text(raw, "org") or _text(raw, "_enterprise")
    if actor_name is None or operation is None or (endpoint_ip is None and endpoint_name is None):
        return [_source_record(connector, stream_name, raw)]
    actor_id = _optional_int(raw, "actor_id")
    return [
        _checked(
            ApiActivity(
                type_uid=ApiActivity.CLASS_UID * 100 + _ACTIVITY_OTHER,
                activity_id=_ACTIVITY_OTHER,
                severity_id=0,
                time=_time_ms(raw.get("@timestamp") or raw.get("created_at"), ctx),
                metadata=_metadata(uid=_record_key(raw)),
                cloud=_cloud(),
                osint=[],
                actor=Actor(user=User(name=actor_name, uid=str(actor_id) if actor_id is not None else None)),
                api=Api(operation=operation),
                src_endpoint=NetworkEndpoint(ip=endpoint_ip, name=endpoint_name),
                raw_data=_evidence(raw),
            )
        )
    ]


def _audit_event(connector: GitHubBase, raw: dict[str, Any], ctx: MapContext) -> list[BaseModel]:
    return _audit_api_activity(connector, "audit_events", raw, ctx)


def _audit_stream_file(connector: GitHubBase, raw: dict[str, Any], ctx: MapContext) -> list[BaseModel]:
    if raw.get("_partial_coverage") is True or "_stream_error" in raw:
        return [_source_record(connector, "audit_stream_files", raw)]
    return _audit_api_activity(connector, "audit_stream_files", raw, ctx)


_HANDLERS: dict[str, Handler] = {
    "code_scanning_alerts": _code_scanning_alert,
    "dependabot_alerts": _dependabot_alert,
    "secret_scanning_alerts": _secret_scanning_alert,
    "branch_protection": _branch_protection,
    "pull_requests": _pull_request,
    "audit_events": _audit_event,
    "audit_stream_files": _audit_stream_file,
}

# Streams whose records map to a kit SourceRecord with no OCSF class.
_SOURCE_STREAMS = frozenset(
    {
        "reviews",
        "review_comments",
        "repositories",
        "organizations",
        "users",
        "teams",
        "team_members",
        "team_repositories",
        "collaborators",
        "organization_external_identities",
        "branches",
        "tags",
        "commits",
        "repository_files",
        "workflows",
        "workflow_runs",
        "workflow_jobs",
        "workflow_artifacts",
        "actions_caches",
        "actions_runners",
        "commit_statuses",
        "check_runs",
    }
)


def map_stream_record(
    connector: GitHubBase, stream_name: str, raw: dict[str, Any], ctx: MapContext
) -> list[BaseModel]:
    """Map one raw record from ``stream_name`` into OCSF models, a ticket, or source records."""
    handler = _HANDLERS.get(stream_name)
    if handler is not None:
        return handler(connector, raw, ctx)
    if stream_name in _SOURCE_STREAMS:
        return [_source_record(connector, stream_name, raw)]
    raise ConfigError(f"GitHub stream {stream_name!r} has no mapper")
