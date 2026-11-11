"""Fortify Software Security Center (SSC) connector.

Streams read findings, artifacts, and activity over the SSC REST API. Writes go through
``@action`` with a revision precondition: each plan is read-only, and apply re-checks the
revision before writing. Uploads and purges are asynchronous or destructive, so they never
report success from the HTTP response alone.

[UNVERIFIED] Delta export (``/issuesDeltaExports``), the ZIP layout of delta payloads, the
webhook signature scheme, and webhook retry behavior are not confirmed against a live
server. Incremental issue sync therefore falls back to a full reconciliation when delta
cannot be validated.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from collections.abc import AsyncIterator
from datetime import datetime
from typing import Any, ClassVar
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field

from icuhub.connectors._fortify.importers import iter_fortify_xml, iter_fpr
from icuhub.connectors._fortify.mappers import map_fpr_issue as map_fpr_record
from icuhub.connectors._fortify.mappers import map_report_issue as map_report_record
from icuhub.connectors.fortify_ssc.models import (
    AddIssueCommentArgs,
    ArtifactArgs,
    ArtifactOutput,
    ArtifactStatus,
    AssignIssueArgs,
    AuditIssueArgs,
    CreateWebhookArgs,
    FortifySscConfig,
    GetIssueArgs,
    IssueAuditArgs,
    IssueAuditOutput,
    IssueAuditRecord,
    IssueCommentArgs,
    IssueCommentOutput,
    IssueCommentRecord,
    IssueDetailArgs,
    IssueDetailOutput,
    IssueDetailRecord,
    IssueListArgs,
    IssueListOutput,
    IssueRecord,
    ProbeArgs,
    ProjectVersionInfo,
    ProjectVersionListArgs,
    ProjectVersionListOutput,
    ProjectVersionRecord,
    PurgeArtifactArgs,
    PurgeProjectVersionArgs,
    SetIssueSuppressionArgs,
    TargetProbeOutput,
    UploadFprArgs,
    WebhookDefinitionRecord,
    WebhookDeliveryRecord,
    WebhookHistoryArgs,
    WebhookHistoryOutput,
    WebhookListArgs,
    WebhookListOutput,
)
from icuhub.connectors.fortify_ssc.webhooks import SscHmacVerifier, parse_delivery_payload
from icuhub.kit.auth import AuthStrategy, HeaderToken
from icuhub.kit.connector import Connector, action, importer, mapper, operation, stream, webhook
from icuhub.kit.cursors import SequenceCursor, SnapshotCursor, TimeIdCursor
from icuhub.kit.errors import (
    AuthFailed,
    ConfigError,
    NotFound,
    OutcomeUnknown,
    PermissionDenied,
    RateLimited,
    StalePlan,
    TransientVendorError,
    VendorContractError,
)
from icuhub.kit.mapping import EnumTable, bounded_raw, severity_id_from_label
from icuhub.kit.paginate import offset_pages
from icuhub.kit.types import (
    ActionOutcome,
    ActionPlan,
    CapabilityHealth,
    HealthReport,
    ImportedFile,
    MapContext,
    RawBatch,
    StreamRecord,
    Target,
    WebhookDelivery,
)
from icuhub.kit.webhook import WebhookVerifier
from icuhub_schemas.ocsf import Cloud, FindingInfo, Metadata, Product, VulnerabilityFinding

__all__ = [
    "AddIssueCommentArgs",
    "AssignIssueArgs",
    "AuditIssueArgs",
    "CreateWebhookArgs",
    "FortifySsc",
    "FortifySscConfig",
    "GetIssueArgs",
    "IssueListArgs",
    "PurgeArtifactArgs",
    "PurgeProjectVersionArgs",
    "SetIssueSuppressionArgs",
    "UploadFprArgs",
]

_WEBHOOK_EVENTS = (
    "ANALYSIS_RESULT_UPLOAD_COMPLETE_SUCCESS",
    "ANALYSIS_RESULT_UPLOAD_FAILURE",
    "ANALYSIS_RESULT_INDEXING_COMPLETED",
)
_API = "/api/v1"
_PAGE_LIMIT = 200
_MAX_PAGES = 10_000
_MAX_DOWNLOAD_BYTES = 512 * 1024 * 1024


class FindingRecord(BaseModel):
    """Normalized SSC issue. ``revision`` drives every write precondition."""

    model_config = ConfigDict(extra="forbid")

    issue_instance_id: str
    issue_id: int
    project_version_id: int
    revision: int
    rule_guid: str | None
    category: str | None
    file_path: str | None
    line: int | None
    audit_state: str | None
    friority: str | None = None
    suppressed: bool
    removed: bool
    updated_at: datetime
    fingerprint_inputs: dict[str, Any] = Field(default_factory=dict)


class ArtifactRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    artifact_id: int
    project_version_id: int
    status: str
    sha256: str | None = None
    indexed: bool = False


class ActivityRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: int
    project_version_id: int | None
    event_type: str
    occurred_at: datetime


class IssueOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding: FindingRecord


class AuditResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    issue_id: int
    revision: int
    audit_state: str | None


class ProjectVersionArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    project_version_id: int = Field(ge=1)


class DeltaExportArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    export_id: int = Field(ge=1)


class DeltaExportOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    export_id: int
    state: str
    detail: dict[str, Any] = Field(default_factory=dict)


class WebhookDeliveryArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    webhook_id: int = Field(ge=1)
    delivery_id: int = Field(ge=1)


class WebhookDeliveryOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    delivery: WebhookDeliveryRecord


class FprArtifactRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    artifact_id: int
    sha256: str


def _str_or_none(raw: dict[str, Any], key: str) -> str | None:
    value = raw.get(key)
    if value is None or isinstance(value, str):
        return value
    raise VendorContractError(f"{key} must be a string or null")


def _int_required(raw: dict[str, Any], key: str) -> int:
    value = raw.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise VendorContractError(f"{key} must be an integer")
    return value


def _str_required(raw: dict[str, Any], key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value:
        raise VendorContractError(f"{key} must be a non-empty string")
    return value


def _parse_ts(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise VendorContractError(f"{field} must be an ISO-8601 string")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise VendorContractError(f"{field} is not ISO-8601") from exc


def _data_list(body: Any) -> list[dict[str, Any]]:
    """Extract the ``data`` array from an SSC list response."""
    if not isinstance(body, dict) or not isinstance(body.get("data"), list):
        raise VendorContractError("SSC list response must contain a 'data' array")
    items = body["data"]
    if not all(isinstance(item, dict) for item in items):
        raise VendorContractError("SSC list response items must be objects")
    return items


def _data_object(body: Any) -> dict[str, Any]:
    """Extract the ``data`` object from an SSC single-resource response."""
    if not isinstance(body, dict) or not isinstance(body.get("data"), dict):
        raise VendorContractError("SSC response must contain a 'data' object")
    return body["data"]


def _issue_id_of(raw: dict[str, Any]) -> str:
    return _str_required(raw, "issueInstanceId")


def _issue_updated_at(raw: dict[str, Any]) -> datetime:
    return _parse_ts(raw.get("foundDate"), "foundDate")


def _activity_seq(raw: dict[str, Any]) -> int:
    return _int_required(raw, "id")


def _audit_state(raw: dict[str, Any]) -> str | None:
    value = raw.get("issueStatus")
    if value is None or isinstance(value, str):
        return value
    raise VendorContractError("issueStatus must be a string or null")


_SSC_PRODUCT_NAME = "Fortify Software Security Center"
_SSC_VENDOR_NAME = "OpenText"
_SSC_CLOUD_PROVIDER = "fortify_ssc"
# SSC friority labels map onto OCSF severity; an absent or unlisted label stays Unknown (0), never invented.
_FRIORITY_SEVERITY = EnumTable(mapping={"Critical": 5, "High": 4, "Medium": 3, "Low": 2}, default=0)
# OCSF FindingStatusId values used for SSC issues (see _status_of for the precedence rule).
_STATUS_NEW = 1
_STATUS_SUPPRESSED = 3
_STATUS_RESOLVED = 4


def _status_of(record: FindingRecord) -> tuple[int, str]:
    """Return (OCSF status_id, status label) for an SSC issue.

    ``removed`` takes precedence over ``suppressed``: removal is an observed fact (the defect is no
    longer evident in the latest analysis), while suppression is an auditor judgment that can coexist
    with it. The raw ``issueStatus`` label is preserved separately in ``status_detail``.
    """
    if record.removed:
        return _STATUS_RESOLVED, "Resolved"
    if record.suppressed:
        return _STATUS_SUPPRESSED, "Suppressed"
    return _STATUS_NEW, "New"


def _finding_record(raw: dict[str, Any]) -> FindingRecord:
    project_version = raw.get("projectVersionId")
    if not isinstance(project_version, int) or isinstance(project_version, bool):
        raise VendorContractError("projectVersionId must be an integer")
    return FindingRecord(
        issue_instance_id=_issue_id_of(raw),
        issue_id=_int_required(raw, "id"),
        project_version_id=project_version,
        revision=_int_required(raw, "revision"),
        rule_guid=_str_or_none(raw, "primaryRuleGuid"),
        category=_str_or_none(raw, "issueName"),
        file_path=_str_or_none(raw, "fullFileName"),
        line=raw.get("lineNumber") if isinstance(raw.get("lineNumber"), int) else None,
        audit_state=_audit_state(raw),
        friority=_str_or_none(raw, "friority"),
        suppressed=bool(raw.get("suppressed", False)),
        removed=bool(raw.get("removed", False)),
        updated_at=_issue_updated_at(raw),
        fingerprint_inputs={
            "algorithmVersion": 1,
            "primaryRuleGuid": _str_or_none(raw, "primaryRuleGuid"),
            "issueName": _str_or_none(raw, "issueName"),
            "kingdom": _str_or_none(raw, "kingdom"),
            "fullFileName": _str_or_none(raw, "fullFileName"),
            "lineNumber": raw.get("lineNumber"),
        },
    )


def _as_path(path: str) -> str:
    return f"{_API}{path}"


# The connector targets SSC 24.2 and later; the probe's webappVersion is the discovery source.
_MIN_SSC_VERSION = (24, 2)


def _ssc_version_tuple(text: str) -> tuple[int, ...] | None:
    """Parse a dotted numeric SSC version such as ``25.4.0.0137``; None when it is not numeric."""
    parts = text.split(".")
    if not all(part.isdigit() for part in parts):
        return None
    return tuple(int(part) for part in parts)


def _context_root_of(base_url: str) -> str:
    """Return the operator-configured context root (the path of ``base_url``) without a trailing slash."""
    return urlsplit(base_url).path.rstrip("/")


def _upload_file_name(fpr_sha256: str) -> str:
    # The artifact schema carries no sha256, so the name encodes it for read-back matching.
    return f"icuhub-{fpr_sha256}.fpr"


def _artifact_id_of(body: Any) -> int | None:
    data = body.get("data") if isinstance(body, dict) else None
    if isinstance(data, dict) and isinstance(data.get("id"), int) and not isinstance(data.get("id"), bool):
        return data["id"]
    return None


def _prior_artifact_id(outcome: ActionOutcome) -> int | None:
    if not outcome.result:
        return None
    value = outcome.result.get("artifact_id")
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _is_upload_of(artifact: dict[str, Any], file_name: str, size: int) -> bool:
    return artifact.get("fileSize") == size and file_name in (
        artifact.get("originalFileName"),
        artifact.get("fileName"),
    )


def _project_version_record(raw: dict[str, Any]) -> ProjectVersionRecord:
    project = raw.get("project")
    project_name: str | None = None
    if isinstance(project, dict):
        candidate = project.get("name")
        if candidate is not None and not isinstance(candidate, str):
            raise VendorContractError("project.name must be a string or null")
        project_name = candidate
    elif isinstance(project, str):
        project_name = project
    elif project is not None:
        raise VendorContractError("project must be an object, string, or null")
    return ProjectVersionRecord(
        project_version_id=_int_required(raw, "id"),
        project_name=project_name,
        version_name=_str_required(raw, "name"),
        folder_guid=_str_or_none(raw, "folderGuid"),
    )


class FortifySsc(Connector):
    kind: ClassVar[str] = "fortify_ssc"
    version: ClassVar[str] = "0.1.0"
    display_name: ClassVar[str] = "Fortify Software Security Center"
    config_model: ClassVar[type[FortifySscConfig]] = FortifySscConfig
    auth_modes: ClassVar[tuple[str, ...]] = ("HeaderToken",)
    capabilities: ClassVar[tuple[str, ...]] = ("FindingSource", "TelemetrySource")
    flows: ClassVar[tuple[str, ...]] = ("F-108",)

    async def build_auth(self) -> AuthStrategy:
        if not isinstance(self.config, FortifySscConfig):
            raise ConfigError("fortify_ssc requires a FortifySscConfig")
        token = await self.ctx.secrets.resolve(self.config.api_token)
        try:
            text = token.decode("ascii")
        except UnicodeDecodeError as exc:
            raise ConfigError("api_token must be ASCII text") from exc
        return HeaderToken("Authorization", text, prefix="FortifyToken ")

    async def _probe_session(self) -> TargetProbeOutput:
        """[UNVERIFIED] Read version, context root, and permissions from ``userSession/info``.

        The response field names are not confirmed against a live server or a primary source.
        """
        result = await self.http.request("POST", _as_path("/userSession/info"), json="")
        return TargetProbeOutput.model_validate(_data_object(result.json()))

    async def check(self) -> HealthReport:
        try:
            probe = await self._probe_session()
        except AuthFailed:
            return HealthReport(
                status="failing",
                capabilities={"FindingSource": CapabilityHealth(status="failing", reason="vendor rejected credentials")},
            )
        except PermissionDenied as exc:
            return HealthReport(
                status="degraded",
                capabilities={"FindingSource": CapabilityHealth(status="degraded", reason=str(exc))},
            )
        except (RateLimited, TransientVendorError):
            return HealthReport(
                status="degraded",
                capabilities={"FindingSource": CapabilityHealth(status="degraded", reason="vendor unavailable")},
            )
        version = _ssc_version_tuple(probe.target_version)
        if version is None or version < _MIN_SSC_VERSION:
            return HealthReport(
                status="failing",
                capabilities={
                    "FindingSource": CapabilityHealth(
                        status="failing",
                        reason=f"SSC {probe.target_version} is unsupported; 24.2 or later is required",
                    )
                },
                vendor_version=probe.target_version,
            )
        if probe.effective_context_root.rstrip("/") != _context_root_of(self.config.base_url):
            return HealthReport(
                status="failing",
                capabilities={
                    "FindingSource": CapabilityHealth(
                        status="failing",
                        reason="base_url path does not match the server effective context root",
                    )
                },
                vendor_version=probe.target_version,
            )
        return HealthReport(
            status="healthy",
            capabilities={"FindingSource": CapabilityHealth(status="healthy")},
            vendor_version=probe.target_version,
        )

    def webhook_verifier(self, secret: bytes) -> WebhookVerifier | None:
        return SscHmacVerifier(secret)

    @stream(
        "issues",
        cursor=TimeIdCursor,
        capability="FindingSource",
        ocsf_class=2002,
        modes=("incremental", "full"),
        requires_target=True,
    )
    async def issues(self, target: Target | None, checkpoint: Any, mode: str) -> AsyncIterator[RawBatch]:
        if target is None:
            raise ConfigError("issues stream requires a project version target")
        project_version_id = int(target.source_uid)
        cursor = checkpoint if isinstance(checkpoint, TimeIdCursor) else TimeIdCursor(ts=None)
        # The delta ZIP contract is not live-validated. Both modes therefore perform the
        # documented full reconciliation, including every visibility state, and only the
        # final durable batch closes absence. No offset or delta ID is persisted early.
        params: dict[str, Any] = {
            "fields": "all",
            "orderby": "foundDate",
            "withoutCount": "true",
            "showhidden": "true",
            "showremoved": "true",
            "showsuppressed": "true",
        }
        async for items, _result in offset_pages(
            self.http,
            _as_path(f"/projectVersions/{project_version_id}/issues"),
            params,
            offset_param="start",
            limit_param="limit",
            limit=_PAGE_LIMIT,
            items=_data_list,
            max_pages=_MAX_PAGES,
        ):
            cursor = cursor.advance(items, ts_of=_issue_updated_at, id_of=_issue_id_of)
            yield RawBatch(records=items, checkpoint=cursor, complete=False)
        yield RawBatch(records=[], checkpoint=cursor, complete=True)

    @stream(
        "artifacts",
        cursor=SnapshotCursor,
        capability="FindingSource",
        record_type="artifact",
        modes=("full",),
        requires_target=True,
    )
    async def artifacts(self, target: Target | None, checkpoint: Any, mode: str) -> AsyncIterator[RawBatch]:
        if target is None:
            raise ConfigError("artifacts stream requires a project version target")
        project_version_id = int(target.source_uid)
        async for items, _result in offset_pages(
            self.http,
            _as_path(f"/projectVersions/{project_version_id}/artifacts"),
            {"withoutCount": "true", "fields": "all"},
            offset_param="start",
            limit_param="limit",
            limit=_PAGE_LIMIT,
            items=_data_list,
            max_pages=_MAX_PAGES,
        ):
            yield RawBatch(records=items, checkpoint=checkpoint, complete=False)
        yield RawBatch(records=[], checkpoint=checkpoint, complete=True)

    @stream(
        "activity",
        cursor=SequenceCursor,
        capability="FindingSource",
        record_type="activity",
        requires_target=False,
    )
    async def activity(self, target: Target | None, checkpoint: Any, mode: str) -> AsyncIterator[RawBatch]:
        cursor = checkpoint if isinstance(checkpoint, SequenceCursor) else None
        previous_seq = cursor.seq if cursor is not None and isinstance(cursor.seq, int) else None
        highest_seq = previous_seq
        # The API has no ID filter or ordering parameter. Scan bounded pages and retain the
        # previous checkpoint until the entire traversal succeeds; otherwise a failed early
        # page containing a high ID could hide lower IDs on retry. Duplicate replay is safe.
        async for items, _result in offset_pages(
            self.http,
            _as_path("/activityFeedEvents"),
            {"fields": "all", "withoutCount": "true"},
            offset_param="start",
            limit_param="limit",
            limit=_PAGE_LIMIT,
            items=_data_list,
            max_pages=_MAX_PAGES,
        ):
            visible: list[dict[str, Any]] = []
            for raw in items:
                seq = _activity_seq(raw)
                highest_seq = seq if highest_seq is None else max(highest_seq, seq)
                if mode == "full" or previous_seq is None or seq > previous_seq:
                    visible.append(raw)
            yield RawBatch(records=visible, checkpoint=cursor, complete=False)
        final_cursor = SequenceCursor(seq=highest_seq) if highest_seq is not None else cursor
        yield RawBatch(records=[], checkpoint=final_cursor, complete=True)

    @mapper("issues", version=2)
    def map_issue(self, raw: dict[str, Any], ctx: MapContext) -> list[VulnerabilityFinding]:
        record = _finding_record(raw)
        product = Product(name=_SSC_PRODUCT_NAME, vendor_name=_SSC_VENDOR_NAME)
        status_id, status = _status_of(record)
        return [
            VulnerabilityFinding(
                time=int(record.updated_at.timestamp() * 1000),
                severity_id=severity_id_from_label(record.friority, _FRIORITY_SEVERITY),
                activity_id=1,
                type_uid=200201,
                status_id=status_id,
                status=status,
                status_detail=record.audit_state,
                finding_info=FindingInfo(
                    uid=f"fortify_ssc:pv:{record.project_version_id}:instance:{record.issue_instance_id}",
                    uid_alt=str(record.issue_id),
                    title=record.category,
                    product=product,
                ),
                vulnerabilities=[],
                metadata=Metadata(
                    product=product,
                    uid=f"{record.project_version_id}:{record.issue_instance_id}",
                ),
                cloud=Cloud(provider=_SSC_CLOUD_PROVIDER),
                osint=[],
                unmapped={"fortify_ssc": record.model_dump(mode="json")},
                raw_data=bounded_raw(raw),
            )
        ]

    @mapper("artifacts", version=1)
    def map_artifact(self, raw: dict[str, Any], ctx: MapContext) -> list[ArtifactRecord]:
        return [
            ArtifactRecord(
                artifact_id=_int_required(raw, "id"),
                project_version_id=_int_required(raw, "projectVersionId"),
                status=_str_required(raw, "status"),
                sha256=_str_or_none(raw, "sha256"),
                indexed=raw.get("indexed") is True,
            )
        ]

    @mapper("activity", version=1)
    def map_activity(self, raw: dict[str, Any], ctx: MapContext) -> list[ActivityRecord]:
        project_version = raw.get("projectVersionId")
        if project_version is not None and (not isinstance(project_version, int) or isinstance(project_version, bool)):
            raise VendorContractError("projectVersionId must be an integer or null")
        return [
            ActivityRecord(
                event_id=_activity_seq(raw),
                project_version_id=project_version,
                event_type=_str_required(raw, "eventType"),
                occurred_at=_parse_ts(raw.get("eventDate"), "eventDate"),
            )
        ]

    @stream(
        "fpr_issues",
        cursor=SnapshotCursor,
        capability="FindingSource",
        ocsf_class=2002,
        modes=("full", "replay"),
        requires_target=False,
    )
    async def fpr_issues(
        self, target: Target | None, checkpoint: SnapshotCursor | None, mode: str
    ) -> AsyncIterator[RawBatch]:
        raise ConfigError("fpr_issues is offline-import-driven; submit a local FPR file")
        yield RawBatch(records=[], checkpoint=checkpoint, complete=False)

    @mapper("fpr_issues", version=1)
    def map_fpr_issue(self, raw: dict[str, Any], ctx: MapContext) -> list[Any]:
        return map_fpr_record(raw, ctx)

    @importer(
        "fortify_fpr",
        stream="fpr_issues",
        media_types=("application/zip", "application/octet-stream"),
        extensions=(".fpr",),
    )
    async def import_fpr(self, imported: ImportedFile) -> AsyncIterator[dict[str, Any]]:
        if not isinstance(self.config, FortifySscConfig):
            raise ConfigError("fortify_ssc requires a FortifySscConfig")
        for record in iter_fpr(imported.data, location_semantics=self.config.fpr_location_semantics):
            yield record

    @stream(
        "report_issues",
        cursor=SnapshotCursor,
        capability="FindingSource",
        ocsf_class=2002,
        modes=("full", "replay"),
        requires_target=False,
    )
    async def report_issues(
        self, target: Target | None, checkpoint: SnapshotCursor | None, mode: str
    ) -> AsyncIterator[RawBatch]:
        raise ConfigError("report_issues is offline-import-driven; submit a local Fortify or WebInspect XML report")
        yield RawBatch(records=[], checkpoint=checkpoint, complete=False)

    @mapper("report_issues", version=2)
    def map_report_issue(self, raw: dict[str, Any], ctx: MapContext) -> list[Any]:
        return map_report_record(raw, ctx)

    @importer(
        "fortify_report",
        stream="report_issues",
        media_types=("application/xml", "text/xml"),
        extensions=(".xml",),
    )
    async def import_report(self, imported: ImportedFile) -> AsyncIterator[dict[str, Any]]:
        for record in iter_fortify_xml(imported.data):
            yield record

    @webhook(event_types=_WEBHOOK_EVENTS)
    def parse_delivery(self, delivery: WebhookDelivery) -> list[StreamRecord]:
        return parse_delivery_payload(delivery)

    async def _bounded_list(
        self,
        path: str,
        *,
        limit: int,
        max_pages: int,
        params: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        async for items, _result in offset_pages(
            self.http,
            path,
            {"withoutCount": "true", **(params or {})},
            offset_param="start",
            limit_param="limit",
            limit=limit,
            items=_data_list,
            max_pages=max_pages,
        ):
            records.extend(items)
        return records

    @operation(
        "probe_target",
        input_model=ProbeArgs,
        output_model=TargetProbeOutput,
        classification="read",
        capability="FindingSource",
    )
    async def probe_target(self, args: ProbeArgs) -> TargetProbeOutput:
        return await self._probe_session()

    @operation(
        "list_project_versions",
        input_model=ProjectVersionListArgs,
        output_model=ProjectVersionListOutput,
        classification="read",
        capability="FindingSource",
    )
    async def list_project_versions(self, args: ProjectVersionListArgs) -> ProjectVersionListOutput:
        records = await self._bounded_list(
            _as_path("/projectVersions"),
            limit=args.limit,
            max_pages=args.max_pages,
            params={"includeInactive": str(args.include_inactive).lower(), "fields": "all"},
        )
        return ProjectVersionListOutput(records=[_project_version_record(raw) for raw in records])

    @operation(
        "list_issues",
        input_model=IssueListArgs,
        output_model=IssueListOutput,
        classification="read",
        capability="FindingSource",
    )
    async def list_issues(self, args: IssueListArgs) -> IssueListOutput:
        records = await self._bounded_list(
            _as_path(f"/projectVersions/{args.project_version_id}/issues"),
            limit=args.limit,
            max_pages=args.max_pages,
            params={
                "fields": "all",
                "showhidden": "true",
                "showremoved": "true",
                "showsuppressed": "true",
            },
        )
        return IssueListOutput(issues=[IssueRecord.model_validate(raw) for raw in records])

    @operation(
        "get_issue_details",
        input_model=IssueDetailArgs,
        output_model=IssueDetailOutput,
        classification="read",
        capability="FindingSource",
    )
    async def get_issue_details(self, args: IssueDetailArgs) -> IssueDetailOutput:
        result = await self.http.request(
            "GET", _as_path(f"/issueDetails/{args.issue_id}"), params={"fields": "all"}
        )
        issue = IssueDetailRecord.model_validate(_data_object(result.json()))
        if issue.project_version_id != args.project_version_id:
            raise VendorContractError("issue detail belongs to a different project version")
        return IssueDetailOutput(issue=issue)

    @operation(
        "list_issue_audit",
        input_model=IssueAuditArgs,
        output_model=IssueAuditOutput,
        classification="read",
        capability="FindingSource",
    )
    async def list_issue_audit(self, args: IssueAuditArgs) -> IssueAuditOutput:
        result = await self.http.request(
            "GET", _as_path(f"/issues/{args.issue_id}/auditHistory"), params={"fields": "all"}
        )
        records = _data_list(result.json())
        if len(records) > args.limit:
            raise VendorContractError("issue audit response exceeds the configured bound")
        audit = [IssueAuditRecord.model_validate(raw) for raw in records]
        if any(record.issue_id != args.issue_id for record in audit):
            raise VendorContractError("issue audit response contains another issue")
        return IssueAuditOutput(audit=audit)

    @operation(
        "list_comments",
        input_model=IssueCommentArgs,
        output_model=IssueCommentOutput,
        classification="read",
        capability="FindingSource",
    )
    async def list_comments(self, args: IssueCommentArgs) -> IssueCommentOutput:
        records = await self._bounded_list(
            _as_path(f"/issues/{args.issue_id}/comments"),
            limit=args.limit,
            max_pages=args.max_pages,
            params={"fields": "all"},
        )
        comments = [IssueCommentRecord.model_validate(raw) for raw in records]
        if any(record.issue_id != args.issue_id for record in comments):
            raise VendorContractError("issue comment response contains another issue")
        return IssueCommentOutput(comments=comments)

    @operation(
        "get_artifact",
        input_model=ArtifactArgs,
        output_model=ArtifactOutput,
        classification="read",
        capability="FindingSource",
    )
    async def get_artifact(self, args: ArtifactArgs) -> ArtifactOutput:
        result = await self.http.request("GET", _as_path(f"/artifacts/{args.artifact_id}"))
        return ArtifactOutput(artifact=ArtifactStatus.model_validate(_data_object(result.json())))

    @operation(
        "list_webhooks",
        input_model=WebhookListArgs,
        output_model=WebhookListOutput,
        classification="read",
        capability="FindingSource",
    )
    async def list_webhooks(self, args: WebhookListArgs) -> WebhookListOutput:
        records = await self._bounded_list(
            _as_path("/webhooks"),
            limit=args.limit,
            max_pages=args.max_pages,
            params={"fields": "all", "orderby": "id"},
        )
        return WebhookListOutput(webhooks=[WebhookDefinitionRecord.model_validate(raw) for raw in records])

    @operation(
        "list_webhook_history",
        input_model=WebhookHistoryArgs,
        output_model=WebhookHistoryOutput,
        classification="read",
        capability="FindingSource",
    )
    async def list_webhook_history(self, args: WebhookHistoryArgs) -> WebhookHistoryOutput:
        records = await self._bounded_list(
            _as_path(f"/webhooks/{args.webhook_id}/history"),
            limit=args.limit,
            max_pages=args.max_pages,
            params={"fields": "all"},
        )
        deliveries = [WebhookDeliveryRecord.model_validate(raw) for raw in records]
        if any(record.webhook_id != args.webhook_id for record in deliveries):
            raise VendorContractError("webhook history contains another webhook")
        return WebhookHistoryOutput(deliveries=deliveries)

    @operation(
        "get_issue",
        input_model=GetIssueArgs,
        output_model=IssueOutput,
        classification="read",
        capability="FindingSource",
    )
    async def get_issue(self, args: GetIssueArgs) -> IssueOutput:
        result = await self.http.request(
            "GET",
            _as_path(f"/projectVersions/{args.project_version_id}/issues/{args.issue_id}"),
            params={"fields": "all", "withoutCount": "true"},
        )
        body = result.json()
        if not isinstance(body, dict) or not isinstance(body.get("data"), dict):
            raise VendorContractError("issue response must carry a 'data' object")
        return IssueOutput(finding=_finding_record(body["data"]))

    @operation(
        "get_project_version",
        input_model=ProjectVersionArgs,
        output_model=ProjectVersionInfo,
        classification="read",
        capability="FindingSource",
    )
    async def get_project_version(self, args: ProjectVersionArgs) -> ProjectVersionInfo:
        result = await self.http.request("GET", _as_path(f"/projectVersions/{args.project_version_id}"))
        return ProjectVersionInfo(record=_project_version_record(_data_object(result.json())))

    @operation(
        "get_delta_export",
        input_model=DeltaExportArgs,
        output_model=DeltaExportOutput,
        classification="read",
        capability="FindingSource",
    )
    async def get_delta_export(self, args: DeltaExportArgs) -> DeltaExportOutput:
        """[UNVERIFIED] Poll a delta export. Its URL and response shape are unconfirmed against a live server."""
        result = await self.http.request("GET", _as_path(f"/issuesDeltaExports/{args.export_id}"))
        data = _data_object(result.json())
        state = _str_required(data, "status")
        if state not in {"EXPORT_PROCESS_STARTED", "EXPORT_PROCESS_COMPLETED", "EXPORT_PROCESS_FAILED"}:
            raise VendorContractError(f"unexpected delta export state {state!r}")
        export_id = _int_required(data, "id")
        if export_id != args.export_id:
            raise VendorContractError("delta export response has a different ID")
        return DeltaExportOutput(export_id=export_id, state=state, detail=data)

    @operation(
        "get_webhook_delivery",
        input_model=WebhookDeliveryArgs,
        output_model=WebhookDeliveryOutput,
        classification="read",
        capability="FindingSource",
    )
    async def get_webhook_delivery(self, args: WebhookDeliveryArgs) -> WebhookDeliveryOutput:
        """[UNVERIFIED] Read one webhook delivery record; retry and header behavior are unconfirmed."""
        result = await self.http.request(
            "GET", _as_path(f"/webhooks/{args.webhook_id}/history/{args.delivery_id}")
        )
        delivery = WebhookDeliveryRecord.model_validate(_data_object(result.json()))
        if delivery.webhook_id != args.webhook_id or delivery.delivery_id != args.delivery_id:
            raise VendorContractError("webhook delivery response has a different identity")
        return WebhookDeliveryOutput(delivery=delivery)

    @operation(
        "download_fpr",
        input_model=ArtifactArgs,
        output_model=FprArtifactRef,
        classification="read",
        capability="FindingSource",
    )
    async def download_fpr(self, args: ArtifactArgs) -> FprArtifactRef:
        """Fetch an FPR artifact through a single-use download token; the token is never logged."""
        token_result = await self.http.request(
            "POST",
            _as_path("/tokens"),
            json={"type": "DOWNLOAD"},
            idempotency="non_idempotent",
            expected=(200, 201),
        )
        body = token_result.json()
        if not isinstance(body, dict) or not isinstance(body.get("data"), dict):
            raise VendorContractError("token response must carry a 'data' object")
        token = _str_required(body["data"], "token")
        data = await self.http.stream_download(
            "GET",
            _as_path(f"/artifacts/{args.artifact_id}/download?mat={token}"),
            max_bytes=_MAX_DOWNLOAD_BYTES,
        )
        return FprArtifactRef(artifact_id=args.artifact_id, sha256=hashlib.sha256(data).hexdigest())

    @action(
        "audit_issue",
        classification="write",
        capability="FindingSource",
        input_model=AuditIssueArgs,
        idempotency="none",
    )
    async def plan_audit_issue(self, args: AuditIssueArgs) -> ActionPlan:
        self._require_write()
        current = await self._current_at_revision(args.project_version_id, args.issue_id, args.revision)
        current_index = _custom_tag_index(current["customTagValues"], args.custom_tag_guid)
        return ActionPlan(
            action="audit_issue",
            target_ref=f"fortify_ssc:issue:{args.project_version_id}:{args.issue_id}",
            diff={
                "customTag": {
                    "guid": args.custom_tag_guid,
                    "from": current_index,
                    "to": args.new_custom_tag_index,
                }
            },
            preconditions={"revision": args.revision},
            idempotency_key=(
                f"audit:{args.project_version_id}:{args.issue_id}:{args.revision}:"
                f"{args.custom_tag_guid}:{args.new_custom_tag_index}"
            ),
            changed=current_index != args.new_custom_tag_index,
            request={
                "method": "POST",
                "path": _as_path(f"/projectVersions/{args.project_version_id}/issues/action/audit"),
                "json": {
                    "issues": [{"id": args.issue_id, "revision": args.revision}],
                    "customTagAudit": [
                        {
                            "customTagGuid": args.custom_tag_guid,
                            "newCustomTagIndex": args.new_custom_tag_index,
                        }
                    ],
                    "comment": args.comment,
                },
            },
        )

    @plan_audit_issue.apply
    async def apply_audit_issue(self, plan: ActionPlan) -> ActionOutcome:
        if not plan.changed:
            return ActionOutcome(status="no_op", vendor_ref=plan.target_ref)
        await self._check_revision(plan)
        try:
            result = await self.http.request(
                "POST",
                plan.request["path"],
                json=plan.request["json"],
                idempotency="non_idempotent",
                expected=(200, 201),
            )
        except OutcomeUnknown as exc:
            return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))
        vendor_error = _vendor_action_error(plan.target_ref, result.json())
        if vendor_error is not None:
            return vendor_error
        prior = ActionOutcome(status="accepted_async", vendor_ref=plan.target_ref)
        try:
            return await self.reconcile_audit_issue(plan, prior)
        except (OutcomeUnknown, TransientVendorError, RateLimited) as exc:
            return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))

    @plan_audit_issue.reconcile
    async def reconcile_audit_issue(
        self, plan: ActionPlan, outcome: ActionOutcome
    ) -> ActionOutcome:
        pv, issue = _ids_from_ref(plan.target_ref)
        current = await self._issue_summary(pv, issue)
        desired = plan.request["json"]["customTagAudit"][0]
        current_index = _custom_tag_index(current["customTagValues"], desired["customTagGuid"])
        if current_index == desired["newCustomTagIndex"]:
            return ActionOutcome(
                status="succeeded",
                vendor_ref=plan.target_ref,
                result={"reconciled": True, "customTag": desired},
            )
        return ActionOutcome(
            status="failed",
            vendor_ref=plan.target_ref,
            error=f"issue {issue} custom tag is at index {current_index!r}",
        )

    @action(
        "set_issue_suppression",
        classification="write",
        capability="FindingSource",
        input_model=SetIssueSuppressionArgs,
        idempotency="natural_key",
    )
    async def plan_set_issue_suppression(self, args: SetIssueSuppressionArgs) -> ActionPlan:
        self._require_write()
        current = await self._current_at_revision(args.project_version_id, args.issue_id, args.revision)
        return ActionPlan(
            action="set_issue_suppression",
            target_ref=f"fortify_ssc:issue:{args.project_version_id}:{args.issue_id}",
            diff={"suppressed": {"from": current["suppressed"], "to": args.suppressed}},
            preconditions={"revision": args.revision},
            idempotency_key=(
                f"suppress:{args.project_version_id}:{args.issue_id}:{args.revision}:{args.suppressed}"
            ),
            changed=current["suppressed"] != args.suppressed,
            request={
                "method": "POST",
                "path": _as_path(f"/projectVersions/{args.project_version_id}/issues/action/suppress"),
                "json": {
                    "issues": [{"id": args.issue_id, "revision": args.revision}],
                    "suppressed": args.suppressed,
                },
            },
        )

    @plan_set_issue_suppression.apply
    async def apply_set_issue_suppression(self, plan: ActionPlan) -> ActionOutcome:
        if not plan.changed:
            return ActionOutcome(status="no_op", vendor_ref=plan.target_ref)
        await self._check_revision(plan)
        try:
            result = await self.http.request(
                "POST",
                plan.request["path"],
                json=plan.request["json"],
                idempotency="non_idempotent",
                expected=(200, 201),
            )
        except OutcomeUnknown as exc:
            return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))
        vendor_error = _vendor_action_error(plan.target_ref, result.json())
        if vendor_error is not None:
            return vendor_error
        prior = ActionOutcome(status="accepted_async", vendor_ref=plan.target_ref)
        try:
            return await self.reconcile_set_issue_suppression(plan, prior)
        except (OutcomeUnknown, TransientVendorError, RateLimited) as exc:
            return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))

    @plan_set_issue_suppression.reconcile
    async def reconcile_set_issue_suppression(
        self, plan: ActionPlan, outcome: ActionOutcome
    ) -> ActionOutcome:
        pv, issue = _ids_from_ref(plan.target_ref)
        current = await self._issue_summary(pv, issue)
        if current["suppressed"] == plan.request["json"]["suppressed"]:
            return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref, result={"reconciled": True})
        return ActionOutcome(status="failed", vendor_ref=plan.target_ref, error="suppression state did not converge")

    @action(
        "assign_issue",
        classification="write",
        capability="FindingSource",
        input_model=AssignIssueArgs,
        idempotency="none",
    )
    async def plan_assign_issue(self, args: AssignIssueArgs) -> ActionPlan:
        self._require_write()
        current = await self._current_at_revision(args.project_version_id, args.issue_id, args.revision)
        return ActionPlan(
            action="assign_issue",
            target_ref=f"fortify_ssc:issue:{args.project_version_id}:{args.issue_id}",
            diff={"assignee": {"from": current["assignee"], "to": args.assignee}},
            preconditions={"revision": args.revision},
            idempotency_key=f"assign:{args.project_version_id}:{args.issue_id}:{args.revision}:{args.assignee}",
            changed=current["assignee"] != args.assignee,
            request={
                "method": "POST",
                "path": _as_path(f"/projectVersions/{args.project_version_id}/issues/action/assignUser"),
                "json": {
                    "issues": [{"id": args.issue_id, "revision": args.revision}],
                    "user": args.assignee,
                },
            },
        )

    @plan_assign_issue.apply
    async def apply_assign_issue(self, plan: ActionPlan) -> ActionOutcome:
        if not plan.changed:
            return ActionOutcome(status="no_op", vendor_ref=plan.target_ref)
        await self._check_revision(plan)
        try:
            result = await self.http.request(
                "POST",
                plan.request["path"],
                json=plan.request["json"],
                idempotency="non_idempotent",
                expected=(200, 201),
            )
        except OutcomeUnknown as exc:
            return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))
        vendor_error = _vendor_action_error(plan.target_ref, result.json())
        if vendor_error is not None:
            return vendor_error
        prior = ActionOutcome(status="accepted_async", vendor_ref=plan.target_ref)
        try:
            return await self.reconcile_assign_issue(plan, prior)
        except (OutcomeUnknown, TransientVendorError, RateLimited) as exc:
            return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))

    @plan_assign_issue.reconcile
    async def reconcile_assign_issue(
        self, plan: ActionPlan, outcome: ActionOutcome
    ) -> ActionOutcome:
        pv, issue = _ids_from_ref(plan.target_ref)
        current = await self._issue_summary(pv, issue)
        if current["assignee"] == plan.request["json"]["user"]:
            return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref, result={"reconciled": True})
        return ActionOutcome(status="failed", vendor_ref=plan.target_ref, error="assignee did not converge")

    @action(
        "add_issue_comment",
        classification="write",
        capability="FindingSource",
        input_model=AddIssueCommentArgs,
        idempotency="none",
    )
    async def plan_add_issue_comment(self, args: AddIssueCommentArgs) -> ActionPlan:
        self._require_write()
        await self._current_at_revision(args.project_version_id, args.issue_id, args.revision)
        return ActionPlan(
            action="add_issue_comment",
            target_ref=f"fortify_ssc:issue:{args.project_version_id}:{args.issue_id}",
            diff={"comment": {"added": _digest(args.comment)}},
            preconditions={"revision": args.revision},
            idempotency_key=f"comment:{args.project_version_id}:{args.issue_id}:{_digest(args.comment)}",
            changed=True,
            request={
                "method": "POST",
                "path": _as_path(f"/projectVersions/{args.project_version_id}/issues/action/audit"),
                "json": {
                    "issues": [{"id": args.issue_id, "revision": args.revision}],
                    "comment": args.comment,
                },
            },
        )

    @plan_add_issue_comment.apply
    async def apply_add_issue_comment(self, plan: ActionPlan) -> ActionOutcome:
        await self._check_revision(plan)
        try:
            result = await self.http.request(
                "POST",
                plan.request["path"],
                json=plan.request["json"],
                idempotency="non_idempotent",
                expected=(200, 201),
            )
        except OutcomeUnknown as exc:
            return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))
        vendor_error = _vendor_action_error(plan.target_ref, result.json())
        if vendor_error is not None:
            return vendor_error
        prior = ActionOutcome(status="accepted_async", vendor_ref=plan.target_ref)
        try:
            return await self.reconcile_add_issue_comment(plan, prior)
        except (OutcomeUnknown, TransientVendorError, RateLimited) as exc:
            return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))

    @plan_add_issue_comment.reconcile
    async def reconcile_add_issue_comment(
        self, plan: ActionPlan, outcome: ActionOutcome
    ) -> ActionOutcome:
        pv, issue = _ids_from_ref(plan.target_ref)
        wanted = plan.diff["comment"]["added"]
        comments = await self.list_comments(
            IssueCommentArgs(project_version_id=pv, issue_id=issue)
        )
        for comment in comments.comments:
            if _digest(comment.comment) == wanted:
                return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref, result={"reconciled": True})
        return ActionOutcome(
            status="unverified",
            vendor_ref=plan.target_ref,
            error="comment not present in bounded comment list; absence cannot be confirmed",
        )

    @action(
        "upload_fpr",
        classification="write",
        capability="FindingSource",
        input_model=UploadFprArgs,
        idempotency="natural_key",
    )
    async def plan_upload_fpr(self, args: UploadFprArgs) -> ActionPlan:
        self._require_write()
        try:
            raw_bytes = base64.b64decode(args.fpr_base64, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise VendorContractError("fpr_base64 is not valid base64") from exc
        if hashlib.sha256(raw_bytes).hexdigest() != args.fpr_sha256:
            raise VendorContractError("fpr_sha256 does not match the uploaded bytes")
        return ActionPlan(
            action="upload_fpr",
            target_ref=f"fortify_ssc:project_version:{args.project_version_id}",
            diff={"artifact": {"sha256": args.fpr_sha256, "bytes": len(raw_bytes)}},
            preconditions={
                "sha256": args.fpr_sha256,
                "bytes": len(raw_bytes),
                "file_name": _upload_file_name(args.fpr_sha256),
            },
            idempotency_key=f"upload:{args.project_version_id}:{args.fpr_sha256}",
            changed=True,
            request={
                "method": "POST",
                "path": _as_path(f"/projectVersions/{args.project_version_id}/artifacts"),
                "fpr_base64": args.fpr_base64,
            },
        )

    @plan_upload_fpr.apply
    async def apply_upload_fpr(self, plan: ActionPlan) -> ActionOutcome:
        payload = base64.b64decode(plan.request["fpr_base64"], validate=True)
        existing = await self._find_uploaded_artifact(
            _pv_from_ref(plan.target_ref), plan.preconditions["file_name"], plan.preconditions["bytes"]
        )
        if existing is not None:
            # Natural-key idempotency: an identical artifact already exists, so no second write.
            prior = ActionOutcome(
                status="accepted_async", vendor_ref=plan.target_ref, result={"artifact_id": existing.get("id")}
            )
            return await self._settle_upload(plan, prior)
        try:
            result = await self.http.request(
                "POST",
                plan.request["path"],
                files={"file": (plan.preconditions["file_name"], payload, "application/octet-stream")},
                idempotency="non_idempotent",
                expected=(200, 201, 202),
            )
        except OutcomeUnknown as exc:
            return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))
        artifact_id = _artifact_id_of(result.json())
        if artifact_id is None:
            return ActionOutcome(
                status="outcome_unknown",
                vendor_ref=plan.target_ref,
                error="upload response carried no artifact id",
            )
        prior = ActionOutcome(
            status="accepted_async", vendor_ref=plan.target_ref, result={"artifact_id": artifact_id}
        )
        return await self._settle_upload(plan, prior)

    async def _settle_upload(self, plan: ActionPlan, prior: ActionOutcome) -> ActionOutcome:
        try:
            return await self.reconcile_upload_fpr(plan, prior)
        except (OutcomeUnknown, TransientVendorError, RateLimited) as exc:
            return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))

    @plan_upload_fpr.reconcile
    async def reconcile_upload_fpr(
        self, plan: ActionPlan, outcome: ActionOutcome
    ) -> ActionOutcome:
        artifact = await self._uploaded_artifact(plan, outcome)
        if artifact is None:
            return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error="uploaded artifact not found yet")
        if artifact.get("status") == "ERROR_PROCESSING":
            return ActionOutcome(status="failed", vendor_ref=plan.target_ref, error="artifact processing failed")
        indexed = artifact.get("indexed") is True
        return ActionOutcome(
            status="succeeded" if indexed else "accepted_async",
            vendor_ref=plan.target_ref,
            result={"artifact_id": artifact.get("id"), "indexed": indexed},
        )

    async def _uploaded_artifact(self, plan: ActionPlan, outcome: ActionOutcome) -> dict[str, Any] | None:
        file_name = plan.preconditions["file_name"]
        size = plan.preconditions["bytes"]
        prior_id = _prior_artifact_id(outcome)
        if prior_id is not None:
            try:
                artifact = await self._artifact_state(prior_id)
            except (NotFound, VendorContractError):
                artifact = None
            if artifact is not None and _is_upload_of(artifact, file_name, size):
                return artifact
        return await self._find_uploaded_artifact(_pv_from_ref(plan.target_ref), file_name, size)

    async def _find_uploaded_artifact(self, project_version_id: int, file_name: str, size: int) -> dict[str, Any] | None:
        async for items, _result in offset_pages(
            self.http,
            _as_path(f"/projectVersions/{project_version_id}/artifacts"),
            {"withoutCount": "true", "fields": "all"},
            offset_param="start",
            limit_param="limit",
            limit=_PAGE_LIMIT,
            items=_data_list,
            max_pages=_MAX_PAGES,
        ):
            for artifact in items:
                if _is_upload_of(artifact, file_name, size):
                    return artifact
        return None

    @action(
        "create_webhook",
        classification="write",
        capability="FindingSource",
        input_model=CreateWebhookArgs,
        idempotency="none",
    )
    async def plan_create_webhook(self, args: CreateWebhookArgs) -> ActionPlan:
        self._require_write()
        payload = {
            "url": args.url,
            "contentType": args.content_type,
            "objectVersion": args.object_version,
            "active": args.active,
            "allowInsecureTLS": args.allow_insecure_tls,
            "monitorApps": args.monitor_apps,
            "monitorEvents": args.monitor_events,
            "monitoredAppVersionIds": args.monitored_app_version_ids,
            "monitoredAppVersionEvents": args.monitored_app_version_events,
            "monitoredGlobalEvents": args.monitored_global_events,
        }
        return ActionPlan(
            action="create_webhook",
            target_ref=f"fortify_ssc:webhook:{_digest(args.url)}",
            diff={"webhook": {"url_sha256": _digest(args.url), "monitorEvents": args.monitor_events}},
            preconditions={"object_version": args.object_version},
            idempotency_key=f"webhook:{_digest(args.url)}:{args.object_version}",
            changed=True,
            request={"method": "POST", "path": _as_path("/webhooks"), "json": payload},
        )

    @plan_create_webhook.apply
    async def apply_create_webhook(self, plan: ActionPlan) -> ActionOutcome:
        try:
            result = await self.http.request(
                "POST",
                plan.request["path"],
                json=plan.request["json"],
                idempotency="non_idempotent",
                expected=(200, 201),
            )
        except OutcomeUnknown as exc:
            return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))
        data = _data_object(result.json())
        webhook_id = data.get("id")
        if not isinstance(webhook_id, int) or isinstance(webhook_id, bool) or webhook_id < 1:
            return ActionOutcome(
                status="outcome_unknown",
                vendor_ref=plan.target_ref,
                error="webhook create response carried no valid id",
            )
        prior = ActionOutcome(
            status="accepted_async", vendor_ref=plan.target_ref, result={"webhook_id": webhook_id}
        )
        try:
            return await self.reconcile_create_webhook(plan, prior)
        except (OutcomeUnknown, TransientVendorError, RateLimited) as exc:
            return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))

    @plan_create_webhook.reconcile
    async def reconcile_create_webhook(
        self, plan: ActionPlan, outcome: ActionOutcome
    ) -> ActionOutcome:
        desired = plan.request["json"]
        prior_id = outcome.result.get("webhook_id") if outcome.result else None
        candidates: list[WebhookDefinitionRecord] = []
        if isinstance(prior_id, int) and not isinstance(prior_id, bool):
            try:
                result = await self.http.request("GET", _as_path(f"/webhooks/{prior_id}"))
            except NotFound:
                pass
            else:
                candidates = [WebhookDefinitionRecord.model_validate(_data_object(result.json()))]
        else:
            candidates = (await self.list_webhooks(WebhookListArgs())).webhooks
        matches = []
        for candidate in candidates:
            actual = candidate.model_dump(by_alias=True, mode="json")
            if all(actual.get(key) == value for key, value in desired.items()):
                matches.append(candidate)
        if len(matches) == 1:
            return ActionOutcome(
                status="succeeded",
                vendor_ref=plan.target_ref,
                result={"reconciled": True, "webhook_id": matches[0].webhook_id},
            )
        if not matches:
            return ActionOutcome(
                status="failed",
                vendor_ref=plan.target_ref,
                error="webhook absent after create",
            )
        return ActionOutcome(
            status="outcome_unknown",
            vendor_ref=plan.target_ref,
            error=f"webhook read-back produced {len(matches)} matching definitions",
        )

    @action(
        "purge_artifact",
        classification="destructive",
        capability="FindingSource",
        input_model=PurgeArtifactArgs,
        idempotency="none",
    )
    async def plan_purge_artifact(self, args: PurgeArtifactArgs) -> ActionPlan:
        self._require_destructive()
        return ActionPlan(
            action="purge_artifact",
            target_ref=f"fortify_ssc:artifact:{args.artifact_id}",
            diff={"purge": {"artifact_id": args.artifact_id}},
            preconditions={"version_number": args.version_number, "approval_ref": args.approval_ref},
            idempotency_key=f"purge-artifact:{args.artifact_id}:{args.version_number}",
            changed=True,
            request={
                "method": "POST",
                "path": _as_path("/artifacts/action/purge"),
                "json": {"artifactIds": [args.artifact_id]},
            },
        )

    @plan_purge_artifact.apply
    async def apply_purge_artifact(self, plan: ActionPlan) -> ActionOutcome:
        artifact_id = _ids_of_artifact_ref(plan.target_ref)
        try:
            current = await self._artifact_state(artifact_id)
        except NotFound:
            return ActionOutcome(status="failed", vendor_ref=plan.target_ref, error="artifact not found before purge")
        if current.get("versionNumber") != plan.preconditions["version_number"]:
            raise StalePlan(f"artifact {artifact_id} moved to version {current.get('versionNumber')} after planning")
        prior = ActionOutcome(status="accepted_async", vendor_ref=plan.target_ref, result={"purged": False})
        purge_started = ("PURGING", "ERROR_PURGING", "PURGED", "DELETED")
        if current.get("purged") is True or current.get("status") in purge_started:
            # A purge already ran or is running; re-sending it would be a second write.
            return await self._settle_purge(plan, prior)
        try:
            await self.http.request(
                "POST",
                plan.request["path"],
                json=plan.request["json"],
                idempotency="non_idempotent",
                expected=(200,),
            )
        except OutcomeUnknown as exc:
            return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))
        return await self._settle_purge(plan, prior)

    async def _settle_purge(self, plan: ActionPlan, prior: ActionOutcome) -> ActionOutcome:
        try:
            return await self.reconcile_purge_artifact(plan, prior)
        except (OutcomeUnknown, TransientVendorError, RateLimited) as exc:
            return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))

    @plan_purge_artifact.reconcile
    async def reconcile_purge_artifact(
        self, plan: ActionPlan, outcome: ActionOutcome
    ) -> ActionOutcome:
        artifact_id = _ids_of_artifact_ref(plan.target_ref)
        try:
            current = await self._artifact_state(artifact_id)
        except NotFound:
            # The plan confirmed the artifact existed, so a later 404 means the row is gone.
            return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref, result={"purged": True})
        status = current.get("status")
        if current.get("purged") is True or status in ("PURGED", "DELETED"):
            return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref, result={"purged": True})
        if status == "PURGING":
            return ActionOutcome(status="accepted_async", vendor_ref=plan.target_ref, result={"purged": False})
        if status == "ERROR_PURGING":
            return ActionOutcome(status="failed", vendor_ref=plan.target_ref, error="artifact purge reported an error")
        return ActionOutcome(
            status="failed",
            vendor_ref=plan.target_ref,
            error="artifact still present after purge",
        )

    @action(
        "purge_project_version",
        classification="destructive",
        capability="FindingSource",
        input_model=PurgeProjectVersionArgs,
        idempotency="none",
    )
    async def plan_purge_project_version(self, args: PurgeProjectVersionArgs) -> ActionPlan:
        self._require_destructive()
        await self.http.request("GET", _as_path(f"/projectVersions/{args.project_version_id}"))
        artifacts = await self._bounded_list(
            _as_path(f"/projectVersions/{args.project_version_id}/artifacts"),
            limit=_PAGE_LIMIT,
            max_pages=_MAX_PAGES,
            params={"fields": "all"},
        )
        artifact_ids = sorted(_int_required(artifact, "id") for artifact in artifacts)
        return ActionPlan(
            action="purge_project_version",
            target_ref=f"fortify_ssc:project_version:{args.project_version_id}",
            diff={"purge": {"project_version_id": args.project_version_id, "artifact_ids": artifact_ids}},
            preconditions={"approval_ref": args.approval_ref, "artifact_ids": artifact_ids},
            idempotency_key=f"purge-pv:{args.project_version_id}:{args.approval_ref}",
            changed=bool(artifact_ids),
            request={
                "method": "POST",
                "path": _as_path("/projectVersions/action/purge"),
                "json": {"projectVersionIds": [args.project_version_id]},
            },
        )

    @plan_purge_project_version.apply
    async def apply_purge_project_version(self, plan: ActionPlan) -> ActionOutcome:
        if not plan.changed:
            return ActionOutcome(status="no_op", vendor_ref=plan.target_ref, result={"purged": True})
        artifact_ids = plan.preconditions["artifact_ids"]
        prior = ActionOutcome(
            status="accepted_async", vendor_ref=plan.target_ref, result={"artifact_ids": artifact_ids}
        )
        for artifact_id in artifact_ids:
            try:
                current = await self._artifact_state(artifact_id)
            except NotFound:
                continue
            if current.get("purged") is True or current.get("status") in {
                "PURGING",
                "ERROR_PURGING",
                "PURGED",
                "DELETED",
            }:
                return await self._settle_project_version_purge(plan, prior)
        try:
            await self.http.request(
                "POST",
                plan.request["path"],
                json=plan.request["json"],
                idempotency="non_idempotent",
                expected=(200,),
            )
        except OutcomeUnknown as exc:
            return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))
        return await self._settle_project_version_purge(plan, prior)

    async def _settle_project_version_purge(
        self, plan: ActionPlan, prior: ActionOutcome
    ) -> ActionOutcome:
        try:
            return await self.reconcile_purge_project_version(plan, prior)
        except (OutcomeUnknown, TransientVendorError, RateLimited) as exc:
            return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))

    @plan_purge_project_version.reconcile
    async def reconcile_purge_project_version(
        self, plan: ActionPlan, outcome: ActionOutcome
    ) -> ActionOutcome:
        artifact_ids = plan.preconditions["artifact_ids"]
        pending = False
        for artifact_id in artifact_ids:
            try:
                current = await self._artifact_state(artifact_id)
            except NotFound:
                continue
            status = current.get("status")
            if current.get("purged") is True or status in {"PURGED", "DELETED"}:
                continue
            if status == "ERROR_PURGING":
                return ActionOutcome(
                    status="failed",
                    vendor_ref=plan.target_ref,
                    error=f"artifact {artifact_id} purge reported an error",
                )
            if status == "PURGING":
                pending = True
                continue
            return ActionOutcome(
                status="outcome_unknown",
                vendor_ref=plan.target_ref,
                error=f"artifact {artifact_id} is not purged",
            )
        if pending:
            return ActionOutcome(
                status="accepted_async",
                vendor_ref=plan.target_ref,
                result={"artifact_ids": artifact_ids, "purged": False},
            )
        return ActionOutcome(
            status="succeeded",
            vendor_ref=plan.target_ref,
            result={"artifact_ids": artifact_ids, "purged": True},
        )

    async def _artifact_state(self, artifact_id: int) -> dict[str, Any]:
        result = await self.http.request("GET", _as_path(f"/artifacts/{artifact_id}"), params={"fields": "all"})
        return _data_object(result.json())

    async def _issue_summary(self, project_version_id: int, issue_id: int) -> dict[str, Any]:
        result = await self.http.request(
            "GET",
            _as_path(f"/issueDetails/{issue_id}"),
            params={"fields": "all"},
        )
        raw = _data_object(result.json())
        if _int_required(raw, "id") != issue_id or _int_required(raw, "projectVersionId") != project_version_id:
            raise VendorContractError("issue detail response has a different identity")
        assigned = raw.get("assignedUser")
        if assigned is not None and not isinstance(assigned, dict):
            raise VendorContractError("assignedUser must be an object or null")
        custom_tags = raw.get("customTagValues", [])
        if not isinstance(custom_tags, list) or not all(isinstance(value, dict) for value in custom_tags):
            raise VendorContractError("customTagValues must be an array of objects")
        return {
            "revision": _int_required(raw, "revision"),
            "customTagValues": custom_tags,
            "suppressed": bool(raw.get("suppressed", False)),
            "assignee": _str_or_none(assigned, "userName") if isinstance(assigned, dict) else None,
        }

    async def _current_at_revision(
        self, project_version_id: int, issue_id: int, revision: int
    ) -> dict[str, Any]:
        current = await self._issue_summary(project_version_id, issue_id)
        if current["revision"] != revision:
            raise StalePlan(f"issue {issue_id} is at revision {current['revision']}, not {revision}")
        return current

    def _require_write(self) -> None:
        if not isinstance(self.config, FortifySscConfig) or not self.config.write_enabled:
            raise PermissionDenied("write", "write actions require write_enabled on this connection")

    def _require_destructive(self) -> None:
        self._require_write()
        if not isinstance(self.config, FortifySscConfig) or not self.config.destructive_enabled:
            raise PermissionDenied("destructive", "purge actions require destructive_enabled on this connection")

    async def _check_revision(self, plan: ActionPlan) -> None:
        pv, issue = _ids_from_ref(plan.target_ref)
        current = await self._issue_summary(pv, issue)
        if current["revision"] != plan.preconditions["revision"]:
            raise StalePlan(f"issue {issue} moved to revision {current['revision']} after planning")


def _ids_from_ref(target_ref: str) -> tuple[int, int]:
    parts = target_ref.split(":")
    if len(parts) != 4 or parts[0] != "fortify_ssc" or parts[1] != "issue":
        raise VendorContractError(f"malformed issue target_ref {target_ref!r}")
    return int(parts[2]), int(parts[3])


def _pv_from_ref(target_ref: str) -> int:
    parts = target_ref.split(":")
    if len(parts) != 3 or parts[0] != "fortify_ssc" or parts[1] != "project_version":
        raise VendorContractError(f"malformed project_version target_ref {target_ref!r}")
    return int(parts[2])


def _ids_of_artifact_ref(target_ref: str) -> int:
    parts = target_ref.split(":")
    if len(parts) != 3 or parts[0] != "fortify_ssc" or parts[1] != "artifact":
        raise VendorContractError(f"malformed artifact target_ref {target_ref!r}")
    return int(parts[2])


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _custom_tag_index(values: list[dict[str, Any]], guid: str) -> int | None:
    matches = [value for value in values if value.get("customTagGuid") == guid]
    if len(matches) > 1:
        raise VendorContractError("customTagValues contains duplicate tag GUIDs")
    return _int_required(matches[0], "newCustomTagIndex") if matches else None


def _vendor_action_error(target_ref: str, body: Any) -> ActionOutcome | None:
    data = _data_object(body)
    status = _str_required(data, "status")
    if status in {"success", "created"}:
        return None
    message = data.get("message")
    detail = message if isinstance(message, str) and message else f"vendor action status {status!r}"
    return ActionOutcome(status="failed", vendor_ref=target_ref, error=detail)
