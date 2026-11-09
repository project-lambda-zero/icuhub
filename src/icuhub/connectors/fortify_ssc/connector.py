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

from pydantic import BaseModel, ConfigDict, Field

from icuhub.connectors.fortify_ssc.models import (
    AddIssueCommentArgs,
    AssignIssueArgs,
    AuditIssueArgs,
    CreateWebhookArgs,
    FortifySscConfig,
    GetIssueArgs,
    IssueListArgs,
    PurgeArtifactArgs,
    PurgeProjectVersionArgs,
    SetIssueSuppressionArgs,
    UploadFprArgs,
)
from icuhub.connectors.fortify_ssc.webhooks import SscHmacVerifier, parse_delivery_payload
from icuhub.kit.auth import AuthStrategy, HeaderToken
from icuhub.kit.connector import Connector, action, mapper, operation, stream, webhook
from icuhub.kit.cursors import SequenceCursor, SnapshotCursor, TimeIdCursor
from icuhub.kit.errors import (
    AuthFailed,
    ConfigError,
    OutcomeUnknown,
    PermissionDenied,
    RateLimited,
    StalePlan,
    TransientVendorError,
    VendorContractError,
)
from icuhub.kit.paginate import offset_pages
from icuhub.kit.types import (
    ActionOutcome,
    ActionPlan,
    CapabilityHealth,
    HealthReport,
    MapContext,
    RawBatch,
    StreamRecord,
    Target,
    WebhookDelivery,
)
from icuhub.kit.webhook import WebhookVerifier

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

_WEBHOOK_EVENTS = ("ISSUE_CHANGED", "ARTIFACT_PROCESSED", "PROJECT_VERSION_CHANGED")
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


class ProjectVersionRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    project_version_id: int
    project_name: str | None
    version_name: str
    folder_guid: str | None


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

    export_id: str = Field(min_length=1, max_length=128)


class DeltaExportOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    export_id: str
    state: str
    detail: dict[str, Any] = Field(default_factory=dict)


class WebhookDeliveryArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    webhook_id: int = Field(ge=1)


class WebhookDeliveryOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    webhook_id: int
    detail: dict[str, Any] = Field(default_factory=dict)


class FprArtifactRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    artifact_id: int
    sha256: str


class ArtifactArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    artifact_id: int = Field(ge=1)


class ProjectVersionInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    record: ProjectVersionRecord


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


def _issue_id_of(raw: dict[str, Any]) -> str:
    return _str_required(raw, "issueInstanceId")


def _issue_updated_at(raw: dict[str, Any]) -> datetime:
    return _parse_ts(raw.get("updated"), "updated")


def _activity_seq(raw: dict[str, Any]) -> int:
    return _int_required(raw, "id")


def _audit_state(raw: dict[str, Any]) -> str | None:
    value = raw.get("auditState")
    if value is None or isinstance(value, str):
        return value
    raise VendorContractError("auditState must be a string or null")


def _as_path(path: str) -> str:
    return f"{_API}{path}"


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

    async def check(self) -> HealthReport:
        try:
            await self.http.request("GET", _as_path("/projectVersions"), params={"limit": 1, "withoutCount": "true"})
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
        return HealthReport(
            status="healthy",
            capabilities={"FindingSource": CapabilityHealth(status="healthy")},
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
        params: dict[str, Any] = {"fields": "all", "orderby": "updated", "withoutCount": "true"}
        window = cursor.window_start()
        if mode == "incremental" and window is not None:
            params["filter"] = f"updated:[{window.isoformat()}]"
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
        if mode == "full":
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
            _as_path("/artifacts"),
            {"q": f"projectVersionId:{project_version_id}", "withoutCount": "true", "fields": "all"},
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
        params: dict[str, Any] = {"orderby": "id", "withoutCount": "true"}
        if mode == "incremental" and cursor is not None and isinstance(cursor.seq, int):
            params["q"] = f"id:[{cursor.seq + 1} TO *]"
        current: SequenceCursor | None = cursor
        async for items, _result in offset_pages(
            self.http,
            _as_path("/activities"),
            params,
            offset_param="start",
            limit_param="limit",
            limit=_PAGE_LIMIT,
            items=_data_list,
            max_pages=_MAX_PAGES,
        ):
            for raw in items:
                seq = _activity_seq(raw)
                current = SequenceCursor(seq=seq) if current is None else current.advance(seq)
            yield RawBatch(records=items, checkpoint=current, complete=False)
        yield RawBatch(records=[], checkpoint=current, complete=True)

    @mapper("issues", version=1)
    def map_issue(self, raw: dict[str, Any], ctx: MapContext) -> list[FindingRecord]:
        project_version = raw.get("projectVersionId")
        if not isinstance(project_version, int) or isinstance(project_version, bool):
            raise VendorContractError("projectVersionId must be an integer")
        return [
            FindingRecord(
                issue_instance_id=_issue_id_of(raw),
                issue_id=_int_required(raw, "id"),
                project_version_id=project_version,
                revision=_int_required(raw, "revision"),
                rule_guid=_str_or_none(raw, "primaryRuleGuid"),
                category=_str_or_none(raw, "category"),
                file_path=_str_or_none(raw, "fileName"),
                line=raw.get("lineNumber") if isinstance(raw.get("lineNumber"), int) else None,
                audit_state=_audit_state(raw),
                suppressed=bool(raw.get("suppressed", False)),
                removed=bool(raw.get("removed", False)),
                updated_at=_parse_ts(raw.get("updated"), "updated"),
                fingerprint_inputs={
                    "primaryRuleGuid": _str_or_none(raw, "primaryRuleGuid"),
                    "category": _str_or_none(raw, "category"),
                    "fileName": _str_or_none(raw, "fileName"),
                    "lineNumber": raw.get("lineNumber"),
                },
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
                event_type=_str_required(raw, "type"),
                occurred_at=_parse_ts(raw.get("eventDate"), "eventDate"),
            )
        ]

    @webhook(event_types=_WEBHOOK_EVENTS, header_event="x-ssc-event")
    def parse_delivery(self, delivery: WebhookDelivery) -> list[StreamRecord]:
        return parse_delivery_payload(delivery)

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
        ctx = MapContext(
            connection_id=self.ctx.connection_id,
            tenant_id=self.ctx.tenant_id,
            connector_kind=self.kind,
            received_at=self.ctx.clock(),
        )
        return IssueOutput(finding=self.map_issue(body["data"], ctx)[0])

    @operation(
        "get_project_version",
        input_model=ProjectVersionArgs,
        output_model=ProjectVersionInfo,
        classification="read",
        capability="FindingSource",
    )
    async def get_project_version(self, args: ProjectVersionArgs) -> ProjectVersionInfo:
        result = await self.http.request("GET", _as_path(f"/projectVersions/{args.project_version_id}"))
        body = result.json()
        if not isinstance(body, dict) or not isinstance(body.get("data"), dict):
            raise VendorContractError("project version response must carry a 'data' object")
        raw = body["data"]
        return ProjectVersionInfo(
            record=ProjectVersionRecord(
                project_version_id=_int_required(raw, "id"),
                project_name=_str_or_none(raw, "project") if isinstance(raw.get("project"), str) else None,
                version_name=_str_required(raw, "name"),
                folder_guid=_str_or_none(raw, "folderGuid"),
            )
        )

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
        body = result.json()
        if not isinstance(body, dict):
            raise VendorContractError("delta export response must be an object")
        state = _str_required(body, "state")
        if state not in {"started", "completed", "failed"}:
            raise VendorContractError(f"unexpected delta export state {state!r}")
        return DeltaExportOutput(export_id=args.export_id, state=state, detail=body)

    @operation(
        "get_webhook_delivery",
        input_model=WebhookDeliveryArgs,
        output_model=WebhookDeliveryOutput,
        classification="read",
        capability="FindingSource",
    )
    async def get_webhook_delivery(self, args: WebhookDeliveryArgs) -> WebhookDeliveryOutput:
        """[UNVERIFIED] Read one webhook delivery record; retry and header behavior are unconfirmed."""
        result = await self.http.request("GET", _as_path(f"/webhooks/{args.webhook_id}"))
        body = result.json()
        if not isinstance(body, dict):
            raise VendorContractError("webhook response must be an object")
        return WebhookDeliveryOutput(webhook_id=args.webhook_id, detail=body)

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
        current = await self._issue_summary(args.project_version_id, args.issue_id)
        return ActionPlan(
            action="audit_issue",
            target_ref=f"fortify_ssc:issue:{args.project_version_id}:{args.issue_id}",
            diff={"auditState": {"from": current["auditState"], "to": args.audit_state}},
            preconditions={"revision": args.revision},
            idempotency_key=f"audit:{args.project_version_id}:{args.issue_id}:{args.revision}:{args.audit_state}",
            changed=current["auditState"] != args.audit_state,
            request={
                "method": "POST",
                "path": _as_path(f"/projectVersions/{args.project_version_id}/issues/{args.issue_id}/audit"),
                "json": {"auditState": args.audit_state, "comment": args.comment, "revision": args.revision},
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
        return _audit_outcome(plan.target_ref, result.json())

    @plan_audit_issue.reconcile
    async def reconcile_audit_issue(self, plan: ActionPlan) -> ActionOutcome:
        pv, issue = _ids_from_ref(plan.target_ref)
        current = await self._issue_summary(pv, issue)
        if current["auditState"] == plan.request["json"]["auditState"]:
            return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref, result={"reconciled": True})
        return ActionOutcome(
            status="failed",
            vendor_ref=plan.target_ref,
            error=f"issue {issue} is in {current['auditState']!r}",
        )

    @action(
        "set_issue_suppression",
        classification="write",
        capability="FindingSource",
        input_model=SetIssueSuppressionArgs,
        idempotency="natural_key",
    )
    async def plan_set_issue_suppression(self, args: SetIssueSuppressionArgs) -> ActionPlan:
        current = await self._issue_summary(args.project_version_id, args.issue_id)
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
                "path": _as_path(f"/projectVersions/{args.project_version_id}/issues/{args.issue_id}/suppress"),
                "json": {"suppressed": args.suppressed, "revision": args.revision},
            },
        )

    @plan_set_issue_suppression.apply
    async def apply_set_issue_suppression(self, plan: ActionPlan) -> ActionOutcome:
        if not plan.changed:
            return ActionOutcome(status="no_op", vendor_ref=plan.target_ref)
        await self._check_revision(plan)
        try:
            await self.http.request(
                "POST",
                plan.request["path"],
                json=plan.request["json"],
                idempotency="non_idempotent",
                expected=(200, 201, 204),
            )
        except OutcomeUnknown as exc:
            return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))
        return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref)

    @plan_set_issue_suppression.reconcile
    async def reconcile_set_issue_suppression(self, plan: ActionPlan) -> ActionOutcome:
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
        current = await self._issue_summary(args.project_version_id, args.issue_id)
        return ActionPlan(
            action="assign_issue",
            target_ref=f"fortify_ssc:issue:{args.project_version_id}:{args.issue_id}",
            diff={"assignee": {"from": current["assignee"], "to": args.assignee}},
            preconditions={"revision": args.revision},
            idempotency_key=f"assign:{args.project_version_id}:{args.issue_id}:{args.revision}:{args.assignee}",
            changed=current["assignee"] != args.assignee,
            request={
                "method": "POST",
                "path": _as_path(f"/projectVersions/{args.project_version_id}/issues/{args.issue_id}/assign"),
                "json": {"assignee": args.assignee, "revision": args.revision},
            },
        )

    @plan_assign_issue.apply
    async def apply_assign_issue(self, plan: ActionPlan) -> ActionOutcome:
        if not plan.changed:
            return ActionOutcome(status="no_op", vendor_ref=plan.target_ref)
        await self._check_revision(plan)
        try:
            await self.http.request(
                "POST",
                plan.request["path"],
                json=plan.request["json"],
                idempotency="non_idempotent",
                expected=(200, 201, 204),
            )
        except OutcomeUnknown as exc:
            return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))
        return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref)

    @plan_assign_issue.reconcile
    async def reconcile_assign_issue(self, plan: ActionPlan) -> ActionOutcome:
        pv, issue = _ids_from_ref(plan.target_ref)
        current = await self._issue_summary(pv, issue)
        if current["assignee"] == plan.request["json"]["assignee"]:
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
        await self._check_issue_exists(args.project_version_id, args.issue_id)
        return ActionPlan(
            action="add_issue_comment",
            target_ref=f"fortify_ssc:issue:{args.project_version_id}:{args.issue_id}",
            diff={"comment": {"added": _digest(args.comment)}},
            preconditions={"revision": args.revision},
            idempotency_key=f"comment:{args.project_version_id}:{args.issue_id}:{_digest(args.comment)}",
            changed=True,
            request={
                "method": "POST",
                "path": _as_path(f"/projectVersions/{args.project_version_id}/issues/{args.issue_id}/comments"),
                "json": {"comment": args.comment, "revision": args.revision},
            },
        )

    @plan_add_issue_comment.apply
    async def apply_add_issue_comment(self, plan: ActionPlan) -> ActionOutcome:
        await self._check_revision(plan)
        try:
            await self.http.request(
                "POST",
                plan.request["path"],
                json=plan.request["json"],
                idempotency="non_idempotent",
                expected=(200, 201),
            )
        except OutcomeUnknown as exc:
            return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))
        return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref)

    @plan_add_issue_comment.reconcile
    async def reconcile_add_issue_comment(self, plan: ActionPlan) -> ActionOutcome:
        pv, issue = _ids_from_ref(plan.target_ref)
        wanted = plan.diff["comment"]["added"]
        result = await self.http.request(
            "GET",
            _as_path(f"/projectVersions/{pv}/issues/{issue}/comments"),
            params={"withoutCount": "true"},
        )
        for comment in _data_list(result.json()):
            if _digest(_str_required(comment, "comment")) == wanted:
                return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref, result={"reconciled": True})
        return ActionOutcome(status="failed", vendor_ref=plan.target_ref, error="comment not found after write")

    @action(
        "upload_fpr",
        classification="write",
        capability="FindingSource",
        input_model=UploadFprArgs,
        idempotency="natural_key",
    )
    async def plan_upload_fpr(self, args: UploadFprArgs) -> ActionPlan:
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
            preconditions={"sha256": args.fpr_sha256},
            idempotency_key=f"upload:{args.project_version_id}:{args.fpr_sha256}",
            changed=True,
            request={
                "method": "POST",
                "path": _as_path(f"/projectVersions/{args.project_version_id}/artifacts"),
                "json": {"sha256": args.fpr_sha256, "autoPublish": args.auto_publish, "fpr": args.fpr_base64},
            },
        )

    @plan_upload_fpr.apply
    async def apply_upload_fpr(self, plan: ActionPlan) -> ActionOutcome:
        try:
            result = await self.http.request(
                "POST",
                plan.request["path"],
                json=plan.request["json"],
                idempotency="non_idempotent",
                expected=(200, 201, 202),
            )
        except OutcomeUnknown as exc:
            return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))
        body = result.json()
        artifact_id = body.get("data", {}).get("id") if isinstance(body, dict) and isinstance(body.get("data"), dict) else None
        return ActionOutcome(
            status="accepted_async",
            vendor_ref=plan.target_ref,
            result={"artifact_id": artifact_id, "sha256": plan.preconditions["sha256"]},
        )

    @plan_upload_fpr.reconcile
    async def reconcile_upload_fpr(self, plan: ActionPlan) -> ActionOutcome:
        pv = _pv_from_ref(plan.target_ref)
        result = await self.http.request(
            "GET",
            _as_path(f"/projectVersions/{pv}/artifacts"),
            params={"withoutCount": "true", "fields": "all"},
        )
        wanted = plan.preconditions["sha256"]
        for artifact in _data_list(result.json()):
            if artifact.get("sha256") != wanted:
                continue
            if artifact.get("status") == "PROCESSING_ERROR":
                return ActionOutcome(status="failed", vendor_ref=plan.target_ref, error="artifact processing failed")
            if artifact.get("indexed") is True:
                return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref, result={"indexed": True})
            return ActionOutcome(status="accepted_async", vendor_ref=plan.target_ref, result={"indexed": False})
        return ActionOutcome(status="failed", vendor_ref=plan.target_ref, error="uploaded artifact not found")

    @action(
        "create_webhook",
        classification="write",
        capability="FindingSource",
        input_model=CreateWebhookArgs,
        idempotency="none",
    )
    async def plan_create_webhook(self, args: CreateWebhookArgs) -> ActionPlan:
        return ActionPlan(
            action="create_webhook",
            target_ref=f"fortify_ssc:webhook:{args.name}",
            diff={"webhook": {"name": args.name, "events": args.event_types}},
            preconditions={"object_version": args.object_version},
            idempotency_key=f"webhook:{args.name}:{_digest(args.target_url)}",
            changed=True,
            request={
                "method": "POST",
                "path": _as_path("/webhooks"),
                "json": {
                    "name": args.name,
                    "targetUrl": args.target_url,
                    "eventTypes": args.event_types,
                    "objectVersion": args.object_version,
                },
            },
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
        return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref, result={"status_code": result.status})

    @plan_create_webhook.reconcile
    async def reconcile_create_webhook(self, plan: ActionPlan) -> ActionOutcome:
        name = plan.diff["webhook"]["name"]
        result = await self.http.request("GET", _as_path("/webhooks"), params={"withoutCount": "true"})
        for hook in _data_list(result.json()):
            if hook.get("name") == name:
                return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref, result={"reconciled": True})
        return ActionOutcome(status="failed", vendor_ref=plan.target_ref, error="webhook not found after create")

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
                "method": "DELETE",
                "path": _as_path(f"/artifacts/{args.artifact_id}"),
                "params": {"versionNumber": args.version_number},
            },
        )

    @plan_purge_artifact.apply
    async def apply_purge_artifact(self, plan: ActionPlan) -> ActionOutcome:
        try:
            await self.http.request(
                "DELETE",
                plan.request["path"],
                params=plan.request["params"],
                idempotency="non_idempotent",
                expected=(200, 204),
            )
        except OutcomeUnknown as exc:
            return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))
        return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref)

    @action(
        "purge_project_version",
        classification="destructive",
        capability="FindingSource",
        input_model=PurgeProjectVersionArgs,
        idempotency="none",
    )
    async def plan_purge_project_version(self, args: PurgeProjectVersionArgs) -> ActionPlan:
        self._require_destructive()
        return ActionPlan(
            action="purge_project_version",
            target_ref=f"fortify_ssc:project_version:{args.project_version_id}",
            diff={"purge": {"project_version_id": args.project_version_id}},
            preconditions={"approval_ref": args.approval_ref},
            idempotency_key=f"purge-pv:{args.project_version_id}:{args.approval_ref}",
            changed=True,
            request={"method": "DELETE", "path": _as_path(f"/projectVersions/{args.project_version_id}")},
        )

    @plan_purge_project_version.apply
    async def apply_purge_project_version(self, plan: ActionPlan) -> ActionOutcome:
        try:
            await self.http.request(
                "DELETE",
                plan.request["path"],
                idempotency="non_idempotent",
                expected=(200, 204),
            )
        except OutcomeUnknown as exc:
            return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))
        return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref)

    async def _issue_summary(self, project_version_id: int, issue_id: int) -> dict[str, Any]:
        result = await self.http.request(
            "GET",
            _as_path(f"/projectVersions/{project_version_id}/issues/{issue_id}"),
            params={"fields": "all", "withoutCount": "true"},
        )
        body = result.json()
        if not isinstance(body, dict) or not isinstance(body.get("data"), dict):
            raise VendorContractError("issue response must carry a 'data' object")
        raw = body["data"]
        return {
            "revision": _int_required(raw, "revision"),
            "auditState": _audit_state(raw),
            "suppressed": bool(raw.get("suppressed", False)),
            "assignee": _str_or_none(raw, "assignee"),
        }

    async def _check_issue_exists(self, project_version_id: int, issue_id: int) -> None:
        await self._issue_summary(project_version_id, issue_id)

    def _require_destructive(self) -> None:
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


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _audit_outcome(target_ref: str, body: Any) -> ActionOutcome:
    if not isinstance(body, dict) or not isinstance(body.get("data"), dict):
        raise VendorContractError("audit response must carry a 'data' object")
    return ActionOutcome(
        status="succeeded",
        vendor_ref=target_ref,
        result={"auditState": _audit_state(body["data"])},
    )
