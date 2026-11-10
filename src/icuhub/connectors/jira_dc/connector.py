"""Jira Data Center connector: personal access tokens, REST API v2, polled and webhook-delivered records.

Paths and response fields marked [UNVERIFIED] are not sourced in docs/VENDOR_CONNECTORS.md; confirm them
against a live Data Center instance before relying on them. Mapping, webhook parsing, and the shared
Jira models live in ``icuhub.connectors._jira``.
"""

from __future__ import annotations

import base64
import hashlib
from collections.abc import AsyncIterator
from typing import Any, ClassVar, Literal

from pydantic import BaseModel, ConfigDict, Field

from icuhub.connectors._jira import mappers as jira
from icuhub.connectors._jira.base import JiraBase
from icuhub.connectors._jira.helpers import (
    audit_id,
    audit_ts,
    changelog_histories,
    comment_marker,
    comment_ts,
    digest,
    history_ts,
    issue_state,
    issue_updated,
    link_exists,
    list_field,
    multipart,
    record_id,
    require_field,
    route_label,
    seg,
    status_changed_to,
    time_cursor,
    value_matches,
)
from icuhub.connectors._jira.models import (
    AddCommentInput,
    AttachmentInput,
    CreateIssueInput,
    DeleteAttachmentInput,
    DeleteCommentInput,
    DeleteIssueInput,
    DeleteWebhookInput,
    IssueInput,
    JiraDataCenterConfig,
    LinkIssueInput,
    TransitionIssueInput,
    UpdateIssueInput,
)
from icuhub.connectors._jira.webhooks import EVENT_TYPES, parse_jira_delivery
from icuhub.connectors.jira_dc import attachments as attachment_reads
from icuhub.connectors.jira_dc.audit_collector import MAX_AUDIT_RECORD_BYTES, open_audit_collector
from icuhub.connectors.jira_dc.audit_files import AuditLogCursor, parse_audit_batch
from icuhub.connectors.jira_dc.comments_links import (
    AddRemoteLinkArgs,
    GetEditMetadataArgs,
    GetEditMetadataOutput,
    ListCommentsArgs,
    ListCommentsOutput,
    ListFieldsArgs,
    ListFieldsOutput,
    ListProjectsArgs,
    ListProjectsOutput,
    ListRemoteLinksArgs,
    ListRemoteLinksOutput,
    UpdateCommentArgs,
    comment_body_digest,
    comment_body_matches,
    comment_page,
    comment_update_payload,
    edit_metadata_fields,
    field_list,
    find_remote_link,
    next_comment_offset,
    persisted_remote_link_id,
    project_list,
    remote_link_list,
    remote_link_payload,
)
from icuhub.connectors.jira_dc.webhook_registration import (
    REGISTRATION_PATH,
    CreateDcWebhookInput,
    DcWebhookRegistration,
    DcWebhooksOutput,
    ListWebhooksArgs,
    RegistrationFamily,
    create_body,
    create_statuses,
    delete_path,
    find_by_id,
    find_registration,
    parse_registrations,
    registration_health,
    registration_id,
    resolve_family,
    server_version_numbers,
)
from icuhub.kit.auth import AuthStrategy, BearerToken
from icuhub.kit.connector import action, mapper, operation, stream, webhook
from icuhub.kit.cursors import SnapshotCursor, TimeIdCursor
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
from icuhub.kit.types import (
    ActionOutcome,
    ActionPlan,
    CapabilityHealth,
    HealthReport,
    MapContext,
    RawBatch,
    SourceRecord,
    StreamRecord,
    Target,
    TicketRecord,
    WebhookDelivery,
)
from icuhub_schemas.ocsf import ApiActivity

__all__ = ["JiraDataCenter", "SearchIssuesArgs", "CreateMetadataArgs", "IssueRefArgs"]

_CAPABILITY = "Tracker"
_ISSUE_STATE_FIELDS = "id,updated,status"


def _with_string_id(raw: dict[str, Any]) -> dict[str, Any]:
    """Jira auditing returns integer record ids; the shared mapper requires a string id."""
    record_id = raw.get("id")
    if isinstance(record_id, int) and not isinstance(record_id, bool):
        return {**raw, "id": str(record_id)}
    return raw


# ---------------------------------------------------------------- operation I/O


class SearchIssuesArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    jql: str = Field(min_length=1)
    start_at: int = Field(default=0, ge=0)
    max_results: int = Field(default=50, ge=1, le=1000)
    fields: list[str] = Field(default_factory=lambda: ["id", "key", "summary", "status", "updated"])


class IssueRefArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    issue_id_or_key: str = Field(min_length=1)


class CreateMetadataArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    project_key: str = Field(min_length=1)
    issue_type_id: str | None = None


class SearchIssuesOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    issues: list[TicketRecord]
    start_at: int
    total: int


class IssueOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    issue: TicketRecord
    raw_status: str


class TransitionsOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    transitions: list[dict[str, Any]]


class CreateMetadataOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    projects: list[dict[str, Any]]


# ---------------------------------------------------------------- connector


class JiraDataCenter(JiraBase):
    kind: ClassVar[str] = "jira_dc"
    version: ClassVar[str] = "0.1.0"
    display_name: ClassVar[str] = "Jira Data Center"
    config_model: ClassVar[type[JiraDataCenterConfig]] = JiraDataCenterConfig
    auth_modes: ClassVar[tuple[str, ...]] = ("BearerToken",)
    capabilities: ClassVar[tuple[str, ...]] = (_CAPABILITY,)
    flows: ClassVar[tuple[str, ...]] = ("F-029", "F-107")
    api_version: ClassVar[Literal["2"]] = "2"
    search_order: ClassVar[str] = "ORDER BY updated ASC, id ASC"

    # ------------------------------------------------------------ plumbing

    def _cfg(self) -> JiraDataCenterConfig:
        if not isinstance(self.config, JiraDataCenterConfig):
            raise ConfigError("jira_dc requires a JiraDataCenterConfig")
        return self.config

    def installation_id(self) -> str:
        return self.ctx.connection_id

    def _search(self, jql: str, fields: str, expand: str | None = None) -> AsyncIterator[Any]:
        params: dict[str, Any] = {"jql": jql, "fields": fields}
        if expand is not None:
            params["expand"] = expand
        return self._paged(
            "/rest/api/2/search", params, "issues", offset_param="startAt", limit_param="maxResults"
        )

    async def _search_one(self, jql: str) -> list[dict[str, Any]]:
        body = await self._get_object("/rest/api/2/search", {"jql": jql, "fields": "id,key", "maxResults": 2})
        return list_field(body, "issues")

    # ------------------------------------------------------------ auth + health

    async def build_auth(self) -> AuthStrategy:
        cfg = self._cfg()
        token = await self.ctx.secrets.resolve(cfg.personal_access_token)
        try:
            text = token.decode("ascii")
        except UnicodeDecodeError as exc:
            raise ConfigError("personal_access_token must be ASCII text") from exc
        return BearerToken(text)

    async def check(self) -> HealthReport:
        try:
            # [UNVERIFIED] identity probe path; /myself needs no administrator rights.
            await self.http.request("GET", "/rest/api/2/myself")
        except AuthFailed:
            return HealthReport(
                status="failing",
                capabilities={_CAPABILITY: CapabilityHealth(status="failing", reason="vendor rejected credentials")},
            )
        except PermissionDenied as exc:
            return HealthReport(
                status="degraded",
                capabilities={_CAPABILITY: CapabilityHealth(status="degraded", reason=str(exc))},
            )
        except (RateLimited, TransientVendorError):
            return HealthReport(
                status="degraded",
                capabilities={_CAPABILITY: CapabilityHealth(status="degraded", reason="vendor unavailable")},
            )
        return HealthReport(status="healthy", capabilities={_CAPABILITY: CapabilityHealth(status="healthy")})

    # ------------------------------------------------------------ webhooks

    @webhook(event_types=EVENT_TYPES)
    def receive_event(self, delivery: WebhookDelivery) -> list[StreamRecord]:
        return parse_jira_delivery(
            delivery,
            installation=self.ctx.connection_id,
            base_url=self._cfg().base_url,
            connection_id=self.ctx.connection_id,
        )

    # ------------------------------------------------------------ streams

    @stream(
        "issues",
        cursor=TimeIdCursor,
        capability=_CAPABILITY,
        modes=("incremental", "full"),
        requires_target=False,
    )
    async def issues(self, target: Target | None, checkpoint: Any, mode: str) -> AsyncIterator[RawBatch]:
        cursor = time_cursor(checkpoint)
        jql = self._search_jql(cursor.window_start() if mode == "incremental" else None)
        async for page, _result in self._search(jql, "*all"):
            cursor = cursor.advance(page, ts_of=issue_updated, id_of=record_id)
            yield RawBatch(records=page, checkpoint=cursor, complete=False)
        if mode == "full":
            yield RawBatch(records=[], checkpoint=cursor, complete=True)

    @stream("projects", cursor=SnapshotCursor, capability=_CAPABILITY, modes=("full",), requires_target=False)
    async def projects(self, target: Target | None, checkpoint: Any, mode: str) -> AsyncIterator[RawBatch]:
        # [UNVERIFIED] project list path; /rest/api/2/project returns a bare array on Data Center.
        body = await self._json("GET", "/rest/api/2/project")
        if not isinstance(body, list):
            raise VendorContractError("Jira project listing must be an array")
        yield RawBatch(records=body, checkpoint=checkpoint, complete=False)
        yield RawBatch(records=[], checkpoint=checkpoint, complete=True)

    @stream(
        "comments",
        cursor=TimeIdCursor,
        capability=_CAPABILITY,
        modes=("incremental", "full"),
        requires_target=False,
    )
    async def comments(self, target: Target | None, checkpoint: Any, mode: str) -> AsyncIterator[RawBatch]:
        cursor = time_cursor(checkpoint)
        jql = self._search_jql(cursor.window_start() if mode == "incremental" else None)
        async for issue_page, _result in self._search(jql, "id,key"):
            for issue in issue_page:
                parent = {"id": jira.required_str(issue, "id"), "key": jira.required_str(issue, "key")}
                pages = self._paged(
                    f"/rest/api/2/issue/{seg(parent['id'])}/comment",
                    None,
                    "comments",
                    offset_param="startAt",
                    limit_param="maxResults",
                )
                async for page, _page_result in pages:
                    records = [{**comment, "_jira_issue": parent} for comment in page]
                    cursor = cursor.advance(records, ts_of=comment_ts, id_of=record_id)
                    yield RawBatch(records=records, checkpoint=cursor, complete=False)
        if mode == "full":
            yield RawBatch(records=[], checkpoint=cursor, complete=True)

    @stream(
        "attachments",
        cursor=TimeIdCursor,
        capability=_CAPABILITY,
        modes=("incremental", "full"),
        requires_target=False,
    )
    async def attachments(self, target: Target | None, checkpoint: Any, mode: str) -> AsyncIterator[RawBatch]:
        """Non-finding evidence records carried on each issue's attachment field."""
        async for batch in attachment_reads.stream_attachments(self, checkpoint, mode):
            yield batch

    @stream(
        "issue_changelogs",
        cursor=TimeIdCursor,
        capability=_CAPABILITY,
        modes=("incremental", "full"),
        requires_target=False,
    )
    async def issue_changelogs(self, target: Target | None, checkpoint: Any, mode: str) -> AsyncIterator[RawBatch]:
        cursor = time_cursor(checkpoint)
        jql = self._search_jql(cursor.window_start() if mode == "incremental" else None)
        async for issue_page, _result in self._search(jql, "id,key", expand="changelog"):
            records: list[dict[str, Any]] = []
            for issue in issue_page:
                parent = {"id": jira.required_str(issue, "id"), "key": jira.required_str(issue, "key")}
                records.extend({**history, "_jira_issue": parent} for history in changelog_histories(issue))
            cursor = cursor.advance(records, ts_of=history_ts, id_of=record_id)
            yield RawBatch(records=records, checkpoint=cursor, complete=False)
        if mode == "full":
            yield RawBatch(records=[], checkpoint=cursor, complete=True)

    @stream(
        "audit_records",
        cursor=TimeIdCursor,
        capability=_CAPABILITY,
        ocsf_class=6003,
        modes=("incremental", "full"),
        requires_target=False,
    )
    async def audit_records(self, target: Target | None, checkpoint: Any, mode: str) -> AsyncIterator[RawBatch]:
        # [UNVERIFIED] auditing path and response envelope; the spec leaves audit source IDs unsourced.
        cursor = time_cursor(checkpoint)
        window = cursor.window_start() if mode == "incremental" else None
        pages = self._paged(
            "/rest/api/2/auditing/record", None, "records", offset_param="offset", limit_param="limit"
        )
        async for page, _result in pages:
            fresh = [record for record in page if window is None or audit_ts(record) >= window]
            cursor = cursor.advance(fresh, ts_of=audit_ts, id_of=audit_id)
            yield RawBatch(records=fresh, checkpoint=cursor, complete=False)
        if mode == "full":
            yield RawBatch(records=[], checkpoint=cursor, complete=True)

    @stream(
        "audit_log_files",
        cursor=AuditLogCursor,
        capability=_CAPABILITY,
        ocsf_class=6003,
        modes=("incremental",),
        requires_target=False,
    )
    async def audit_log_files(self, target: Target | None, checkpoint: Any, mode: str) -> AsyncIterator[RawBatch]:
        # [UNVERIFIED] node-local audit JSONL served by the TLS file collector; each response is the complete file.
        cfg = self._cfg()
        cursor = checkpoint if isinstance(checkpoint, AuditLogCursor) else AuditLogCursor()
        if not cfg.audit_files:
            yield RawBatch(records=[], checkpoint=cursor, complete=True)
            return
        collector = await open_audit_collector(cfg, self.ctx.secrets, self.ctx.clock)
        try:
            for source in cfg.audit_files:
                content = await collector.stream_download("GET", source.url, max_bytes=cfg.audit_max_bytes)
                batch = parse_audit_batch(
                    node=source.node,
                    path=source.path,
                    content=content,
                    previous=cursor.position(source.node, source.path),
                    max_record_bytes=MAX_AUDIT_RECORD_BYTES,
                )
                cursor = cursor.advance_file(source.node, source.path, batch.position)
                yield RawBatch(records=batch.records, checkpoint=cursor, complete=False)
        finally:
            await collector.aclose()
        yield RawBatch(records=[], checkpoint=cursor, complete=True)

    # ------------------------------------------------------------ mappers

    @mapper("audit_log_files", version=1)
    def map_audit_log_file(self, raw: dict[str, Any], ctx: MapContext) -> list[ApiActivity]:
        # Audit record ids are per-node counters, so the node name scopes the record identity.
        scoped = {**raw, "id": f"{raw['_jira_node']}/{raw['id']}"}
        return [jira.map_audit(_with_string_id(scoped), ctx)]

    @mapper("issues", version=1)
    def map_issue(self, raw: dict[str, Any], ctx: MapContext) -> list[TicketRecord]:
        return [jira.map_issue(raw, ctx)]

    @mapper("projects", version=1)
    def map_project(self, raw: dict[str, Any], ctx: MapContext) -> list[SourceRecord]:
        return [jira.map_project(raw, ctx)]

    @mapper("comments", version=1)
    def map_comment(self, raw: dict[str, Any], ctx: MapContext) -> list[SourceRecord]:
        return [jira.map_comment(raw, ctx)]

    @mapper("attachments", version=1)
    def map_attachment(self, raw: dict[str, Any], ctx: MapContext) -> list[SourceRecord]:
        return [attachment_reads.map_attachment(raw, ctx)]

    @mapper("issue_changelogs", version=1)
    def map_changelog(self, raw: dict[str, Any], ctx: MapContext) -> list[ApiActivity]:
        return [jira.map_changelog(raw, ctx)]

    @mapper("audit_records", version=1)
    def map_audit(self, raw: dict[str, Any], ctx: MapContext) -> list[ApiActivity]:
        return [jira.map_audit(_with_string_id(raw), ctx)]

    # ------------------------------------------------------------ operations

    @operation(
        "search_issues",
        input_model=SearchIssuesArgs,
        output_model=SearchIssuesOutput,
        classification="read",
        capability=_CAPABILITY,
    )
    async def search_issues(self, args: SearchIssuesArgs) -> SearchIssuesOutput:
        body = await self._get_object(
            "/rest/api/2/search",
            {
                "jql": args.jql,
                "startAt": args.start_at,
                "maxResults": args.max_results,
                "fields": ",".join(args.fields),
            },
        )
        total = body.get("total")
        if isinstance(total, bool) or not isinstance(total, int):
            raise VendorContractError("Jira search response must carry an integer total")
        ctx = self._map_ctx()
        issues = [jira.map_issue(raw, ctx) for raw in list_field(body, "issues")]
        return SearchIssuesOutput(issues=issues, start_at=args.start_at, total=total)

    @operation(
        "get_issue",
        input_model=IssueInput,
        output_model=IssueOutput,
        classification="read",
        capability=_CAPABILITY,
    )
    async def get_issue(self, args: IssueInput) -> IssueOutput:
        # [UNVERIFIED] single issue path /rest/api/2/issue/{id}; spec leaves the read path unsourced.
        expand = [name for name, on in (("changelog", args.include_changelog), ("renderedFields", args.include_rendered_fields)) if on]
        params = {"expand": ",".join(expand)} if expand else None
        body = await self._get_object(f"/rest/api/2/issue/{seg(args.issue_id_or_key)}", params)
        fields = body.get("fields")
        status = fields.get("status") if isinstance(fields, dict) else None
        status_name = status.get("name") if isinstance(status, dict) else None
        if not isinstance(status_name, str):
            raise VendorContractError("Jira issue carries no status name")
        return IssueOutput(issue=jira.map_issue(body, self._map_ctx()), raw_status=status_name)

    @operation(
        "get_attachment",
        input_model=attachment_reads.GetAttachmentArgs,
        output_model=attachment_reads.GetAttachmentOutput,
        classification="read",
        capability=_CAPABILITY,
    )
    async def get_attachment(self, args: attachment_reads.GetAttachmentArgs) -> attachment_reads.GetAttachmentOutput:
        return await attachment_reads.get_attachment(self, args)

    @operation(
        "download_attachment",
        input_model=attachment_reads.DownloadAttachmentArgs,
        output_model=attachment_reads.DownloadAttachmentOutput,
        classification="read",
        capability=_CAPABILITY,
    )
    async def download_attachment(
        self,
        args: attachment_reads.DownloadAttachmentArgs,
    ) -> attachment_reads.DownloadAttachmentOutput:
        # [UNVERIFIED] metadata content URL and redirect behavior; confirm on a Data Center instance.
        return await attachment_reads.download_attachment(self, args)

    @operation(
        "list_transitions",
        input_model=IssueRefArgs,
        output_model=TransitionsOutput,
        classification="read",
        capability=_CAPABILITY,
    )
    async def list_transitions(self, args: IssueRefArgs) -> TransitionsOutput:
        issue = await self._get_issue(args.issue_id_or_key, fields="id")
        return TransitionsOutput(transitions=await self._transitions(jira.required_str(issue, "id")))

    @operation(
        "get_create_metadata",
        input_model=CreateMetadataArgs,
        output_model=CreateMetadataOutput,
        classification="read",
        capability=_CAPABILITY,
    )
    async def get_create_metadata(self, args: CreateMetadataArgs) -> CreateMetadataOutput:
        # [UNVERIFIED] createmeta path and parameters; confirm on a Data Center instance.
        params: dict[str, Any] = {"projectKeys": args.project_key, "expand": "projects.issuetypes.fields"}
        if args.issue_type_id is not None:
            params["issuetypeIds"] = args.issue_type_id
        body = await self._get_object("/rest/api/2/issue/createmeta", params)
        return CreateMetadataOutput(projects=list_field(body, "projects"))

    @operation(
        "list_comments",
        input_model=ListCommentsArgs,
        output_model=ListCommentsOutput,
        classification="read",
        capability=_CAPABILITY,
    )
    async def list_comments(self, args: ListCommentsArgs) -> ListCommentsOutput:
        body = await self._get_object(
            f"{self._issue_path(args.issue_id_or_key)}/comment",
            {"startAt": args.start_at, "maxResults": args.max_results},
        )
        comments = comment_page(body)
        return ListCommentsOutput(
            comments=comments,
            next_start_at=next_comment_offset(args.start_at, len(comments), args.max_results),
        )

    @operation(
        "list_remote_links",
        input_model=ListRemoteLinksArgs,
        output_model=ListRemoteLinksOutput,
        classification="read",
        capability=_CAPABILITY,
    )
    async def list_remote_links(self, args: ListRemoteLinksArgs) -> ListRemoteLinksOutput:
        # [UNVERIFIED] DC remote link read path /rest/api/2/issue/{id}/remotelink; confirm on a Data Center instance.
        body = await self._json("GET", f"{self._issue_path(args.issue_id_or_key)}/remotelink")
        return ListRemoteLinksOutput(links=remote_link_list(body))

    @operation(
        "get_edit_metadata",
        input_model=GetEditMetadataArgs,
        output_model=GetEditMetadataOutput,
        classification="read",
        capability=_CAPABILITY,
    )
    async def get_edit_metadata(self, args: GetEditMetadataArgs) -> GetEditMetadataOutput:
        # [UNVERIFIED] DC editmeta response shape {"fields": {...}}; confirm on a Data Center instance.
        body = await self._json("GET", f"{self._issue_path(args.issue_id_or_key)}/editmeta")
        return GetEditMetadataOutput(fields=edit_metadata_fields(body))

    @operation(
        "list_fields",
        input_model=ListFieldsArgs,
        output_model=ListFieldsOutput,
        classification="read",
        capability=_CAPABILITY,
    )
    async def list_fields(self, args: ListFieldsArgs) -> ListFieldsOutput:
        # [UNVERIFIED] DC field catalogue /rest/api/2/field returning a bare array; confirm on a Data Center instance.
        return ListFieldsOutput(fields=field_list(await self._json("GET", self._api_path("/field"))))

    @operation(
        "list_projects",
        input_model=ListProjectsArgs,
        output_model=ListProjectsOutput,
        classification="read",
        capability=_CAPABILITY,
    )
    async def list_projects(self, args: ListProjectsArgs) -> ListProjectsOutput:
        # [UNVERIFIED] DC project listing /rest/api/2/project returning a bare array; shared with the projects stream.
        return ListProjectsOutput(projects=project_list(await self._json("GET", self._api_path("/project"))))

    # ------------------------------------------------------------ actions: create_issue

    @action(
        "create_issue",
        classification="write",
        capability=_CAPABILITY,
        input_model=CreateIssueInput,
        idempotency="natural_key",
    )
    async def plan_create_issue(self, args: CreateIssueInput) -> ActionPlan:
        label = route_label(args.route_key)
        existing = await self._search_one(f'labels = "{label}"')
        if existing:
            key = jira.required_str(existing[0], "key")
            return ActionPlan(
                action="create_issue",
                target_ref=f"jira_issue:{key}",
                diff={},
                preconditions={"route_label": label},
                idempotency_key=self.action_identity("create_issue", args.route_key),
                changed=False,
                request={"method": "GET", "path": f"/rest/api/2/issue/{seg(key)}"},
            )
        fields: dict[str, Any] = dict(args.fields)
        fields.update(
            {
                "project": {"key": args.project_key},
                "issuetype": {"name": args.issue_type},
                "summary": args.summary,
                "labels": [*args.labels, label],
            }
        )
        if args.description is not None:
            fields["description"] = args.description
        return ActionPlan(
            action="create_issue",
            target_ref=f"route:{label}",
            diff={"summary": args.summary, "project_key": args.project_key, "issue_type": args.issue_type},
            preconditions={"route_label": label},
            idempotency_key=self.action_identity("create_issue", args.route_key),
            changed=True,
            request={"method": "POST", "path": "/rest/api/2/issue", "json": {"fields": fields}},
        )

    @plan_create_issue.apply
    async def apply_create_issue(self, plan: ActionPlan) -> ActionOutcome:
        if not plan.changed:
            return ActionOutcome(status="no_op", vendor_ref=plan.target_ref)
        try:
            body = await self._json(
                "POST",
                plan.request["path"],
                json=plan.request["json"],
                idempotency="non_idempotent",
                expected=(200, 201),
            )
        except OutcomeUnknown as exc:
            return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))
        key = jira.required_str(body, "key") if isinstance(body, dict) else None
        if key is None:
            raise VendorContractError("Jira create response must be an object")
        return ActionOutcome(status="succeeded", vendor_ref=f"jira_issue:{key}", result={"key": key})

    @plan_create_issue.reconcile
    async def reconcile_create_issue(self, plan: ActionPlan, outcome: ActionOutcome) -> ActionOutcome:
        matches = await self._search_one(f'labels = "{plan.preconditions["route_label"]}"')
        if not matches:
            return ActionOutcome(
                status="failed",
                vendor_ref=plan.target_ref,
                error="no issue carries the route label after the write timed out",
            )
        key = jira.required_str(matches[0], "key")
        return ActionOutcome(status="succeeded", vendor_ref=f"jira_issue:{key}", result={"key": key})

    # ------------------------------------------------------------ actions: update_issue_fields

    @action(
        "update_issue_fields",
        classification="write",
        capability=_CAPABILITY,
        input_model=UpdateIssueInput,
        idempotency="none",
    )
    async def plan_update_issue_fields(self, args: UpdateIssueInput) -> ActionPlan:
        preconditions = {"id": args.expected_id, "updated": args.expected_updated, "status": args.expected_status}
        await self._assert_state(args.issue_id_or_key, preconditions)
        return ActionPlan(
            action="update_issue_fields",
            target_ref=f"jira_issue:{args.expected_id}",
            diff={"fields": args.fields},
            preconditions=preconditions,
            idempotency_key=digest("update_issue_fields", args.model_dump_json()),
            changed=True,
            request={
                "method": "PUT",
                "path": f"/rest/api/2/issue/{seg(args.expected_id)}",
                "json": {"fields": args.fields},
            },
        )

    @plan_update_issue_fields.apply
    async def apply_update_issue_fields(self, plan: ActionPlan) -> ActionOutcome:
        await self._assert_state(plan.preconditions["id"], plan.preconditions)
        try:
            await self.http.request(
                "PUT",
                plan.request["path"],
                json=plan.request["json"],
                idempotency="idempotent_write",
                expected=(204,),
            )
        except OutcomeUnknown as exc:
            return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))
        return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref)

    @plan_update_issue_fields.reconcile
    async def reconcile_update_issue_fields(self, plan: ActionPlan, outcome: ActionOutcome) -> ActionOutcome:
        issue = await self._get_issue(plan.preconditions["id"], fields=",".join(plan.diff["fields"]))
        fields = issue.get("fields")
        if not isinstance(fields, dict):
            raise VendorContractError("Jira issue fields must be an object")
        if all(value_matches(value, fields.get(name)) for name, value in plan.diff["fields"].items()):
            return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref)
        return ActionOutcome(status="failed", vendor_ref=plan.target_ref, error="requested fields are not present")

    # ------------------------------------------------------------ actions: add_comment

    @action("add_comment", classification="write", capability=_CAPABILITY, input_model=AddCommentInput, idempotency="key")
    async def plan_add_comment(self, args: AddCommentInput) -> ActionPlan:
        if not isinstance(args.body, str):
            raise ConfigError("Jira Data Center comments take a plain string body")
        issue = await self._get_issue(args.issue_id_or_key, fields="id")
        issue_id = jira.required_str(issue, "id")
        marker = comment_marker(args.action_key)
        existing = await self._find_comment(issue_id, marker)
        if existing is not None:
            return ActionPlan(
                action="add_comment",
                target_ref=f"jira_comment:{jira.required_str(existing, 'id')}",
                diff={},
                preconditions={"issue_id": issue_id, "marker": marker},
                idempotency_key=digest("add_comment", issue_id, args.action_key),
                changed=False,
                request={"method": "GET", "path": f"/rest/api/2/issue/{seg(issue_id)}/comment"},
            )
        payload: dict[str, Any] = {"body": f"{args.body}\n\n{marker}"}
        if args.visibility is not None:
            payload["visibility"] = args.visibility
        return ActionPlan(
            action="add_comment",
            target_ref=f"jira_issue:{issue_id}",
            diff={"body_length": len(args.body)},
            preconditions={"issue_id": issue_id, "marker": marker},
            idempotency_key=digest("add_comment", issue_id, args.action_key),
            changed=True,
            request={"method": "POST", "path": f"/rest/api/2/issue/{seg(issue_id)}/comment", "json": payload},
        )

    @plan_add_comment.apply
    async def apply_add_comment(self, plan: ActionPlan) -> ActionOutcome:
        if not plan.changed:
            return ActionOutcome(status="no_op", vendor_ref=plan.target_ref)
        try:
            body = await self._json(
                "POST",
                plan.request["path"],
                json=plan.request["json"],
                idempotency="non_idempotent",
                expected=(200, 201),
            )
        except OutcomeUnknown as exc:
            return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))
        if not isinstance(body, dict):
            raise VendorContractError("Jira comment response must be an object")
        comment_id = jira.required_str(body, "id")
        return ActionOutcome(status="succeeded", vendor_ref=f"jira_comment:{comment_id}", result={"id": comment_id})

    @plan_add_comment.reconcile
    async def reconcile_add_comment(self, plan: ActionPlan, outcome: ActionOutcome) -> ActionOutcome:
        found = await self._find_comment(plan.preconditions["issue_id"], plan.preconditions["marker"])
        if found is None:
            return ActionOutcome(status="failed", vendor_ref=plan.target_ref, error="comment marker not found after write")
        comment_id = jira.required_str(found, "id")
        return ActionOutcome(status="succeeded", vendor_ref=f"jira_comment:{comment_id}", result={"id": comment_id})

    # ------------------------------------------------------------ actions: transition_issue

    @action(
        "transition_issue",
        classification="write",
        capability=_CAPABILITY,
        input_model=TransitionIssueInput,
        idempotency="none",
    )
    async def plan_transition_issue(self, args: TransitionIssueInput) -> ActionPlan:
        state = issue_state(await self._get_issue(args.issue_id_or_key, fields=_ISSUE_STATE_FIELDS))
        if state["status"] == args.to_status:
            return ActionPlan(
                action="transition_issue",
                target_ref=f"jira_issue:{state['id']}",
                diff={"to_status": args.to_status},
                preconditions=state,
                idempotency_key=digest("transition_issue", state["id"], args.to_status),
                changed=False,
                request={"method": "GET", "path": f"/rest/api/2/issue/{seg(state['id'])}"},
            )
        matches = [
            transition
            for transition in await self._transitions(state["id"])
            if isinstance(transition.get("to"), dict) and transition["to"].get("name") == args.to_status
        ]
        if len(matches) != 1:
            raise ConfigError(
                f"expected exactly one transition from {state['status']!r} to {args.to_status!r}, found {len(matches)}"
            )
        payload: dict[str, Any] = {"transition": {"id": jira.required_str(matches[0], "id")}}
        if args.fields:
            payload["fields"] = args.fields
        return ActionPlan(
            action="transition_issue",
            target_ref=f"jira_issue:{state['id']}",
            diff={"from_status": state["status"], "to_status": args.to_status},
            preconditions=state,
            idempotency_key=digest("transition_issue", state["id"], state["updated"], args.to_status),
            changed=True,
            request={"method": "POST", "path": f"/rest/api/2/issue/{seg(state['id'])}/transitions", "json": payload},
        )

    @plan_transition_issue.apply
    async def apply_transition_issue(self, plan: ActionPlan) -> ActionOutcome:
        if not plan.changed:
            return ActionOutcome(status="no_op", vendor_ref=plan.target_ref)
        await self._assert_state(plan.preconditions["id"], plan.preconditions)
        try:
            await self.http.request(
                "POST",
                plan.request["path"],
                json=plan.request["json"],
                idempotency="non_idempotent",
                expected=(204,),
            )
        except OutcomeUnknown as exc:
            return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))
        return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref)

    @plan_transition_issue.reconcile
    async def reconcile_transition_issue(self, plan: ActionPlan, outcome: ActionOutcome) -> ActionOutcome:
        target = plan.diff["to_status"]
        issue = await self._get_issue(plan.preconditions["id"], fields="status", expand="changelog")
        if issue_state(issue)["status"] != target:
            return ActionOutcome(status="failed", vendor_ref=plan.target_ref, error="issue is not in the target status")
        if not status_changed_to(issue, target):
            return ActionOutcome(
                status="failed",
                vendor_ref=plan.target_ref,
                error="status matches but the changelog records no transition to it",
            )
        return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref)

    # ------------------------------------------------------------ actions: link_issue

    @action("link_issue", classification="write", capability=_CAPABILITY, input_model=LinkIssueInput, idempotency="natural_key")
    async def plan_link_issue(self, args: LinkIssueInput) -> ActionPlan:
        inward = await self._get_issue(args.inward_issue, fields="issuelinks")
        link_key = digest("link_issue", args.inward_issue, args.outward_issue, args.link_type)
        if link_exists(inward, args.link_type, args.outward_issue):
            return ActionPlan(
                action="link_issue",
                target_ref=f"jira_link:{link_key}",
                diff={},
                preconditions={"inward": args.inward_issue, "outward": args.outward_issue, "link_type": args.link_type},
                idempotency_key=link_key,
                changed=False,
                request={"method": "GET", "path": f"/rest/api/2/issue/{seg(args.inward_issue)}"},
            )
        payload: dict[str, Any] = {
            "type": {"name": args.link_type},
            "inwardIssue": {"key": args.inward_issue},
            "outwardIssue": {"key": args.outward_issue},
        }
        if args.comment is not None:
            payload["comment"] = {"body": args.comment} if isinstance(args.comment, str) else args.comment
        return ActionPlan(
            action="link_issue",
            target_ref=f"jira_link:{link_key}",
            diff={"link_type": args.link_type},
            preconditions={"inward": args.inward_issue, "outward": args.outward_issue, "link_type": args.link_type},
            idempotency_key=link_key,
            changed=True,
            request={"method": "POST", "path": "/rest/api/2/issueLink", "json": payload},
        )

    @plan_link_issue.apply
    async def apply_link_issue(self, plan: ActionPlan) -> ActionOutcome:
        if not plan.changed:
            return ActionOutcome(status="no_op", vendor_ref=plan.target_ref)
        try:
            await self.http.request(
                "POST",
                plan.request["path"],
                json=plan.request["json"],
                idempotency="non_idempotent",
                expected=(201,),
            )
        except OutcomeUnknown as exc:
            return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))
        return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref)

    @plan_link_issue.reconcile
    async def reconcile_link_issue(self, plan: ActionPlan, outcome: ActionOutcome) -> ActionOutcome:
        inward = await self._get_issue(plan.preconditions["inward"], fields="issuelinks")
        if link_exists(inward, plan.preconditions["link_type"], plan.preconditions["outward"]):
            return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref)
        return ActionOutcome(status="failed", vendor_ref=plan.target_ref, error="link not present after write")

    # ------------------------------------------------------------ actions: add_attachment

    @action(
        "add_attachment",
        classification="write",
        capability=_CAPABILITY,
        input_model=AttachmentInput,
        idempotency="natural_key",
    )
    async def plan_add_attachment(self, args: AttachmentInput) -> ActionPlan:
        cfg = self._cfg()
        content = base64.b64decode(args.content_base64, validate=True)
        if len(content) > cfg.attachment_max_bytes:
            raise ConfigError(f"attachment exceeds attachment_max_bytes ({cfg.attachment_max_bytes})")
        content_sha256 = hashlib.sha256(content).hexdigest()
        issue = await self._get_issue(args.issue_id_or_key, fields="id")
        issue_id = jira.required_str(issue, "id")
        key = digest("add_attachment", issue_id, args.filename, str(len(content)), content_sha256)
        preconditions = {"issue_id": issue_id, "filename": args.filename, "size": str(len(content))}
        existing = await self._find_attachment(issue_id, args.filename, len(content))
        path = f"/rest/api/2/issue/{seg(issue_id)}/attachments"
        if existing is not None:
            return ActionPlan(
                action="add_attachment",
                target_ref=f"jira_attachment:{jira.required_str(existing, 'id')}",
                diff={},
                preconditions=preconditions,
                idempotency_key=key,
                changed=False,
                request={"method": "GET", "path": f"/rest/api/2/issue/{seg(issue_id)}"},
            )
        return ActionPlan(
            action="add_attachment",
            target_ref=f"jira_issue:{issue_id}",
            diff={"filename": args.filename, "size": len(content), "content_sha256": content_sha256},
            preconditions=preconditions,
            idempotency_key=key,
            changed=True,
            request={
                "method": "POST",
                "path": path,
                "media_type": args.media_type,
                "content_base64": args.content_base64,
            },
        )

    @plan_add_attachment.apply
    async def apply_add_attachment(self, plan: ActionPlan) -> ActionOutcome:
        if not plan.changed:
            return ActionOutcome(status="no_op", vendor_ref=plan.target_ref)
        content = base64.b64decode(plan.request["content_base64"], validate=True)
        boundary = f"icuhub{plan.idempotency_key[:24]}"
        body = multipart(boundary, plan.preconditions["filename"], plan.request["media_type"], content)
        headers = {"X-Atlassian-Token": "no-check", "Content-Type": f"multipart/form-data; boundary={boundary}"}
        try:
            result = await self.http.request(
                "POST",
                plan.request["path"],
                content=body,
                headers=headers,
                idempotency="non_idempotent",
                expected=(200,),
            )
        except OutcomeUnknown as exc:
            return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))
        uploaded = result.json()
        if not isinstance(uploaded, list) or not uploaded or not isinstance(uploaded[0], dict):
            raise VendorContractError("Jira attachment upload must return a list of attachments")
        attachment_id = jira.required_str(uploaded[0], "id")
        return ActionOutcome(status="succeeded", vendor_ref=f"jira_attachment:{attachment_id}", result={"id": attachment_id})

    @plan_add_attachment.reconcile
    async def reconcile_add_attachment(self, plan: ActionPlan, outcome: ActionOutcome) -> ActionOutcome:
        found = await self._find_attachment(
            plan.preconditions["issue_id"], plan.preconditions["filename"], int(plan.preconditions["size"])
        )
        if found is None:
            return ActionOutcome(status="failed", vendor_ref=plan.target_ref, error="attachment not found after write")
        attachment_id = jira.required_str(found, "id")
        return ActionOutcome(status="succeeded", vendor_ref=f"jira_attachment:{attachment_id}", result={"id": attachment_id})

    # ------------------------------------------------------------ actions: update_comment

    @action("update_comment", classification="write", capability=_CAPABILITY, input_model=UpdateCommentArgs, idempotency="natural_key")
    async def plan_update_comment(self, args: UpdateCommentArgs) -> ActionPlan:
        path = f"{self._issue_path(args.issue_id_or_key)}/comment/{seg(args.comment_id)}"
        comment = await self._get_object(path)
        require_field(comment, "updated", args.expected_updated, "comment")
        key = digest("update_comment", args.issue_id_or_key, args.comment_id, comment_body_digest(args.body))
        target_ref = f"jira_comment:{args.comment_id}"
        if comment_body_matches(comment, args.body):
            return ActionPlan(
                action="update_comment",
                target_ref=target_ref,
                diff={},
                preconditions={"path": path, "expected_updated": args.expected_updated},
                idempotency_key=key,
                changed=False,
                request={"method": "GET", "path": path},
            )
        return ActionPlan(
            action="update_comment",
            target_ref=target_ref,
            diff={"body_length": len(args.body)},
            preconditions={"path": path, "expected_updated": args.expected_updated},
            idempotency_key=key,
            changed=True,
            request={"method": "PUT", "path": path, "json": comment_update_payload(args.body)},
        )

    @plan_update_comment.apply
    async def apply_update_comment(self, plan: ActionPlan) -> ActionOutcome:
        if not plan.changed:
            return ActionOutcome(status="no_op", vendor_ref=plan.target_ref)
        path = plan.preconditions["path"]
        require_field(await self._get_object(path), "updated", plan.preconditions["expected_updated"], "comment")
        try:
            # [UNVERIFIED] DC comment update PUT /rest/api/2/issue/{id}/comment/{cid} with a plain body; confirm on a Data Center instance.
            await self._json(
                "PUT",
                path,
                json=plan.request["json"],
                idempotency="idempotent_write",
                expected=(200,),
            )
        except OutcomeUnknown as exc:
            return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))
        return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref)

    @plan_update_comment.reconcile
    async def reconcile_update_comment(self, plan: ActionPlan, outcome: ActionOutcome) -> ActionOutcome:
        comment = await self._get_object(plan.preconditions["path"])
        if comment_body_matches(comment, plan.request["json"]["body"]):
            return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref)
        return ActionOutcome(status="failed", vendor_ref=plan.target_ref, error="comment body does not match the plan after write")

    # ------------------------------------------------------------ actions: add_remote_link

    @action("add_remote_link", classification="write", capability=_CAPABILITY, input_model=AddRemoteLinkArgs, idempotency="natural_key")
    async def plan_add_remote_link(self, args: AddRemoteLinkArgs) -> ActionPlan:
        issue = await self._get_issue(args.issue_id_or_key, fields="id")
        issue_id = jira.required_str(issue, "id")
        # [UNVERIFIED] DC remote link path /rest/api/2/issue/{id}/remotelink; confirm on a Data Center instance.
        path = f"{self._issue_path(issue_id)}/remotelink"
        key = digest("add_remote_link", issue_id, args.global_id)
        existing = find_remote_link(remote_link_list(await self._json("GET", path)), args.global_id)
        if existing is not None:
            link_id = persisted_remote_link_id(existing)
            if link_id is None:
                raise VendorContractError("Jira remote link carries no usable id")
            return ActionPlan(
                action="add_remote_link",
                target_ref=f"jira_remote_link:{link_id}",
                diff={},
                preconditions={"path": path, "global_id": args.global_id},
                idempotency_key=key,
                changed=False,
                request={"method": "GET", "path": path},
            )
        return ActionPlan(
            action="add_remote_link",
            target_ref=f"jira_issue:{issue_id}",
            diff={"url": args.url},
            preconditions={"path": path, "global_id": args.global_id},
            idempotency_key=key,
            changed=True,
            request={"method": "POST", "path": path, "json": remote_link_payload(args)},
        )

    @plan_add_remote_link.apply
    async def apply_add_remote_link(self, plan: ActionPlan) -> ActionOutcome:
        if not plan.changed:
            return ActionOutcome(status="no_op", vendor_ref=plan.target_ref)
        try:
            # [UNVERIFIED] DC remote link create returns 200 or 201 with the created link object; confirm on a Data Center instance.
            body = await self._json(
                "POST",
                plan.request["path"],
                json=plan.request["json"],
                idempotency="non_idempotent",
                expected=(200, 201),
            )
        except OutcomeUnknown as exc:
            return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))
        if not isinstance(body, dict):
            raise VendorContractError("Jira remote link response must be an object")
        link_id = persisted_remote_link_id(body)
        if link_id is None:
            raise VendorContractError("Jira remote link response carries no usable id")
        return ActionOutcome(status="succeeded", vendor_ref=f"jira_remote_link:{link_id}", result={"id": link_id})

    @plan_add_remote_link.reconcile
    async def reconcile_add_remote_link(self, plan: ActionPlan, outcome: ActionOutcome) -> ActionOutcome:
        links = remote_link_list(await self._json("GET", plan.preconditions["path"]))
        found = find_remote_link(links, plan.preconditions["global_id"])
        if found is None:
            return ActionOutcome(status="failed", vendor_ref=plan.target_ref, error="remote link not found after write")
        link_id = persisted_remote_link_id(found)
        if link_id is None:
            raise VendorContractError("Jira remote link carries no usable id")
        return ActionOutcome(status="succeeded", vendor_ref=f"jira_remote_link:{link_id}", result={"id": link_id})

    # ------------------------------------------------------------ webhook registration

    async def _registration_family(self) -> RegistrationFamily:
        # [UNVERIFIED] DC serverInfo at /rest/api/2/serverInfo exposing versionNumbers; confirm on a Data Center instance.
        body = await self._json("GET", self._api_path("/serverInfo"))
        return resolve_family(self.config.webhook_registration_family, server_version_numbers(body))

    async def _registrations(self) -> list[DcWebhookRegistration]:
        # [UNVERIFIED] DC webhook plugin registration list returning a bare array; confirm on a Data Center instance.
        return parse_registrations(await self._json("GET", REGISTRATION_PATH))

    async def _checked_registration(self, webhook_id: str, expected_url: str) -> DcWebhookRegistration | None:
        registration = find_by_id(await self._registrations(), webhook_id)
        if registration is not None and registration.url != expected_url:
            raise StalePlan("Jira webhook URL changed since the plan was made")
        return registration

    @operation(
        "list_webhooks",
        input_model=ListWebhooksArgs,
        output_model=DcWebhooksOutput,
        classification="read",
        capability=_CAPABILITY,
    )
    async def list_webhooks(self, args: ListWebhooksArgs) -> DcWebhooksOutput:
        registrations = await self._registrations()
        return DcWebhooksOutput(
            family=await self._registration_family(),
            status=registration_health(registrations),
            registrations=registrations,
        )

    @action(
        "create_webhook",
        classification="write",
        capability=_CAPABILITY,
        input_model=CreateDcWebhookInput,
        idempotency="natural_key",
    )
    async def plan_create_webhook(self, args: CreateDcWebhookInput) -> ActionPlan:
        family = await self._registration_family()
        key = digest("create_webhook", args.url, ",".join(args.events), args.jql_filter)
        preconditions = {"url": args.url, "events": ",".join(args.events), "jql_filter": args.jql_filter}
        existing = find_registration(await self._registrations(), args.url, args.events, args.jql_filter)
        if existing is not None:
            return ActionPlan(
                action="create_webhook",
                target_ref=f"jira_webhook:{existing.id}",
                diff={},
                preconditions=preconditions,
                idempotency_key=key,
                changed=False,
                request={"method": "GET", "path": REGISTRATION_PATH},
            )
        return ActionPlan(
            action="create_webhook",
            target_ref=f"jira_webhook_route:{key}",
            diff={"url": args.url, "events": list(args.events), "jql_filter": args.jql_filter},
            preconditions=preconditions,
            idempotency_key=key,
            changed=True,
            request={"method": "POST", "path": REGISTRATION_PATH, "json": create_body(args), "family": family},
        )

    @plan_create_webhook.apply
    async def apply_create_webhook(self, plan: ActionPlan) -> ActionOutcome:
        if not plan.changed:
            return ActionOutcome(status="no_op", vendor_ref=plan.target_ref)
        family: RegistrationFamily = plan.request["family"]
        try:
            body = await self._json(
                "POST",
                plan.request["path"],
                json=plan.request["json"],
                idempotency="non_idempotent",
                expected=create_statuses(family),
            )
        except OutcomeUnknown as exc:
            return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))
        webhook_id = registration_id(body) if isinstance(body, dict) else None
        if webhook_id is None:
            if family == "jira_10":
                # [UNVERIFIED] Jira 10 may accept registration asynchronously without an id; reconcile finds it by url, events, and filter.
                return ActionOutcome(status="accepted_async", vendor_ref=plan.target_ref)
            raise VendorContractError("Jira DC webhook create response must carry an id")
        return ActionOutcome(status="succeeded", vendor_ref=f"jira_webhook:{webhook_id}", result={"id": webhook_id})

    @plan_create_webhook.reconcile
    async def reconcile_create_webhook(self, plan: ActionPlan, outcome: ActionOutcome) -> ActionOutcome:
        found = find_registration(
            await self._registrations(),
            plan.preconditions["url"],
            plan.preconditions["events"].split(","),
            plan.preconditions["jql_filter"],
        )
        if found is None:
            return ActionOutcome(status="failed", vendor_ref=plan.target_ref, error="webhook not found after write")
        return ActionOutcome(status="succeeded", vendor_ref=f"jira_webhook:{found.id}", result={"id": found.id})

    @action(
        "delete_webhook",
        classification="destructive",
        capability=_CAPABILITY,
        input_model=DeleteWebhookInput,
        idempotency="key",
    )
    async def plan_delete_webhook(self, args: DeleteWebhookInput) -> ActionPlan:
        self.require_destructive("delete_webhook")
        preconditions = {"webhook_id": args.webhook_id, "url": args.expected_url}
        key = digest("delete_webhook", args.webhook_id, args.expected_url)
        target_ref = f"jira_webhook:{args.webhook_id}"
        if await self._checked_registration(args.webhook_id, args.expected_url) is None:
            return ActionPlan(
                action="delete_webhook",
                target_ref=target_ref,
                diff={},
                preconditions=preconditions,
                idempotency_key=key,
                changed=False,
                request={"method": "GET", "path": REGISTRATION_PATH},
            )
        return ActionPlan(
            action="delete_webhook",
            target_ref=target_ref,
            diff={"url": args.expected_url},
            preconditions=preconditions,
            idempotency_key=key,
            changed=True,
            request={"method": "DELETE", "path": delete_path(args.webhook_id)},
        )

    @plan_delete_webhook.apply
    async def apply_delete_webhook(self, plan: ActionPlan) -> ActionOutcome:
        self.require_destructive("delete_webhook")
        if not plan.changed:
            return ActionOutcome(status="no_op", vendor_ref=plan.target_ref)
        if await self._checked_registration(plan.preconditions["webhook_id"], plan.preconditions["url"]) is None:
            return ActionOutcome(status="no_op", vendor_ref=plan.target_ref)
        try:
            # [UNVERIFIED] DC webhook delete status codes; confirm on a Data Center instance.
            await self.http.request(
                "DELETE",
                plan.request["path"],
                idempotency="idempotent_write",
                expected=(200, 202, 204),
            )
        except OutcomeUnknown as exc:
            return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))
        return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref)

    @plan_delete_webhook.reconcile
    async def reconcile_delete_webhook(self, plan: ActionPlan, outcome: ActionOutcome) -> ActionOutcome:
        if find_by_id(await self._registrations(), plan.preconditions["webhook_id"]) is None:
            return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref)
        return ActionOutcome(status="failed", vendor_ref=plan.target_ref, error="webhook still registered")

    # ------------------------------------------------------------ actions: destructive deletes

    @action("delete_issue", classification="destructive", capability=_CAPABILITY, input_model=DeleteIssueInput, idempotency="none")
    async def plan_delete_issue(self, args: DeleteIssueInput) -> ActionPlan:
        self.require_destructive("delete_issue")
        state = issue_state(await self._get_issue(args.issue_id_or_key, fields=_ISSUE_STATE_FIELDS))
        if state["id"] != args.expected_id:
            raise StalePlan("Jira issue id no longer matches the expected id")
        path = f"/rest/api/2/issue/{seg(state['id'])}"
        return ActionPlan(
            action="delete_issue",
            target_ref=f"jira_issue:{state['id']}",
            diff={"delete_subtasks": args.delete_subtasks},
            preconditions=state,
            idempotency_key=digest("delete_issue", state["id"], state["updated"]),
            changed=True,
            request={
                "method": "DELETE",
                "path": path,
                "params": {"deleteSubtasks": "true" if args.delete_subtasks else "false"},
            },
        )

    @plan_delete_issue.apply
    async def apply_delete_issue(self, plan: ActionPlan) -> ActionOutcome:
        self.require_destructive("delete_issue")
        await self._assert_state(plan.preconditions["id"], plan.preconditions)
        try:
            await self.http.request(
                "DELETE",
                plan.request["path"],
                params=plan.request["params"],
                idempotency="idempotent_write",
                expected=(204,),
            )
        except OutcomeUnknown as exc:
            return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))
        return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref)

    @plan_delete_issue.reconcile
    async def reconcile_delete_issue(self, plan: ActionPlan, outcome: ActionOutcome) -> ActionOutcome:
        if await self._is_absent(plan.request["path"]):
            return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref)
        return ActionOutcome(status="failed", vendor_ref=plan.target_ref, error="issue still exists after delete")

    @action("delete_comment", classification="destructive", capability=_CAPABILITY, input_model=DeleteCommentInput, idempotency="none")
    async def plan_delete_comment(self, args: DeleteCommentInput) -> ActionPlan:
        self.require_destructive("delete_comment")
        path = f"/rest/api/2/issue/{seg(args.issue_id_or_key)}/comment/{seg(args.comment_id)}"
        require_field(await self._get_object(path), "updated", args.expected_updated, "comment")
        return ActionPlan(
            action="delete_comment",
            target_ref=f"jira_comment:{args.comment_id}",
            diff={"comment_id": args.comment_id},
            preconditions={"updated": args.expected_updated},
            idempotency_key=digest("delete_comment", args.issue_id_or_key, args.comment_id, args.expected_updated),
            changed=True,
            request={"method": "DELETE", "path": path},
        )

    @plan_delete_comment.apply
    async def apply_delete_comment(self, plan: ActionPlan) -> ActionOutcome:
        self.require_destructive("delete_comment")
        require_field(await self._get_object(plan.request["path"]), "updated", plan.preconditions["updated"], "comment")
        try:
            await self.http.request("DELETE", plan.request["path"], idempotency="idempotent_write", expected=(204,))
        except OutcomeUnknown as exc:
            return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))
        return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref)

    @plan_delete_comment.reconcile
    async def reconcile_delete_comment(self, plan: ActionPlan, outcome: ActionOutcome) -> ActionOutcome:
        if await self._is_absent(plan.request["path"]):
            return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref)
        return ActionOutcome(status="failed", vendor_ref=plan.target_ref, error="comment still exists after delete")

    @action(
        "delete_attachment",
        classification="destructive",
        capability=_CAPABILITY,
        input_model=DeleteAttachmentInput,
        idempotency="none",
    )
    async def plan_delete_attachment(self, args: DeleteAttachmentInput) -> ActionPlan:
        self.require_destructive("delete_attachment")
        path = f"/rest/api/2/attachment/{seg(args.attachment_id)}"
        require_field(await self._get_object(path), "created", args.expected_created, "attachment")
        return ActionPlan(
            action="delete_attachment",
            target_ref=f"jira_attachment:{args.attachment_id}",
            diff={"attachment_id": args.attachment_id},
            preconditions={"created": args.expected_created},
            idempotency_key=digest("delete_attachment", args.attachment_id, args.expected_created),
            changed=True,
            request={"method": "DELETE", "path": path},
        )

    @plan_delete_attachment.apply
    async def apply_delete_attachment(self, plan: ActionPlan) -> ActionOutcome:
        self.require_destructive("delete_attachment")
        require_field(
            await self._get_object(plan.request["path"]), "created", plan.preconditions["created"], "attachment"
        )
        try:
            await self.http.request("DELETE", plan.request["path"], idempotency="idempotent_write", expected=(204,))
        except OutcomeUnknown as exc:
            return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))
        return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref)

    @plan_delete_attachment.reconcile
    async def reconcile_delete_attachment(self, plan: ActionPlan, outcome: ActionOutcome) -> ActionOutcome:
        if await self._is_absent(plan.request["path"]):
            return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref)
        return ActionOutcome(status="failed", vendor_ref=plan.target_ref, error="attachment still exists after delete")
