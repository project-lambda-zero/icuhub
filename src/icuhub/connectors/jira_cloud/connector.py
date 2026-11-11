"""Jira Cloud connector: Basic/API-token, bearer, and OAuth 2.0 (3LO) auth, REST API v3.

Cloud differences from Data Center live here: enhanced JQL search at ``/rest/api/3/search/jql``
traversed by ``nextPageToken``, Atlassian Document Format (ADF) comment bodies, the
``api.atlassian.com/ex/jira/{cloudId}`` gateway, and dynamic webhook registrations that expire
after 30 days. Mapping, webhook parsing, and the shared Jira models live in
``icuhub.connectors._jira``.

Paths and response fields marked [UNVERIFIED] are not sourced in docs/VENDOR_CONNECTORS.md;
confirm them against a live Cloud tenant before relying on them.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import AsyncIterator
from datetime import timedelta
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
    route_label,
    seg,
    status_changed_to,
    time_cursor,
    value_matches,
)
from icuhub.connectors._jira.models import (
    AddCommentInput,
    AttachmentContent,
    AttachmentInput,
    CreateIssueInput,
    CreateMetadataInput,
    CreateWebhookInput,
    DeleteAttachmentInput,
    DeleteCommentInput,
    DeleteIssueInput,
    DeleteWebhookInput,
    DownloadAttachmentInput,
    EmptyInput,
    IssueCommentsInput,
    IssueInput,
    JiraCloudConfig,
    LinkIssueInput,
    PropertyInput,
    RefreshWebhookInput,
    RemoteLinkInput,
    SearchInput,
    TransitionIssueInput,
    UpdateCommentInput,
    UpdateIssueInput,
)
from icuhub.connectors._jira.webhooks import EVENT_TYPES, JiraDeliveryVerifier, parse_jira_delivery
from icuhub.connectors.jira_cloud.webhooks import OAuthBearerJwt
from icuhub.kit.auth import AuthStrategy, BasicAuth, BearerToken, OAuth2RefreshToken
from icuhub.kit.connector import action, mapper, operation, stream, webhook
from icuhub.kit.cursors import SnapshotCursor, TimeIdCursor
from icuhub.kit.errors import (
    AuthFailed,
    BudgetExhausted,
    ConfigError,
    ConnectorError,
    OutcomeUnknown,
    PaginationLoop,
    PermissionDenied,
    RateLimited,
    StalePlan,
    TransientVendorError,
    VendorContractError,
)
from icuhub.kit.paginate import token_pages
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

__all__ = ["JiraCloud"]

_CAPABILITY = "Tracker"
_ATLASSIAN_TOKEN_URL = "https://auth.atlassian.com/oauth/token"
_ISSUE_STATE_FIELDS = "id,updated,status"
_SEARCH_PATH = "/rest/api/3/search/jql"
# Dynamic webhook registrations expire after 30 days; flag them for refresh a week early.
_WEBHOOK_REFRESH_WINDOW = timedelta(days=7)
_WEBHOOK_PATH = "/rest/api/3/webhook"  # Dynamic registration endpoints: developer.atlassian.com api-group-webhooks.
# Read-back failures after a submitted write that leave the outcome reconcilable.
_READ_BACK_AMBIGUOUS = (TransientVendorError, RateLimited)


_RECONCILE_FIELDS = ["id", "key", "summary", "status", "updated"]
_RECONCILE_CHUNK = 100


def _jql_literal(value: str) -> str:
    """Quote a user-supplied issue key or ID as a JQL string literal."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _issue_in_jql(refs: list[str]) -> str:
    # [UNVERIFIED] JQL ``issue`` accepting keys and IDs in one ``in (...)`` list is not confirmed against a primary source.
    return "issue in (" + ", ".join(_jql_literal(ref) for ref in refs) + ")"


def _failed_delivery(raw: dict[str, Any]) -> FailedWebhookDelivery:
    """Parse one dead-letter entry; the affected issue ID comes from the original delivery body."""
    raw = _with_string_id(raw)
    failure_time = raw.get("failureTime")
    if not isinstance(failure_time, int):
        raise VendorContractError("Jira failed webhook must carry an integer failureTime")
    issue_id: str | None = None
    body_text = raw.get("body")
    if isinstance(body_text, str):
        try:
            payload = json.loads(body_text)
        except ValueError:
            payload = None
        issue = payload.get("issue") if isinstance(payload, dict) else None
        candidate = issue.get("id") if isinstance(issue, dict) else None
        if isinstance(candidate, str) and candidate.isdigit():
            issue_id = candidate
    return FailedWebhookDelivery(
        id=jira.required_str(raw, "id"),
        url=jira.required_str(raw, "url"),
        failure_time_ms=failure_time,
        issue_id=issue_id,
    )


def _with_string_id(raw: dict[str, Any]) -> dict[str, Any]:
    """Jira returns integer record ids (audit records, webhooks); the shared helpers require a string id."""
    value = raw.get("id")
    if isinstance(value, int) and not isinstance(value, bool):
        return {**raw, "id": str(value)}
    return raw


def _attachment_ts(raw: dict[str, Any]) -> Any:
    return jira.parse_time(raw.get("created"), "attachment.created")


def _adf_body(body: str | dict[str, Any], marker: str | None = None) -> dict[str, Any]:
    """Build an ADF document for a comment body, appending the idempotency marker if given."""
    if isinstance(body, dict):
        if body.get("type") != "doc":
            raise ConfigError("Jira Cloud comment bodies must be ADF documents with type 'doc'")
        if marker is None:
            return body
        if marker in str(body):
            return body
        content = [*body.get("content", []), _adf_paragraph(marker)]
        return {**body, "content": content}
    text = f"{body}\n\n{marker}" if marker is not None else body
    return {"type": "doc", "version": 1, "content": [_adf_paragraph(text)]}


def _adf_paragraph(text: str) -> dict[str, Any]:
    return {"type": "paragraph", "content": [{"type": "text", "text": text}]}


def _comment_text(body: Any) -> str:
    """Comparable form of a comment body: plain strings as-is, ADF documents by their string form."""
    if isinstance(body, str):
        return body
    return str(body)


# ---------------------------------------------------------------- operation I/O


class SearchIssuesOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    issues: list[TicketRecord]
    next_page_token: str | None


class IssueOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    issue: TicketRecord
    raw_status: str


class TransitionsOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    transitions: list[dict[str, Any]]


class CreateMetadataOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    values: list[dict[str, Any]]


class IssueCommentsOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    comments: list[SourceRecord]
    total: int


class RemoteLinksOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    links: list[dict[str, Any]]


class IssuePropertyOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key: str
    value: Any


class WebhookRegistration(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    url: str
    events: list[str]
    expiration_date: str | None
    needs_refresh: bool


class WebhooksOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    registrations: list[WebhookRegistration]
    failed_deliveries: list[FailedWebhookDelivery]
    reconciled_issues: list[TicketRecord]


class ReconcileIssuesInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    issue_ids_or_keys: list[str] = Field(min_length=1, max_length=100)
    fields: list[str] = Field(default_factory=lambda: list(_RECONCILE_FIELDS))


class ReconcileIssuesOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    issues: list[TicketRecord]
    missing: list[str]


class FailedWebhookDelivery(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    url: str
    failure_time_ms: int
    issue_id: str | None


class IssueRefArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    issue_id_or_key: str = Field(min_length=1)


# ---------------------------------------------------------------- connector


class JiraCloud(JiraBase):
    kind: ClassVar[str] = "jira_cloud"
    version: ClassVar[str] = "0.1.0"
    display_name: ClassVar[str] = "Jira Cloud"
    config_model: ClassVar[type[JiraCloudConfig]] = JiraCloudConfig
    auth_modes: ClassVar[tuple[str, ...]] = ("BasicAuth", "OAuth2RefreshToken", "BearerToken")
    capabilities: ClassVar[tuple[str, ...]] = (_CAPABILITY,)
    flows: ClassVar[tuple[str, ...]] = ("F-029", "F-107")
    api_version: ClassVar[Literal["3"]] = "3"
    search_order: ClassVar[str] = "ORDER BY updated ASC, key ASC"

    # ------------------------------------------------------------ plumbing

    def _cfg(self) -> JiraCloudConfig:
        if not isinstance(self.config, JiraCloudConfig):
            raise ConfigError("jira_cloud requires a JiraCloudConfig")
        return self.config

    def installation_id(self) -> str:
        """The explicit cloudId is the tenant identity; never the first accessible resource."""
        return self._cfg().cloud_id or self.ctx.connection_id

    def _search(self, jql: str, fields: str, expand: str | None = None) -> AsyncIterator[Any]:
        params: dict[str, Any] = {"jql": jql, "fields": fields, "maxResults": self.config.page_size}
        if expand is not None:
            params["expand"] = expand
        return token_pages(
            self.http,
            _SEARCH_PATH,
            params,
            token_param="nextPageToken",
            next_token=lambda body: body.get("nextPageToken") if isinstance(body, dict) else None,
            items=lambda body: list_field(body, "issues"),
            max_pages=self.config.max_pages,
        )

    async def _search_one(self, jql: str) -> list[dict[str, Any]]:
        body = await self._get_object(_SEARCH_PATH, {"jql": jql, "fields": "id,key", "maxResults": 2})
        return list_field(body, "issues")

    async def _reconcile_search(self, jql: str, reconcile_ids: list[int], fields: list[str]) -> list[dict[str, Any]]:
        """Collect every page of a reconciling search; returns only once the response reports ``isLast``.

        An empty page with a continuation token is not treated as the end, so absence can only be
        derived from a fetch that the vendor declared complete.
        """
        cfg = self._cfg()
        found: list[dict[str, Any]] = []
        seen_tokens: set[str] = set()
        token: str | None = None
        for _ in range(cfg.max_pages):
            payload: dict[str, Any] = {
                "jql": jql,
                "fields": fields,
                "maxResults": cfg.page_size,
                "reconcileIssues": reconcile_ids,
            }
            if token is not None:
                payload["nextPageToken"] = token
            body = await self._json("POST", _SEARCH_PATH, json=payload)
            if not isinstance(body, dict):
                raise VendorContractError("Jira search response must be an object")
            found.extend(list_field(body, "issues"))
            if body.get("isLast") is True:
                return found
            raw_next = body.get("nextPageToken")
            if not isinstance(raw_next, str) or not raw_next:
                raise VendorContractError("Jira search response is neither last nor paged")
            if raw_next in seen_tokens:
                raise PaginationLoop(f"pagination token repeated for {_SEARCH_PATH}")
            seen_tokens.add(raw_next)
            token = raw_next
        raise BudgetExhausted(f"reconcile search of {_SEARCH_PATH} exceeded {cfg.max_pages} pages")

    # ------------------------------------------------------------ auth + health

    async def _secret_text(self, ref: Any, name: str) -> str:
        secret = await self.ctx.secrets.resolve(ref)
        try:
            return secret.decode("ascii")
        except UnicodeDecodeError as exc:
            raise ConfigError(f"{name} must be ASCII text") from exc

    async def build_auth(self) -> AuthStrategy:
        cfg = self._cfg()
        if cfg.auth_method == "basic":
            if not cfg.account_email:
                raise ConfigError("account_email is required for basic auth")
            token = await self._secret_text(cfg.api_token, "api_token")
            return BasicAuth(cfg.account_email, token)
        if cfg.auth_method == "bearer":
            token = await self._secret_text(cfg.access_token, "access_token")
            return BearerToken(token)
        if not cfg.client_id:
            raise ConfigError("client_id is required for oauth2_3lo auth")
        client_secret = await self._secret_text(cfg.client_secret, "client_secret")
        refresh_token = await self._secret_text(cfg.refresh_token, "refresh_token")
        return OAuth2RefreshToken(
            token_url=_ATLASSIAN_TOKEN_URL,
            client_id=cfg.client_id,
            client_secret=client_secret,
            refresh_token=refresh_token,
            on_rotate=lambda rotated: self._persist_refresh_token(cfg.refresh_token, rotated),
        )

    async def _persist_refresh_token(self, ref: Any, rotated: str) -> None:
        # Atlassian rotates refresh tokens on every grant; the previous value is dead after this point.
        await self.ctx.secrets.rotate(ref, rotated.encode("ascii"))

    def webhook_verifier(self, secret: bytes) -> JiraDeliveryVerifier:
        """OAuth 2.0 app deliveries carry a bearer JWT signed with the app client secret.

        The shared-token and X-Hub-Signature schemes do not apply to this registration path.
        """
        return JiraDeliveryVerifier(OAuthBearerJwt(secret))

    async def check(self) -> HealthReport:
        try:
            await self.http.request("GET", "/rest/api/3/myself")
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
            installation=self.installation_id(),
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
            cursor = self.advance_cursor(cursor, page, ts_of=issue_updated, id_of=record_id)
            yield RawBatch(records=page, checkpoint=cursor, complete=False)
        if mode == "full":
            yield RawBatch(records=[], checkpoint=cursor, complete=True)

    @stream("projects", cursor=SnapshotCursor, capability=_CAPABILITY, modes=("full",), requires_target=False)
    async def projects(self, target: Target | None, checkpoint: Any, mode: str) -> AsyncIterator[RawBatch]:
        # [UNVERIFIED] paged project search path; spec leaves project read paths unsourced.
        pages = self._paged(
            "/rest/api/3/project/search", None, "values", offset_param="startAt", limit_param="maxResults"
        )
        async for page, _result in pages:
            yield RawBatch(records=page, checkpoint=checkpoint, complete=False)
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
                    f"{self._issue_path(parent['id'])}/comment",
                    None,
                    "comments",
                    offset_param="startAt",
                    limit_param="maxResults",
                )
                async for comment_page, _page_result in pages:
                    records = [{**comment, "_jira_issue": parent} for comment in comment_page]
                    cursor = self.advance_cursor(cursor, records, ts_of=comment_ts, id_of=record_id)
                    yield RawBatch(records=records, checkpoint=cursor, complete=False)
        if mode == "full":
            yield RawBatch(records=[], checkpoint=cursor, complete=True)

    @stream(
        "issue_changelogs",
        cursor=TimeIdCursor,
        capability=_CAPABILITY,
        ocsf_class=6003,
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
            cursor = self.advance_cursor(cursor, records, ts_of=history_ts, id_of=record_id)
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
        """Non-finding evidence records carried on each issue's ``attachment`` field."""
        cursor = time_cursor(checkpoint)
        jql = self._search_jql(cursor.window_start() if mode == "incremental" else None)
        async for issue_page, _result in self._search(jql, "id,key,attachment"):
            records: list[dict[str, Any]] = []
            for issue in issue_page:
                parent = {"id": jira.required_str(issue, "id"), "key": jira.required_str(issue, "key")}
                fields = issue.get("fields")
                found = fields.get("attachment", []) if isinstance(fields, dict) else []
                if not isinstance(found, list):
                    raise VendorContractError("Jira issue attachment field must be a list")
                records.extend({**item, "_jira_issue": parent} for item in found if isinstance(item, dict))
            cursor = self.advance_cursor(cursor, records, ts_of=_attachment_ts, id_of=record_id)
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
        # Administrative scope is not always granted: PermissionDenied propagates so the run is
        # marked not_evaluated rather than closing absence over an empty snapshot.
        cursor = time_cursor(checkpoint)
        window = cursor.window_start() if mode == "incremental" else None
        pages = self._paged("/rest/api/3/auditing/record", None, "records", offset_param="offset", limit_param="limit")
        async for page, _result in pages:
            fresh = [record for record in page if window is None or audit_ts(record) >= window]
            cursor = self.advance_cursor(cursor, fresh, ts_of=audit_ts, id_of=audit_id)
            yield RawBatch(records=fresh, checkpoint=cursor, complete=False)
        if mode == "full":
            yield RawBatch(records=[], checkpoint=cursor, complete=True)

    # ------------------------------------------------------------ mappers

    @mapper("issues", version=1)
    def map_issue(self, raw: dict[str, Any], ctx: MapContext) -> list[TicketRecord]:
        return [jira.map_issue(raw, ctx)]

    @mapper("projects", version=1)
    def map_project(self, raw: dict[str, Any], ctx: MapContext) -> list[SourceRecord]:
        return [jira.map_project(raw, ctx)]

    @mapper("comments", version=1)
    def map_comment(self, raw: dict[str, Any], ctx: MapContext) -> list[SourceRecord]:
        return [jira.map_comment(raw, ctx)]

    @mapper("issue_changelogs", version=1)
    def map_changelog(self, raw: dict[str, Any], ctx: MapContext) -> list[ApiActivity]:
        return [jira.map_changelog(raw, ctx)]

    @mapper("attachments", version=1)
    def map_attachment(self, raw: dict[str, Any], ctx: MapContext) -> list[SourceRecord]:
        return [jira.map_attachment(raw, ctx)]

    @mapper("audit_records", version=1)
    def map_audit(self, raw: dict[str, Any], ctx: MapContext) -> list[ApiActivity]:
        return [jira.map_audit(_with_string_id(raw), ctx)]

    # ------------------------------------------------------------ operations

    @operation(
        "search_issues",
        input_model=SearchInput,
        output_model=SearchIssuesOutput,
        classification="read",
        capability=_CAPABILITY,
    )
    async def search_issues(self, args: SearchInput) -> SearchIssuesOutput:
        body = await self._get_object(
            _SEARCH_PATH,
            {"jql": args.jql, "fields": ",".join(args.fields), "maxResults": args.max_results},
        )
        ctx = self._map_ctx()
        issues = [jira.map_issue(raw, ctx) for raw in list_field(body, "issues")]
        token = body.get("nextPageToken")
        if token is not None and not isinstance(token, str):
            raise VendorContractError("Jira enhanced search nextPageToken must be a string")
        return SearchIssuesOutput(issues=issues, next_page_token=token)

    @operation(
        "get_issue",
        input_model=IssueInput,
        output_model=IssueOutput,
        classification="read",
        capability=_CAPABILITY,
    )
    async def get_issue(self, args: IssueInput) -> IssueOutput:
        expand = [
            name
            for name, on in (("changelog", args.include_changelog), ("renderedFields", args.include_rendered_fields))
            if on
        ]
        body = await self._get_issue(args.issue_id_or_key, fields="*all", expand=",".join(expand) if expand else None)
        fields = body.get("fields")
        status = fields.get("status") if isinstance(fields, dict) else None
        status_name = status.get("name") if isinstance(status, dict) else None
        if not isinstance(status_name, str):
            raise VendorContractError("Jira issue carries no status name")
        return IssueOutput(issue=jira.map_issue(body, self._map_ctx()), raw_status=status_name)

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
        input_model=CreateMetadataInput,
        output_model=CreateMetadataOutput,
        classification="read",
        capability=_CAPABILITY,
    )
    async def get_create_metadata(self, args: CreateMetadataInput) -> CreateMetadataOutput:
        # [UNVERIFIED] createfield metadata path and parameters; spec leaves metadata paths unsourced.
        params: dict[str, Any] = {"startAt": args.start_at, "maxResults": args.max_results}
        if args.issue_type_id is not None:
            params["issueTypeId"] = args.issue_type_id
        body = await self._get_object(f"/rest/api/3/issue/createmeta/{seg(args.project_id_or_key)}/issuetypes", params)
        return CreateMetadataOutput(values=list_field(body, "values"))

    @operation(
        "list_issue_comments",
        input_model=IssueCommentsInput,
        output_model=IssueCommentsOutput,
        classification="read",
        capability=_CAPABILITY,
    )
    async def list_issue_comments(self, args: IssueCommentsInput) -> IssueCommentsOutput:
        issue = await self._get_issue(args.issue_id_or_key, fields="id,key")
        parent = {"id": jira.required_str(issue, "id"), "key": jira.required_str(issue, "key")}
        body = await self._get_object(
            f"{self._issue_path(parent['id'])}/comment",
            {"startAt": args.start_at, "maxResults": args.max_results},
        )
        total = body.get("total")
        if isinstance(total, bool) or not isinstance(total, int):
            raise VendorContractError("Jira comment listing must carry an integer total")
        ctx = self._map_ctx()
        comments = [jira.map_comment({**raw, "_jira_issue": parent}, ctx) for raw in list_field(body, "comments")]
        return IssueCommentsOutput(comments=comments, total=total)

    @operation(
        "download_attachment",
        input_model=DownloadAttachmentInput,
        output_model=AttachmentContent,
        classification="read",
        capability=_CAPABILITY,
    )
    async def download_attachment(self, args: DownloadAttachmentInput) -> AttachmentContent:
        # [UNVERIFIED] attachment metadata/content paths; spec names bounded downloads but not paths.
        max_bytes = min(args.max_bytes, self._cfg().attachment_max_bytes)
        meta = await self._get_object(f"/rest/api/3/attachment/{seg(args.attachment_id)}")
        size = meta.get("size")
        if isinstance(size, int) and not isinstance(size, bool) and size > max_bytes:
            raise ConfigError(f"attachment size {size} exceeds the {max_bytes} byte limit")
        content = await self.http.stream_download(
            "GET", f"/rest/api/3/attachment/content/{seg(args.attachment_id)}", max_bytes=max_bytes
        )
        if isinstance(size, int) and not isinstance(size, bool) and len(content) != size:
            raise VendorContractError(
                f"Jira attachment size mismatch: metadata declares {size} bytes, content carries {len(content)}"
            )
        return AttachmentContent(
            attachment_id=args.attachment_id,
            filename=jira.required_str(meta, "filename"),
            media_type=meta.get("mimeType") if isinstance(meta.get("mimeType"), str) else None,
            size=len(content),
            sha256=hashlib.sha256(content).hexdigest(),
            content_base64=base64.b64encode(content).decode("ascii"),
        )

    @operation(
        "list_remote_links",
        input_model=IssueRefArgs,
        output_model=RemoteLinksOutput,
        classification="read",
        capability=_CAPABILITY,
    )
    async def list_remote_links(self, args: IssueRefArgs) -> RemoteLinksOutput:
        # [UNVERIFIED] remote link read path; used for route reconciliation read-back.
        body = await self._json("GET", f"{self._issue_path(args.issue_id_or_key)}/remotelink")
        if not isinstance(body, list):
            raise VendorContractError("Jira remote link listing must be an array")
        return RemoteLinksOutput(links=[item for item in body if isinstance(item, dict)])

    @operation(
        "get_issue_property",
        input_model=PropertyInput,
        output_model=IssuePropertyOutput,
        classification="read",
        capability=_CAPABILITY,
    )
    async def get_issue_property(self, args: PropertyInput) -> IssuePropertyOutput:
        # [UNVERIFIED] issue property read path; holds the persisted ICUHUB route key.
        body = await self._get_object(f"{self._issue_path(args.issue_id_or_key)}/properties/{seg(args.property_key)}")
        return IssuePropertyOutput(key=args.property_key, value=body.get("value"))

    @operation(
        "list_webhooks",
        input_model=EmptyInput,
        output_model=WebhooksOutput,
        classification="read",
        capability=_CAPABILITY,
    )
    async def list_webhooks(self, args: EmptyInput) -> WebhooksOutput:
        """Registration listing, expiry health, and authoritative re-read of issues behind dead-lettered deliveries.

        A dead-lettered delivery means its change never reached the event stream, so the affected issues are
        re-read through the complete reconciling search rather than trusted from the webhook body.
        """
        registrations = await self._webhook_registrations()
        failed = await self._failed_webhook_deliveries()
        affected = sorted({f.issue_id for f in failed if f.issue_id is not None})
        reconciled: list[TicketRecord] = []
        ctx = self._map_ctx()
        for start in range(0, len(affected), _RECONCILE_CHUNK):
            chunk = affected[start : start + _RECONCILE_CHUNK]
            found = await self._reconcile_search(_issue_in_jql(chunk), [int(ref) for ref in chunk], _RECONCILE_FIELDS)
            reconciled.extend(jira.map_issue(raw, ctx) for raw in found)
        now = self.ctx.clock()
        output: list[WebhookRegistration] = []
        for raw in registrations:
            expiration = raw.get("expirationDate")
            needs_refresh = True
            if isinstance(expiration, str):
                needs_refresh = jira.parse_time(expiration, "webhook.expirationDate") - now <= _WEBHOOK_REFRESH_WINDOW
            output.append(
                WebhookRegistration(
                    id=jira.required_str(raw, "id"),
                    url=jira.required_str(raw, "url"),
                    events=[str(event) for event in raw.get("events", [])]
                    if isinstance(raw.get("events"), list)
                    else [],
                    expiration_date=expiration if isinstance(expiration, str) else None,
                    needs_refresh=needs_refresh,
                )
            )
        return WebhooksOutput(registrations=output, failed_deliveries=failed, reconciled_issues=reconciled)

    @operation(
        "reconcile_issues",
        input_model=ReconcileIssuesInput,
        output_model=ReconcileIssuesOutput,
        classification="read",
        capability=_CAPABILITY,
    )
    async def reconcile_issues(self, args: ReconcileIssuesInput) -> ReconcileIssuesOutput:
        """Authoritative read of named issues; absence is only meaningful over this complete fetch.

        Enhanced JQL search with ``reconcileIssues`` (integer IDs) gives read-after-write
        consistency for the named issues.
        """
        reconcile_ids = [int(ref) for ref in args.issue_ids_or_keys if ref.isdigit()]
        found = await self._reconcile_search(_issue_in_jql(args.issue_ids_or_keys), reconcile_ids, args.fields)
        ctx = self._map_ctx()
        issues = [jira.map_issue(raw, ctx) for raw in found]
        seen = {str(raw.get("id")) for raw in found} | {str(raw.get("key")) for raw in found}
        missing = [ref for ref in args.issue_ids_or_keys if ref not in seen]
        return ReconcileIssuesOutput(issues=issues, missing=missing)

    async def _failed_webhook_deliveries(self) -> list[FailedWebhookDelivery]:
        """Dead-lettered deliveries; paged by the vendor's ``failedAfter`` cursor URL, not ``startAt``."""
        cfg = self._cfg()
        failures: list[FailedWebhookDelivery] = []
        path = f"{_WEBHOOK_PATH}/failed?maxResults={cfg.page_size}"
        seen_next: set[str] = set()
        for _ in range(cfg.max_pages):
            body = await self._json("GET", path)
            if not isinstance(body, dict):
                raise VendorContractError("Jira failed-webhook response must be an object")
            for raw in list_field(body, "values"):
                failures.append(_failed_delivery(raw))
            next_url = body.get("next")
            if next_url is None:
                return failures
            if not isinstance(next_url, str) or not next_url:
                raise VendorContractError("Jira failed-webhook next must be a non-empty string")
            if next_url in seen_next:
                raise PaginationLoop(f"pagination URL repeated for {_WEBHOOK_PATH}/failed")
            seen_next.add(next_url)
            path = next_url
        raise BudgetExhausted(f"failed-webhook listing exceeded {cfg.max_pages} pages")

    async def _webhook_registrations(self) -> list[dict[str, Any]]:
        registrations: list[dict[str, Any]] = []
        pages = self._paged(_WEBHOOK_PATH, None, "values", offset_param="startAt", limit_param="maxResults")
        async for page, _result in pages:
            registrations.extend(_with_string_id(raw) for raw in page)
        return registrations

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
                request={"method": "GET", "path": self._issue_path(key)},
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
            fields["description"] = (
                _adf_body(args.description) if isinstance(args.description, str) else args.description
            )
        return ActionPlan(
            action="create_issue",
            target_ref=f"route:{label}",
            diff={"summary": args.summary, "project_key": args.project_key, "issue_type": args.issue_type},
            preconditions={"route_label": label},
            idempotency_key=self.action_identity("create_issue", args.route_key),
            changed=True,
            request={"method": "POST", "path": self._api_path("/issue"), "json": {"fields": fields}},
        )

    async def _created_issue_result(self, key: str) -> ActionOutcome:
        vendor_ref = f"jira_issue:{key}"
        try:
            raw = await self._get_issue(key, fields="id,updated,status")
            ticket = jira.map_issue(raw, self._map_ctx())
        except ConnectorError as exc:
            return ActionOutcome(
                status="outcome_unknown",
                vendor_ref=vendor_ref,
                result={"key": key},
                error=type(exc).__name__,
            )
        return ActionOutcome(
            status="succeeded",
            vendor_ref=vendor_ref,
            result={
                "id": raw["id"],
                "key": key,
                "revision": ticket.revision,
                "url": ticket.url,
            },
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
        if not isinstance(body, dict):
            raise VendorContractError("Jira create response must be an object")
        key = jira.required_str(body, "key")
        return await self._created_issue_result(key)

    @plan_create_issue.reconcile
    async def reconcile_create_issue(self, plan: ActionPlan, _outcome: ActionOutcome) -> ActionOutcome:
        matches = await self._search_one(f'labels = "{plan.preconditions["route_label"]}"')
        if not matches:
            return ActionOutcome(
                status="failed",
                vendor_ref=plan.target_ref,
                error="no issue carries the route label after the write timed out",
            )
        key = jira.required_str(matches[0], "key")
        return await self._created_issue_result(key)

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
                "path": self._issue_path(args.expected_id),
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
    async def reconcile_update_issue_fields(self, plan: ActionPlan, _outcome: ActionOutcome) -> ActionOutcome:
        issue = await self._get_issue(plan.preconditions["id"], fields=",".join(plan.diff["fields"]))
        fields = issue.get("fields")
        if not isinstance(fields, dict):
            raise VendorContractError("Jira issue fields must be an object")
        if all(value_matches(value, fields.get(name)) for name, value in plan.diff["fields"].items()):
            return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref)
        omitted = [name for name in plan.diff["fields"] if name not in fields]
        if omitted:
            return ActionOutcome(
                status="unverified",
                vendor_ref=plan.target_ref,
                error=f"read-back omitted requested fields: {', '.join(sorted(omitted))}",
            )
        return ActionOutcome(status="failed", vendor_ref=plan.target_ref, error="requested fields are not present")

    # ------------------------------------------------------------ actions: add_comment / update_comment

    @action(
        "add_comment", classification="write", capability=_CAPABILITY, input_model=AddCommentInput, idempotency="key"
    )
    async def plan_add_comment(self, args: AddCommentInput) -> ActionPlan:
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
                request={"method": "GET", "path": f"{self._issue_path(issue_id)}/comment"},
            )
        payload: dict[str, Any] = {"body": _adf_body(args.body, marker)}
        if args.visibility is not None:
            payload["visibility"] = args.visibility
        return ActionPlan(
            action="add_comment",
            target_ref=f"jira_issue:{issue_id}",
            diff={"body_length": len(str(args.body))},
            preconditions={"issue_id": issue_id, "marker": marker},
            idempotency_key=digest("add_comment", issue_id, args.action_key),
            changed=True,
            request={"method": "POST", "path": f"{self._issue_path(issue_id)}/comment", "json": payload},
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
    async def reconcile_add_comment(self, plan: ActionPlan, _outcome: ActionOutcome) -> ActionOutcome:
        found = await self._find_comment(plan.preconditions["issue_id"], plan.preconditions["marker"])
        if found is None:
            return ActionOutcome(status="failed", vendor_ref=plan.target_ref, error="comment marker not found after write")
        comment_id = jira.required_str(found, "id")
        return ActionOutcome(status="succeeded", vendor_ref=f"jira_comment:{comment_id}", result={"id": comment_id})

    @action(
        "update_comment",
        classification="write",
        capability=_CAPABILITY,
        input_model=UpdateCommentInput,
        idempotency="natural_key",
    )
    async def plan_update_comment(self, args: UpdateCommentInput) -> ActionPlan:
        path = f"{self._issue_path(args.issue_id_or_key)}/comment/{seg(args.comment_id)}"
        comment = await self._get_object(path)
        updated = comment.get("updated")
        if updated != args.expected_updated:
            raise StalePlan("Jira comment changed since the plan was made")
        body = _adf_body(args.body)
        key = digest("update_comment", args.comment_id, args.expected_updated, str(args.body))
        if _comment_text(comment.get("body")) == _comment_text(body):
            return ActionPlan(
                action="update_comment",
                target_ref=f"jira_comment:{args.comment_id}",
                diff={},
                preconditions={"comment_id": args.comment_id, "updated": args.expected_updated},
                idempotency_key=key,
                changed=False,
                request={"method": "GET", "path": path},
            )
        return ActionPlan(
            action="update_comment",
            target_ref=f"jira_comment:{args.comment_id}",
            diff={"body_length": len(str(args.body))},
            preconditions={"comment_id": args.comment_id, "updated": args.expected_updated},
            idempotency_key=key,
            changed=True,
            request={"method": "PUT", "path": path, "json": {"body": body}},
        )

    @plan_update_comment.apply
    async def apply_update_comment(self, plan: ActionPlan) -> ActionOutcome:
        if not plan.changed:
            return ActionOutcome(status="no_op", vendor_ref=plan.target_ref)
        try:
            await self._json(
                "PUT",
                plan.request["path"],
                json=plan.request["json"],
                idempotency="idempotent_write",
                expected=(200,),
            )
        except OutcomeUnknown as exc:
            return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))
        return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref)

    @plan_update_comment.reconcile
    async def reconcile_update_comment(self, plan: ActionPlan, _outcome: ActionOutcome) -> ActionOutcome:
        comment = await self._get_object(plan.request["path"])
        expected = plan.request.get("json", {}).get("body")
        if expected is not None and _comment_text(comment.get("body")) == _comment_text(expected):
            return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref)
        return ActionOutcome(status="failed", vendor_ref=plan.target_ref, error="comment body does not match the plan")

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
                request={"method": "GET", "path": self._issue_path(state["id"])},
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
            request={"method": "POST", "path": f"{self._issue_path(state['id'])}/transitions", "json": payload},
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
    async def reconcile_transition_issue(self, plan: ActionPlan, _outcome: ActionOutcome) -> ActionOutcome:
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

    # ------------------------------------------------------------ actions: link_issue / add_remote_link

    @action(
        "link_issue",
        classification="write",
        capability=_CAPABILITY,
        input_model=LinkIssueInput,
        idempotency="natural_key",
    )
    async def plan_link_issue(self, args: LinkIssueInput) -> ActionPlan:
        inward = await self._get_issue(args.inward_issue, fields="issuelinks")
        link_key = digest("link_issue", args.inward_issue, args.outward_issue, args.link_type)
        preconditions = {"inward": args.inward_issue, "outward": args.outward_issue, "link_type": args.link_type}
        if link_exists(inward, args.link_type, args.outward_issue):
            return ActionPlan(
                action="link_issue",
                target_ref=f"jira_link:{link_key}",
                diff={},
                preconditions=preconditions,
                idempotency_key=link_key,
                changed=False,
                request={"method": "GET", "path": self._issue_path(args.inward_issue)},
            )
        payload: dict[str, Any] = {
            "type": {"name": args.link_type},
            "inwardIssue": {"key": args.inward_issue},
            "outwardIssue": {"key": args.outward_issue},
        }
        if args.comment is not None:
            payload["comment"] = {"body": _adf_body(args.comment)}
        return ActionPlan(
            action="link_issue",
            target_ref=f"jira_link:{link_key}",
            diff={"link_type": args.link_type},
            preconditions=preconditions,
            idempotency_key=link_key,
            changed=True,
            request={"method": "POST", "path": self._api_path("/issueLink"), "json": payload},
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
                expected=(200, 201, 204),
            )
        except OutcomeUnknown as exc:
            return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))
        return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref)

    @plan_link_issue.reconcile
    async def reconcile_link_issue(self, plan: ActionPlan, _outcome: ActionOutcome) -> ActionOutcome:
        inward = await self._get_issue(plan.preconditions["inward"], fields="issuelinks")
        if link_exists(inward, plan.preconditions["link_type"], plan.preconditions["outward"]):
            return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref)
        return ActionOutcome(status="failed", vendor_ref=plan.target_ref, error="issue link not found after write")

    @action(
        "add_remote_link",
        classification="write",
        capability=_CAPABILITY,
        input_model=RemoteLinkInput,
        idempotency="natural_key",
    )
    async def plan_add_remote_link(self, args: RemoteLinkInput) -> ActionPlan:
        issue = await self._get_issue(args.issue_id_or_key, fields="id")
        issue_id = jira.required_str(issue, "id")
        key = digest("add_remote_link", issue_id, args.global_id)
        path = f"{self._issue_path(issue_id)}/remotelink"
        existing = await self._json("GET", path)
        if not isinstance(existing, list):
            raise VendorContractError("Jira remote link listing must be an array")
        for link in existing:
            if isinstance(link, dict) and link.get("globalId") == args.global_id:
                return ActionPlan(
                    action="add_remote_link",
                    target_ref=f"jira_remote_link:{link.get('id', key)}",
                    diff={},
                    preconditions={"issue_id": issue_id, "global_id": args.global_id},
                    idempotency_key=key,
                    changed=False,
                    request={"method": "GET", "path": path},
                )
        obj: dict[str, Any] = {"url": args.url, "title": args.title}
        if args.icon is not None:
            obj["icon"] = args.icon
        return ActionPlan(
            action="add_remote_link",
            target_ref=f"jira_issue:{issue_id}",
            diff={"global_id": args.global_id, "url": args.url, "title": args.title},
            preconditions={"issue_id": issue_id, "global_id": args.global_id},
            idempotency_key=key,
            changed=True,
            request={"method": "POST", "path": path, "json": {"globalId": args.global_id, "object": obj}},
        )

    @plan_add_remote_link.apply
    async def apply_add_remote_link(self, plan: ActionPlan) -> ActionOutcome:
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
        link_id = body.get("id") if isinstance(body, dict) else None
        return ActionOutcome(
            status="succeeded",
            vendor_ref=f"jira_remote_link:{link_id}" if link_id is not None else plan.target_ref,
            result={"id": link_id} if link_id is not None else {},
        )

    @plan_add_remote_link.reconcile
    async def reconcile_add_remote_link(self, plan: ActionPlan, _outcome: ActionOutcome) -> ActionOutcome:
        body = await self._json("GET", plan.request["path"])
        if isinstance(body, list):
            for link in body:
                if isinstance(link, dict) and link.get("globalId") == plan.preconditions["global_id"]:
                    return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref)
        return ActionOutcome(status="failed", vendor_ref=plan.target_ref, error="remote link not found after write")

    # ------------------------------------------------------------ actions: upload_attachment

    @action(
        "upload_attachment",
        classification="write",
        capability=_CAPABILITY,
        input_model=AttachmentInput,
        idempotency="key",
    )
    async def plan_upload_attachment(self, args: AttachmentInput) -> ActionPlan:
        cfg = self._cfg()
        content = base64.b64decode(args.content_base64, validate=True)
        if len(content) > cfg.attachment_max_bytes:
            raise ConfigError(f"attachment exceeds attachment_max_bytes ({cfg.attachment_max_bytes})")
        content_sha256 = hashlib.sha256(content).hexdigest()
        issue = await self._get_issue(args.issue_id_or_key, fields="id")
        issue_id = jira.required_str(issue, "id")
        key = digest("upload_attachment", issue_id, args.filename, str(len(content)), content_sha256)
        preconditions = {"issue_id": issue_id, "filename": args.filename, "size": str(len(content))}
        existing = await self._find_attachment(issue_id, args.filename, len(content))
        if existing is not None:
            return ActionPlan(
                action="upload_attachment",
                target_ref=f"jira_attachment:{jira.required_str(existing, 'id')}",
                diff={},
                preconditions=preconditions,
                idempotency_key=key,
                changed=False,
                request={"method": "GET", "path": self._issue_path(issue_id)},
            )
        return ActionPlan(
            action="upload_attachment",
            target_ref=f"jira_issue:{issue_id}",
            diff={"filename": args.filename, "size": len(content), "content_sha256": content_sha256},
            preconditions=preconditions,
            idempotency_key=key,
            changed=True,
            request={
                "method": "POST",
                "path": f"{self._issue_path(issue_id)}/attachments",
                "media_type": args.media_type,
                "content_base64": args.content_base64,
            },
        )

    @plan_upload_attachment.apply
    async def apply_upload_attachment(self, plan: ActionPlan) -> ActionOutcome:
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
        return ActionOutcome(
            status="succeeded", vendor_ref=f"jira_attachment:{attachment_id}", result={"id": attachment_id}
        )

    @plan_upload_attachment.reconcile
    async def reconcile_upload_attachment(self, plan: ActionPlan, _outcome: ActionOutcome) -> ActionOutcome:
        found = await self._find_attachment(
            plan.preconditions["issue_id"], plan.preconditions["filename"], int(plan.preconditions["size"])
        )
        if found is None:
            return ActionOutcome(status="failed", vendor_ref=plan.target_ref, error="attachment not found after write")
        attachment_id = jira.required_str(found, "id")
        return ActionOutcome(
            status="succeeded", vendor_ref=f"jira_attachment:{attachment_id}", result={"id": attachment_id}
        )

    # ------------------------------------------------------------ actions: webhook lifecycle

    @action(
        "create_webhook",
        classification="write",
        capability=_CAPABILITY,
        input_model=CreateWebhookInput,
        idempotency="natural_key",
    )
    async def plan_create_webhook(self, args: CreateWebhookInput) -> ActionPlan:
        key = digest("create_webhook", args.url, ",".join(args.events), args.jql_filter)
        for raw in await self._webhook_registrations():
            events = raw.get("events")
            if raw.get("url") == args.url and isinstance(events, list) and sorted(events) == args.events:
                return ActionPlan(
                    action="create_webhook",
                    target_ref=f"jira_webhook:{jira.required_str(raw, 'id')}",
                    diff={},
                    preconditions={"url": args.url, "events": args.events},
                    idempotency_key=key,
                    changed=False,
                    request={"method": "GET", "path": _WEBHOOK_PATH},
                )
        return ActionPlan(
            action="create_webhook",
            target_ref=f"webhook:{key}",
            diff={"url": args.url, "events": args.events, "jql_filter": args.jql_filter},
            preconditions={"url": args.url, "events": args.events},
            idempotency_key=key,
            changed=True,
            request={
                "method": "POST",
                "path": _WEBHOOK_PATH,
                "json": {"url": args.url, "webhooks": [{"events": args.events, "jqlFilter": args.jql_filter}]},
            },
        )

    @plan_create_webhook.apply
    async def apply_create_webhook(self, plan: ActionPlan) -> ActionOutcome:
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
        results = body.get("webhookRegistrationResult") if isinstance(body, dict) else None
        if not isinstance(results, list) or not results or not isinstance(results[0], dict):
            raise VendorContractError("Jira webhook registration must return webhookRegistrationResult")
        result = results[0]
        if "createdWebhookId" not in result:
            return ActionOutcome(
                status="failed",
                vendor_ref=plan.target_ref,
                error=f"Jira webhook registration failed: {result.get('errors', result)}",
            )
        webhook_id = str(result["createdWebhookId"])
        try:
            registrations = await self._webhook_registrations()
        except _READ_BACK_AMBIGUOUS as exc:
            return ActionOutcome(
                status="outcome_unknown",
                vendor_ref=plan.target_ref,
                error=f"registration read-back after create failed: {exc}",
            )
        entry = next((raw for raw in registrations if str(raw.get("id")) == webhook_id), None)
        if entry is None:
            return ActionOutcome(
                status="failed",
                vendor_ref=plan.target_ref,
                error="created webhook is absent from the registration read-back",
            )
        if "url" not in entry:
            return ActionOutcome(
                status="unverified",
                vendor_ref=plan.target_ref,
                error="registration read-back omitted the webhook URL",
            )
        if entry["url"] != plan.preconditions["url"]:
            return ActionOutcome(
                status="failed",
                vendor_ref=plan.target_ref,
                error="created webhook URL differs from the approved URL",
            )
        return ActionOutcome(
            status="succeeded",
            vendor_ref=f"jira_webhook:{webhook_id}",
            result={"id": webhook_id},
        )

    @plan_create_webhook.reconcile
    async def reconcile_create_webhook(self, plan: ActionPlan, _outcome: ActionOutcome) -> ActionOutcome:
        for raw in await self._webhook_registrations():
            if raw.get("url") == plan.preconditions["url"]:
                webhook_id = jira.required_str(raw, "id")
                return ActionOutcome(
                    status="succeeded",
                    vendor_ref=f"jira_webhook:{webhook_id}",
                    result={"id": webhook_id, "expiration_date": raw.get("expirationDate")},
                )
        registrations = await self._webhook_registrations()
        if any("url" not in raw for raw in registrations):
            return ActionOutcome(
                status="unverified",
                vendor_ref=plan.target_ref,
                error="registration read-back omitted webhook URLs; the approved registration cannot be established",
            )
        return ActionOutcome(
            status="failed",
            vendor_ref=plan.target_ref,
            error="webhook not registered in the authoritative read-back after write",
        )

    @action(
        "delete_webhook",
        classification="destructive",
        capability=_CAPABILITY,
        input_model=DeleteWebhookInput,
        idempotency="key",
    )
    async def plan_delete_webhook(self, args: DeleteWebhookInput) -> ActionPlan:
        self.require_destructive("delete_webhook")
        for raw in await self._webhook_registrations():
            if jira.required_str(raw, "id") == args.webhook_id:
                if raw.get("url") != args.expected_url:
                    raise StalePlan("Jira webhook URL changed since the plan was made")
                return ActionPlan(
                    action="delete_webhook",
                    target_ref=f"jira_webhook:{args.webhook_id}",
                    diff={"url": args.expected_url},
                    preconditions={"webhook_id": args.webhook_id, "url": args.expected_url},
                    idempotency_key=digest("delete_webhook", args.webhook_id, args.expected_url),
                    changed=True,
                    request={"method": "DELETE", "path": _WEBHOOK_PATH, "json": {"webhookIds": [int(args.webhook_id)]}},
                )
        return ActionPlan(
            action="delete_webhook",
            target_ref=f"jira_webhook:{args.webhook_id}",
            diff={},
            preconditions={"webhook_id": args.webhook_id, "url": args.expected_url},
            idempotency_key=digest("delete_webhook", args.webhook_id, args.expected_url),
            changed=False,
            request={"method": "GET", "path": _WEBHOOK_PATH},
        )

    @plan_delete_webhook.apply
    async def apply_delete_webhook(self, plan: ActionPlan) -> ActionOutcome:
        self.require_destructive("delete_webhook")
        if not plan.changed:
            return ActionOutcome(status="no_op", vendor_ref=plan.target_ref)
        try:
            await self.http.request(
                "DELETE",
                plan.request["path"],
                json=plan.request["json"],
                idempotency="idempotent_write",
                expected=(200, 202, 204),
            )
        except OutcomeUnknown as exc:
            return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))
        try:
            registrations = await self._webhook_registrations()
        except _READ_BACK_AMBIGUOUS as exc:
            return ActionOutcome(
                status="outcome_unknown",
                vendor_ref=plan.target_ref,
                error=f"registration read-back after delete failed: {exc}",
            )
        if self._still_registered(plan.preconditions["webhook_id"], registrations):
            return ActionOutcome(status="failed", vendor_ref=plan.target_ref, error="webhook still registered")
        return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref)

    @plan_delete_webhook.reconcile
    async def reconcile_delete_webhook(self, plan: ActionPlan, _outcome: ActionOutcome) -> ActionOutcome:
        if self._still_registered(plan.preconditions["webhook_id"], await self._webhook_registrations()):
            return ActionOutcome(status="failed", vendor_ref=plan.target_ref, error="webhook still registered")
        return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref)

    @staticmethod
    def _still_registered(webhook_id: str, registrations: list[dict[str, Any]]) -> bool:
        return any(jira.required_str(raw, "id") == webhook_id for raw in registrations)

    @action(
        "refresh_webhook",
        classification="write",
        capability=_CAPABILITY,
        input_model=RefreshWebhookInput,
        idempotency="natural_key",
    )
    async def plan_refresh_webhook(self, args: RefreshWebhookInput) -> ActionPlan:
        """Extend dynamic registrations before the 30-day expiry; no-op when nothing is registered."""
        by_id = {jira.required_str(raw, "id"): raw for raw in await self._webhook_registrations()}
        missing = [webhook_id for webhook_id in args.webhook_ids if webhook_id not in by_id]
        if missing:
            raise StalePlan(f"Jira webhook registrations no longer exist: {','.join(missing)}")
        key = digest("refresh_webhook", ",".join(sorted(args.webhook_ids)))
        return ActionPlan(
            action="refresh_webhook",
            target_ref=f"jira_webhook:{','.join(sorted(args.webhook_ids))}",
            diff={"webhook_ids": sorted(args.webhook_ids)},
            preconditions={
                "webhook_ids": sorted(args.webhook_ids),
                "expiration_before": {value: by_id[value].get("expirationDate") for value in sorted(args.webhook_ids)},
            },
            idempotency_key=key,
            changed=True,
            request={
                "method": "PUT",
                "path": f"{_WEBHOOK_PATH}/refresh",
                "json": {"webhookIds": [int(value) for value in args.webhook_ids]},
            },
        )

    @plan_refresh_webhook.apply
    async def apply_refresh_webhook(self, plan: ActionPlan) -> ActionOutcome:
        try:
            await self.http.request(
                "PUT",
                plan.request["path"],
                json=plan.request["json"],
                idempotency="idempotent_write",
                expected=(202,),
            )
        except OutcomeUnknown as exc:
            return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))
        try:
            registrations = await self._webhook_registrations()
        except _READ_BACK_AMBIGUOUS as exc:
            return ActionOutcome(
                status="outcome_unknown",
                vendor_ref=plan.target_ref,
                error=f"registration read-back after refresh failed: {exc}",
            )
        return self._refresh_outcome(plan, registrations)

    @plan_refresh_webhook.reconcile
    async def reconcile_refresh_webhook(self, plan: ActionPlan, _outcome: ActionOutcome) -> ActionOutcome:
        return self._refresh_outcome(plan, await self._webhook_registrations())

    @staticmethod
    def _refresh_outcome(plan: ActionPlan, registrations: list[dict[str, Any]]) -> ActionOutcome:
        """Judge a refresh against the authoritative registration list.

        A requested registration absent from the list is a definitive failure. A present registration whose
        expiry is missing or has not advanced past the pre-refresh value is unverified: the refresh endpoint
        answers 202, so the extension may still be pending and the read-back cannot establish it.
        """
        by_id = {jira.required_str(raw, "id"): raw for raw in registrations}
        webhook_ids: list[str] = plan.preconditions["webhook_ids"]
        missing = [value for value in webhook_ids if value not in by_id]
        if missing:
            return ActionOutcome(
                status="failed",
                vendor_ref=plan.target_ref,
                error=f"registrations absent from the read-back: {','.join(missing)}; re-create them",
            )
        before_map: dict[str, Any] = plan.preconditions["expiration_before"]
        pending: list[str] = []
        for value in webhook_ids:
            after = by_id[value].get("expirationDate")
            before = before_map.get(value)
            if not isinstance(after, str) or not isinstance(before, str):
                pending.append(value)
                continue
            if jira.parse_time(after, "webhook.expirationDate") <= jira.parse_time(before, "webhook.expirationDate"):
                pending.append(value)
        if pending:
            return ActionOutcome(
                status="unverified",
                vendor_ref=plan.target_ref,
                error=f"expiry not verifiably extended in the read-back: {','.join(pending)}",
            )
        return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref)

    # ------------------------------------------------------------ actions: destructive deletes

    @action(
        "delete_issue",
        classification="destructive",
        capability=_CAPABILITY,
        input_model=DeleteIssueInput,
        idempotency="none",
    )
    async def plan_delete_issue(self, args: DeleteIssueInput) -> ActionPlan:
        self.require_destructive("delete_issue")
        issue = await self._get_issue(args.issue_id_or_key, fields="id")
        issue_id = jira.required_str(issue, "id")
        if issue_id != args.expected_id:
            raise StalePlan("Jira issue ID does not match the planned target")
        return ActionPlan(
            action="delete_issue",
            target_ref=f"jira_issue:{issue_id}",
            diff={"delete_subtasks": args.delete_subtasks},
            preconditions={"id": issue_id},
            idempotency_key=digest("delete_issue", issue_id),
            changed=True,
            request={
                "method": "DELETE",
                "path": self._issue_path(issue_id),
                "params": {"deleteSubtasks": "true" if args.delete_subtasks else "false"},
            },
        )

    @plan_delete_issue.apply
    async def apply_delete_issue(self, plan: ActionPlan) -> ActionOutcome:
        self.require_destructive("delete_issue")
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
    async def reconcile_delete_issue(self, plan: ActionPlan, _outcome: ActionOutcome) -> ActionOutcome:
        if await self._is_absent(plan.request["path"]):
            return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref)
        return ActionOutcome(status="failed", vendor_ref=plan.target_ref, error="issue still exists after delete")

    @action(
        "delete_comment",
        classification="destructive",
        capability=_CAPABILITY,
        input_model=DeleteCommentInput,
        idempotency="natural_key",
    )
    async def plan_delete_comment(self, args: DeleteCommentInput) -> ActionPlan:
        self.require_destructive("delete_comment")
        path = f"{self._issue_path(args.issue_id_or_key)}/comment/{seg(args.comment_id)}"
        comment = await self._get_object(path)
        if comment.get("updated") != args.expected_updated:
            raise StalePlan("Jira comment changed since the plan was made")
        return ActionPlan(
            action="delete_comment",
            target_ref=f"jira_comment:{args.comment_id}",
            diff={},
            preconditions={"comment_id": args.comment_id, "updated": args.expected_updated},
            idempotency_key=digest("delete_comment", args.comment_id, args.expected_updated),
            changed=True,
            request={"method": "DELETE", "path": path},
        )

    @plan_delete_comment.apply
    async def apply_delete_comment(self, plan: ActionPlan) -> ActionOutcome:
        self.require_destructive("delete_comment")
        try:
            await self.http.request(
                "DELETE",
                plan.request["path"],
                idempotency="idempotent_write",
                expected=(204,),
            )
        except OutcomeUnknown as exc:
            return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))
        return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref)

    @plan_delete_comment.reconcile
    async def reconcile_delete_comment(self, plan: ActionPlan, _outcome: ActionOutcome) -> ActionOutcome:
        if await self._is_absent(plan.request["path"]):
            return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref)
        return ActionOutcome(status="failed", vendor_ref=plan.target_ref, error="comment still exists after delete")

    @action(
        "delete_attachment",
        classification="destructive",
        capability=_CAPABILITY,
        input_model=DeleteAttachmentInput,
        idempotency="natural_key",
    )
    async def plan_delete_attachment(self, args: DeleteAttachmentInput) -> ActionPlan:
        self.require_destructive("delete_attachment")
        # [UNVERIFIED] attachment metadata path; same resource family as the bounded download.
        path = f"/rest/api/3/attachment/{seg(args.attachment_id)}"
        attachment = await self._get_object(path)
        if attachment.get("created") != args.expected_created:
            raise StalePlan("Jira attachment changed since the plan was made")
        return ActionPlan(
            action="delete_attachment",
            target_ref=f"jira_attachment:{args.attachment_id}",
            diff={"filename": attachment.get("filename")},
            preconditions={"attachment_id": args.attachment_id, "created": args.expected_created},
            idempotency_key=digest("delete_attachment", args.attachment_id, args.expected_created),
            changed=True,
            request={"method": "DELETE", "path": path},
        )

    @plan_delete_attachment.apply
    async def apply_delete_attachment(self, plan: ActionPlan) -> ActionOutcome:
        self.require_destructive("delete_attachment")
        try:
            await self.http.request(
                "DELETE",
                plan.request["path"],
                idempotency="idempotent_write",
                expected=(204,),
            )
        except OutcomeUnknown as exc:
            return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))
        return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref)

    @plan_delete_attachment.reconcile
    async def reconcile_delete_attachment(self, plan: ActionPlan, _outcome: ActionOutcome) -> ActionOutcome:
        if await self._is_absent(plan.request["path"]):
            return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref)
        return ActionOutcome(status="failed", vendor_ref=plan.target_ref, error="attachment still exists after delete")
