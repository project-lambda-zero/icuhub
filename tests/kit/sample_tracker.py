"""Reference tracker connector exercising every kit decorator. Test fixture only; never added to CONNECTORS."""

import json
from collections.abc import AsyncIterator
from datetime import datetime
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict, Field

from icuhub.kit.auth import AuthStrategy, BearerToken
from icuhub.kit.connector import Connector, action, importer, mapper, operation, stream, webhook
from icuhub.kit.cursors import TimeIdCursor
from icuhub.kit.errors import (
    AuthFailed,
    ConfigError,
    OutcomeUnknown,
    RateLimited,
    StalePlan,
    TransientVendorError,
    VendorContractError,
)
from icuhub.kit.mapping import EnumTable
from icuhub.kit.paginate import offset_pages
from icuhub.kit.types import (
    ActionOutcome,
    ActionPlan,
    CapabilityHealth,
    ConnectorConfig,
    HealthReport,
    ImportedFile,
    MapContext,
    RawBatch,
    Scope,
    SecretRef,
    StreamRecord,
    Target,
    TicketRecord,
    WebhookDelivery,
)
from icuhub.kit.webhook import HmacSignature, WebhookVerifier

__all__ = ["GetTicketArgs", "SampleTracker", "SampleTrackerConfig", "TransitionArgs"]

_STATUS_CATEGORY = EnumTable(
    mapping={"To Do": "open", "In Progress": "in_progress", "Done": "done"},
    default="unknown",
)
_EVENT_TYPES = ("issue.created", "issue.updated", "issue.deleted")
_KEY_PATTERN = r"^[A-Z][A-Z0-9]{1,9}-[1-9][0-9]{0,8}$"


class SampleTrackerConfig(ConnectorConfig):
    api_token: SecretRef


class GetTicketArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key: str = Field(pattern=_KEY_PATTERN)


class TransitionArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key: str = Field(pattern=_KEY_PATTERN)
    expected_status: str = Field(min_length=1)
    to_status: str = Field(min_length=1)


def _str_field(raw: dict[str, Any], field: str) -> str:
    value = raw.get(field)
    if not isinstance(value, str) or not value:
        raise VendorContractError(f"{field} must be a non-empty string")
    return value


def _parse_ts(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise VendorContractError(f"{field} must be an ISO-8601 string")
    try:
        return datetime.fromisoformat(value)
    except ValueError as exc:
        raise VendorContractError(f"{field} is not ISO-8601") from exc


def _issues_of(body: Any) -> list[dict[str, Any]]:
    if not isinstance(body, dict) or not isinstance(body.get("issues"), list):
        raise VendorContractError("issue list response must contain an 'issues' array")
    return body["issues"]


def _updated_at(raw: dict[str, Any]) -> datetime:
    return _parse_ts(raw.get("updated_at"), "updated_at")


def _issue_key(raw: dict[str, Any]) -> str:
    return _str_field(raw, "key")


def _key_from_ref(target_ref: str) -> str:
    return target_ref.removeprefix("sample_tracker:issue:")


class SampleTracker(Connector):
    kind: ClassVar[str] = "sample_tracker"
    version: ClassVar[str] = "0.1.0"
    display_name: ClassVar[str] = "Sample Tracker"
    config_model: ClassVar[type[ConnectorConfig]] = SampleTrackerConfig
    auth_modes: ClassVar[tuple[str, ...]] = ("BearerToken",)
    capabilities: ClassVar[tuple[str, ...]] = ("Tracker",)
    scopes: ClassVar[tuple[Scope, ...]] = (
        Scope(name="issues:read", probe="GET /api/me", required_by=("Tracker",)),
    )
    flows: ClassVar[tuple[str, ...]] = ("ticket_sync",)

    async def build_auth(self) -> AuthStrategy:
        if not isinstance(self.config, SampleTrackerConfig):
            raise ConfigError("sample_tracker requires SampleTrackerConfig")
        token = await self.ctx.secrets.resolve(self.config.api_token)
        try:
            text = token.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ConfigError("api_token must be UTF-8 text") from exc
        return BearerToken(text)

    async def check(self) -> HealthReport:
        try:
            await self.http.request("GET", "/api/me")
        except AuthFailed:
            return HealthReport(
                status="failing",
                capabilities={"Tracker": CapabilityHealth(status="failing", reason="vendor rejected credentials")},
            )
        except (RateLimited, TransientVendorError):
            return HealthReport(
                status="degraded",
                capabilities={"Tracker": CapabilityHealth(status="degraded", reason="vendor unavailable")},
            )
        return HealthReport(status="healthy", capabilities={"Tracker": CapabilityHealth(status="healthy")})

    def webhook_verifier(self, secret: bytes) -> WebhookVerifier | None:
        return HmacSignature(
            "x-tracker-signature",
            secret,
            id_header="x-tracker-delivery",
            event_header="x-tracker-event",
        )

    @stream(
        "tickets",
        cursor=TimeIdCursor,
        capability="Tracker",
        record_type="ticket",
        requires_target=False,
    )
    async def tickets(self, target: Target | None, checkpoint: Any, mode: str) -> AsyncIterator[RawBatch]:
        cursor = checkpoint if isinstance(checkpoint, TimeIdCursor) else TimeIdCursor(ts=None)
        params: dict[str, Any] = {"sort": "updated", "order": "asc"}
        window = cursor.window_start()
        if mode == "incremental" and window is not None:
            params["updated_since"] = window.isoformat()
        async for items, _result in offset_pages(
            self.http,
            "/api/issues",
            params,
            offset_param="offset",
            limit_param="limit",
            limit=100,
            items=_issues_of,
        ):
            cursor = cursor.advance(items, ts_of=_updated_at, id_of=_issue_key)
            yield RawBatch(records=items, checkpoint=cursor, complete=False)
        if mode == "full":
            yield RawBatch(records=[], checkpoint=cursor, complete=True)

    @mapper("tickets", version=1)
    def map_ticket(self, raw: dict[str, Any], ctx: MapContext) -> list[TicketRecord]:
        key = _issue_key(raw)
        status = _str_field(raw, "status")
        version = raw.get("version")
        if not isinstance(version, int) or isinstance(version, bool):
            raise VendorContractError("version must be an integer")
        resolution = raw.get("resolution")
        if resolution is not None and not isinstance(resolution, str):
            raise VendorContractError("resolution must be a string or null")
        url = raw.get("web_url")
        if url is not None and not isinstance(url, str):
            raise VendorContractError("web_url must be a string or null")
        labels = raw.get("labels", [])
        if not isinstance(labels, list) or not all(isinstance(label, str) for label in labels):
            raise VendorContractError("labels must be an array of strings")
        return [
            TicketRecord(
                uid=key,
                key=key,
                revision=str(version),
                data={"summary": _str_field(raw, "summary"), "status": status},
                links={"self": f"/api/issues/{key}"},
                status=status,
                status_category=_STATUS_CATEGORY.lookup(status),
                resolution=resolution,
                url=url,
                updated_at=_parse_ts(raw.get("updated_at"), "updated_at"),
                labels=labels,
            )
        ]

    @webhook(event_types=_EVENT_TYPES, header_event="x-tracker-event")
    def parse_delivery(self, delivery: WebhookDelivery) -> list[StreamRecord]:
        event_type = delivery.headers.get("x-tracker-event")
        if event_type not in _EVENT_TYPES:
            raise VendorContractError("unsupported tracker event type")
        try:
            payload = json.loads(delivery.body)
        except ValueError as exc:
            raise VendorContractError("webhook body is not valid JSON") from exc
        if not isinstance(payload, dict) or not isinstance(payload.get("issue"), dict):
            raise VendorContractError("webhook body must contain an 'issue' object")
        return [
            StreamRecord(
                stream="tickets",
                raw=payload["issue"],
                target_uid=None,
                event="delete" if event_type == "issue.deleted" else "upsert",
            )
        ]

    @importer(
        "tickets_json",
        stream="tickets",
        media_types=("application/json",),
        extensions=(".json",),
    )
    async def parse_tickets_json(self, file: ImportedFile) -> AsyncIterator[dict[str, Any]]:
        try:
            payload = json.loads(file.data)
        except ValueError as exc:
            raise VendorContractError("tickets export is not valid JSON") from exc
        if not isinstance(payload, list):
            raise VendorContractError("tickets export must be a JSON array")
        for item in payload:
            if not isinstance(item, dict):
                raise VendorContractError("tickets export items must be objects")
            yield item

    @operation("get_ticket", classification="read", capability="Tracker", input_model=GetTicketArgs, output_model=TicketRecord)
    async def get_ticket(self, args: GetTicketArgs) -> TicketRecord:
        result = await self.http.request("GET", f"/api/issues/{args.key}")
        map_ctx = MapContext(
            connection_id=self.ctx.connection_id,
            tenant_id=self.ctx.tenant_id,
            connector_kind=self.kind,
            received_at=self.ctx.clock(),
        )
        return self.map_ticket(result.json(), map_ctx)[0]

    async def _current_status(self, key: str) -> str:
        result = await self.http.request("GET", f"/api/issues/{key}")
        body = result.json()
        if not isinstance(body, dict):
            raise VendorContractError("issue response must be an object")
        return _str_field(body, "status")

    @action(
        "transition_ticket",
        classification="write",
        capability="Tracker",
        input_model=TransitionArgs,
        idempotency="key",
    )
    async def plan_transition(self, args: TransitionArgs) -> ActionPlan:
        current = await self._current_status(args.key)
        return ActionPlan(
            action="transition_ticket",
            target_ref=f"sample_tracker:issue:{args.key}",
            diff={"status": {"from": current, "to": args.to_status}},
            preconditions={"status": args.expected_status},
            idempotency_key=f"transition:{args.key}:{args.expected_status}:{args.to_status}",
            changed=current != args.to_status,
            request={
                "method": "POST",
                "path": f"/api/issues/{args.key}/transitions",
                "json": {"status": args.to_status},
            },
        )

    @plan_transition.apply
    async def apply_transition(self, plan: ActionPlan) -> ActionOutcome:
        if not plan.changed:
            return ActionOutcome(status="no_op", vendor_ref=plan.target_ref)
        key = _key_from_ref(plan.target_ref)
        current = await self._current_status(key)
        if current != plan.preconditions["status"]:
            raise StalePlan(f"ticket {key} moved to {current!r} after planning")
        try:
            result = await self.http.request(
                "POST",
                plan.request["path"],
                json=plan.request["json"],
                headers={"Idempotency-Key": plan.idempotency_key},
                idempotency="idempotent_write",
                expected=(200, 204),
            )
        except OutcomeUnknown as exc:
            return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))
        return ActionOutcome(
            status="succeeded",
            vendor_ref=plan.target_ref,
            result={"status_code": result.status},
        )

    @plan_transition.reconcile
    async def reconcile_transition(self, plan: ActionPlan) -> ActionOutcome:
        key = _key_from_ref(plan.target_ref)
        wanted = plan.request["json"]["status"]
        current = await self._current_status(key)
        if current == wanted:
            return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref, result={"reconciled": True})
        return ActionOutcome(
            status="failed",
            vendor_ref=plan.target_ref,
            error=f"ticket {key} is in {current!r}, not {wanted!r}",
        )
