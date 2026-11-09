"""Test-only connector used by core integration tests. Never registered in CONNECTORS."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict

from icuhub.kit.auth import AuthStrategy, BearerToken
from icuhub.kit.connector import Connector, action, importer, mapper, operation, stream, webhook
from icuhub.kit.cursors import TimeIdCursor
from icuhub.kit.errors import VendorContractError
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
    SourceRecord,
    StreamRecord,
    TargetRecord,
    TicketRecord,
    WebhookDelivery,
)
from icuhub.kit.webhook import HmacSignature, WebhookVerifier
from icuhub_schemas import ocsf

__all__ = ["CreateIssueArgs", "SampleConfig", "SampleScanner", "SampleScannerB", "SampleTracker"]

_CVE = "CVE-2026-0001"
_PURL = "pkg:pypi/requests@2.31.0"


class SampleConfig(ConnectorConfig):
    api_token: SecretRef


class CreateIssueArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    summary: str
    description: str = ""
    labels: list[str] = []
    priority: str | None = None
    project: str | None = None
    project_key: str | None = None
    issue_type: str | None = None
    assignee: str | None = None
    fields: dict[str, Any] = {}
    icuhub_case_id: str | None = None
    icuhub_route_key: str | None = None


def _finding(raw: dict[str, Any], ctx: MapContext) -> ocsf.VulnerabilityFinding:
    if raw.get("bad"):
        raise VendorContractError("record marked bad")
    cve = raw.get("cve", _CVE)
    purl = raw.get("purl", _PURL)
    severity = int(raw.get("severity_id", 4))
    return ocsf.VulnerabilityFinding(
        activity_id=1,
        time=raw.get("time", 1_700_000_000_000),
        severity_id=severity,
        cloud=ocsf.Cloud(provider="on-prem"),
        osint=[],
        metadata=ocsf.Metadata(product=ocsf.Product(name=ctx.connector_kind, vendor_name="ICUHUB")),
        finding_info=ocsf.FindingInfo(
            uid=raw["uid"],
            title=raw.get("title", "sample finding"),
            src_url=raw.get("url"),
        ),
        vulnerabilities=[
            ocsf.Vulnerability(
                cve=ocsf.Cve(uid=cve),
                affected_packages=[
                    ocsf.AffectedPackage(
                        name=purl.split("/")[-1].split("@")[0], purl=purl, version=purl.rsplit("@", 1)[-1]
                    )
                ],
            )
        ],
        resources=[ocsf.ResourceDetails(uid=purl, name="sample-package")],
        status_id=raw.get("status_id", 1),
        status=raw.get("status", "open"),
    )


class _SampleBase(Connector):
    version: ClassVar[str] = "0.1.0"
    display_name: ClassVar[str] = "Sample"
    config_model: ClassVar[type[ConnectorConfig]] = SampleConfig
    auth_modes: ClassVar[tuple[str, ...]] = ("BearerToken",)
    capabilities: ClassVar[tuple[str, ...]] = ("FindingSource", "Tracker")
    scopes: ClassVar[tuple[Scope, ...]] = (Scope(name="read", probe="GET /api/ping", required_by=("FindingSource",)),)
    flows: ClassVar[tuple[str, ...]] = ("F-999",)

    async def build_auth(self) -> AuthStrategy:
        config = self.config
        assert isinstance(config, SampleConfig)
        token = await self.ctx.secrets.resolve(config.api_token)
        return BearerToken(token.decode())

    async def check(self) -> HealthReport:
        try:
            await self.http.request("GET", "/api/ping")
        except Exception as exc:  # noqa: BLE001 - failure class is recorded at this boundary
            return HealthReport(
                status="degraded",
                capabilities={"FindingSource": CapabilityHealth(status="degraded", reason=type(exc).__name__)},
            )
        return HealthReport(status="healthy", capabilities={"FindingSource": CapabilityHealth(status="healthy")})

    async def discover(self) -> AsyncIterator[TargetRecord]:
        yield TargetRecord(source_uid="proj-1", kind="project", display_name="Project One")
        yield TargetRecord(source_uid="proj-2", kind="project", display_name="Project Two")

    def webhook_verifier(self, secret: bytes) -> WebhookVerifier | None:
        return HmacSignature("x-sample-signature", secret, id_header="x-sample-delivery", event_header="x-sample-event")

    @webhook(event_types=("issue_updated",))
    def parse_issue(self, delivery: WebhookDelivery) -> Any:
        yield StreamRecord(stream="tickets", raw=json.loads(delivery.body))

    @stream("findings", ocsf_class=2002, cursor=TimeIdCursor, modes=("incremental", "full"), capability="FindingSource", requires_target=False)
    async def findings(self, target: Any, checkpoint: TimeIdCursor | None, mode: str) -> AsyncIterator[RawBatch]:
        result = await self.http.request("GET", "/api/findings")
        records = result.json()["items"]
        cursor = checkpoint or TimeIdCursor(ts=None)
        for raw in records:
            cursor = cursor.advance(
                [raw],
                ts_of=lambda r: datetime.fromtimestamp(r["updated"] / 1000, UTC),
                id_of=lambda r: r["uid"],
            )
        yield RawBatch(records=records, checkpoint=cursor, complete=mode == "full")

    @mapper("findings", version=1)
    def map_finding(self, raw: dict[str, Any], ctx: MapContext) -> list[Any]:
        return [_finding(raw, ctx)]

    @stream(
        "targeted_findings",
        ocsf_class=2002,
        cursor=TimeIdCursor,
        modes=("full",),
        capability="FindingSource",
        requires_target=True,
    )
    async def targeted_findings(self, target: Any, checkpoint: TimeIdCursor | None, mode: str) -> AsyncIterator[RawBatch]:
        raw = {
            "uid": f"{target.source_uid}-finding",
            "cve": _CVE,
            "purl": _PURL,
            "updated": 1_700_000_000_000,
            "title": f"finding for {target.source_uid}",
        }
        yield RawBatch(records=[raw], checkpoint=checkpoint or TimeIdCursor(ts=None), complete=True)

    @mapper("targeted_findings", version=1)
    def map_targeted_finding(self, raw: dict[str, Any], ctx: MapContext) -> list[Any]:
        return [_finding(raw, ctx)]

    @stream("tickets", record_type="ticket", cursor=TimeIdCursor, modes=("incremental",), capability="Tracker", requires_target=False)
    async def tickets(self, target: Any, checkpoint: TimeIdCursor | None, mode: str) -> AsyncIterator[RawBatch]:
        result = await self.http.request("GET", "/api/tickets")
        yield RawBatch(records=result.json()["items"], checkpoint=checkpoint or TimeIdCursor(ts=None))

    @mapper("tickets", version=1)
    def map_ticket(self, raw: dict[str, Any], ctx: MapContext) -> list[TicketRecord]:
        return [
            TicketRecord(
                uid=raw["key"],
                key=raw["key"],
                status=raw["status"],
                status_category=raw["status_category"],
                revision=raw.get("revision"),
                url=raw.get("url"),
                data=raw,
            )
        ]

    @operation(
        "ping",
        classification="read",
        capability="FindingSource",
        input_model=CreateIssueArgs,
        output_model=CreateIssueArgs,
    )
    async def ping(self, args: CreateIssueArgs) -> CreateIssueArgs:
        await self.http.request("GET", "/api/ping")
        return CreateIssueArgs(summary="pong", description=args.summary)

    @action(
        "create_issue",
        classification="write",
        capability="Tracker",
        input_model=CreateIssueArgs,
        idempotency="natural_key",
    )
    async def plan_create(self, args: CreateIssueArgs) -> ActionPlan:
        if args.icuhub_route_key:
            result = await self.http.request("GET", "/api/issues", params={"route_key": args.icuhub_route_key})
            existing = result.json().get("items", [])
            if existing:
                return ActionPlan(
                    action="create_issue",
                    target_ref=f"sample:issue:{existing[0]['key']}",
                    diff={},
                    preconditions={"route_key": args.icuhub_route_key},
                    idempotency_key=args.icuhub_route_key,
                    changed=False,
                    request={},
                )
        return ActionPlan(
            action="create_issue",
            target_ref="sample:issue:new",
            diff={"summary": args.summary},
            preconditions={},
            idempotency_key=args.icuhub_route_key or args.summary,
            changed=True,
            request={"summary": args.summary, "description": args.description, "route_key": args.icuhub_route_key},
        )

    @plan_create.apply
    async def apply_create(self, plan: ActionPlan) -> ActionOutcome:
        if plan.request.get("fail"):
            return ActionOutcome(status="failed", error="vendor rejected")
        if plan.request.get("summary") == "unknown":
            return ActionOutcome(status="outcome_unknown")
        result = await self.http.request("POST", "/api/issues", json=plan.request)
        body = result.json()
        return ActionOutcome(status="succeeded", vendor_ref=body["key"], result=body)

    @plan_create.reconcile
    async def reconcile_create(self, plan: ActionPlan) -> ActionOutcome:
        result = await self.http.request("GET", "/api/issues", params={"route_key": plan.idempotency_key})
        items = result.json().get("items", [])
        if items:
            return ActionOutcome(status="succeeded", vendor_ref=items[0]["key"], result=items[0])
        return ActionOutcome(status="outcome_unknown")

    @action(
        "delete_issue",
        classification="destructive",
        capability="Tracker",
        input_model=CreateIssueArgs,
        idempotency="none",
    )
    async def plan_delete(self, args: CreateIssueArgs) -> ActionPlan:
        return ActionPlan(
            action="delete_issue",
            target_ref=f"sample:issue:{args.summary}",
            diff={"delete": args.summary},
            preconditions={},
            idempotency_key=args.summary,
            changed=True,
            request={"key": args.summary},
        )

    @plan_delete.apply
    async def apply_delete(self, plan: ActionPlan) -> ActionOutcome:
        await self.http.request("DELETE", f"/api/issues/{plan.request['key']}")
        return ActionOutcome(status="succeeded")

    @webhook(event_types=("issue.updated",), header_event="x-sample-event")
    def parse_delivery(self, delivery: WebhookDelivery) -> list[StreamRecord]:
        payload = json.loads(delivery.body)
        return [StreamRecord(stream="tickets", raw=payload["issue"])]

    @importer("sample_report", stream="findings", media_types=("application/json",), extensions=(".json",))
    async def parse_report(self, file: ImportedFile) -> AsyncIterator[dict[str, Any]]:
        document = json.loads(file.data)
        for item in document["items"]:
            yield item


class SampleScanner(_SampleBase):
    kind: ClassVar[str] = "sample_scanner"


class SampleScannerB(_SampleBase):
    kind: ClassVar[str] = "sample_scanner_b"


class SampleTracker(_SampleBase):
    kind: ClassVar[str] = "sample_tracker_core"


def source_record(uid: str) -> SourceRecord:
    return SourceRecord(record_type="project", uid=uid, data={})
