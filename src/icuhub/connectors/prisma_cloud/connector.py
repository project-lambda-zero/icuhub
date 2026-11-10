"""Prisma Cloud connector with Compute streams, reads, and guarded writes."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

from icuhub.connectors.prisma_cloud import mapping
from icuhub.connectors.prisma_cloud.cspm import PrismaCspm
from icuhub.connectors.prisma_cloud.models import (
    CollectionInput,
    ComputeQueryInput,
    DeleteCollectionInput,
    EmptyInput,
    IncidentInput,
    ReadResult,
    RuntimeTimesliceInput,
    StartRegistryScanInput,
)
from icuhub.kit.connector import action, mapper, operation, stream
from icuhub.kit.cursors import SnapshotCursor, TimeIdCursor
from icuhub.kit.errors import OutcomeUnknown, StalePlan, TransientVendorError, VendorContractError
from icuhub.kit.types import ActionOutcome, ActionPlan, MapContext, RawBatch

__all__ = ["PrismaCloud"]


class PrismaCloud(PrismaCspm):
    # --------------------------------------------------------------- Compute reads

    async def _compute_page(self, path: str, args: ComputeQueryInput) -> tuple[list[dict[str, Any]], int | None]:
        params = args.model_dump(mode="json", exclude_none=True)
        params["collections"] = args.collections or self._cfg().compute_collections
        result = await self._request("compute", "GET", self._compute_path(path), params=params)
        body = result.json()
        items = self._array(body, f"Compute {path}")
        total = body.get("total") if isinstance(body, dict) else None
        if total is not None and (not isinstance(total, int) or total < 0):
            raise VendorContractError(f"Compute {path} total must be a non-negative integer")
        return items, total

    async def _compute_all(self, path: str, args: ComputeQueryInput | None = None) -> tuple[list[dict[str, Any]], int]:
        args = args or ComputeQueryInput(limit=min(self._cfg().page_size, 50))
        records: list[dict[str, Any]] = []
        pages = 0
        for offset in range(args.offset, self._cfg().max_pages * args.limit + args.offset, args.limit):
            page_args = args.model_copy(update={"offset": offset})
            items, total = await self._compute_page(path, page_args)
            records.extend(items)
            pages += 1
            if len(items) < args.limit:
                return records, pages
            if total is not None and len(records) + args.offset >= total:
                return records, pages
            if total is None and len(items) == 0:
                return records, pages
        raise VendorContractError(f"Compute {path} pagination budget exhausted")

    async def _asset_findings(self, path: str, field: str) -> AsyncIterator[RawBatch]:
        assets, _pages = await self._compute_all(path)
        records: list[dict[str, Any]] = []
        for asset in assets:
            findings = asset.get(field) or []
            if not isinstance(findings, list):
                raise VendorContractError(f"Compute asset field {field} must be an array")
            for finding in findings:
                if not isinstance(finding, dict):
                    raise VendorContractError(f"Compute asset field {field} contains a non-object")
                records.append({"_asset": asset, "_finding": finding})
        async for batch in self._snapshot(records):
            yield batch

    @stream("compute_image_vulnerabilities", ocsf_class=2002, cursor=SnapshotCursor, modes=("full",), capability="FindingSource", requires_target=False)
    async def compute_image_vulnerabilities(self, target: Any, checkpoint: Any, mode: str) -> AsyncIterator[RawBatch]:
        async for batch in self._asset_findings("/images", "vulnerabilities"):
            yield batch

    @stream("compute_host_vulnerabilities", ocsf_class=2002, cursor=SnapshotCursor, modes=("full",), capability="FindingSource", requires_target=False)
    async def compute_host_vulnerabilities(self, target: Any, checkpoint: Any, mode: str) -> AsyncIterator[RawBatch]:
        async for batch in self._asset_findings("/hosts", "vulnerabilities"):
            yield batch

    @stream("compute_container_vulnerabilities", ocsf_class=2002, cursor=SnapshotCursor, modes=("full",), capability="FindingSource", requires_target=False)
    async def compute_container_vulnerabilities(self, target: Any, checkpoint: Any, mode: str) -> AsyncIterator[RawBatch]:
        async for batch in self._asset_findings("/containers", "vulnerabilities"):
            yield batch

    @stream("compute_registry_vulnerabilities", ocsf_class=2002, cursor=SnapshotCursor, modes=("full",), capability="FindingSource", requires_target=False)
    async def compute_registry_vulnerabilities(self, target: Any, checkpoint: Any, mode: str) -> AsyncIterator[RawBatch]:
        async for batch in self._asset_findings("/registry", "vulnerabilities"):
            yield batch

    @stream("compute_image_compliance", ocsf_class=2003, cursor=SnapshotCursor, modes=("full",), capability="FindingSource", requires_target=False)
    async def compute_image_compliance(self, target: Any, checkpoint: Any, mode: str) -> AsyncIterator[RawBatch]:
        async for batch in self._asset_findings("/images", "complianceIssues"):
            yield batch

    @stream("compute_host_compliance", ocsf_class=2003, cursor=SnapshotCursor, modes=("full",), capability="FindingSource", requires_target=False)
    async def compute_host_compliance(self, target: Any, checkpoint: Any, mode: str) -> AsyncIterator[RawBatch]:
        async for batch in self._asset_findings("/hosts", "complianceIssues"):
            yield batch

    @stream("compute_container_compliance", ocsf_class=2003, cursor=SnapshotCursor, modes=("full",), capability="FindingSource", requires_target=False)
    async def compute_container_compliance(self, target: Any, checkpoint: Any, mode: str) -> AsyncIterator[RawBatch]:
        async for batch in self._asset_findings("/containers", "complianceIssues"):
            yield batch

    @stream("compute_registry_compliance", ocsf_class=2003, cursor=SnapshotCursor, modes=("full",), capability="FindingSource", requires_target=False)
    async def compute_registry_compliance(self, target: Any, checkpoint: Any, mode: str) -> AsyncIterator[RawBatch]:
        async for batch in self._asset_findings("/registry", "complianceIssues"):
            yield batch

    @mapper("compute_image_vulnerabilities", version=1)
    def map_image_vulnerabilities(self, raw: dict[str, Any], ctx: MapContext) -> list[Any]:
        return mapping.map_asset_finding(raw, ctx, "vulnerability")

    @mapper("compute_host_vulnerabilities", version=1)
    def map_host_vulnerabilities(self, raw: dict[str, Any], ctx: MapContext) -> list[Any]:
        return mapping.map_asset_finding(raw, ctx, "vulnerability")

    @mapper("compute_container_vulnerabilities", version=1)
    def map_container_vulnerabilities(self, raw: dict[str, Any], ctx: MapContext) -> list[Any]:
        return mapping.map_asset_finding(raw, ctx, "vulnerability")

    @mapper("compute_registry_vulnerabilities", version=1)
    def map_registry_vulnerabilities(self, raw: dict[str, Any], ctx: MapContext) -> list[Any]:
        return mapping.map_asset_finding(raw, ctx, "vulnerability")

    @mapper("compute_image_compliance", version=1)
    def map_image_compliance(self, raw: dict[str, Any], ctx: MapContext) -> list[Any]:
        return mapping.map_asset_finding(raw, ctx, "compliance")

    @mapper("compute_host_compliance", version=1)
    def map_host_compliance(self, raw: dict[str, Any], ctx: MapContext) -> list[Any]:
        return mapping.map_asset_finding(raw, ctx, "compliance")

    @mapper("compute_container_compliance", version=1)
    def map_container_compliance(self, raw: dict[str, Any], ctx: MapContext) -> list[Any]:
        return mapping.map_asset_finding(raw, ctx, "compliance")

    @mapper("compute_registry_compliance", version=1)
    def map_registry_compliance(self, raw: dict[str, Any], ctx: MapContext) -> list[Any]:
        return mapping.map_asset_finding(raw, ctx, "compliance")

    async def _runtime_events(self, path: str, checkpoint: TimeIdCursor | None, mode: str) -> AsyncIterator[RawBatch]:
        cursor = checkpoint or TimeIdCursor(ts=None, overlap_s=self._cfg().alert_overlap_s)
        start = cursor.window_start() if mode == "incremental" else None
        args = ComputeQueryInput(limit=min(self._cfg().page_size, 50), start_time_ms=int(start.timestamp() * 1000) if start else None)
        seen: set[str] = set()
        for offset in range(0, self._cfg().max_pages * args.limit, args.limit):
            page_args = args.model_copy(update={"offset": offset})
            items, total = await self._compute_page(path, page_args)
            records: list[dict[str, Any]] = []
            for item in items:
                uid = str(item.get("id") or item.get("auditId") or item.get("_id") or "")
                if not uid or uid in seen:
                    continue
                stamp = datetime.fromtimestamp(mapping.parse_ms(item.get("time") or item.get("timestamp"), self.ctx.clock()) / 1000, tz=UTC)
                if cursor.is_duplicate(stamp, uid):
                    continue
                seen.add(uid)
                records.append(item)
            cursor = cursor.advance(records, lambda item: datetime.fromtimestamp(mapping.parse_ms(item.get("time") or item.get("timestamp"), self.ctx.clock()) / 1000, tz=UTC), lambda item: str(item.get("id") or item.get("auditId") or item.get("_id")))
            complete = len(items) < args.limit or (total is not None and offset + len(items) >= total)
            yield RawBatch(records=records, checkpoint=cursor, complete=complete)
            if complete:
                return
        raise VendorContractError(f"Compute {path} pagination budget exhausted")

    @stream("compute_runtime_container_audits", ocsf_class=2004, cursor=TimeIdCursor, modes=("incremental", "full"), capability="TelemetrySource", requires_target=False)
    async def compute_runtime_container_audits(self, target: Any, checkpoint: TimeIdCursor | None, mode: str) -> AsyncIterator[RawBatch]:
        async for batch in self._runtime_events("/audits/runtime/container", checkpoint, mode):
            yield batch

    @stream("compute_runtime_host_audits", ocsf_class=2004, cursor=TimeIdCursor, modes=("incremental", "full"), capability="TelemetrySource", requires_target=False)
    async def compute_runtime_host_audits(self, target: Any, checkpoint: TimeIdCursor | None, mode: str) -> AsyncIterator[RawBatch]:
        async for batch in self._runtime_events("/audits/runtime/host", checkpoint, mode):
            yield batch

    @mapper("compute_runtime_container_audits", version=1)
    def map_runtime_container_audits(self, raw: dict[str, Any], ctx: MapContext) -> list[Any]:
        return mapping.map_runtime_detection(raw, ctx)

    @mapper("compute_runtime_host_audits", version=1)
    def map_runtime_host_audits(self, raw: dict[str, Any], ctx: MapContext) -> list[Any]:
        return mapping.map_runtime_detection(raw, ctx)

    @stream("compute_runtime_incidents", ocsf_class=2004, cursor=SnapshotCursor, modes=("full",), capability="TelemetrySource", requires_target=False)
    async def compute_runtime_incidents(self, target: Any, checkpoint: Any, mode: str) -> AsyncIterator[RawBatch]:
        records: list[dict[str, Any]] = []
        for acknowledged in (False, True):
            items, _pages = await self._compute_all("/audits/incidents", ComputeQueryInput(limit=min(self._cfg().page_size, 50), acknowledged=acknowledged))
            records.extend(items)
        async for batch in self._snapshot(records):
            yield batch

    @mapper("compute_runtime_incidents", version=1)
    def map_runtime_incidents(self, raw: dict[str, Any], ctx: MapContext) -> list[Any]:
        return mapping.map_runtime_detection(raw, ctx)

    @stream("compute_waas_alerts", ocsf_class=2004, cursor=TimeIdCursor, modes=("incremental",), capability="TelemetrySource", requires_target=False)
    async def compute_waas_alerts(self, target: Any, checkpoint: TimeIdCursor | None, mode: str) -> AsyncIterator[RawBatch]:
        async for batch in self._runtime_events("/audits/firewall/app", checkpoint, mode):
            yield batch

    @mapper("compute_waas_alerts", version=1)
    def map_waas_alerts(self, raw: dict[str, Any], ctx: MapContext) -> list[Any]:
        return mapping.map_runtime_detection(raw, ctx)

    @stream("compute_defenders", record_type="defender", cursor=SnapshotCursor, modes=("full",), capability="TelemetrySource", requires_target=False)
    async def compute_defenders(self, target: Any, checkpoint: Any, mode: str) -> AsyncIterator[RawBatch]:
        records, _pages = await self._compute_all("/defenders")
        async for batch in self._snapshot(records):
            yield batch

    @mapper("compute_defenders", version=1)
    def map_compute_defenders(self, raw: dict[str, Any], ctx: MapContext) -> list[Any]:
        return mapping.map_nonfinding(raw, ctx, "defender", 3005)

    @stream("compute_collections", record_type="collection", cursor=SnapshotCursor, modes=("full",), capability="TelemetrySource", requires_target=False)
    async def compute_collections(self, target: Any, checkpoint: Any, mode: str) -> AsyncIterator[RawBatch]:
        records, _pages = await self._compute_all("/collections")
        async for batch in self._snapshot(records):
            yield batch

    @mapper("compute_collections", version=1)
    def map_compute_collections(self, raw: dict[str, Any], ctx: MapContext) -> list[Any]:
        return mapping.map_nonfinding(raw, ctx, "collection", 3005)

    # --------------------------------------------------------------- Compute operations

    @operation("get_compute_version", classification="read", capability="FindingSource", input_model=EmptyInput, output_model=ReadResult)
    async def get_compute_version(self, args: EmptyInput) -> ReadResult:
        result = await self._request("compute", "GET", self._compute_path("/version"))
        return ReadResult(data=self._object(result, "Compute version"), pages=1)

    @operation("list_collections", classification="read", capability="FindingSource", input_model=ComputeQueryInput, output_model=ReadResult)
    async def list_collections(self, args: ComputeQueryInput) -> ReadResult:
        items, pages = await self._compute_all("/collections", args)
        return ReadResult(items=items, total=len(items), pages=pages, complete=True)

    @operation("get_compute_images", classification="read", capability="FindingSource", input_model=ComputeQueryInput, output_model=ReadResult)
    async def get_compute_images(self, args: ComputeQueryInput) -> ReadResult:
        items, pages = await self._compute_all("/images", args)
        return ReadResult(items=items, total=len(items), pages=pages, complete=True)

    @operation("get_compute_hosts", classification="read", capability="FindingSource", input_model=ComputeQueryInput, output_model=ReadResult)
    async def get_compute_hosts(self, args: ComputeQueryInput) -> ReadResult:
        items, pages = await self._compute_all("/hosts", args)
        return ReadResult(items=items, total=len(items), pages=pages, complete=True)

    @operation("get_compute_containers", classification="read", capability="FindingSource", input_model=ComputeQueryInput, output_model=ReadResult)
    async def get_compute_containers(self, args: ComputeQueryInput) -> ReadResult:
        items, pages = await self._compute_all("/containers", args)
        return ReadResult(items=items, total=len(items), pages=pages, complete=True)

    @operation("get_compute_registry", classification="read", capability="FindingSource", input_model=ComputeQueryInput, output_model=ReadResult)
    async def get_compute_registry(self, args: ComputeQueryInput) -> ReadResult:
        items, pages = await self._compute_all("/registry", args)
        return ReadResult(items=items, total=len(items), pages=pages, complete=True)

    @operation("list_defenders", classification="read", capability="TelemetrySource", input_model=ComputeQueryInput, output_model=ReadResult)
    async def list_defenders(self, args: ComputeQueryInput) -> ReadResult:
        items, pages = await self._compute_all("/defenders", args)
        return ReadResult(items=items, total=len(items), pages=pages, complete=True)

    @operation("get_runtime_incidents", classification="read", capability="TelemetrySource", input_model=ComputeQueryInput, output_model=ReadResult)
    async def get_runtime_incidents(self, args: ComputeQueryInput) -> ReadResult:
        items, pages = await self._compute_all("/audits/incidents", args)
        return ReadResult(items=items, total=len(items), pages=pages, complete=True)

    @operation("get_runtime_container_audits", classification="read", capability="TelemetrySource", input_model=ComputeQueryInput, output_model=ReadResult)
    async def get_runtime_container_audits(self, args: ComputeQueryInput) -> ReadResult:
        items, pages = await self._compute_all("/audits/runtime/container", args)
        return ReadResult(items=items, total=len(items), pages=pages, complete=True)

    @operation("get_runtime_host_audits", classification="read", capability="TelemetrySource", input_model=ComputeQueryInput, output_model=ReadResult)
    async def get_runtime_host_audits(self, args: ComputeQueryInput) -> ReadResult:
        items, pages = await self._compute_all("/audits/runtime/host", args)
        return ReadResult(items=items, total=len(items), pages=pages, complete=True)

    @operation("get_waas_alerts", classification="read", capability="TelemetrySource", input_model=ComputeQueryInput, output_model=ReadResult)
    async def get_waas_alerts(self, args: ComputeQueryInput) -> ReadResult:
        items, pages = await self._compute_all("/audits/firewall/app", args)
        return ReadResult(items=items, total=len(items), pages=pages, complete=True)

    @operation("get_runtime_timeslice", classification="read", capability="TelemetrySource", input_model=RuntimeTimesliceInput, output_model=ReadResult)
    async def get_runtime_timeslice(self, args: RuntimeTimesliceInput) -> ReadResult:
        result = await self._request("compute", "GET", self._compute_path("/audits/runtime/timeslice"), params=args.model_dump(mode="json"))
        return ReadResult(data=self._object(result, "runtime timeslice"), pages=1)

    # --------------------------------------------------------------- Compute actions

    @action("start_registry_scan", classification="write", capability="Enforcer", input_model=StartRegistryScanInput, idempotency="natural_key")
    async def plan_start_registry_scan(self, args: StartRegistryScanInput) -> ActionPlan:
        self._require_edition("compute")
        payload = args.model_dump(mode="json", exclude_none=True)
        basis = [self._profile_base("compute"), payload]
        return ActionPlan(
            action="start_registry_scan",
            target_ref=f"prisma_registry:{args.registry}:{args.repository or '*'}:{args.digest or '*'}",
            diff={"start_scan": payload},
            preconditions={"input_sha256": self._digest(basis)},
            idempotency_key=self._digest(["start_registry_scan", basis]),
            changed=True,
            request={"payload": payload},
        )

    @plan_start_registry_scan.apply
    async def apply_start_registry_scan(self, plan: ActionPlan) -> ActionOutcome:
        try:
            result = await self._request("compute", "POST", self._compute_path("/registry/scan"), json=plan.request["payload"], idempotency="non_idempotent", expected=(200, 201, 202, 204))
        except (OutcomeUnknown, TransientVendorError):
            return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref)
        if result.status == 202:
            return ActionOutcome(status="accepted_async", vendor_ref=plan.target_ref)
        return ActionOutcome(status="accepted_async", vendor_ref=plan.target_ref, result={"http_status": result.status})

    @plan_start_registry_scan.reconcile
    async def reconcile_start_registry_scan(self, plan: ActionPlan) -> ActionOutcome:
        payload = plan.request["payload"]
        query = ComputeQueryInput(repository=payload.get("repository"), digest=payload.get("digest"), limit=50)
        items, _pages = await self._compute_all("/registry", query)
        expected_digest = payload.get("digest")
        expected_repo = payload.get("repository")
        for item in items:
            repo_tag = item.get("repoTag") or {}
            repo = repo_tag.get("repo") or item.get("repository")
            digest = item.get("_id") or item.get("digest")
            if (not expected_repo or repo == expected_repo) and (not expected_digest or digest == expected_digest):
                return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref, result={"asset": item})
        return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref)

    async def _incident(self, incident_id: str) -> dict[str, Any]:
        result = await self._request("compute", "GET", self._compute_path(f"/audits/incidents/{incident_id}"))
        return self._object(result, "incident")

    def _incident_plan(self, name: str, incident: dict[str, Any], incident_id: str, desired: bool) -> ActionPlan:
        current = bool(incident.get("acknowledged", False))
        return ActionPlan(
            action=name,
            target_ref=f"prisma_incident:{incident_id}",
            diff={"acknowledged": {"from": current, "to": desired}},
            preconditions={"expected_acknowledged": current, "state_sha256": self._digest({"id": incident.get("id"), "acknowledged": current})},
            idempotency_key=self._digest([self.ctx.tenant_id, incident_id, desired]),
            changed=current != desired,
            request={"incident_id": incident_id, "acknowledged": desired},
        )

    async def _apply_incident(self, plan: ActionPlan) -> ActionOutcome:
        if not plan.changed:
            return ActionOutcome(status="no_op", vendor_ref=plan.target_ref)
        incident_id = str(plan.request["incident_id"])
        current = await self._incident(incident_id)
        if bool(current.get("acknowledged", False)) != plan.preconditions["expected_acknowledged"]:
            raise StalePlan(f"incident {incident_id} changed after planning")
        desired = bool(plan.request["acknowledged"])
        try:
            await self._request("compute", "PATCH", self._compute_path(f"/audits/incidents/{incident_id}"), json={"acknowledged": desired}, idempotency="idempotent_write", expected=(200, 202, 204))
        except (OutcomeUnknown, TransientVendorError):
            return ActionOutcome(status="outcome_unknown", vendor_ref=incident_id)
        read_back = await self._incident(incident_id)
        if bool(read_back.get("acknowledged", False)) != desired:
            return ActionOutcome(status="failed", vendor_ref=incident_id, error="incident acknowledgment read-back mismatch", result={"incident": read_back})
        return ActionOutcome(status="succeeded", vendor_ref=incident_id, result={"incident": read_back})

    async def _reconcile_incident(self, plan: ActionPlan) -> ActionOutcome:
        incident = await self._incident(str(plan.request["incident_id"]))
        if bool(incident.get("acknowledged", False)) == bool(plan.request["acknowledged"]):
            return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref, result={"incident": incident})
        return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, result={"incident": incident})

    @action("acknowledge_incident", classification="write", capability="Enforcer", input_model=IncidentInput, idempotency="natural_key")
    async def plan_acknowledge_incident(self, args: IncidentInput) -> ActionPlan:
        self._require_edition("compute")
        return self._incident_plan("acknowledge_incident", await self._incident(args.incident_id), args.incident_id, True)

    @plan_acknowledge_incident.apply
    async def apply_acknowledge_incident(self, plan: ActionPlan) -> ActionOutcome:
        return await self._apply_incident(plan)

    @plan_acknowledge_incident.reconcile
    async def reconcile_acknowledge_incident(self, plan: ActionPlan) -> ActionOutcome:
        return await self._reconcile_incident(plan)

    @action("unacknowledge_incident", classification="write", capability="Enforcer", input_model=IncidentInput, idempotency="natural_key")
    async def plan_unacknowledge_incident(self, args: IncidentInput) -> ActionPlan:
        self._require_edition("compute")
        return self._incident_plan("unacknowledge_incident", await self._incident(args.incident_id), args.incident_id, False)

    @plan_unacknowledge_incident.apply
    async def apply_unacknowledge_incident(self, plan: ActionPlan) -> ActionOutcome:
        return await self._apply_incident(plan)

    @plan_unacknowledge_incident.reconcile
    async def reconcile_unacknowledge_incident(self, plan: ActionPlan) -> ActionOutcome:
        return await self._reconcile_incident(plan)

    async def _collection(self, name: str) -> tuple[dict[str, Any] | None, int]:
        result = await self._request("compute", "GET", self._compute_path(f"/collections/{name}"), expected=(200, 404))
        if result.status == 404:
            return None, 404
        return self._object(result, "collection"), 200

    @staticmethod
    def _collection_fields(payload: dict[str, Any]) -> dict[str, Any]:
        return {key: payload.get(key) for key in ("description", "color", "resources")}

    @action("create_or_update_collection", classification="write", capability="Enforcer", input_model=CollectionInput, idempotency="natural_key")
    async def plan_create_or_update_collection(self, args: CollectionInput) -> ActionPlan:
        self._require_edition("compute")
        existing, status = await self._collection(args.name)
        payload = args.model_dump(mode="json")
        changed = existing is None or self._collection_fields(existing) != self._collection_fields(payload)
        return ActionPlan(
            action="create_or_update_collection",
            target_ref=f"prisma_collection:{args.name}",
            diff={"before": self._collection_fields(existing) if existing else None, "after": self._collection_fields(payload)},
            preconditions={"existing_sha256": self._digest(existing) if existing else None, "http_status": status},
            idempotency_key=self._digest([self.ctx.tenant_id, "collection", args.name, payload]),
            changed=changed,
            request={"name": args.name, "payload": payload, "method": "PUT" if existing else "POST"},
        )

    @plan_create_or_update_collection.apply
    async def apply_create_or_update_collection(self, plan: ActionPlan) -> ActionOutcome:
        if not plan.changed:
            return ActionOutcome(status="no_op", vendor_ref=plan.target_ref)
        name = str(plan.request["name"])
        existing, status = await self._collection(name)
        current_digest = self._digest(existing) if existing else None
        if current_digest != plan.preconditions["existing_sha256"] or status != plan.preconditions["http_status"]:
            raise StalePlan(f"collection {name} changed after planning")
        method = str(plan.request["method"])
        path = self._compute_path("/collections" if method == "POST" else f"/collections/{name}")
        try:
            await self._request("compute", method, path, json=plan.request["payload"], idempotency="idempotent_write", expected=(200, 201, 204))
        except (OutcomeUnknown, TransientVendorError):
            return ActionOutcome(status="outcome_unknown", vendor_ref=name)
        read_back, read_status = await self._collection(name)
        if read_status != 200 or read_back is None or self._collection_fields(read_back) != self._collection_fields(plan.request["payload"]):
            return ActionOutcome(status="failed", vendor_ref=name, error="collection read-back mismatch", result={"collection": read_back})
        return ActionOutcome(status="succeeded", vendor_ref=name, result={"collection": read_back})

    @plan_create_or_update_collection.reconcile
    async def reconcile_create_or_update_collection(self, plan: ActionPlan) -> ActionOutcome:
        collection, status = await self._collection(str(plan.request["name"]))
        if status == 200 and collection is not None and self._collection_fields(collection) == self._collection_fields(plan.request["payload"]):
            return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref, result={"collection": collection})
        return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref)

    @action("delete_collection", classification="destructive", capability="Enforcer", input_model=DeleteCollectionInput, idempotency="natural_key")
    async def plan_delete_collection(self, args: DeleteCollectionInput) -> ActionPlan:
        self._require_edition("compute")
        self.require_destructive("delete_collection")
        existing, _status = await self._collection(args.name)
        return ActionPlan(
            action="delete_collection",
            target_ref=f"prisma_collection:{args.name}",
            diff={"delete": self._collection_fields(existing) if existing else None},
            preconditions={"existing_sha256": self._digest(existing) if existing else None},
            idempotency_key=self._digest([self.ctx.tenant_id, "delete_collection", args.name]),
            changed=existing is not None,
            request={"name": args.name},
        )

    @plan_delete_collection.apply
    async def apply_delete_collection(self, plan: ActionPlan) -> ActionOutcome:
        if not plan.changed:
            return ActionOutcome(status="no_op", vendor_ref=plan.target_ref)
        name = str(plan.request["name"])
        existing, _status = await self._collection(name)
        current_digest = self._digest(existing) if existing else None
        if current_digest != plan.preconditions["existing_sha256"]:
            raise StalePlan(f"collection {name} changed after planning")
        try:
            await self._request("compute", "DELETE", self._compute_path(f"/collections/{name}"), idempotency="idempotent_write", expected=(200, 202, 204, 404))
        except (OutcomeUnknown, TransientVendorError):
            return ActionOutcome(status="outcome_unknown", vendor_ref=name)
        read_back, status = await self._collection(name)
        if status != 404:
            return ActionOutcome(status="failed", vendor_ref=name, error="collection still exists after delete", result={"collection": read_back})
        return ActionOutcome(status="succeeded", vendor_ref=name)

    @plan_delete_collection.reconcile
    async def reconcile_delete_collection(self, plan: ActionPlan) -> ActionOutcome:
        _collection, status = await self._collection(str(plan.request["name"]))
        if status == 404:
            return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref)
        return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref)
