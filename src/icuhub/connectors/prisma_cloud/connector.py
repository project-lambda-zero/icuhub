"""Prisma Cloud connector with Compute streams, reads, and guarded writes."""

from __future__ import annotations

import json
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
from icuhub.kit.cursors import SnapshotCursor, TimeIdCursor, TimeIdSnapshotCursor
from icuhub.kit.errors import (
    ConfigError,
    NotFound,
    OutcomeUnknown,
    StalePlan,
    TransientVendorError,
    VendorContractError,
)
from icuhub.kit.types import ActionOutcome, ActionPlan, MapContext, RawBatch

__all__ = ["PrismaCloud"]

_TARGET_ENV = "x-prisma-cloud-target-env"
# Documented WAAS audit paths per deployment type (OAS: /audits/firewall/app/{type}).
_WAAS_PATHS: tuple[str, ...] = (
    "/audits/firewall/app/host",
    "/audits/firewall/app/agentless",
    "/audits/firewall/app/app-embedded",
    "/audits/firewall/app/serverless",
    "/audits/firewall/app/container",
)


def _target_env(path: str) -> dict[str, str]:
    """Return the per-endpoint permission header; empty when no permission is documented for the path."""
    if path.startswith("/audits/firewall/app/"):
        permission = "monitorWAAS"
    elif path.startswith("/audits/incidents"):
        permission = "monitorRuntimeIncidents"
    elif path == "/audits/runtime/container":
        permission = "monitorRuntimeContainers"
    elif path in ("/images", "/registry", "/registry/scan"):
        permission = "monitorImages"
    else:
        return {}
    return {_TARGET_ENV: json.dumps({"permission": permission})}


def _item_id(item: dict[str, Any]) -> str | None:
    """Return the stable Compute record identity used by runtime and audit responses."""
    value = item.get("_id") or item.get("id") or item.get("auditId")
    return None if value in (None, "") else str(value)


def _runtime_key(path: str, item: dict[str, Any]) -> str:
    key = _item_id(item)
    if key is None:
        raise VendorContractError(f"Compute {path} audit record lacks _id, id, or auditId")
    return key


def _required_ms(value: Any, label: str) -> int:
    parsed = mapping.parse_ms(value)
    if parsed <= 0:
        raise VendorContractError(f"{label} is not a valid timestamp")
    return parsed


def _event_time(item: dict[str, Any]) -> datetime:
    value = item.get("time") or item.get("timestamp")
    timestamp_ms = mapping.parse_ms(value)
    if timestamp_ms <= 0:
        raise VendorContractError("Compute audit record has no valid time or timestamp")
    return datetime.fromtimestamp(timestamp_ms / 1000, tz=UTC)


def _admit_page(path: str, items: list[dict[str, Any]], seen: set[str], limit: int) -> list[dict[str, Any]]:
    """Drop records already seen in this pass; a full page of only known records means the offset cycled."""
    fresh: list[dict[str, Any]] = []
    for item in items:
        key = _item_id(item)
        if key is None:
            key = "json:" + json.dumps(item, sort_keys=True, default=str, separators=(",", ":"))
        if key in seen:
            continue
        seen.add(key)
        fresh.append(item)
    if len(items) == limit and not fresh:
        raise VendorContractError(f"Compute {path} page repeated known records")
    return fresh


class PrismaCloud(PrismaCspm):
    # --------------------------------------------------------------- Compute reads

    async def _compute_page(self, path: str, args: ComputeQueryInput) -> tuple[list[dict[str, Any]], int | None]:
        params = args.model_dump(mode="json", exclude_none=True)
        params["collections"] = args.collections or self._cfg().compute_collections
        if path in ("/images", "/registry"):
            params["compact"] = False
        if path == "/registry" and "image_id" in params:
            params["imageID"] = params.pop("image_id")
        result = await self._request("compute", "GET", self._compute_path(path), params=params, headers=_target_env(path))
        body = result.json()
        items = self._array(body, f"Compute {path}")
        total = body.get("total") if isinstance(body, dict) else None
        if total is not None and (not isinstance(total, int) or total < 0):
            raise VendorContractError(f"Compute {path} total must be a non-negative integer")
        return items, total

    async def _compute_all(self, path: str, args: ComputeQueryInput | None = None) -> tuple[list[dict[str, Any]], int]:
        args = args or ComputeQueryInput(limit=min(self._cfg().page_size, 50))
        records: list[dict[str, Any]] = []
        seen: set[str] = set()
        pages = 0
        for offset in range(args.offset, self._cfg().max_pages * args.limit + args.offset, args.limit):
            page_args = args.model_copy(update={"offset": offset})
            items, total = await self._compute_page(path, page_args)
            records.extend(_admit_page(path, items, seen, args.limit))
            pages += 1
            if len(items) < args.limit:
                return records, pages
            if total is not None and offset + len(items) >= total:
                return records, pages
        raise VendorContractError(f"Compute {path} pagination budget exhausted")

    async def _compute_partitioned(
        self,
        path: str,
        args: ComputeQueryInput | None = None,
        *,
        acknowledgment_states: bool = True,
    ) -> tuple[list[dict[str, Any]], int]:
        args = args or ComputeQueryInput(limit=min(self._cfg().page_size, 50))
        collections: list[str | None] = list(args.collections or self._cfg().compute_collections) or [None]
        states = (
            [args.acknowledged]
            if args.acknowledged is not None or not acknowledgment_states
            else [False, True]
        )
        records: list[dict[str, Any]] = []
        seen: dict[str, str] = {}
        pages = 0
        for collection in collections:
            for acknowledged in states:
                partition = args.model_copy(
                    update={
                        "collections": [collection] if collection is not None else [],
                        "acknowledged": acknowledged,
                    }
                )
                items, partition_pages = await self._compute_all(path, partition)
                pages += partition_pages
                for item in items:
                    key = _item_id(item)
                    fingerprint = json.dumps(item, sort_keys=True, default=str, separators=(",", ":"))
                    if key is not None and key in seen:
                        if seen[key] != fingerprint:
                            raise VendorContractError(
                                f"Compute {path} record {key} changed while reading acknowledgment/collection partitions"
                            )
                        continue
                    if key is not None:
                        seen[key] = fingerprint
                    records.append(
                        {
                            **item,
                            "_partition": {"collection": collection, "acknowledged": acknowledged},
                        }
                    )
        return records, pages

    async def _asset_findings(self, path: str, field: str) -> AsyncIterator[RawBatch]:
        assets, _pages = await self._compute_partitioned(path)
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

    async def _runtime_events(
        self,
        paths: str | tuple[str, ...],
        checkpoint: TimeIdSnapshotCursor | None,
        mode: str,
        *,
        acknowledgment_states: bool = True,
    ) -> AsyncIterator[RawBatch]:
        path_list = (paths,) if isinstance(paths, str) else paths
        committed = checkpoint or TimeIdSnapshotCursor(ts=None, overlap_s=self._cfg().alert_overlap_s)
        cursor = committed
        if mode == "full":
            started_at = self.ctx.clock()
            cursor = cursor.model_copy(
                update={
                    "snapshot_id": self._digest([self.ctx.connection_id, path_list, started_at.isoformat()])[:32],
                    "snapshot_started_at": started_at,
                }
            )
        start = cursor.window_start() if mode == "incremental" else None
        seen: set[str] = set()
        records: list[dict[str, Any]] = []
        for path in path_list:
            args = ComputeQueryInput(
                limit=min(self._cfg().page_size, 50),
                start_time_ms=int(start.timestamp() * 1000) if start else None,
            )
            items, _pages = await self._compute_partitioned(
                path, args, acknowledgment_states=acknowledgment_states
            )
            for item in items:
                source_uid = _runtime_key(path, item)
                uid = f"{path}:{source_uid}" if len(path_list) > 1 else source_uid
                if uid in seen:
                    continue
                stamp = _event_time(item)
                if cursor.is_duplicate(stamp, uid):
                    continue
                seen.add(uid)
                records.append({**item, "_audit_uid": uid, "_audit_path": path})
        cursor = cursor.advance(
            records,
            lambda item: _event_time(item),
            lambda item: str(item["_audit_uid"]),
        )
        yield RawBatch(records=records, checkpoint=cursor, complete=True)

    @stream("compute_runtime_container_audits", ocsf_class=2004, cursor=TimeIdSnapshotCursor, modes=("incremental", "full"), capability="TelemetrySource", requires_target=False)
    async def compute_runtime_container_audits(self, target: Any, checkpoint: TimeIdCursor | None, mode: str) -> AsyncIterator[RawBatch]:
        async for batch in self._runtime_events("/audits/runtime/container", checkpoint, mode):
            yield batch

    @stream("compute_runtime_host_audits", ocsf_class=2004, cursor=TimeIdSnapshotCursor, modes=("incremental", "full"), capability="TelemetrySource", requires_target=False)
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
        records, _pages = await self._compute_partitioned("/audits/incidents")
        async for batch in self._snapshot(records):
            yield batch

    @mapper("compute_runtime_incidents", version=1)
    def map_runtime_incidents(self, raw: dict[str, Any], ctx: MapContext) -> list[Any]:
        return mapping.map_runtime_detection(raw, ctx)

    @stream("compute_waas_alerts", ocsf_class=2004, cursor=TimeIdCursor, modes=("incremental",), capability="TelemetrySource", requires_target=False)
    async def compute_waas_alerts(self, target: Any, checkpoint: TimeIdCursor | None, mode: str) -> AsyncIterator[RawBatch]:
        async for batch in self._runtime_events(
            _WAAS_PATHS, checkpoint, mode, acknowledgment_states=False
        ):
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
        return mapping.map_nonfinding(raw, ctx, "defender", None)

    @stream("compute_collections", record_type="collection", cursor=SnapshotCursor, modes=("full",), capability="TelemetrySource", requires_target=False)
    async def compute_collections(self, target: Any, checkpoint: Any, mode: str) -> AsyncIterator[RawBatch]:
        records, _pages = await self._compute_all("/collections")
        async for batch in self._snapshot(records):
            yield batch

    @mapper("compute_collections", version=1)
    def map_compute_collections(self, raw: dict[str, Any], ctx: MapContext) -> list[Any]:
        return mapping.map_nonfinding(raw, ctx, "collection", None)

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
        items: list[dict[str, Any]] = []
        pages = 0
        for path in _WAAS_PATHS:
            partition_items, partition_pages = await self._compute_partitioned(
                path, args, acknowledgment_states=False
            )
            pages += partition_pages
            items.extend(
                {**item, "_audit_uid": f"{path}:{_runtime_key(path, item)}", "_audit_path": path}
                for item in partition_items
            )
        return ReadResult(items=items, total=len(items), pages=pages, complete=True)

    @operation("get_runtime_timeslice", classification="read", capability="TelemetrySource", input_model=RuntimeTimesliceInput, output_model=ReadResult)
    async def get_runtime_timeslice(self, args: RuntimeTimesliceInput) -> ReadResult:
        path = f"/audits/runtime/{args.audit_type}/timeslice"
        params = args.model_dump(mode="json", exclude={"audit_type"})
        result = await self._request("compute", "GET", self._compute_path(path), params=params)
        return ReadResult(data=self._object(result, "runtime timeslice"), pages=1)

    # --------------------------------------------------------------- Compute actions

    async def _registry_status(self) -> dict[str, Any]:
        result = await self._request(
            "compute",
            "GET",
            self._compute_path("/statuses/registry"),
            headers=_target_env("/registry"),
        )
        return self._object(result, "registry scan status")

    async def _registry_matches(self, plan: ActionPlan) -> list[dict[str, Any]]:
        tag = plan.request["payload"]["tag"]
        query = ComputeQueryInput(image_id=str(tag["digest"]), limit=50)
        items, _pages = await self._compute_all("/registry", query)
        matches: list[dict[str, Any]] = []
        for item in items:
            repo_tag = item.get("repoTag") or {}
            if repo_tag.get("registry") != tag["registry"]:
                continue
            if repo_tag.get("repo") != tag["repo"]:
                continue
            digest = item.get("_id") or item.get("digest") or item.get("imageID")
            if digest == tag["digest"]:
                matches.append(item)
        return matches

    @action("start_registry_scan", classification="write", capability="Enforcer", input_model=StartRegistryScanInput, idempotency="natural_key")
    async def plan_start_registry_scan(self, args: StartRegistryScanInput) -> ActionPlan:
        self._require_edition("compute")
        tag: dict[str, Any] = {
            "registry": args.registry,
            "repo": args.repository,
            "digest": args.digest,
        }
        if args.tag is not None:
            tag["tag"] = args.tag
        payload: dict[str, Any] = {"tag": tag}
        if args.on_demand:
            payload["onDemandScan"] = True
        else:
            status = await self._registry_status()
            if status and not isinstance(status.get("completed"), bool):
                raise VendorContractError("registry scan status completed must be boolean")
            if status.get("completed") is False:
                raise ConfigError("a regular registry scan is already ongoing")
        basis = [self._profile_base("compute"), payload]
        return ActionPlan(
            action="start_registry_scan",
            target_ref=f"prisma_registry:{args.registry}:{args.repository}:{args.digest}",
            diff={"start_scan": payload},
            preconditions={"input_sha256": self._digest(basis)},
            idempotency_key=self._digest(["start_registry_scan", basis]),
            changed=True,
            request={"payload": payload, "requested_at": self.ctx.clock().isoformat()},
        )

    @plan_start_registry_scan.apply
    async def apply_start_registry_scan(self, plan: ActionPlan) -> ActionOutcome:
        on_demand = bool(plan.request["payload"].get("onDemandScan"))
        baseline: dict[str, Any] = {"requested_at": plan.request["requested_at"]}
        try:
            if on_demand:
                baseline["pre_send_scan_times"] = [
                    str(item["scanTime"])
                    for item in await self._registry_matches(plan)
                    if item.get("scanTime")
                ]
            else:
                status = await self._registry_status()
                if status and not isinstance(status.get("completed"), bool):
                    raise VendorContractError("registry scan status completed must be boolean")
                if status.get("completed") is False:
                    raise ConfigError("a regular registry scan is already ongoing")
                baseline["pre_send_scan_time"] = status.get("scanTime")
        except (OutcomeUnknown, TransientVendorError) as exc:
            return ActionOutcome(
                status="failed",
                vendor_ref=plan.target_ref,
                error=f"registry baseline failed; scan not submitted: {type(exc).__name__}",
            )
        try:
            result = await self._request(
                "compute",
                "POST",
                self._compute_path("/registry/scan"),
                json=plan.request["payload"],
                headers=_target_env("/registry/scan"),
                idempotency="non_idempotent",
                expected=(200, 201, 202, 204),
            )
        except (OutcomeUnknown, TransientVendorError):
            return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, result=baseline)
        return ActionOutcome(
            status="accepted_async",
            vendor_ref=plan.target_ref,
            result={**baseline, "http_status": result.status},
        )

    @plan_start_registry_scan.reconcile
    async def reconcile_start_registry_scan(self, plan: ActionPlan, outcome: ActionOutcome) -> ActionOutcome:
        requested_raw = outcome.result.get("requested_at")
        if requested_raw is None:
            return ActionOutcome(
                status="outcome_unknown",
                vendor_ref=plan.target_ref,
                error="no pre-send registry baseline recorded",
            )
        requested_ms = _required_ms(requested_raw, "registry requested_at")
        on_demand = bool(plan.request["payload"].get("onDemandScan"))
        if on_demand:
            if "pre_send_scan_times" not in outcome.result:
                return ActionOutcome(
                    status="outcome_unknown",
                    vendor_ref=plan.target_ref,
                    error="no pre-send registry result baseline recorded",
                )
            baseline_times = {
                _required_ms(value, "pre-send registry scanTime")
                for value in outcome.result["pre_send_scan_times"]
            }
            matches = await self._registry_matches(plan)
            for item in matches:
                if not item.get("scanTime"):
                    continue
                scan_ms = _required_ms(item["scanTime"], "registry result scanTime")
                if scan_ms >= requested_ms and scan_ms not in baseline_times:
                    return ActionOutcome(
                        status="succeeded",
                        vendor_ref=plan.target_ref,
                        result={"asset": item},
                    )
            return ActionOutcome(status="unverified", vendor_ref=plan.target_ref)

        if "pre_send_scan_time" not in outcome.result:
            return ActionOutcome(
                status="outcome_unknown",
                vendor_ref=plan.target_ref,
                error="no pre-send registry status baseline recorded",
            )
        status = await self._registry_status()
        if status.get("completed") is False:
            return ActionOutcome(status="accepted_async", vendor_ref=plan.target_ref)
        scan_time = status.get("scanTime")
        baseline_raw = outcome.result["pre_send_scan_time"]
        if not scan_time or _required_ms(scan_time, "registry status scanTime") < requested_ms:
            return ActionOutcome(status="unverified", vendor_ref=plan.target_ref)
        if baseline_raw and _required_ms(scan_time, "registry status scanTime") <= _required_ms(
            baseline_raw, "pre-send registry status scanTime"
        ):
            return ActionOutcome(status="unverified", vendor_ref=plan.target_ref)
        matches = await self._registry_matches(plan)
        for item in matches:
            if item.get("scanTime") and _required_ms(item["scanTime"], "registry result scanTime") >= requested_ms:
                return ActionOutcome(
                    status="succeeded",
                    vendor_ref=plan.target_ref,
                    result={"asset": item, "scan_status": status},
                )
        return ActionOutcome(status="unverified", vendor_ref=plan.target_ref)

    async def _incident_partition(self, incident_id: str, acknowledged: bool) -> dict[str, Any] | None:
        items, _pages = await self._compute_all(
            "/audits/incidents",
            ComputeQueryInput(limit=50, acknowledged=acknowledged),
        )
        matches = [item for item in items if _item_id(item) == incident_id]
        if len(matches) > 1:
            raise VendorContractError(f"incident {incident_id} appears more than once in one acknowledgment partition")
        return matches[0] if matches else None

    async def _incident(self, incident_id: str) -> dict[str, Any]:
        partitions = [
            item
            for item in (
                await self._incident_partition(incident_id, False),
                await self._incident_partition(incident_id, True),
            )
            if item is not None
        ]
        if not partitions:
            raise NotFound(f"Prisma incident {incident_id} was not found in either acknowledgment partition")
        if len(partitions) != 1:
            raise VendorContractError(f"incident {incident_id} appears in both acknowledgment partitions")
        return partitions[0]

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
            await self._request(
                "compute",
                "PATCH",
                self._compute_path(f"/audits/incidents/acknowledge/{incident_id}"),
                json={"acknowledged": desired},
                headers=_target_env("/audits/incidents"),
                idempotency="idempotent_write",
                expected=(200, 202, 204),
            )
        except (OutcomeUnknown, TransientVendorError):
            return ActionOutcome(status="outcome_unknown", vendor_ref=incident_id)
        return await self._incident_outcome(plan)

    async def _incident_outcome(self, plan: ActionPlan) -> ActionOutcome:
        incident_id = str(plan.request["incident_id"])
        desired = bool(plan.request["acknowledged"])
        incident = await self._incident_partition(incident_id, desired)
        if incident is not None:
            if not isinstance(incident.get("acknowledged"), bool):
                raise VendorContractError("incident read-back acknowledged must be boolean")
            if incident["acknowledged"] is desired:
                return ActionOutcome(
                    status="succeeded",
                    vendor_ref=plan.target_ref,
                    result={"incident": incident},
                )
        opposite = await self._incident_partition(incident_id, not desired)
        if opposite is not None:
            return ActionOutcome(
                status="failed",
                vendor_ref=plan.target_ref,
                error="incident remains in the opposite acknowledgment partition",
                result={"incident": opposite},
            )
        return ActionOutcome(status="unverified", vendor_ref=plan.target_ref)

    async def _reconcile_incident(self, plan: ActionPlan, outcome: ActionOutcome) -> ActionOutcome:
        return await self._incident_outcome(plan)

    @action("acknowledge_incident", classification="write", capability="Enforcer", input_model=IncidentInput, idempotency="natural_key")
    async def plan_acknowledge_incident(self, args: IncidentInput) -> ActionPlan:
        self._require_edition("compute")
        return self._incident_plan("acknowledge_incident", await self._incident(args.incident_id), args.incident_id, True)

    @plan_acknowledge_incident.apply
    async def apply_acknowledge_incident(self, plan: ActionPlan) -> ActionOutcome:
        return await self._apply_incident(plan)

    @plan_acknowledge_incident.reconcile
    async def reconcile_acknowledge_incident(self, plan: ActionPlan, outcome: ActionOutcome) -> ActionOutcome:
        return await self._reconcile_incident(plan, outcome)

    @action("unacknowledge_incident", classification="write", capability="Enforcer", input_model=IncidentInput, idempotency="natural_key")
    async def plan_unacknowledge_incident(self, args: IncidentInput) -> ActionPlan:
        self._require_edition("compute")
        return self._incident_plan("unacknowledge_incident", await self._incident(args.incident_id), args.incident_id, False)

    @plan_unacknowledge_incident.apply
    async def apply_unacknowledge_incident(self, plan: ActionPlan) -> ActionOutcome:
        return await self._apply_incident(plan)

    @plan_unacknowledge_incident.reconcile
    async def reconcile_unacknowledge_incident(self, plan: ActionPlan, outcome: ActionOutcome) -> ActionOutcome:
        return await self._reconcile_incident(plan, outcome)

    async def _collection(self, name: str) -> tuple[dict[str, Any] | None, int]:
        collections, _pages = await self._compute_all("/collections")
        matches = [item for item in collections if item.get("name") == name]
        if len(matches) > 1:
            raise VendorContractError(f"Compute collection name {name!r} is not unique")
        return (matches[0], 200) if matches else (None, 404)

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
    async def reconcile_create_or_update_collection(self, plan: ActionPlan, outcome: ActionOutcome) -> ActionOutcome:
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
    async def reconcile_delete_collection(self, plan: ActionPlan, outcome: ActionOutcome) -> ActionOutcome:
        _collection, status = await self._collection(str(plan.request["name"]))
        if status == 404:
            return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref)
        return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref)
