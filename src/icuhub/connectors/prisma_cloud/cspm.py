"""Prisma Cloud CSPM streams, reads, and governed alert actions."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

from icuhub.connectors.prisma_cloud import mapping
from icuhub.connectors.prisma_cloud.base import PrismaBase
from icuhub.connectors.prisma_cloud.models import (
    AccountInput,
    AlertExportInput,
    AlertIdInput,
    AlertListInput,
    AuditListInput,
    CompliancePostureInput,
    DismissAlertInput,
    DownloadExportInput,
    EmptyInput,
    ExportDownloadResult,
    ExportJobInput,
    InventoryInput,
    PolicyListInput,
    ReadResult,
    RemediateAlertInput,
    ReopenAlertInput,
    ResourceInput,
    RqlInput,
    RqlPageInput,
    SnoozeAlertInput,
)
from icuhub.kit.connector import action, mapper, operation, stream
from icuhub.kit.cursors import SnapshotCursor, TimeIdCursor
from icuhub.kit.errors import ConfigError, OutcomeUnknown, StalePlan, TransientVendorError, VendorContractError
from icuhub.kit.types import ActionOutcome, ActionPlan, MapContext, RawBatch

__all__ = ["PrismaCspm"]

_ALERT_STATUSES = ["open", "resolved", "dismissed", "snoozed"]


class PrismaCspm(PrismaBase):
    # --------------------------------------------------------------- request helpers

    def _alert_payload(self, args: AlertListInput, *, mode: str | None = None) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "detailed": args.detailed,
            "limit": args.limit,
            "offset": args.offset,
            "filters": [],
        }
        if args.page_token:
            payload["pageToken"] = args.page_token
        if args.start_time_ms is not None or args.end_time_ms is not None:
            payload["timeRange"] = {
                "type": "absolute",
                "startTime": args.start_time_ms,
                "endTime": args.end_time_ms,
            }
        if args.statuses:
            payload["filters"].append({"name": "alert.status", "operator": "IN", "value": args.statuses})
        if args.policy_types:
            payload["filters"].append({"name": "policy.type", "operator": "IN", "value": args.policy_types})
        if args.account_ids:
            payload["filters"].append({"name": "cloud.accountId", "operator": "IN", "value": args.account_ids})
        if mode == "full" and not args.statuses:
            payload["filters"].append({"name": "alert.status", "operator": "IN", "value": _ALERT_STATUSES})
        return payload

    async def _alert_page(self, args: AlertListInput, *, mode: str | None = None) -> tuple[list[dict[str, Any]], str | None]:
        result = await self._request("cspm", "POST", "/v2/alert", json=self._alert_payload(args, mode=mode))
        body = self._object(result, "alert list")
        items = self._array(body, "alert list", ("items",))
        token = body.get("nextPageToken")
        if token is not None and not isinstance(token, str):
            raise VendorContractError("alert list page token must be a string or null")
        return items, token

    async def _rql_pages(
        self, args: RqlInput, expected_metadata: dict[str, Any] | None = None
    ) -> AsyncIterator[tuple[list[dict[str, Any]], str | None, dict[str, Any]]]:
        token = args.page_token
        first = token is None
        expected_metadata = dict(expected_metadata or {})
        if not first and not expected_metadata:
            raise ConfigError("RQL continuation requires page-one expected_metadata")
        seen: set[str] = set()
        for _ in range(self._cfg().max_pages):
            payload: dict[str, Any] = {"query": args.query, "limit": args.limit}
            if args.time_range is not None:
                payload["timeRange"] = args.time_range
            if token:
                payload["pageToken"] = token
            result = await self._request("cspm", "POST", "/v2/config", json=payload)
            body = self._object(result, "RQL search")
            data = body.get("data") if isinstance(body.get("data"), dict) else body
            items = self._array(data, "RQL search", ("items", "results"))
            metadata = data.get("metadata") if isinstance(data, dict) else None
            if first:
                if not isinstance(metadata, dict):
                    raise VendorContractError("RQL first page is missing metadata")
                expected_metadata = metadata
                first = False
            elif not isinstance(metadata, dict) or metadata.get("schema") != expected_metadata.get("schema"):
                raise VendorContractError("RQL continuation lost metadata or changed schema")
            next_token = data.get("nextPageToken") if isinstance(data, dict) else None
            if next_token is not None and not isinstance(next_token, str):
                raise VendorContractError("RQL page token must be a string or null")
            yield items, next_token, expected_metadata
            if not next_token:
                return
            if next_token in seen or next_token == token:
                raise VendorContractError("RQL page token made no forward progress")
            seen.add(next_token)
            token = next_token
        raise VendorContractError("RQL pagination budget exhausted")

    async def _rql_all(
        self, args: RqlInput, expected_metadata: dict[str, Any] | None = None
    ) -> tuple[list[dict[str, Any]], dict[str, Any], int]:
        records: list[dict[str, Any]] = []
        metadata: dict[str, Any] = {}
        pages = 0
        async for items, _token, page_metadata in self._rql_pages(args, expected_metadata):
            records.extend(items)
            metadata = page_metadata
            pages += 1
        return records, metadata, pages

    async def _snapshot(self, records: list[dict[str, Any]]) -> AsyncIterator[RawBatch]:
        cursor = SnapshotCursor(snapshot_id=self._digest(records)[:32], started_at=self.ctx.clock())
        yield RawBatch(records=records, checkpoint=cursor, complete=False)
        yield RawBatch(records=[], checkpoint=cursor, complete=True)

    # --------------------------------------------------------------- alert streams

    async def _alerts(self, policy_type: str, checkpoint: TimeIdCursor | None, mode: str) -> AsyncIterator[RawBatch]:
        cursor = checkpoint or TimeIdCursor(ts=None, overlap_s=self._cfg().alert_overlap_s)
        start = cursor.window_start() if mode == "incremental" else None
        args = AlertListInput(
            detailed=True,
            limit=min(self._cfg().page_size, 1000),
            start_time_ms=int(start.timestamp() * 1000) if start else None,
            statuses=_ALERT_STATUSES,
            policy_types=[policy_type] if policy_type != "detection" else sorted(mapping.DETECTION_POLICY_TYPES),
        )
        seen_ids: set[str] = set()
        seen_tokens: set[str] = set()
        token: str | None = None
        for _ in range(self._cfg().max_pages):
            args.page_token = token
            items, next_token = await self._alert_page(args, mode=mode)
            records: list[dict[str, Any]] = []
            for item in items:
                uid = str(item.get("id") or item.get("alertId") or "")
                if not uid or uid in seen_ids:
                    continue
                when = mapping.parse_ms(item.get("time") or item.get("alertTime"))
                if when <= 0:
                    raise VendorContractError(f"alert {uid} has no valid alert time")
                stamp = datetime.fromtimestamp(when / 1000, tz=UTC)
                if cursor.is_duplicate(stamp, uid):
                    continue
                seen_ids.add(uid)
                records.append(item)
            cursor = cursor.advance(
                records,
                lambda item: datetime.fromtimestamp(mapping.parse_ms(item.get("time") or item.get("alertTime")) / 1000, tz=UTC),
                lambda item: str(item.get("id") or item.get("alertId")),
            )
            yield RawBatch(records=records, checkpoint=cursor, complete=next_token is None)
            if next_token is None:
                return
            if next_token in seen_tokens or next_token == token:
                raise VendorContractError("alert page token made no forward progress")
            seen_tokens.add(next_token)
            token = next_token
        raise VendorContractError("alert pagination budget exhausted")

    @stream("cspm_config_alerts", ocsf_class=2003, cursor=TimeIdCursor, modes=("incremental", "full"), capability="FindingSource", requires_target=False)
    async def cspm_config_alerts(self, target: Any, checkpoint: TimeIdCursor | None, mode: str) -> AsyncIterator[RawBatch]:
        async for batch in self._alerts("config", checkpoint, mode):
            yield batch

    @stream("cspm_vulnerability_alerts", ocsf_class=2002, cursor=TimeIdCursor, modes=("incremental", "full"), capability="FindingSource", requires_target=False)
    async def cspm_vulnerability_alerts(self, target: Any, checkpoint: TimeIdCursor | None, mode: str) -> AsyncIterator[RawBatch]:
        async for batch in self._alerts("vulnerability", checkpoint, mode):
            yield batch

    @stream("cspm_detection_alerts", ocsf_class=2004, cursor=TimeIdCursor, modes=("incremental", "full"), capability="FindingSource", requires_target=False)
    async def cspm_detection_alerts(self, target: Any, checkpoint: TimeIdCursor | None, mode: str) -> AsyncIterator[RawBatch]:
        async for batch in self._alerts("detection", checkpoint, mode):
            yield batch

    @mapper("cspm_config_alerts", version=1)
    def map_config_alerts(self, raw: dict[str, Any], ctx: MapContext) -> list[Any]:
        return mapping.map_alert(raw, ctx, "compliance")

    @mapper("cspm_vulnerability_alerts", version=1)
    def map_vulnerability_alerts(self, raw: dict[str, Any], ctx: MapContext) -> list[Any]:
        return mapping.map_alert(raw, ctx, "vulnerability")

    @mapper("cspm_detection_alerts", version=1)
    def map_detection_alerts(self, raw: dict[str, Any], ctx: MapContext) -> list[Any]:
        return mapping.map_alert(raw, ctx, "detection")

    # --------------------------------------------------------------- CSPM snapshots

    @stream("cspm_compliance_posture", record_type="compliance_posture", cursor=SnapshotCursor, modes=("full",), capability="FindingSource", requires_target=False)
    async def cspm_compliance_posture(self, target: Any, checkpoint: Any, mode: str) -> AsyncIterator[RawBatch]:
        result = await self._request("cspm", "POST", "/compliance/posture", json={})
        body = self._object(result, "compliance posture")
        async for batch in self._snapshot([body]):
            yield batch

    @mapper("cspm_compliance_posture", version=1)
    def map_compliance_posture(self, raw: dict[str, Any], ctx: MapContext) -> list[Any]:
        return mapping.map_nonfinding(raw, ctx, "compliance_posture", 3005)

    @stream("cspm_audit_events", ocsf_class=6003, cursor=TimeIdCursor, modes=("incremental",), capability="TelemetrySource", requires_target=False)
    async def cspm_audit_events(self, target: Any, checkpoint: TimeIdCursor | None, mode: str) -> AsyncIterator[RawBatch]:
        cursor = checkpoint or TimeIdCursor(ts=None, overlap_s=self._cfg().alert_overlap_s)
        start = cursor.window_start()
        args = AuditListInput(limit=self._cfg().page_size, start_time_ms=int(start.timestamp() * 1000) if start else None)
        seen: set[str] = set()
        for offset in range(0, self._cfg().max_pages * self._cfg().page_size, self._cfg().page_size):
            args.offset = offset
            result = await self._request("cspm", "GET", "/audit/event", params={"limit": args.limit, "offset": offset, "startTime": args.start_time_ms})
            records = []
            for item in self._array(result.json(), "audit events"):
                uid = str(item.get("id") or item.get("eventId") or "")
                if not uid or uid in seen:
                    continue
                stamp = datetime.fromtimestamp(mapping.parse_ms(item.get("timestamp") or item.get("time"), self.ctx.clock()) / 1000, tz=UTC)
                if cursor.is_duplicate(stamp, uid):
                    continue
                seen.add(uid)
                records.append(item)
            cursor = cursor.advance(records, lambda item: datetime.fromtimestamp(mapping.parse_ms(item.get("timestamp") or item.get("time"), self.ctx.clock()) / 1000, tz=UTC), lambda item: str(item.get("id") or item.get("eventId")))
            complete = len(records) < self._cfg().page_size
            yield RawBatch(records=records, checkpoint=cursor, complete=complete)
            if complete:
                return
        raise VendorContractError("audit event pagination budget exhausted")

    @mapper("cspm_audit_events", version=1)
    def map_audit_events(self, raw: dict[str, Any], ctx: MapContext) -> list[Any]:
        return mapping.map_cspm_audit(raw, ctx)

    async def _rql_snapshot(self, query: str) -> AsyncIterator[RawBatch]:
        records, metadata, _pages = await self._rql_all(RqlInput(query=query, limit=self._cfg().page_size))
        for record in records:
            record["_rql_metadata"] = metadata
        async for batch in self._snapshot(records):
            yield batch

    @stream("cspm_resources_snapshot", record_type="resource", cursor=SnapshotCursor, modes=("full",), capability="FindingSource", requires_target=False)
    async def cspm_resources_snapshot(self, target: Any, checkpoint: Any, mode: str) -> AsyncIterator[RawBatch]:
        async for batch in self._rql_snapshot("config from cloud.resource"):
            yield batch

    @mapper("cspm_resources_snapshot", version=1)
    def map_resources_snapshot(self, raw: dict[str, Any], ctx: MapContext) -> list[Any]:
        return mapping.map_nonfinding(raw, ctx, "resource", 3005)

    @stream("cspm_resource_misconfigurations_snapshot", ocsf_class=2003, cursor=SnapshotCursor, modes=("full",), capability="FindingSource", requires_target=False)
    async def cspm_resource_misconfigurations_snapshot(self, target: Any, checkpoint: Any, mode: str) -> AsyncIterator[RawBatch]:
        async for batch in self._rql_snapshot("config from cloud.resource where policy.type = 'config'"):
            yield batch

    @mapper("cspm_resource_misconfigurations_snapshot", version=1)
    def map_resource_misconfigurations(self, raw: dict[str, Any], ctx: MapContext) -> list[Any]:
        if "policy" not in raw:
            raw = {**raw, "policy": {"policyId": raw.get("policyId"), "name": raw.get("policyName"), "policyType": "config"}}
        return mapping.map_alert(raw, ctx, "compliance")

    @stream("cspm_vulnerability_export", ocsf_class=2002, cursor=SnapshotCursor, modes=("full",), capability="FindingSource", requires_target=False)
    async def cspm_vulnerability_export(self, target: Any, checkpoint: Any, mode: str) -> AsyncIterator[RawBatch]:
        submitted = await self._request("cspm", "POST", "/vulnerability/export", json={"format": "json"}, idempotency="non_idempotent")
        job = self._object(submitted, "vulnerability export")
        job_id = str(job.get("jobId") or job.get("id") or "")
        if not job_id:
            raise VendorContractError("vulnerability export returned no job ID")
        download = await self._download_export(job_id, ExportJobInput(job_id=job_id), DownloadExportInput(job_id=job_id), "/vulnerability/export")
        records = download.records
        for index, record in enumerate(records):
            record["_export_sha256"] = download.sha256
            record["_row_identity"] = str(record.get("id") or record.get("_id") or self._digest([download.sha256, index]))
        async for batch in self._snapshot(records):
            yield batch

    @mapper("cspm_vulnerability_export", version=1)
    def map_vulnerability_export(self, raw: dict[str, Any], ctx: MapContext) -> list[Any]:
        enriched = {
            **raw,
            "id": raw.get("id") or raw.get("_row_identity"),
            "policy": {**dict(raw.get("policy") or {}), "policyType": "vulnerability"},
        }
        return mapping.map_alert(enriched, ctx, "vulnerability")

    @stream("cspm_accounts_snapshot", record_type="cloud_account", cursor=SnapshotCursor, modes=("full",), capability="FindingSource", requires_target=False)
    async def cspm_accounts_snapshot(self, target: Any, checkpoint: Any, mode: str) -> AsyncIterator[RawBatch]:
        result = await self._request("cspm", "GET", "/cloud")
        accounts = self._array(result.json(), "cloud accounts", ("cloudAccounts", "items", "data"))
        async for batch in self._snapshot(accounts):
            yield batch

    @mapper("cspm_accounts_snapshot", version=1)
    def map_accounts_snapshot(self, raw: dict[str, Any], ctx: MapContext) -> list[Any]:
        return mapping.map_account(raw, ctx)

    @stream("cspm_rql_assets", record_type="rql_asset", cursor=SnapshotCursor, modes=("full",), capability="FindingSource", requires_target=False)
    async def cspm_rql_assets(self, target: Any, checkpoint: Any, mode: str) -> AsyncIterator[RawBatch]:
        async for batch in self._rql_snapshot("config from cloud.resource"):
            yield batch

    @mapper("cspm_rql_assets", version=1)
    def map_rql_assets(self, raw: dict[str, Any], ctx: MapContext) -> list[Any]:
        return mapping.map_nonfinding(raw, ctx, "rql_asset", 3005)

    @stream("cspm_policies", record_type="policy", cursor=SnapshotCursor, modes=("full",), capability="FindingSource", requires_target=False)
    async def cspm_policies(self, target: Any, checkpoint: Any, mode: str) -> AsyncIterator[RawBatch]:
        result = await self.list_policies_v2(PolicyListInput(limit=self._cfg().page_size))
        if not result.complete:
            raise VendorContractError("policy snapshot did not complete")
        async for batch in self._snapshot(result.items):
            yield batch

    @mapper("cspm_policies", version=1)
    def map_cspm_policies(self, raw: dict[str, Any], ctx: MapContext) -> list[Any]:
        return mapping.map_nonfinding(raw, ctx, "policy", 3005)

    @stream("cspm_inventory_aggregates", record_type="inventory_aggregate", cursor=SnapshotCursor, modes=("full",), capability="FindingSource", requires_target=False)
    async def cspm_inventory_aggregates(self, target: Any, checkpoint: Any, mode: str) -> AsyncIterator[RawBatch]:
        result = await self.get_inventory_v3(InventoryInput())
        if not result.complete:
            raise VendorContractError("inventory snapshot did not complete")
        async for batch in self._snapshot(result.items or ([result.data] if result.data else [])):
            yield batch

    @mapper("cspm_inventory_aggregates", version=1)
    def map_inventory_aggregates(self, raw: dict[str, Any], ctx: MapContext) -> list[Any]:
        return mapping.map_nonfinding(raw, ctx, "inventory_aggregate", 3005)

    # --------------------------------------------------------------- CSPM read operations

    @operation("list_alerts_v2", classification="read", capability="FindingSource", input_model=AlertListInput, output_model=ReadResult)
    async def list_alerts_v2(self, args: AlertListInput) -> ReadResult:
        items, token = await self._alert_page(args)
        return ReadResult(items=items, next_page_token=token, pages=1, complete=True)

    @operation("get_alert", classification="read", capability="FindingSource", input_model=AlertIdInput, output_model=ReadResult)
    async def get_alert(self, args: AlertIdInput) -> ReadResult:
        result = await self._request("cspm", "GET", f"/alert/{args.alert_id}")
        return ReadResult(data=self._object(result, "alert detail"), pages=1)

    @operation("list_alert_filters", classification="read", capability="FindingSource", input_model=EmptyInput, output_model=ReadResult)
    async def list_alert_filters(self, args: EmptyInput) -> ReadResult:
        result = await self._request("cspm", "GET", "/alert/filter")
        return ReadResult(items=self._array(result.json(), "alert filters"), pages=1)

    @operation("submit_alert_export", classification="read", capability="FindingSource", input_model=AlertExportInput, output_model=ReadResult)
    async def submit_alert_export(self, args: AlertExportInput) -> ReadResult:
        payload = args.model_dump(mode="json", exclude_none=True)
        result = await self._request("cspm", "POST", "/alert/export", json=payload, idempotency="non_idempotent")
        return ReadResult(data=self._object(result, "alert export"), pages=1)

    @operation("get_alert_export_status", classification="read", capability="FindingSource", input_model=ExportJobInput, output_model=ReadResult)
    async def get_alert_export_status(self, args: ExportJobInput) -> ReadResult:
        result = await self._request("cspm", "GET", f"/alert/export/{args.job_id}")
        return ReadResult(data=self._object(result, "alert export status"), pages=1)

    async def _download_export(self, job_id: str, job: ExportJobInput, download: DownloadExportInput, root: str) -> ExportDownloadResult:
        deadline = datetime.now(UTC).timestamp() + job.timeout_s
        while True:
            result = await self._request("cspm", "GET", f"{root}/{job_id}")
            body = self._object(result, "export status")
            state = str(body.get("status") or body.get("state") or "").lower()
            if state in {"complete", "completed", "ready", "succeeded", "success"}:
                break
            if state in {"failed", "expired", "cancelled", "canceled"}:
                raise VendorContractError(f"export {job_id} ended as {state}")
            if datetime.now(UTC).timestamp() >= deadline:
                raise VendorContractError(f"export {job_id} did not complete before its deadline")
            await asyncio.sleep(job.poll_interval_s)
        data = await self.http.stream_download(self._url("cspm", f"{root}/{job_id}/download"), max_bytes=download.max_bytes)
        digest = hashlib.sha256(data).hexdigest()
        records: list[dict[str, Any]] = []
        try:
            parsed = json.loads(data)
        except (UnicodeDecodeError, json.JSONDecodeError):
            parsed = None
        if parsed is not None:
            records = self._array(parsed, "export download")
        return ExportDownloadResult(
            job_id=job_id,
            sha256=digest,
            size_bytes=len(data),
            media_type="application/json" if records else "application/octet-stream",
            content_base64=base64.b64encode(data).decode("ascii"),
            records=records,
            complete=True,
        )

    @operation("download_alert_export", classification="read", capability="FindingSource", input_model=DownloadExportInput, output_model=ExportDownloadResult)
    async def download_alert_export(self, args: DownloadExportInput) -> ExportDownloadResult:
        return await self._download_export(args.job_id, ExportJobInput(job_id=args.job_id), args, "/alert/export")

    @operation("get_compliance_posture", classification="read", capability="FindingSource", input_model=CompliancePostureInput, output_model=ReadResult)
    async def get_compliance_posture(self, args: CompliancePostureInput) -> ReadResult:
        result = await self._request("cspm", "POST", "/compliance/posture", json=args.model_dump(mode="json", exclude_none=True))
        body = self._object(result, "compliance posture")
        return ReadResult(data=body, items=self._array(body, "compliance posture") if any(isinstance(body.get(k), list) for k in ("items", "results", "data")) else [], pages=1)

    @operation("list_policies_v2", classification="read", capability="FindingSource", input_model=PolicyListInput, output_model=ReadResult)
    async def list_policies_v2(self, args: PolicyListInput) -> ReadResult:
        items: list[dict[str, Any]] = []
        pages = 0
        for offset in range(args.offset, self._cfg().max_pages * args.limit + args.offset, args.limit):
            result = await self._request("cspm", "GET", "/v2/policy", params={"limit": args.limit, "offset": offset, "policyTypes": args.policy_types})
            page = self._array(result.json(), "policy list")
            items.extend(page)
            pages += 1
            if len(page) < args.limit:
                return ReadResult(items=items, total=len(items), pages=pages, complete=True)
        raise VendorContractError("policy pagination budget exhausted")

    @operation("search_config_v2", classification="read", capability="FindingSource", input_model=RqlInput, output_model=ReadResult)
    async def search_config_v2(self, args: RqlInput) -> ReadResult:
        items, metadata, pages = await self._rql_all(args)
        return ReadResult(items=items, data={"metadata": metadata}, total=len(items), pages=pages, complete=True)

    @operation("search_config_page", classification="read", capability="FindingSource", input_model=RqlPageInput, output_model=ReadResult)
    async def search_config_page(self, args: RqlPageInput) -> ReadResult:
        rql = RqlInput(query=args.query, limit=args.limit, page_token=args.page_token, time_range=args.time_range)
        async for items, token, metadata in self._rql_pages(rql, args.expected_metadata):
            if args.expected_metadata and metadata.get("schema") != args.expected_metadata.get("schema"):
                raise VendorContractError("RQL continuation metadata schema downgrade")
            return ReadResult(items=items, next_page_token=token, data={"metadata": metadata}, pages=1, complete=True)
        raise VendorContractError("RQL page returned no result")

    @operation("get_inventory_v3", classification="read", capability="FindingSource", input_model=InventoryInput, output_model=ReadResult)
    async def get_inventory_v3(self, args: InventoryInput) -> ReadResult:
        result = await self._request("cspm", "POST", "/v3/inventory", json=args.model_dump(mode="json", exclude_none=True))
        body = self._object(result, "inventory aggregates")
        groups = body.get("groups") or body.get("items") or []
        if not isinstance(groups, list) or not all(isinstance(item, dict) for item in groups):
            raise VendorContractError("inventory aggregate groups must be an object array")
        return ReadResult(data=body, items=groups, pages=1, complete=True)

    @operation("get_resource", classification="read", capability="FindingSource", input_model=ResourceInput, output_model=ReadResult)
    async def get_resource(self, args: ResourceInput) -> ReadResult:
        selector = args.query or f"config from cloud.resource where id = '{args.rrn or args.resource_id}'"
        items, metadata, pages = await self._rql_all(
            RqlInput(query=selector, limit=args.limit, page_token=args.page_token), args.expected_metadata
        )
        return ReadResult(items=items, data={"metadata": metadata}, pages=pages, complete=True)

    @operation("list_resources", classification="read", capability="FindingSource", input_model=ResourceInput, output_model=ReadResult)
    async def list_resources(self, args: ResourceInput) -> ReadResult:
        return await self.get_resource(args)

    @operation("get_account_status", classification="read", capability="FindingSource", input_model=AccountInput, output_model=ReadResult)
    async def get_account_status(self, args: AccountInput) -> ReadResult:
        result = await self._request("cspm", "GET", f"/cloud/{args.account_id}", params={"cloudType": args.cloud_type})
        return ReadResult(data=self._object(result, "cloud account status"), pages=1)

    @operation("list_account_owners", classification="read", capability="FindingSource", input_model=AccountInput, output_model=ReadResult)
    async def list_account_owners(self, args: AccountInput) -> ReadResult:
        result = await self._request("cspm", "GET", f"/cloud/{args.account_id}/owners", params={"cloudType": args.cloud_type})
        return ReadResult(items=self._array(result.json(), "cloud account owners", ("owners", "items", "data")), pages=1)

    @operation("get_alert_remediation", classification="read", capability="FindingSource", input_model=AlertIdInput, output_model=ReadResult)
    async def get_alert_remediation(self, args: AlertIdInput) -> ReadResult:
        result = await self._request("cspm", "GET", f"/alert/{args.alert_id}/remediation")
        return ReadResult(data=self._object(result, "alert remediation"), pages=1)

    @operation("list_audit_events", classification="read", capability="TelemetrySource", input_model=AuditListInput, output_model=ReadResult)
    async def list_audit_events(self, args: AuditListInput) -> ReadResult:
        result = await self._request("cspm", "GET", "/audit/event", params=args.model_dump(mode="json", exclude_none=True))
        return ReadResult(items=self._array(result.json(), "audit events"), pages=1)

    @operation("submit_vulnerability_export", classification="read", capability="FindingSource", input_model=EmptyInput, output_model=ReadResult)
    async def submit_vulnerability_export(self, args: EmptyInput) -> ReadResult:
        result = await self._request("cspm", "POST", "/vulnerability/export", json={"format": "json"}, idempotency="non_idempotent")
        return ReadResult(data=self._object(result, "vulnerability export"), pages=1)

    @operation("get_vulnerability_export_status", classification="read", capability="FindingSource", input_model=ExportJobInput, output_model=ReadResult)
    async def get_vulnerability_export_status(self, args: ExportJobInput) -> ReadResult:
        result = await self._request("cspm", "GET", f"/vulnerability/export/{args.job_id}")
        return ReadResult(data=self._object(result, "vulnerability export status"), pages=1)

    @operation("download_vulnerability_export", classification="read", capability="FindingSource", input_model=DownloadExportInput, output_model=ExportDownloadResult)
    async def download_vulnerability_export(self, args: DownloadExportInput) -> ExportDownloadResult:
        return await self._download_export(args.job_id, ExportJobInput(job_id=args.job_id), args, "/vulnerability/export")

    # --------------------------------------------------------------- alert actions

    async def _alert_state(self, alert_id: str) -> dict[str, Any]:
        result = await self._request("cspm", "GET", f"/alert/{alert_id}")
        return self._object(result, "alert state")

    @staticmethod
    def _alert_preconditions(alert: dict[str, Any]) -> dict[str, Any]:
        relevant = {
            "status": alert.get("status"),
            "dismissalNote": alert.get("dismissalNote"),
            "dismissalExpirationTs": alert.get("dismissalExpirationTs"),
            "policy": alert.get("policy"),
            "resource": alert.get("resource"),
        }
        return {"expected_status": alert.get("status"), "state_sha256": PrismaBase._digest(relevant)}

    def _alert_plan(self, name: str, alert_id: str, alert: dict[str, Any], desired: str, payload: dict[str, Any], path: str, changed: bool) -> ActionPlan:
        return ActionPlan(
            action=name,
            target_ref=f"prisma_alert:{alert_id}",
            diff={"status": {"from": alert.get("status"), "to": desired}, "payload": payload},
            preconditions=self._alert_preconditions(alert),
            idempotency_key=self._digest([self.ctx.tenant_id, alert_id, name, desired, payload]),
            changed=changed,
            request={"method": "PATCH", "path": path, "payload": payload, "alert_id": alert_id, "desired_status": desired},
        )

    async def _apply_alert_plan(self, plan: ActionPlan) -> ActionOutcome:
        if not plan.changed:
            return ActionOutcome(status="no_op", vendor_ref=plan.target_ref)
        alert_id = str(plan.request["alert_id"])
        current = await self._alert_state(alert_id)
        if self._alert_preconditions(current)["state_sha256"] != plan.preconditions["state_sha256"]:
            raise StalePlan(f"alert {alert_id} changed after planning")
        desired = str(plan.request["desired_status"])
        if str(current.get("status")).lower() == desired and plan.action != "reopen_alert":
            return ActionOutcome(status="no_op", vendor_ref=alert_id, result={"alert": current})
        try:
            await self._request(
                "cspm",
                str(plan.request["method"]),
                str(plan.request["path"]),
                json=plan.request["payload"],
                idempotency="non_idempotent",
                expected=(200, 202, 204),
            )
        except (OutcomeUnknown, TransientVendorError):
            return ActionOutcome(status="outcome_unknown", vendor_ref=alert_id)
        read_back = await self._alert_state(alert_id)
        actual = str(read_back.get("status") or "").lower()
        expiry_ok = True
        if plan.action == "snooze_alert":
            expected_expiry = plan.request["payload"].get("dismissalExpirationTs")
            expiry_ok = not expected_expiry or read_back.get("dismissalExpirationTs") == expected_expiry
        if actual != desired or not expiry_ok:
            return ActionOutcome(status="failed", vendor_ref=alert_id, error=f"alert read-back is {actual!r}, expected {desired!r}", result={"alert": read_back})
        return ActionOutcome(status="succeeded", vendor_ref=alert_id, result={"alert": read_back})

    async def _reconcile_alert_plan(self, plan: ActionPlan, outcome: ActionOutcome) -> ActionOutcome:
        alert = await self._alert_state(str(plan.request["alert_id"]))
        actual = str(alert.get("status") or "").lower()
        if actual == plan.request["desired_status"]:
            return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref, result={"alert": alert})
        return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, result={"alert": alert})

    @action("dismiss_alert", classification="write", capability="Enforcer", input_model=DismissAlertInput, idempotency="natural_key")
    async def plan_dismiss_alert(self, args: DismissAlertInput) -> ActionPlan:
        self._require_edition("cspm")
        alert = await self._alert_state(args.alert_id)
        payload = {"alerts": [args.alert_id], "dismissalNote": args.note}
        changed = str(alert.get("status")).lower() != "dismissed"
        return self._alert_plan("dismiss_alert", args.alert_id, alert, "dismissed", payload, "/alert/dismiss", changed)

    @plan_dismiss_alert.apply
    async def apply_dismiss_alert(self, plan: ActionPlan) -> ActionOutcome:
        return await self._apply_alert_plan(plan)

    @plan_dismiss_alert.reconcile
    async def reconcile_dismiss_alert(self, plan: ActionPlan, outcome: ActionOutcome) -> ActionOutcome:
        return await self._reconcile_alert_plan(plan, outcome)

    @action("snooze_alert", classification="write", capability="Enforcer", input_model=SnoozeAlertInput, idempotency="natural_key")
    async def plan_snooze_alert(self, args: SnoozeAlertInput) -> ActionPlan:
        self._require_edition("cspm")
        alert = await self._alert_state(args.alert_id)
        expiry = args.dismiss_until.astimezone(UTC).isoformat().replace("+00:00", "Z")
        payload = {"alerts": [args.alert_id], "dismissalNote": args.note, "dismissalExpirationTs": expiry}
        changed = str(alert.get("status")).lower() != "snoozed" or alert.get("dismissalExpirationTs") != expiry
        return self._alert_plan("snooze_alert", args.alert_id, alert, "snoozed", payload, "/alert/snooze", changed)

    @plan_snooze_alert.apply
    async def apply_snooze_alert(self, plan: ActionPlan) -> ActionOutcome:
        return await self._apply_alert_plan(plan)

    @plan_snooze_alert.reconcile
    async def reconcile_snooze_alert(self, plan: ActionPlan, outcome: ActionOutcome) -> ActionOutcome:
        return await self._reconcile_alert_plan(plan, outcome)

    @action("reopen_alert", classification="write", capability="Enforcer", input_model=ReopenAlertInput, idempotency="natural_key")
    async def plan_reopen_alert(self, args: ReopenAlertInput) -> ActionPlan:
        self._require_edition("cspm")
        alert = await self._alert_state(args.alert_id)
        status = str(alert.get("status") or "").lower()
        if status not in {"dismissed", "snoozed", "resolved", "open"}:
            raise ConfigError(f"alert status {status!r} cannot be reopened")
        payload = {"alerts": [args.alert_id], **({"note": args.note} if args.note else {})}
        return self._alert_plan("reopen_alert", args.alert_id, alert, "open", payload, "/alert/reopen", status != "open")

    @plan_reopen_alert.apply
    async def apply_reopen_alert(self, plan: ActionPlan) -> ActionOutcome:
        return await self._apply_alert_plan(plan)

    @plan_reopen_alert.reconcile
    async def reconcile_reopen_alert(self, plan: ActionPlan, outcome: ActionOutcome) -> ActionOutcome:
        return await self._reconcile_alert_plan(plan, outcome)

    @action("remediate_alert", classification="destructive", capability="Enforcer", input_model=RemediateAlertInput, idempotency="natural_key")
    async def plan_remediate_alert(self, args: RemediateAlertInput) -> ActionPlan:
        self._require_edition("cspm")
        self.require_destructive("remediate_alert")
        alert = await self._alert_state(args.alert_id)
        remediation = (await self.get_alert_remediation(AlertIdInput(alert_id=args.alert_id))).data
        if not isinstance(remediation, dict) or not (remediation.get("command") or remediation.get("diff") or remediation.get("cliScript")):
            raise VendorContractError("remediation preview has no command or diff")
        payload = {"alerts": [args.alert_id], "remediation": remediation}
        return self._alert_plan("remediate_alert", args.alert_id, alert, "resolved", payload, "/alert/remediate", str(alert.get("status")).lower() == "open")

    @plan_remediate_alert.apply
    async def apply_remediate_alert(self, plan: ActionPlan) -> ActionOutcome:
        return await self._apply_alert_plan(plan)

    @plan_remediate_alert.reconcile
    async def reconcile_remediate_alert(self, plan: ActionPlan, outcome: ActionOutcome) -> ActionOutcome:
        return await self._reconcile_alert_plan(plan, outcome)
