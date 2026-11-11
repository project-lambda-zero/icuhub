"""Nessus read-only connector: scans, history exports, uploads (MVP 4.9)."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any, ClassVar

from icuhub.connectors.nessus.mapping import event_uid, is_compliance, map_compliance, map_finding
from icuhub.connectors.nessus.models import (
    CreateExportArgs,
    DownloadExportArgs,
    GetExportStatusArgs,
    ListHistoryArgs,
    ListScansArgs,
    NessusConfig,
    NessusExport,
    NessusExportDownload,
    NessusExportStatus,
    NessusFindingRecord,
    NessusHistoryList,
    NessusReportContext,
    NessusScanList,
)
from icuhub.connectors.nessus.parser import NessusImportLimits, file_sha256, iter_nessus
from icuhub.kit.auth import HeaderToken, SessionLogin
from icuhub.kit.connector import Connector, importer, mapper, operation, stream
from icuhub.kit.cursors import SnapshotCursor, TimeIdCursor
from icuhub.kit.errors import PermissionDenied, VendorContractError
from icuhub.kit.types import (
    CapabilityHealth,
    HealthReport,
    ImportedFile,
    MapContext,
    RawBatch,
    Scope,
    SourceRecord,
    TargetRecord,
)

__all__ = ["Nessus"]

_EXPORT_CAPABLE = ("professional", "expert", "manager", "enterprise")
# Page size and offset ceiling of the scan history listing (ListHistoryArgs bounds).
_HISTORY_PAGE = 200
_HISTORY_MAX_OFFSET = 1_000_000


class Nessus(Connector):
    kind: ClassVar[str] = "nessus"
    version: ClassVar[str] = "0.1.0"
    display_name: ClassVar[str] = "Tenable Nessus"
    config_model: ClassVar[type[NessusConfig]] = NessusConfig
    auth_modes: ClassVar[tuple[str, ...]] = ("api_keys", "username_password_session")
    capabilities: ClassVar[tuple[str, ...]] = ("FindingSource",)
    scopes: ClassVar[tuple[Scope, ...]] = (
        Scope(name="scans", probe="GET /scans", required_by=("FindingSource",)),
        Scope(name="export", probe="POST /scans/{id}/export", required_by=("FindingSource",)),
    )
    flows: ClassVar[tuple[str, ...]] = ("F-001",)

    async def build_auth(self) -> HeaderToken | SessionLogin:
        config = self.config
        assert isinstance(config, NessusConfig)
        if config.auth_mode == "api_keys":
            access = (await self.ctx.secrets.resolve(config.access_key)).decode()  # type: ignore[arg-type]
            secret = (await self.ctx.secrets.resolve(config.secret_key)).decode()  # type: ignore[arg-type]
            return HeaderToken("X-ApiKeys", f"accessKey={access};secretKey={secret}")
        password = (await self.ctx.secrets.resolve(config.password)).decode()  # type: ignore[arg-type]

        async def login() -> tuple[str, str, datetime | None]:
            result = await self.http.request(
                "POST",
                "/session",
                json={"username": config.username, "password": password},
                authenticate=False,
            )
            token = result.json()["token"]
            return "X-Cookie", f"token={token}", None

        return SessionLogin(login=login)

    def _config(self) -> NessusConfig:
        config = self.config
        assert isinstance(config, NessusConfig)
        return config

    def _limits(self) -> NessusImportLimits:
        config = self._config()
        return NessusImportLimits(
            max_bytes=config.max_report_bytes,
            max_hosts=config.max_report_hosts,
            max_items=config.max_report_items,
            max_depth=config.max_depth,
            max_plugin_output_chars=config.max_plugin_output_chars,
        )

    async def check(self) -> HealthReport:
        capabilities: dict[str, CapabilityHealth] = {}
        status = "healthy"
        version = None
        edition = None
        try:
            result = await self.http.request("GET", "/server/properties")
            body = result.json()
            version = body.get("version") or body.get("server_version")
            edition = str(body.get("edition") or body.get("license", {}).get("edition") or "")
        except (OSError, TimeoutError, RuntimeError) as exc:
            return HealthReport(
                status="degraded",
                capabilities={"FindingSource": CapabilityHealth(status="degraded", reason=type(exc).__name__)},
            )
        try:
            await self.http.request("GET", "/scans")
            capabilities["scans"] = CapabilityHealth(status="healthy")
        except PermissionDenied as exc:
            capabilities["scans"] = CapabilityHealth(status="not_evaluated", reason=type(exc).__name__)
            status = "degraded"
        except (OSError, TimeoutError, RuntimeError) as exc:
            capabilities["scans"] = CapabilityHealth(status="degraded", reason=type(exc).__name__)
            status = "degraded"
        lowered = (edition or "").lower()
        if lowered and not any(level in lowered for level in _EXPORT_CAPABLE):
            capabilities["export"] = CapabilityHealth(status="not_evaluated", reason=f"edition {edition} cannot export")
            capabilities["FindingSource"] = CapabilityHealth(
                status="not_evaluated", reason=f"edition {edition} cannot export"
            )
        else:
            capabilities["export"] = CapabilityHealth(status="healthy")
            capabilities["FindingSource"] = capabilities.get(
                "scans", CapabilityHealth(status="healthy")
            )
        return HealthReport(
            status=status, capabilities=capabilities, vendor_version=str(version) if version else None,
            detail={"edition": edition} if edition else {},
        )

    async def discover(self) -> AsyncIterator[TargetRecord]:
        scans = await self.list_scans(ListScansArgs())
        for scan in scans.scans:
            yield TargetRecord(
                source_uid=str(scan.id),
                kind="scan",
                display_name=scan.name or f"scan {scan.id}",
                attributes={"uuid": scan.uuid, "status": scan.status},
            )

    @operation("list_scans", classification="read", capability="FindingSource", input_model=ListScansArgs, output_model=NessusScanList)
    async def list_scans(self, args: ListScansArgs) -> NessusScanList:
        params: dict[str, Any] = {}
        if args.folder_id is not None:
            params["folder_id"] = args.folder_id
        if args.last_modification_date is not None:
            params["last_modification_date"] = args.last_modification_date
        result = await self.http.request("GET", "/scans", params=params)
        return NessusScanList.model_validate(result.json())

    @operation("list_history", classification="read", capability="FindingSource", input_model=ListHistoryArgs, output_model=NessusHistoryList)
    async def list_history(self, args: ListHistoryArgs) -> NessusHistoryList:
        result = await self.http.request(
            "GET",
            f"/scans/{args.scan_id}/history",
            params={
                "limit": args.limit,
                "offset": args.offset,
                "sort": args.sort or "time_end",
                "exclude_rollover": "true",
            },
        )
        body = result.json()
        return NessusHistoryList.model_validate({**body, "limit": args.limit, "offset": args.offset})

    @operation("create_export", classification="read", capability="FindingSource", input_model=CreateExportArgs, output_model=NessusExport)
    async def create_export(self, args: CreateExportArgs) -> NessusExport:
        payload: dict[str, Any] = {"format": "nessus"}
        if args.history_id:
            payload["history_id"] = args.history_id
        result = await self.http.request("POST", f"/scans/{args.scan_id}/export", json=payload, idempotency="non_idempotent")
        body = result.json()
        now = datetime.now(UTC)
        if "file" in body:
            return NessusExport(
                scan_id=args.scan_id,
                history_id=args.history_id,
                file_id=str(body["file"]),
                export_kind="file",
                created_at=now,
                expires_at=now + timedelta(seconds=self._config().export_timeout_s),
            )
        return NessusExport(
            scan_id=args.scan_id,
            history_id=args.history_id,
            file_id=str(body["token"]),
            export_kind="token",
            created_at=now,
            expires_at=now + timedelta(seconds=self._config().export_timeout_s),
        )

    @operation("get_export_status", classification="read", capability="FindingSource", input_model=GetExportStatusArgs, output_model=NessusExportStatus)
    async def get_export_status(self, args: GetExportStatusArgs) -> NessusExportStatus:
        deadline = datetime.now(UTC) + timedelta(seconds=args.timeout_s)
        while True:
            result = await self.http.request("GET", f"/scans/{args.scan_id}/export/{args.file_id}/status")
            body = result.json()
            status = str(body.get("status") or "unknown")
            ready = status == "ready"
            if ready or status in ("error", "cancelled"):
                return NessusExportStatus(
                    status=status,
                    ready=ready,
                    chunks_failed=list(body.get("chunks_failed") or []),
                    chunks_cancelled=list(body.get("chunks_cancelled") or []),
                    detail=body,
                )
            if datetime.now(UTC) >= deadline:
                raise VendorContractError(f"export {args.file_id} not ready within {args.timeout_s}s (last status {status})")
            await asyncio.sleep(args.poll_interval_s)

    @operation("download_export", classification="read", capability="FindingSource", input_model=DownloadExportArgs, output_model=NessusExportDownload)
    async def download_export(self, args: DownloadExportArgs) -> NessusExportDownload:
        data = await self.http.stream_download(
            "GET", f"/scans/{args.scan_id}/export/{args.file_id}/download", max_bytes=self._config().max_report_bytes
        )
        return await self._live_report(data, scan_id=args.scan_id, history_id=args.history_id)

    async def _history_facts(self, scan_id: str, history_id: str) -> tuple[str | None, bool | None]:
        """Return ``(status, archived)`` of one history run, or ``(None, None)`` when it is not listed.

        Pages the history list newest first. Stops at the first matching run, at the end of the
        listing, or at the history API's maximum offset.
        """
        for offset in range(0, _HISTORY_MAX_OFFSET, _HISTORY_PAGE):
            page = await self.list_history(ListHistoryArgs(scan_id=scan_id, offset=offset, limit=_HISTORY_PAGE))
            for run in page.history:
                if str(run.history_id) == history_id:
                    return run.status, run.archived
            if len(page.history) < _HISTORY_PAGE:
                break
        return None, None

    async def _live_report(self, data: bytes, *, scan_id: str, history_id: str | None) -> NessusExportDownload:
        status, archived = (None, None)
        if history_id is not None:
            status, archived = await self._history_facts(scan_id, history_id)
        return self._parse(
            data,
            scan_id=scan_id,
            history_id=history_id,
            history_status=status,
            archived=archived,
            source="live",
        )

    def _parse(
        self,
        data: bytes,
        *,
        scan_id: str | None,
        history_id: str | None,
        history_status: str | None,
        archived: bool | None,
        source: str,
    ) -> NessusExportDownload:
        digest = file_sha256(data)
        rows = list(iter_nessus(data, limits=self._limits()))
        report_name = rows[0][0] if rows else None
        context = NessusReportContext(
            run_uid=f"nessus:{digest}",
            file_sha256=digest,
            source=source,
            scan_id=scan_id,
            history_id=history_id,
            history_status=history_status,
            archived=archived,
            report_name=report_name,
        )
        # Live exports carry the scan id; uploads are scoped by the Report name. Identity never
        # depends on the file bytes, so repeated exports of one scan keep their finding identity.
        scope = f"scan:{scan_id}" if scan_id else f"report:{report_name}"
        records: list[NessusFindingRecord] = []
        truncated = False
        bounded = False
        for _, host, item in rows:
            records.append(
                NessusFindingRecord(
                    event_uid=event_uid(scope, host.model_dump(), item.model_dump()),
                    report=context,
                    host=host,
                    item=item,
                )
            )
            truncated = truncated or item.truncated
            bounded = bounded or item.output_bounded
        return NessusExportDownload(
            report=context,
            records=records,
            file_sha256=digest,
            size_bytes=len(data),
            truncated=truncated,
            output_bounded=bounded,
        )

    @stream("scan_runs", record_type="scan_run", cursor=TimeIdCursor, modes=("incremental", "full"), capability="FindingSource", requires_target=False)
    async def scan_runs(self, target: Any, checkpoint: TimeIdCursor | None, mode: str) -> AsyncIterator[RawBatch]:
        cursor = checkpoint or TimeIdCursor(ts=None)
        scans = await self.list_scans(ListScansArgs())
        records: list[dict[str, Any]] = []
        for scan in scans.scans:
            history = await self.list_history(ListHistoryArgs(scan_id=str(scan.id)))
            for run in history.history:
                if run.time_end:
                    cursor = cursor.advance(
                        [run.model_dump()],
                        ts_of=lambda r: datetime.fromtimestamp(r["time_end"], UTC),
                        id_of=lambda r: str(r["history_id"]),
                    )
                records.append({"scan": scan.model_dump(), "run": run.model_dump()})
        yield RawBatch(records=records, checkpoint=cursor, complete=mode == "full")

    @mapper("scan_runs", version=1)
    def map_scan_run(self, raw: dict[str, Any], ctx: MapContext) -> list[SourceRecord]:
        scan, run = raw["scan"], raw["run"]
        uid = f"nessus:scan:{scan['id']}:history:{run['history_id']}"
        return [
            SourceRecord(
                record_type="scan_run",
                uid=uid,
                revision=str(run.get("time_end") or ""),
                data={"class_uid": 6004, "scan": scan, "run": run},
                links={"scan_id": str(scan["id"]), "history_id": str(run["history_id"])},
            )
        ]

    async def _export_records(self, target: Any, compliance: bool) -> tuple[list[dict[str, Any]], SnapshotCursor]:
        scan_id = str(target.source_uid)
        history_id = (target.attributes or {}).get("history_id")
        export = await self.create_export(CreateExportArgs(scan_id=scan_id, history_id=history_id))
        await self.get_export_status(
            GetExportStatusArgs(
                scan_id=scan_id,
                file_id=export.file_id,
                export_kind=export.export_kind,
                poll_interval_s=self._config().export_poll_interval_s,
                timeout_s=self._config().export_timeout_s,
            )
        )
        data = await self.http.stream_download(
            "GET", f"/scans/{scan_id}/export/{export.file_id}/download", max_bytes=self._config().max_report_bytes
        )
        report = await self._live_report(data, scan_id=scan_id, history_id=history_id)
        records = [
            record.model_dump()
            for record in report.records
            if is_compliance(record.item.model_dump()) == compliance
        ]
        hosts = sorted({record.host.key for record in report.records})
        cursor = SnapshotCursor(
            snapshot_id=report.report.run_uid,
            started_at=datetime.now(UTC),
            targets_done=hosts,
        )
        return records, cursor

    @stream("export_findings", ocsf_class=2002, cursor=SnapshotCursor, modes=("full",), capability="FindingSource", requires_target=True)
    async def export_findings(self, target: Any, checkpoint: SnapshotCursor | None, mode: str) -> AsyncIterator[RawBatch]:
        records, cursor = await self._export_records(target, compliance=False)
        yield RawBatch(records=records, checkpoint=cursor, complete=True)

    @mapper("export_findings", version=1)
    def map_export_finding(self, raw: dict[str, Any], ctx: MapContext) -> list[Any]:
        return map_finding(NessusFindingRecord.model_validate(raw), ctx)

    @stream("compliance_findings", ocsf_class=2003, cursor=SnapshotCursor, modes=("full",), capability="FindingSource", requires_target=True)
    async def compliance_findings(self, target: Any, checkpoint: SnapshotCursor | None, mode: str) -> AsyncIterator[RawBatch]:
        records, cursor = await self._export_records(target, compliance=True)
        yield RawBatch(records=records, checkpoint=cursor, complete=True)

    @mapper("compliance_findings", version=1)
    def map_compliance_finding(self, raw: dict[str, Any], ctx: MapContext) -> list[Any]:
        return map_compliance(NessusFindingRecord.model_validate(raw), ctx)

    async def _import_records(self, imported: ImportedFile, compliance: bool) -> AsyncIterator[dict[str, Any]]:
        report = self._parse(
            imported.data, scan_id=None, history_id=None, history_status=None, archived=None, source="upload"
        )
        for record in report.records:
            if is_compliance(record.item.model_dump()) == compliance:
                yield record.model_dump()

    @importer("nessus_xml", stream="export_findings", media_types=("application/xml", "text/xml"), extensions=(".nessus", ".xml"))
    async def import_nessus_xml(self, imported: ImportedFile) -> AsyncIterator[dict[str, Any]]:
        async for record in self._import_records(imported, compliance=False):
            yield record

    @importer("nessus_xml_compliance", stream="compliance_findings", media_types=("application/xml", "text/xml"), extensions=(".nessus", ".xml"))
    async def import_nessus_compliance(self, imported: ImportedFile) -> AsyncIterator[dict[str, Any]]:
        async for record in self._import_records(imported, compliance=True):
            yield record
