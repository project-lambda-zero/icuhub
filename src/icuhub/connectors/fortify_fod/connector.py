"""Fortify on Demand Web API v3 connector.

Issue changed-since filtering is tenant-unverified, so both issue modes perform a complete
release reconciliation with fixed and suppressed records. Release scans are also fully traversed
because the release collection has no modifiedStartDate parameter; incremental scan batches do not
close absence. Offsets are transient traversal state, never durable checkpoints.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import UTC, datetime
from typing import Any, ClassVar

from icuhub.connectors._fortify.mappers import map_fod_issue
from icuhub.connectors.fortify_fod.models import (
    ApplicationArgs,
    BulkAuditInput,
    CancelScanInput,
    CreateReportInput,
    DataExportArgs,
    DataExportRecord,
    DeleteResourceInput,
    DownloadFprArgs,
    DownloadOutput,
    EmptyArgs,
    FortifyFodConfig,
    ImportScanInput,
    IssueArgs,
    IssueHistoryArgs,
    IssueInstanceArgs,
    ListApplicationsArgs,
    ListDataExportsArgs,
    ListReleasesArgs,
    ListScansArgs,
    MicroservicesArgs,
    ReleaseArgs,
    ReleaseScanArgs,
    ReportArgs,
    ScanRecord,
    StartScanInput,
    VendorListOutput,
    VendorObjectOutput,
)
from icuhub.kit.auth import AuthStrategy, OAuth2ClientCredentials
from icuhub.kit.connector import Connector, action, mapper, operation, stream
from icuhub.kit.cursors import SnapshotCursor, TimeIdCursor
from icuhub.kit.errors import (
    AuthFailed,
    BudgetExhausted,
    ConfigError,
    NotFound,
    OutcomeUnknown,
    PermissionDenied,
    RateLimited,
    StalePlan,
    TransientVendorError,
    VendorContractError,
)
from icuhub.kit.http import HttpResult
from icuhub.kit.types import (
    ActionOutcome,
    ActionPlan,
    CapabilityHealth,
    ConnectorConfig,
    HealthReport,
    MapContext,
    RawBatch,
    Scope,
    Target,
)
from icuhub_schemas.ocsf import VulnerabilityFinding

__all__ = ["FortifyFod"]

_API = "/api/v3"
_VULNERABILITIES_PATH = f"{_API}/releases/{{release_id}}/vulnerabilities"
_BULK_EDIT_PATH = f"{_VULNERABILITIES_PATH}/bulk-edit"
_PAGE_LIMIT = 50
_MAX_PAGES = 10_000
_MAX_UNPAGED = 1_000
_STATUS_FIELDS = ("developerStatus", "auditorStatus", "severity")
_UNVERIFIED_BODY_FIELDS = ("userId", "comment", "attributes")
_SCAN_TERMINAL_SUCCESS = frozenset({"Completed", "Complete", "AnalysisComplete", "Succeeded"})
_SCAN_TERMINAL_FAILED = frozenset({"Failed", "Error", "AnalysisFailed", "Canceled", "Cancelled"})
_REPORT_FAILED = frozenset({"Failed", "Canceled", "Cancelled", "Error"})
_EXPORT_TYPES = frozenset(
    {"IssuesExport", "ScansExport", "ReleasesExport", "ApplicationsExport", "EntitlementConsumptionExport"}
)


def _json_object(result: HttpResult) -> dict[str, Any]:
    body = result.json()
    if not isinstance(body, dict):
        raise VendorContractError("FoD response must be a JSON object")
    return body


def _release_id(target: Target) -> str:
    release_id = target.source_uid
    if not (release_id.isascii() and release_id.isdigit()):
        raise ConfigError(f"fortify_fod release id must be decimal digits, got {release_id!r}")
    return release_id


def _sha256_json(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _int_required(raw: dict[str, Any], key: str) -> int:
    value = raw.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise VendorContractError(f"FoD {key} must be an integer")
    return value


def _str_required(raw: dict[str, Any], key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value:
        raise VendorContractError(f"FoD {key} must be a non-empty string")
    return value


def _parse_time(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise VendorContractError(f"FoD {field} must be an ISO date or date-time")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise VendorContractError(f"FoD {field} must be an ISO date or date-time") from exc
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed


def _issue_time(raw: dict[str, Any]) -> datetime:
    return _parse_time(raw.get("lastModifiedDate"), "lastModifiedDate")


def _scan_time(raw: dict[str, Any]) -> datetime:
    value = raw.get("modifiedDate") or raw.get("completedDateTime") or raw.get("startedDateTime")
    return _parse_time(value, "scan timestamp")


def _issue_identity(raw: dict[str, Any]) -> str:
    return _str_required(raw, "instanceId")


def _desired_status(body: dict[str, Any]) -> dict[str, Any]:
    return {name: body[name] for name in _STATUS_FIELDS if name in body}


def _status_mismatches(states: dict[str, dict[str, Any]], desired: dict[str, Any]) -> list[str]:
    return [
        f"{vuln_id}.{field}"
        for vuln_id, record in states.items()
        for field, wanted in desired.items()
        if record.get(field) != wanted
    ]


def _bulk_edit_error_codes(body: Any) -> list[int] | None:
    if not isinstance(body, list) or not body:
        return None
    codes: list[int] = []
    for entry in body:
        code = entry.get("errorCode") if isinstance(entry, dict) else None
        if isinstance(code, bool) or not isinstance(code, int):
            return None
        codes.append(code)
    return codes


def _contains_integer_id(value: Any, key: str, wanted: int) -> bool:
    if isinstance(value, dict):
        if value.get(key) == wanted:
            return True
        return any(_contains_integer_id(item, key, wanted) for item in value.values())
    if isinstance(value, list):
        return any(_contains_integer_id(item, key, wanted) for item in value)
    return False


class FortifyFod(Connector):
    kind: ClassVar[str] = "fortify_fod"
    version: ClassVar[str] = "0.1.0"
    display_name: ClassVar[str] = "Fortify on Demand"
    config_model: ClassVar[type[ConnectorConfig]] = FortifyFodConfig
    auth_modes: ClassVar[tuple[str, ...]] = ("OAuth2ClientCredentials",)
    capabilities: ClassVar[tuple[str, ...]] = ("FindingSource",)
    flows: ClassVar[tuple[str, ...]] = ("F-228",)
    scopes: ClassVar[tuple[Scope, ...]] = (
        Scope(name="view-apps", probe="GET /api/v3/applications", required_by=("FindingSource",)),
        Scope(name="view-issues", probe="GET /api/v3/releases/{releaseId}/vulnerabilities", required_by=("FindingSource",)),
        Scope(name="view-reports", probe="GET /api/v3/reports/dataexports", required_by=("FindingSource",)),
        Scope(name="manage-issues", probe="POST /api/v3/releases/{releaseId}/vulnerabilities/bulk-edit", required_by=()),
        Scope(name="manage-reports", probe="POST /api/v3/reports", required_by=()),
    )

    def _config(self) -> FortifyFodConfig:
        if not isinstance(self.config, FortifyFodConfig):
            raise ConfigError("fortify_fod requires a FortifyFodConfig")
        return self.config

    def _require_write(self) -> None:
        if not self._config().write_enabled:
            raise PermissionDenied("write", "write actions require write_enabled on this connection")

    def _require_destructive(self) -> None:
        self._require_write()
        if not self._config().destructive_enabled:
            raise PermissionDenied("destructive", "destructive actions require destructive_enabled on this connection")

    async def build_auth(self) -> AuthStrategy:
        config = self._config()
        raw_secret = await self.ctx.secrets.resolve(config.client_secret)
        try:
            client_secret = raw_secret.decode("utf-8")
        except UnicodeDecodeError:
            raise ConfigError("fortify_fod client_secret must be UTF-8") from None
        return OAuth2ClientCredentials(
            token_url=f"{config.base_url.rstrip('/')}/oauth/token",
            client_id=config.client_id,
            client_secret=client_secret,
            scope="api-tenant",
        )

    async def _value(self, path: str, *, params: dict[str, Any] | None = None) -> Any:
        result = await self.http.request("GET", path, params=params, expected=(200, 202))
        if result.status == 202:
            raise TransientVendorError(f"FoD repository is updating at {path}")
        return result.json()

    async def _object(self, path: str, *, params: dict[str, Any] | None = None) -> dict[str, Any]:
        body = await self._value(path, params=params)
        if not isinstance(body, dict):
            raise VendorContractError("FoD response must be a JSON object")
        return body

    async def _pages(
        self, path: str, *, params: dict[str, Any] | None = None
    ) -> AsyncIterator[list[dict[str, Any]]]:
        offset = 0
        total: int | None = None
        pages = 0
        while total is None or offset < total:
            if pages >= _MAX_PAGES:
                raise BudgetExhausted(f"FoD pagination of {path} exceeded {_MAX_PAGES} pages")
            result = await self.http.request(
                "GET",
                path,
                params={**(params or {}), "offset": offset, "limit": self._config().page_size},
                expected=(200, 202),
            )
            if result.status == 202:
                raise TransientVendorError(f"FoD repository is updating at {path}")
            body = _json_object(result)
            if body.get("offset") != offset:
                raise VendorContractError(f"FoD echoed offset {body.get('offset')!r} for requested offset {offset}")
            items = body.get("items")
            page_total = body.get("totalCount")
            if not isinstance(items, list) or not all(isinstance(item, dict) for item in items):
                raise VendorContractError("FoD page items must be a list of objects")
            if isinstance(page_total, bool) or not isinstance(page_total, int) or page_total < 0:
                raise VendorContractError("FoD totalCount must be a non-negative integer")
            if total is None:
                total = page_total
            elif page_total != total:
                raise VendorContractError(f"totalCount changed from {total} to {page_total} during traversal")
            if not items:
                if total == 0 and offset == 0:
                    return
                raise VendorContractError(f"empty page at offset {offset} before totalCount {total}")
            if offset + len(items) > total:
                raise VendorContractError(f"page at offset {offset} overruns totalCount {total}")
            yield items
            pages += 1
            offset += len(items)

    async def _collect(self, path: str, *, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        return [item async for page in self._pages(path, params=params) for item in page]

    async def _issue_pages(self, release_id: str) -> AsyncIterator[list[dict[str, Any]]]:
        seen: set[int] = set()
        async for page in self._pages(
            _VULNERABILITIES_PATH.format(release_id=release_id),
            params={
                "excludeFilters": "true",
                "orderBy": "severity",
                "orderByDirection": "ASC",
                "includeFixed": "true",
                "includeSuppressed": "true",
            },
        ):
            for item in page:
                identity = _int_required(item, "id")
                if identity in seen:
                    raise VendorContractError(f"release {release_id} snapshot repeated issue id {identity}")
                seen.add(identity)
            yield page

    async def _lookup_vulnerability(self, release_id: str, vuln_id: str) -> dict[str, Any]:
        result = await self.http.request(
            "GET",
            _VULNERABILITIES_PATH.format(release_id=release_id),
            params={
                "excludeFilters": "true",
                "filters": f"id:{vuln_id}",
                "includeFixed": "true",
                "includeSuppressed": "true",
                "limit": "2",
            },
            expected=(200, 202),
        )
        if result.status == 202:
            raise TransientVendorError("FoD repository is updating")
        items = _json_object(result).get("items")
        if not isinstance(items, list) or len(items) != 1 or not isinstance(items[0], dict):
            raise VendorContractError(f"vulnerability {vuln_id} lookup must return exactly one record")
        record = items[0]
        if str(record.get("id")) != vuln_id:
            raise VendorContractError(f"vulnerability lookup for {vuln_id} returned id {record.get('id')!r}")
        return record

    async def _read_states(self, release_id: str, vuln_ids: list[str]) -> dict[str, dict[str, Any]]:
        states: dict[str, dict[str, Any]] = {}
        for vuln_id in vuln_ids:
            record = await self._lookup_vulnerability(release_id, vuln_id)
            states[vuln_id] = {field: record.get(field) for field in _STATUS_FIELDS}
        return states

    async def _download_result(
        self, path: str, *, params: dict[str, Any] | None = None
    ) -> HttpResult:
        return await self.http.stream_download_result(
            "GET",
            path,
            params=params,
            max_bytes=self._config().max_download_bytes,
            expected=(200, 202),
        )

    async def _download(
        self, path: str, *, vendor_ref: str, params: dict[str, Any] | None = None
    ) -> DownloadOutput:
        result = await self._download_result(path, params=params)
        if result.status == 202:
            return DownloadOutput(ready=False, vendor_ref=vendor_ref, status="RepositoryUpdating")
        return DownloadOutput(
            ready=True,
            vendor_ref=vendor_ref,
            status="Completed",
            sha256=hashlib.sha256(result.content).hexdigest(),
            size_bytes=len(result.content),
            content_base64=base64.b64encode(result.content).decode("ascii"),
        )

    async def _settle(
        self,
        plan: ActionPlan,
        prior: ActionOutcome,
        reconcile: Callable[[ActionPlan, ActionOutcome], Awaitable[ActionOutcome]],
    ) -> ActionOutcome:
        try:
            return await reconcile(plan, prior)
        except (OutcomeUnknown, TransientVendorError, RateLimited, VendorContractError) as exc:
            return ActionOutcome(
                status="outcome_unknown",
                vendor_ref=plan.target_ref,
                error=str(exc),
                result=prior.result,
            )

    @operation("probe_target", input_model=EmptyArgs, output_model=VendorObjectOutput, classification="read", capability="FindingSource")
    async def probe_target(self, args: EmptyArgs) -> VendorObjectOutput:
        tenant = await self._object(f"{_API}/tenants")
        features = await self._value(f"{_API}/tenants/features")
        entitlements = await self._value(f"{_API}/tenant-entitlements")
        applications = await self._object(f"{_API}/applications", params={"offset": 0, "limit": 1})
        record: dict[str, Any] = {
            "region": self._config().base_url,
            "oauth_scope": "api-tenant",
            "page_size": self._config().page_size,
            "tenant": tenant,
            "features": features,
            "entitlements": entitlements,
            "applications_probe": applications,
        }
        if self._config().probe_release_id is not None:
            record["release_probe"] = await self._object(f"{_API}/releases/{self._config().probe_release_id}")
        return VendorObjectOutput(record=record)

    async def check(self) -> HealthReport:
        try:
            await self.probe_target(EmptyArgs())
        except AuthFailed:
            return HealthReport(status="failing", capabilities={"FindingSource": CapabilityHealth(status="failing", reason="vendor rejected credentials")})
        except (PermissionDenied, RateLimited, TransientVendorError, VendorContractError) as exc:
            return HealthReport(status="degraded", capabilities={"FindingSource": CapabilityHealth(status="degraded", reason=str(exc))})
        return HealthReport(status="healthy", capabilities={"FindingSource": CapabilityHealth(status="healthy")})

    @operation("list_applications", input_model=ListApplicationsArgs, output_model=VendorListOutput, classification="read", capability="FindingSource")
    async def list_applications(self, args: ListApplicationsArgs) -> VendorListOutput:
        params = {"modifiedStartDate": args.modified_since.isoformat()} if args.modified_since else None
        records = await self._collect(f"{_API}/applications", params=params)
        return VendorListOutput(records=records, total_count=len(records))

    @operation("list_microservices", input_model=MicroservicesArgs, output_model=VendorListOutput, classification="read", capability="FindingSource")
    async def list_microservices(self, args: MicroservicesArgs) -> VendorListOutput:
        body = await self._object(f"{_API}/applications/{args.application_id}/microservices")
        items = body.get("items")
        total = body.get("totalCount")
        if not isinstance(items, list) or not all(isinstance(item, dict) for item in items):
            raise VendorContractError("FoD microservice items must be a list of objects")
        if total != len(items):
            raise VendorContractError("FoD microservice response is incomplete")
        if len(items) > _MAX_UNPAGED:
            raise BudgetExhausted(f"FoD microservice response exceeded {_MAX_UNPAGED} records")
        return VendorListOutput(records=items, total_count=len(items))

    @operation("list_releases", input_model=ListReleasesArgs, output_model=VendorListOutput, classification="read", capability="FindingSource")
    async def list_releases(self, args: ListReleasesArgs) -> VendorListOutput:
        path = f"{_API}/applications/{args.application_id}/releases" if args.application_id else f"{_API}/releases"
        params = {"modifiedStartDate": args.modified_since.isoformat()} if args.modified_since else None
        records = await self._collect(path, params=params)
        return VendorListOutput(records=records, total_count=len(records))

    @operation("get_release", input_model=ReleaseArgs, output_model=VendorObjectOutput, classification="read", capability="FindingSource")
    async def get_release(self, args: ReleaseArgs) -> VendorObjectOutput:
        return VendorObjectOutput(record=await self._object(f"{_API}/releases/{args.release_id}"))

    @operation("get_application", input_model=ApplicationArgs, output_model=VendorObjectOutput, classification="read", capability="FindingSource")
    async def get_application(self, args: ApplicationArgs) -> VendorObjectOutput:
        return VendorObjectOutput(record=await self._object(f"{_API}/applications/{args.application_id}"))

    @operation("get_issue", input_model=IssueInstanceArgs, output_model=VendorObjectOutput, classification="read", capability="FindingSource")
    async def get_issue(self, args: IssueInstanceArgs) -> VendorObjectOutput:
        result = await self.http.request(
            "GET",
            _VULNERABILITIES_PATH.format(release_id=args.release_id),
            params={
                "excludeFilters": "true",
                "filters": f"instanceId:{args.instance_id}",
                "includeFixed": "true",
                "includeSuppressed": "true",
                "limit": 2,
            },
            expected=(200, 202),
        )
        if result.status == 202:
            raise TransientVendorError("FoD repository is updating")
        items = _json_object(result).get("items")
        if not isinstance(items, list) or len(items) != 1 or not isinstance(items[0], dict):
            raise VendorContractError("instanceId equality lookup must return exactly one record")
        record = items[0]
        if record.get("instanceId") != args.instance_id:
            raise VendorContractError("instanceId lookup returned a different issue")
        return VendorObjectOutput(record={**record, "_release_id": args.release_id})

    @operation("get_issue_details", input_model=IssueArgs, output_model=VendorObjectOutput, classification="read", capability="FindingSource")
    async def get_issue_details(self, args: IssueArgs) -> VendorObjectOutput:
        return VendorObjectOutput(record=await self._object(f"{_VULNERABILITIES_PATH.format(release_id=args.release_id)}/{args.vuln_id}/details"))

    @operation("get_issue_history", input_model=IssueHistoryArgs, output_model=VendorObjectOutput, classification="read", capability="FindingSource")
    async def get_issue_history(self, args: IssueHistoryArgs) -> VendorObjectOutput:
        return VendorObjectOutput(record=await self._object(
            f"{_VULNERABILITIES_PATH.format(release_id=args.release_id)}/{args.vuln_id}/history",
            params={"includeSystemEvents": str(args.include_system_events).lower()},
        ))

    @operation("get_recommendations", input_model=IssueArgs, output_model=VendorObjectOutput, classification="read", capability="FindingSource")
    async def get_recommendations(self, args: IssueArgs) -> VendorObjectOutput:
        return VendorObjectOutput(record=await self._object(f"{_VULNERABILITIES_PATH.format(release_id=args.release_id)}/{args.vuln_id}/recommendations"))

    @operation("list_scans", input_model=ListScansArgs, output_model=VendorListOutput, classification="read", capability="FindingSource")
    async def list_scans(self, args: ListScansArgs) -> VendorListOutput:
        if args.release_id:
            records = await self._collect(f"{_API}/releases/{args.release_id}/scans")
        else:
            params = {"modifiedStartDate": args.modified_since.isoformat()} if args.modified_since else None
            records = await self._collect(f"{_API}/scans", params=params)
        if args.release_id and args.modified_since:
            records = [record for record in records if _scan_time(record) >= args.modified_since]
        return VendorListOutput(records=records, total_count=len(records))

    @operation("get_scan", input_model=ReleaseScanArgs, output_model=VendorObjectOutput, classification="read", capability="FindingSource")
    async def get_scan(self, args: ReleaseScanArgs) -> VendorObjectOutput:
        return VendorObjectOutput(record=await self._object(f"{_API}/releases/{args.release_id}/scans/{args.scan_id}"))

    @operation("download_fpr", input_model=DownloadFprArgs, output_model=DownloadOutput, classification="read", capability="FindingSource")
    async def download_fpr(self, args: DownloadFprArgs) -> DownloadOutput:
        if args.scan_id is not None:
            return await self._download(f"{_API}/scans/{args.scan_id}/fpr", vendor_ref=f"fortify_fod:scan:{args.scan_id}:fpr")
        return await self._download(
            f"{_API}/releases/{args.release_id}/fpr",
            params={"scanType": args.scan_type},
            vendor_ref=f"fortify_fod:release:{args.release_id}:{args.scan_type}:fpr",
        )

    @operation("get_report", input_model=ReportArgs, output_model=VendorObjectOutput, classification="read", capability="FindingSource")
    async def get_report(self, args: ReportArgs) -> VendorObjectOutput:
        return VendorObjectOutput(record=await self._object(f"{_API}/reports/{args.report_id}"))

    @operation("download_report", input_model=ReportArgs, output_model=DownloadOutput, classification="read", capability="FindingSource")
    async def download_report(self, args: ReportArgs) -> DownloadOutput:
        return await self._download(f"{_API}/reports/{args.report_id}/download", vendor_ref=f"fortify_fod:report:{args.report_id}")

    @operation("list_data_exports", input_model=ListDataExportsArgs, output_model=VendorListOutput, classification="read", capability="FindingSource")
    async def list_data_exports(self, args: ListDataExportsArgs) -> VendorListOutput:
        records = await self._collect(f"{_API}/reports/dataexports")
        if args.data_export_type:
            records = [record for record in records if record.get("dataExportType") == args.data_export_type]
        return VendorListOutput(records=records, total_count=len(records))

    @operation("get_data_export", input_model=DataExportArgs, output_model=VendorObjectOutput, classification="read", capability="FindingSource")
    async def get_data_export(self, args: DataExportArgs) -> VendorObjectOutput:
        records = await self._collect(f"{_API}/reports/dataexports")
        matches = [record for record in records if str(record.get("dataExportId")) == args.data_export_id]
        if not matches:
            raise NotFound(f"FoD data export {args.data_export_id} was not found")
        if len(matches) != 1:
            raise VendorContractError(f"FoD data export {args.data_export_id} is not unique")
        record = matches[0]
        if args.expected_type and record.get("dataExportType") != args.expected_type:
            raise VendorContractError("data export response has a different type")
        return VendorObjectOutput(record=record)

    @operation("download_data_export", input_model=DataExportArgs, output_model=DownloadOutput, classification="read", capability="FindingSource")
    async def download_data_export(self, args: DataExportArgs) -> DownloadOutput:
        job = (await self.get_data_export(args)).record
        status = _str_required(job, "dataExportStatusType")
        if status != "Completed":
            return DownloadOutput(ready=False, vendor_ref=f"fortify_fod:data_export:{args.data_export_id}", status=status)
        return await self._download(
            f"{_API}/reports/dataexports/{args.data_export_id}/download",
            vendor_ref=f"fortify_fod:data_export:{args.data_export_id}",
        )

    @stream("issues", cursor=TimeIdCursor, capability="FindingSource", ocsf_class=2002, modes=("incremental", "full"), requires_target=True)
    async def issues(self, target: Target | None, checkpoint: Any, mode: str) -> AsyncIterator[RawBatch]:
        if target is None:
            raise ConfigError("fortify_fod issues stream requires a release target")
        release_id = _release_id(target)
        cursor = checkpoint if isinstance(checkpoint, TimeIdCursor) else TimeIdCursor(ts=None)
        async for page in self._issue_pages(release_id):
            cursor = cursor.advance(page, ts_of=_issue_time, id_of=_issue_identity)
            yield RawBatch(records=[{**item, "_release_id": release_id} for item in page], checkpoint=cursor, complete=False)
        yield RawBatch(records=[], checkpoint=cursor, complete=True)

    @mapper("issues", version=1)
    def map_issue(self, raw: dict[str, Any], ctx: MapContext) -> list[VulnerabilityFinding]:
        return map_fod_issue(raw, ctx)

    @stream("scans", cursor=TimeIdCursor, capability="FindingSource", record_type="scan", modes=("incremental", "full"), requires_target=True)
    async def scans(self, target: Target | None, checkpoint: Any, mode: str) -> AsyncIterator[RawBatch]:
        if target is None:
            raise ConfigError("fortify_fod scans stream requires a release target")
        release_id = _release_id(target)
        cursor = checkpoint if isinstance(checkpoint, TimeIdCursor) else TimeIdCursor(ts=None)
        async for page in self._pages(f"{_API}/releases/{release_id}/scans"):
            cursor = cursor.advance(page, ts_of=_scan_time, id_of=lambda raw: str(_int_required(raw, "scanId")))
            yield RawBatch(records=page, checkpoint=cursor, complete=False)
        yield RawBatch(records=[], checkpoint=cursor, complete=mode == "full")

    @mapper("scans", version=1)
    def map_scan(self, raw: dict[str, Any], ctx: MapContext) -> list[ScanRecord]:
        status = raw.get("analysisStatusType")
        if status is not None and not isinstance(status, str):
            raise VendorContractError("FoD analysisStatusType must be a string or null")
        return [ScanRecord(scan_id=_int_required(raw, "scanId"), release_id=_int_required(raw, "releaseId"), analysis_status=status, observed_at=_scan_time(raw))]

    @stream("data_exports", cursor=SnapshotCursor, capability="FindingSource", record_type="data_export", modes=("full",), requires_target=False)
    async def data_exports(self, target: Target | None, checkpoint: Any, mode: str) -> AsyncIterator[RawBatch]:
        if isinstance(checkpoint, SnapshotCursor):
            cursor = checkpoint
        else:
            cursor = SnapshotCursor(snapshot_id=f"fortify_fod:data_exports:{self.ctx.clock().isoformat()}", started_at=self.ctx.clock())
        done = set(cursor.targets_done)
        jobs = await self._collect(f"{_API}/reports/dataexports")
        for job in jobs:
            export_id = str(_int_required(job, "dataExportId"))
            if export_id in done:
                continue
            status = _str_required(job, "dataExportStatusType")
            if status not in {"Started", "Completed", "Failed", "Queued", "Canceled"}:
                raise VendorContractError(f"unknown FoD data export status {status!r}")
            export_type = _str_required(job, "dataExportType")
            if export_type not in _EXPORT_TYPES:
                raise VendorContractError(f"unknown FoD data export type {export_type!r}")
            download: dict[str, Any] = {"ready": False, "sha256": None, "size_bytes": 0, "content_base64": None}
            if status == "Completed":
                completed = await self._download(
                    f"{_API}/reports/dataexports/{export_id}/download",
                    vendor_ref=f"fortify_fod:data_export:{export_id}",
                )
                if not completed.ready:
                    raise TransientVendorError(f"completed FoD export {export_id} is not downloadable")
                download = {
                    "ready": True,
                    "sha256": completed.sha256,
                    "size_bytes": completed.size_bytes,
                    "content_base64": completed.content_base64,
                }
            done.add(export_id)
            cursor = cursor.model_copy(update={"targets_done": sorted(done)})
            yield RawBatch(records=[{"job": job, "download": download}], checkpoint=cursor, complete=False)
        yield RawBatch(records=[], checkpoint=cursor, complete=True)

    @mapper("data_exports", version=1)
    def map_data_export(self, raw: dict[str, Any], ctx: MapContext) -> list[DataExportRecord]:
        job = raw.get("job")
        download = raw.get("download")
        if not isinstance(job, dict) or not isinstance(download, dict):
            raise VendorContractError("FoD export envelope must contain job and download objects")
        return [DataExportRecord(
            data_export_id=_int_required(job, "dataExportId"),
            data_export_type=_str_required(job, "dataExportType"),
            status=_str_required(job, "dataExportStatusType"),
            ready=download.get("ready") is True,
            sha256=download.get("sha256") if isinstance(download.get("sha256"), str) else None,
            size_bytes=download.get("size_bytes") if isinstance(download.get("size_bytes"), int) else 0,
        )]

    @action("bulk_audit_issues", classification="write", capability="FindingSource", input_model=BulkAuditInput, idempotency="natural_key", stability="beta")
    async def plan_bulk_audit(self, args: BulkAuditInput) -> ActionPlan:
        self._require_write()
        ids = sorted(set(args.vulnerability_ids), key=int)
        states = await self._read_states(args.release_id, ids)
        body: dict[str, Any] = {"vulnerabilityIds": ids}
        optional: dict[str, Any] = {
            "userId": args.user_id,
            "developerStatus": args.developer_status,
            "auditorStatus": args.auditor_status,
            "severity": args.severity,
            "comment": args.comment,
            "attributes": args.attributes,
        }
        body.update({name: value for name, value in optional.items() if value is not None})
        desired = _desired_status(body)
        status_diff: dict[str, dict[str, dict[str, Any]]] = {}
        for vuln_id, record in states.items():
            changes = {field: {"from": record[field], "to": wanted} for field, wanted in desired.items() if record[field] != wanted}
            if changes:
                status_diff[vuln_id] = changes
        unverified = [name for name in _UNVERIFIED_BODY_FIELDS if name in body]
        return ActionPlan(
            action="bulk_audit_issues",
            target_ref=f"fortify_fod:release:{args.release_id}",
            diff={"status": status_diff, "unverified_fields": unverified},
            preconditions={"release_id": args.release_id, "vulnerability_ids": ids, "state_sha256": _sha256_json(states)},
            idempotency_key="bulk_audit:" + _sha256_json({"release_id": args.release_id, "body": body}),
            changed=bool(status_diff) or bool(unverified),
            request={"method": "POST", "path": _BULK_EDIT_PATH.format(release_id=args.release_id), "params": {}, "json": body},
        )

    @plan_bulk_audit.apply
    async def apply_bulk_audit(self, plan: ActionPlan) -> ActionOutcome:
        if not plan.changed:
            return ActionOutcome(status="no_op", vendor_ref=plan.target_ref)
        release_id: str = plan.preconditions["release_id"]
        ids: list[str] = plan.preconditions["vulnerability_ids"]
        current = await self._read_states(release_id, ids)
        if _sha256_json(current) != plan.preconditions["state_sha256"]:
            raise StalePlan(f"release {release_id} vulnerability state changed after planning")
        try:
            result = await self.http.request("POST", plan.request["path"], params=plan.request["params"], json=plan.request["json"], idempotency="non_idempotent", expected=(200,))
            codes = _bulk_edit_error_codes(result.json())
        except (OutcomeUnknown, TransientVendorError, RateLimited, VendorContractError) as exc:
            return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))
        if codes is None or len(codes) != len(ids):
            return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error="bulk-edit response did not contain one integer errorCode per vulnerability")
        item_results = [{"vulnerability_id": vuln_id, "errorCode": code} for vuln_id, code in zip(ids, codes, strict=True)]
        failed = [code for code in codes if code != 0]
        if failed:
            return ActionOutcome(status="failed", vendor_ref=plan.target_ref, error=f"{len(failed)} bulk-edit entries failed with errorCode {sorted(set(failed))}", result={"item_results": item_results})
        try:
            readback = await self._read_states(release_id, ids)
        except (OutcomeUnknown, TransientVendorError, RateLimited, VendorContractError) as exc:
            return ActionOutcome(
                status="outcome_unknown",
                vendor_ref=plan.target_ref,
                error=str(exc),
                result={"item_results": item_results},
            )
        mismatches = _status_mismatches(readback, _desired_status(plan.request["json"]))
        if mismatches:
            return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=f"bulk-edit reported success but state differs: {', '.join(mismatches)}")
        return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref, result={"entries": len(codes), "item_results": item_results, "unverified_fields": plan.diff["unverified_fields"]})

    @plan_bulk_audit.reconcile
    async def reconcile_bulk_audit(self, plan: ActionPlan, outcome: ActionOutcome) -> ActionOutcome:
        states = await self._read_states(plan.preconditions["release_id"], plan.preconditions["vulnerability_ids"])
        mismatches = _status_mismatches(states, _desired_status(plan.request["json"]))
        if mismatches:
            return ActionOutcome(status="failed", vendor_ref=plan.target_ref, error=f"status not applied: {', '.join(mismatches)}")
        return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref, result={"reconciled": True, "unverified_fields": plan.diff["unverified_fields"]})

    def _payload(self, encoded: str, expected_sha256: str) -> bytes:
        try:
            payload = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise VendorContractError("payload_base64 is not valid base64") from exc
        if len(payload) > self._config().max_payload_bytes:
            raise BudgetExhausted("payload exceeds max_payload_bytes")
        if hashlib.sha256(payload).hexdigest() != expected_sha256:
            raise VendorContractError("payload_sha256 does not match payload bytes")
        return payload

    async def _release_scans(self, release_id: str) -> list[dict[str, Any]]:
        return await self._collect(f"{_API}/releases/{release_id}/scans")

    def _conflicting_scan(self, scans: list[dict[str, Any]]) -> dict[str, Any] | None:
        for scan in scans:
            status = scan.get("analysisStatusType")
            if not isinstance(status, str):
                raise VendorContractError("scan analysisStatusType is required before scan start")
            if status not in _SCAN_TERMINAL_SUCCESS | _SCAN_TERMINAL_FAILED:
                return scan
        return None

    @action("start_scan", classification="write", capability="FindingSource", input_model=StartScanInput, idempotency="none")
    async def plan_start_scan(self, args: StartScanInput) -> ActionPlan:
        self._require_write()
        payload = self._payload(args.payload_base64, args.payload_sha256)
        assessments = await self._collect(f"{_API}/releases/{args.release_id}/assessment-types", params={"scanType": "Static"})
        if not any(record.get("assessmentTypeId") == args.assessment_type_id for record in assessments):
            raise StalePlan("assessment type is not available for this release")
        entitlements = await self._value(f"{_API}/tenant-entitlements")
        if not _contains_integer_id(entitlements, "entitlementId", args.entitlement_id):
            raise StalePlan("entitlement is not available to this tenant")
        scans = await self._release_scans(args.release_id)
        conflict = self._conflicting_scan(scans)
        if conflict is not None:
            raise StalePlan(f"scan {conflict.get('scanId')} is not terminal")
        params: dict[str, Any] = {
            "assessmentTypeId": args.assessment_type_id,
            "fragNo": 0,
            "offset": 0,
            "entitlementId": args.entitlement_id,
            "entitlementFrequencyType": args.entitlement_frequency_type,
            "technologyStack": args.profile.technology_stack,
            "languageLevel": args.profile.language_level,
            "auditPreferenceType": args.profile.audit_preference_type,
            "sastScanPolicy": args.profile.scan_policy,
        }
        params = {key: value for key, value in params.items() if value is not None}
        return ActionPlan(
            action="start_scan",
            target_ref=f"fortify_fod:release:{args.release_id}",
            diff={"start_scan": {"assessmentTypeId": args.assessment_type_id, "entitlementId": args.entitlement_id, "payload_sha256": args.payload_sha256, "billable_acknowledged": True}},
            preconditions={"release_id": args.release_id, "previous_scan_ids": sorted(_int_required(scan, "scanId") for scan in scans), "payload_sha256": args.payload_sha256, "bytes": len(payload)},
            idempotency_key=f"start_scan:{args.release_id}:{args.payload_sha256}:{args.assessment_type_id}",
            changed=True,
            request={"method": "POST", "path": f"{_API}/releases/{args.release_id}/static-scans/start-scan", "params": params, "content_base64": args.payload_base64},
        )

    @plan_start_scan.apply
    async def apply_start_scan(self, plan: ActionPlan) -> ActionOutcome:
        release_id = plan.preconditions["release_id"]
        scans = await self._release_scans(release_id)
        conflict = self._conflicting_scan(scans)
        if conflict is not None:
            raise StalePlan(f"scan {conflict.get('scanId')} became active after planning")
        scan_id: int | None = None
        try:
            result = await self.http.request("POST", plan.request["path"], params=plan.request["params"], content=base64.b64decode(plan.request["content_base64"], validate=True), idempotency="non_idempotent", expected=(200, 202))
            if result.status == 200:
                body = _json_object(result)
                candidate = body.get("scanId")
                if isinstance(candidate, int) and not isinstance(candidate, bool):
                    scan_id = candidate
        except (OutcomeUnknown, TransientVendorError, RateLimited, VendorContractError) as exc:
            return ActionOutcome(
                status="outcome_unknown",
                vendor_ref=plan.target_ref,
                error=str(exc),
                result={"scan_id": scan_id, "previous_scan_ids": plan.preconditions["previous_scan_ids"]},
            )
        prior = ActionOutcome(status="accepted_async", vendor_ref=plan.target_ref, result={"scan_id": scan_id, "previous_scan_ids": plan.preconditions["previous_scan_ids"]})
        return await self._settle(plan, prior, self.reconcile_start_scan)

    async def _reconcile_scan(
        self, plan: ActionPlan, outcome: ActionOutcome
    ) -> ActionOutcome:
        release_id = plan.preconditions["release_id"]
        result = dict(outcome.result or {})
        scan_id = result.get("scan_id")
        if not isinstance(scan_id, int) or isinstance(scan_id, bool):
            previous = set(result.get("previous_scan_ids") or plan.preconditions["previous_scan_ids"])
            scans = await self._release_scans(release_id)
            new_ids = sorted(_int_required(scan, "scanId") for scan in scans if _int_required(scan, "scanId") not in previous)
            if len(new_ids) > 1:
                return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=f"multiple new scans cannot be reconciled: {new_ids}")
            if not new_ids:
                return ActionOutcome(status="accepted_async", vendor_ref=plan.target_ref, result=result)
            scan_id = new_ids[0]
            result["scan_id"] = scan_id
        scan = await self._object(f"{_API}/releases/{release_id}/scans/{scan_id}")
        status = scan.get("analysisStatusType")
        if not isinstance(status, str):
            raise VendorContractError("scan read-back is missing analysisStatusType")
        result["status"] = status
        if status in _SCAN_TERMINAL_SUCCESS:
            return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref, result=result)
        if status in _SCAN_TERMINAL_FAILED:
            return ActionOutcome(status="failed", vendor_ref=plan.target_ref, error=f"scan {scan_id} ended in {status}", result=result)
        return ActionOutcome(status="accepted_async", vendor_ref=plan.target_ref, result=result)

    @plan_start_scan.reconcile
    async def reconcile_start_scan(self, plan: ActionPlan, outcome: ActionOutcome) -> ActionOutcome:
        return await self._reconcile_scan(plan, outcome)

    @action("import_scan", classification="write", capability="FindingSource", input_model=ImportScanInput, idempotency="natural_key")
    async def plan_import_scan(self, args: ImportScanInput) -> ActionPlan:
        self._require_write()
        payload = self._payload(args.payload_base64, args.payload_sha256)
        session = await self._object(f"{_API}/releases/{args.release_id}/import-scan-session-id")
        session_id = _str_required(session, "importScanSessionId")
        scans = await self._release_scans(args.release_id)
        return ActionPlan(
            action="import_scan",
            target_ref=f"fortify_fod:release:{args.release_id}",
            diff={"import_scan": {"payload_sha256": args.payload_sha256, "bytes": len(payload)}},
            preconditions={"release_id": args.release_id, "previous_scan_ids": sorted(_int_required(scan, "scanId") for scan in scans), "payload_sha256": args.payload_sha256, "import_scan_session_id": session_id},
            idempotency_key=f"import_scan:{args.release_id}:{args.payload_sha256}",
            changed=True,
            request={"method": "PUT", "path": f"{_API}/releases/{args.release_id}/static-scans/import-scan", "params": {"fragNo": 0, "offset": 0, "fileLength": len(payload), "importScanSessionId": session_id}, "content_base64": args.payload_base64},
        )

    @plan_import_scan.apply
    async def apply_import_scan(self, plan: ActionPlan) -> ActionOutcome:
        result_data: dict[str, Any] = {"previous_scan_ids": plan.preconditions["previous_scan_ids"], "import_scan_session_id": plan.preconditions["import_scan_session_id"]}
        try:
            result = await self.http.request("PUT", plan.request["path"], params=plan.request["params"], content=base64.b64decode(plan.request["content_base64"], validate=True), idempotency="non_idempotent", expected=(200, 202))
            body = _json_object(result) if result.status == 200 and result.content else {}
        except (OutcomeUnknown, TransientVendorError, RateLimited, VendorContractError) as exc:
            return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc), result=result_data)
        if isinstance(body.get("scanId"), int) and not isinstance(body.get("scanId"), bool):
            result_data["scan_id"] = body["scanId"]
        if isinstance(body.get("referenceId"), str):
            result_data["reference_id"] = body["referenceId"]
        prior = ActionOutcome(status="accepted_async", vendor_ref=plan.target_ref, result=result_data)
        return await self._settle(plan, prior, self.reconcile_import_scan)

    @plan_import_scan.reconcile
    async def reconcile_import_scan(self, plan: ActionPlan, outcome: ActionOutcome) -> ActionOutcome:
        return await self._reconcile_scan(plan, outcome)

    async def _report_matches(self, body: dict[str, Any]) -> list[dict[str, Any]]:
        reports = await self._collect(f"{_API}/reports")
        return [
            report
            for report in reports
            if report.get("applicationId") == body["applicationId"]
            and report.get("releaseId") == body["releaseId"]
            and report.get("reportName") == body["reportName"]
        ]

    @action("create_report", classification="write", capability="FindingSource", input_model=CreateReportInput, idempotency="natural_key")
    async def plan_create_report(self, args: CreateReportInput) -> ActionPlan:
        self._require_write()
        body: dict[str, Any] = {
            "applicationId": int(args.application_id),
            "releaseId": int(args.release_id),
            "reportTemplateTypeId": args.report_template_type_id,
            "reportName": args.report_name,
            "reportFormat": args.report_format,
            "notes": args.notes,
        }
        matches = await self._report_matches(body)
        if len(matches) > 1:
            raise StalePlan("multiple existing reports match the request fingerprint")
        existing_id = matches[0].get("reportId") if matches else None
        return ActionPlan(
            action="create_report",
            target_ref=f"fortify_fod:release:{args.release_id}:report:{_sha256_json(body)}",
            diff={"report": {"name": args.report_name, "format": args.report_format, "existing_report_id": existing_id}},
            preconditions={"release_id": args.release_id, "request_sha256": _sha256_json(body), "existing_report_id": existing_id},
            idempotency_key=f"create_report:{_sha256_json(body)}",
            changed=existing_id is None,
            request={"method": "POST", "path": f"{_API}/reports", "json": body},
        )

    @plan_create_report.apply
    async def apply_create_report(self, plan: ActionPlan) -> ActionOutcome:
        report_id = plan.preconditions["existing_report_id"]
        if report_id is None:
            try:
                result = await self.http.request("POST", plan.request["path"], json=plan.request["json"], idempotency="non_idempotent", expected=(200,))
                body = _json_object(result)
            except (OutcomeUnknown, TransientVendorError, RateLimited, VendorContractError) as exc:
                return ActionOutcome(
                    status="outcome_unknown",
                    vendor_ref=plan.target_ref,
                    error=str(exc),
                    result={"report_id": report_id},
                )
            if body.get("success") is not True:
                return ActionOutcome(status="failed", vendor_ref=plan.target_ref, error="report creation was rejected", result={"errors": body.get("errors")})
            report_id = body.get("reportId")
            if not isinstance(report_id, int) or isinstance(report_id, bool):
                return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error="report response carried no reportId", result={"report_id": None})
        prior = ActionOutcome(status="accepted_async", vendor_ref=plan.target_ref, result={"report_id": report_id})
        return await self._settle(plan, prior, self.reconcile_create_report)

    @plan_create_report.reconcile
    async def reconcile_create_report(self, plan: ActionPlan, outcome: ActionOutcome) -> ActionOutcome:
        report_id = outcome.result.get("report_id") if outcome.result else plan.preconditions["existing_report_id"]
        if not isinstance(report_id, int) or isinstance(report_id, bool):
            matches = await self._report_matches(plan.request["json"])
            if len(matches) > 1:
                return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error="multiple reports match the request fingerprint")
            if not matches:
                return ActionOutcome(status="accepted_async", vendor_ref=plan.target_ref, result={"report_id": None})
            report_id = matches[0].get("reportId")
            if not isinstance(report_id, int) or isinstance(report_id, bool):
                return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error="matching report has no integer reportId")
        report = await self._object(f"{_API}/reports/{report_id}")
        status = report.get("reportStatusType")
        if status in _REPORT_FAILED:
            return ActionOutcome(status="failed", vendor_ref=plan.target_ref, error=f"report ended in {status}", result={"report_id": report_id})
        if report.get("isReceived") is not True and status not in {"Completed", "Complete", "Succeeded"}:
            return ActionOutcome(status="accepted_async", vendor_ref=plan.target_ref, result={"report_id": report_id, "status": status})
        downloaded = await self._download_result(f"{_API}/reports/{report_id}/download")
        if downloaded.status == 202:
            return ActionOutcome(status="accepted_async", vendor_ref=plan.target_ref, result={"report_id": report_id, "status": "RepositoryUpdating"})
        return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref, result={"report_id": report_id, "sha256": hashlib.sha256(downloaded.content).hexdigest(), "size_bytes": len(downloaded.content)})

    @action("cancel_scan", classification="destructive", capability="FindingSource", input_model=CancelScanInput, idempotency="none")
    async def plan_cancel_scan(self, args: CancelScanInput) -> ActionPlan:
        self._require_destructive()
        scan = await self._object(f"{_API}/releases/{args.release_id}/scans/{args.scan_id}")
        status = scan.get("analysisStatusType")
        if not isinstance(status, str):
            raise VendorContractError("scan analysisStatusType is required before cancellation")
        return ActionPlan(
            action="cancel_scan",
            target_ref=f"fortify_fod:release:{args.release_id}:scan:{args.scan_id}",
            diff={"cancel_scan": {"scan_id": int(args.scan_id), "from": status}},
            preconditions={"release_id": args.release_id, "scan_id": int(args.scan_id), "approval_ref": args.approval_ref, "initial_status": status},
            idempotency_key=f"cancel_scan:{args.release_id}:{args.scan_id}:{args.approval_ref}",
            changed=status not in _SCAN_TERMINAL_SUCCESS | _SCAN_TERMINAL_FAILED,
            request={"method": "POST", "path": f"{_API}/releases/{args.release_id}/scans/{args.scan_id}/cancel-scan"},
        )

    @plan_cancel_scan.apply
    async def apply_cancel_scan(self, plan: ActionPlan) -> ActionOutcome:
        if not plan.changed:
            return ActionOutcome(status="no_op", vendor_ref=plan.target_ref, result={"scan_id": plan.preconditions["scan_id"]})
        scan = await self._object(f"{_API}/releases/{plan.preconditions['release_id']}/scans/{plan.preconditions['scan_id']}")
        status = scan.get("analysisStatusType")
        if status in _SCAN_TERMINAL_SUCCESS | _SCAN_TERMINAL_FAILED:
            return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref, result={"scan_id": plan.preconditions["scan_id"], "status": status})
        try:
            result = await self.http.request("POST", plan.request["path"], idempotency="non_idempotent", expected=(202,))
            body = _json_object(result)
        except (OutcomeUnknown, TransientVendorError, RateLimited, VendorContractError) as exc:
            return ActionOutcome(
                status="outcome_unknown",
                vendor_ref=plan.target_ref,
                error=str(exc),
                result={"scan_id": plan.preconditions["scan_id"]},
            )
        if body.get("success") is not True:
            return ActionOutcome(status="failed", vendor_ref=plan.target_ref, error=str(body.get("message") or "scan cancellation was rejected"))
        prior = ActionOutcome(status="accepted_async", vendor_ref=plan.target_ref, result={"scan_id": plan.preconditions["scan_id"], "previous_scan_ids": []})
        return await self._settle(plan, prior, self.reconcile_cancel_scan)

    @plan_cancel_scan.reconcile
    async def reconcile_cancel_scan(self, plan: ActionPlan, outcome: ActionOutcome) -> ActionOutcome:
        scan = await self._object(f"{_API}/releases/{plan.preconditions['release_id']}/scans/{plan.preconditions['scan_id']}")
        status = scan.get("analysisStatusType")
        if status in {"Canceled", "Cancelled"}:
            return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref, result={"scan_id": plan.preconditions["scan_id"], "status": status})
        if status in _SCAN_TERMINAL_FAILED:
            return ActionOutcome(status="failed", vendor_ref=plan.target_ref, error=f"scan ended in {status} rather than cancellation")
        if status in _SCAN_TERMINAL_SUCCESS:
            return ActionOutcome(status="failed", vendor_ref=plan.target_ref, error="scan completed before cancellation")
        return ActionOutcome(status="accepted_async", vendor_ref=plan.target_ref, result={"scan_id": plan.preconditions["scan_id"], "status": status})

    @action("delete_release_application_report", classification="destructive", capability="FindingSource", input_model=DeleteResourceInput, idempotency="none")
    async def plan_delete_resource(self, args: DeleteResourceInput) -> ActionPlan:
        self._require_destructive()
        paths = {"release": f"{_API}/releases/{args.resource_id}", "application": f"{_API}/applications/{args.resource_id}", "report": f"{_API}/reports/{args.resource_id}"}
        path = paths[args.resource_type]
        await self._object(path)
        return ActionPlan(
            action="delete_release_application_report",
            target_ref=f"fortify_fod:{args.resource_type}:{args.resource_id}",
            diff={"delete": {"resource_type": args.resource_type, "resource_id": int(args.resource_id)}},
            preconditions={"resource_type": args.resource_type, "resource_id": args.resource_id, "approval_ref": args.approval_ref, "path": path},
            idempotency_key=f"delete:{args.resource_type}:{args.resource_id}:{args.approval_ref}",
            changed=True,
            request={"method": "DELETE", "path": path},
        )

    @plan_delete_resource.apply
    async def apply_delete_resource(self, plan: ActionPlan) -> ActionOutcome:
        try:
            await self.http.request("DELETE", plan.request["path"], idempotency="non_idempotent", expected=(200, 202, 204))
        except (OutcomeUnknown, TransientVendorError, RateLimited, VendorContractError) as exc:
            return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))
        prior = ActionOutcome(status="accepted_async", vendor_ref=plan.target_ref)
        return await self._settle(plan, prior, self.reconcile_delete_resource)

    @plan_delete_resource.reconcile
    async def reconcile_delete_resource(self, plan: ActionPlan, outcome: ActionOutcome) -> ActionOutcome:
        try:
            await self._object(plan.request["path"])
        except NotFound:
            return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref, result={"deleted": True})
        return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error="resource is still present after deletion")
