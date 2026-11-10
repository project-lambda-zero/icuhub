"""Invicti Enterprise REST API 1.0 connector with canonical sync and governed triage."""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any, ClassVar
from urllib.parse import urlencode

from icuhub.connectors._invicti import (
    InvictiProof,
    InvictiReport,
    InvictiScanResult,
    InvictiWebsite,
    map_issue_to_finding,
    map_report_to_findings,
    map_scan_result_to_finding,
    parse_issue,
    parse_report,
    parse_scan,
    sanitize_proof,
)
from icuhub.connectors.invicti_enterprise.models import (
    DownloadReportArgs,
    EmptyArgs,
    InvictiEnterpriseConfig,
    IssueArgs,
    IssueHistoryOutput,
    IssueListOutput,
    IssueOutput,
    ListIssuesArgs,
    ListScansArgs,
    NotificationListOutput,
    NotificationView,
    ReportOutput,
    ScanArgs,
    ScanListOutput,
    ScanResultOutput,
    ScanViewOutput,
    UpdateIssueInput,
    WebsiteArgs,
    WebsiteOutput,
)
from icuhub.kit.auth import AuthStrategy, BasicAuth
from icuhub.kit.connector import Connector, action, importer, mapper, operation, stream, webhook
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
from icuhub.kit.http import HttpResult
from icuhub.kit.types import (
    ActionOutcome,
    ActionPlan,
    CapabilityHealth,
    HealthReport,
    ImportedFile,
    MapContext,
    RawBatch,
    SourceRecord,
    StreamRecord,
    Target,
    TargetRecord,
    WebhookDelivery,
)
from icuhub.kit.webhook import BasicAuthVerifier, SharedToken, WebhookVerifier

__all__ = ["InvictiEnterprise"]

_CAPABILITY = "FindingSource"


def _timestamp(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.isoformat().replace("+00:00", "Z")


def _parse_time(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise VendorContractError(f"{field} must be an ISO timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise VendorContractError(f"{field} must be an ISO timestamp") from exc
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed


class InvictiEnterprise(Connector):
    kind: ClassVar[str] = "invicti_enterprise"
    version: ClassVar[str] = "0.1.0"
    display_name: ClassVar[str] = "Invicti Enterprise"
    config_model: ClassVar[type[InvictiEnterpriseConfig]] = InvictiEnterpriseConfig
    auth_modes: ClassVar[tuple[str, ...]] = ("BasicAuth",)
    capabilities: ClassVar[tuple[str, ...]] = (_CAPABILITY,)
    flows: ClassVar[tuple[str, ...]] = ("F-123", "F-218")

    def _config(self) -> InvictiEnterpriseConfig:
        if not isinstance(self.config, InvictiEnterpriseConfig):
            raise ConfigError("invicti_enterprise requires InvictiEnterpriseConfig")
        return self.config

    async def build_auth(self) -> AuthStrategy:
        token = await self.ctx.secrets.resolve(self._config().api_token)
        try:
            password = token.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ConfigError("Invicti API token must be UTF-8") from exc
        return BasicAuth(self._config().user_id, password)

    async def _request(self, method: str, path: str, **kwargs: Any) -> HttpResult:
        return await self.http.request(method, path, **kwargs)

    def _json(self, result: HttpResult) -> Any:
        try:
            return json.loads(result.content)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise VendorContractError("Invicti response must be UTF-8 JSON") from exc

    def _object(self, result: HttpResult) -> dict[str, Any]:
        value = self._json(result)
        if not isinstance(value, dict):
            raise VendorContractError("Invicti response must be an object")
        return value

    def _page(self, body: dict[str, Any], page_size: int | None = None) -> tuple[list[dict[str, Any]], bool]:
        values = body.get("List")
        if not isinstance(values, list) or not all(isinstance(item, dict) for item in values):
            raise VendorContractError("Invicti page List must be an array of objects")
        if "HasNextPage" in body:
            has_next = body["HasNextPage"]
            if not isinstance(has_next, bool):
                raise VendorContractError("HasNextPage must be boolean")
        else:
            has_next = len(values) == (page_size or self._config().page_size) and body.get("IsLastPage") is not True
        if not values and has_next:
            raise VendorContractError("Invicti returned an empty page with HasNextPage=true")
        return values, has_next

    async def _paged(self, path: str, params: dict[str, Any], *, pool: str) -> AsyncIterator[list[dict[str, Any]]]:
        page = 1
        while True:
            result = await self._request(
                "GET",
                path,
                params={**params, "page": page, "pageSize": self._config().page_size},
                pool=pool,
            )
            values, has_next = self._page(self._object(result))
            yield values
            if not has_next:
                return
            page += 1

    def _advance(self, cursor: TimeIdCursor, page: list[dict[str, Any]], ts_of: Any, id_of: Any) -> TimeIdCursor:
        advanced = cursor.advance(page, ts_of=ts_of, id_of=id_of)
        if len(advanced.last_ids_at_ts) > self._config().max_tie_ids:
            # Replaying ties is safe; dropping them from suppression bounds memory without losing findings.
            return advanced.model_copy(update={"last_ids_at_ts": []})
        return advanced

    async def check(self) -> HealthReport:
        try:
            await self._request(
                "GET",
                "/issues/allissues",
                params={"page": 1, "pageSize": 1},
                pool="invicti-issues",
            )
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
        return HealthReport(
            status="healthy",
            capabilities={_CAPABILITY: CapabilityHealth(status="healthy")},
            detail={"api_version": "1.0", "manage_issue": "not_evaluated"},
        )

    def webhook_verifier(self, secret: bytes) -> WebhookVerifier | None:
        try:
            text = secret.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ConfigError("Invicti webhook credentials must be UTF-8") from exc
        if self._config().webhook_mode == "static_header":
            if len(text) < 16:
                raise ConfigError("Invicti static webhook token must contain at least 16 characters")
            return SharedToken(self._config().webhook_header, text)
        user, separator, password = text.partition(":")
        if not separator or not user or not password:
            raise ConfigError("Invicti Basic webhook secret must be username:password")
        return BasicAuthVerifier(user, password)

    async def discover(self) -> AsyncIterator[TargetRecord]:
        async for page in self._paged("/scans/list", {}, pool="invicti-default"):
            for raw in page:
                scan = parse_scan(raw)
                if not scan.completed:
                    continue
                yield TargetRecord(
                    source_uid=scan.id,
                    kind="invicti_scan",
                    display_name=f"Invicti scan {scan.id}",
                    attributes={
                        "website_id": scan.website.id,
                        "website_root_url": scan.website.root_url,
                        "state_changed": _timestamp(scan.state_changed),
                    },
                )

    @stream("issues", ocsf_class=2002, cursor=TimeIdCursor, modes=("incremental", "full"), capability=_CAPABILITY, requires_target=False)
    async def issues(self, target: Target | None, checkpoint: TimeIdCursor | None, mode: str) -> AsyncIterator[RawBatch]:
        cursor = checkpoint or TimeIdCursor(ts=None, overlap_s=self._config().overlap_s)
        since = cursor.window_start() if mode == "incremental" else None
        params: dict[str, Any] = {"sort": "LastSeenDate", "direction": "asc"}
        if since is not None:
            params["lastSeenDate"] = _timestamp(since)
        async for page in self._paged("/issues/allissues", params, pool="invicti-issues"):
            cursor = self._advance(cursor, page, ts_of=lambda raw: _parse_time(raw.get("LastSeenDate"), "LastSeenDate"), id_of=lambda raw: str(raw.get("Id")))
            yield RawBatch(records=page, checkpoint=cursor, complete=False)
        if mode == "full":
            yield RawBatch(records=[], checkpoint=cursor, complete=True)

    @mapper("issues", version=1)
    def map_issue(self, raw: dict[str, Any], ctx: MapContext) -> list[Any]:
        return [map_issue_to_finding(parse_issue(raw), ctx)]

    @stream("scans", record_type="invicti_scan", cursor=TimeIdCursor, modes=("incremental", "full"), capability=_CAPABILITY, requires_target=False)
    async def scans(self, target: Target | None, checkpoint: TimeIdCursor | None, mode: str) -> AsyncIterator[RawBatch]:
        cursor = checkpoint or TimeIdCursor(ts=None, overlap_s=self._config().overlap_s)
        params: dict[str, Any] = {}
        path = "/scans/list"
        if mode == "incremental" and cursor.ts is not None:
            path = "/scans/listbystatechanged"
            params = {"startDate": _timestamp(cursor.window_start()), "endDate": _timestamp(self.ctx.clock())}
        async for page in self._paged(path, params, pool="invicti-default"):
            cursor = self._advance(cursor, page, ts_of=lambda raw: _parse_time(raw.get("StateChanged"), "StateChanged"), id_of=lambda raw: str(raw.get("Id")))
            yield RawBatch(records=page, checkpoint=cursor, complete=False)
        if mode == "full":
            yield RawBatch(records=[], checkpoint=cursor, complete=True)

    @mapper("scans", version=1)
    def map_scan(self, raw: dict[str, Any], ctx: MapContext) -> list[SourceRecord]:
        scan = parse_scan(raw)
        return [SourceRecord(record_type="invicti_scan", uid=scan.id, revision=_timestamp(scan.state_changed), data=scan.model_dump(mode="json"))]

    async def _scan_result_records(self, target: Target) -> list[dict[str, Any]]:
        data = await self.http.stream_download(
            "GET", f"/scans/result/{target.source_uid}", max_bytes=self._config().max_report_bytes
        )
        try:
            body = json.loads(data)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise VendorContractError("scan result must be UTF-8 JSON") from exc
        values = body.get("List") if isinstance(body, dict) else body
        if not isinstance(values, list) or not all(isinstance(item, dict) for item in values):
            raise VendorContractError("scan result must be an array of issue objects")
        website_id = target.attributes.get("website_id")
        root = target.attributes.get("website_root_url")
        return [
            {
                "scan_id": target.source_uid,
                "website_id": website_id if isinstance(website_id, str) else None,
                "website_root_url": root if isinstance(root, str) else None,
                "issue": raw,
            }
            for raw in values
        ]

    @stream("scan_results", ocsf_class=2002, cursor=SnapshotCursor, modes=("full",), capability=_CAPABILITY, requires_target=True)
    async def scan_results(self, target: Target | None, checkpoint: SnapshotCursor | None, mode: str) -> AsyncIterator[RawBatch]:
        if target is None or target.kind != "invicti_scan":
            raise ConfigError("scan_results requires a discovered Invicti scan target")
        records = await self._scan_result_records(target)
        cursor = SnapshotCursor(
            snapshot_id=f"scan-result:{target.source_uid}", started_at=self.ctx.clock(), targets_done=[target.source_uid]
        )
        yield RawBatch(records=records, checkpoint=cursor, complete=True)

    @mapper("scan_results", version=1)
    def map_scan_result(self, raw: dict[str, Any], ctx: MapContext) -> list[Any]:
        if set(raw) != {"scan_id", "website_id", "website_root_url", "issue"}:
            raise VendorContractError("invalid Invicti scan-result envelope")
        issue = parse_issue(
            raw["issue"], website_id=raw["website_id"], website_root_url=raw["website_root_url"], scan_id=raw["scan_id"]
        )
        result = InvictiScanResult(scan_id=raw["scan_id"], issue_url=raw["issue"].get("IssueUrl"), issue=issue)
        return [map_scan_result_to_finding(result, ctx)]

    async def _download_report(self, args: DownloadReportArgs, target: Target | None = None) -> InvictiReport:
        query = urlencode({"scanId": args.scan_id, "reportType": args.report_type})
        data = await self.http.stream_download(
            "GET", f"/scans/report?{query}", max_bytes=self._config().max_report_bytes
        )
        attributes = target.attributes if target is not None else {}
        website_id = attributes.get("website_id")
        return parse_report(
            data,
            max_bytes=self._config().max_report_bytes,
            website_id=website_id if isinstance(website_id, str) else None,
        )

    @stream("report_issues", ocsf_class=2002, cursor=SnapshotCursor, modes=("full", "replay"), capability=_CAPABILITY, requires_target=True)
    async def report_issues(self, target: Target | None, checkpoint: SnapshotCursor | None, mode: str) -> AsyncIterator[RawBatch]:
        if target is None or target.kind != "invicti_scan":
            raise ConfigError("report_issues requires a discovered Invicti scan target")
        report = await self._download_report(DownloadReportArgs(scan_id=target.source_uid), target)
        cursor = SnapshotCursor(
            snapshot_id=report.snapshot.snapshot_id, started_at=self.ctx.clock(), targets_done=[target.source_uid]
        )
        yield RawBatch(records=[{"report": report.model_dump(mode="json")}], checkpoint=cursor, complete=True)

    @mapper("report_issues", version=1)
    def map_report_issue(self, raw: dict[str, Any], ctx: MapContext) -> list[Any]:
        if set(raw) != {"report"}:
            raise VendorContractError("invalid Invicti report envelope")
        return map_report_to_findings(InvictiReport.model_validate(raw["report"]), ctx)

    @importer("invicti_json", stream="report_issues", media_types=("application/json",), extensions=(".json",))
    async def import_json(self, imported: ImportedFile) -> AsyncIterator[dict[str, Any]]:
        report = parse_report(imported.data, max_bytes=self._config().max_report_bytes)
        yield {"report": report.model_dump(mode="json")}

    @stream("webhook_receipts", record_type="invicti_webhook_receipt", cursor=SequenceCursor, modes=("event",), capability=_CAPABILITY, requires_target=False)
    async def webhook_receipts(self, target: Target | None, checkpoint: SequenceCursor | None, mode: str) -> AsyncIterator[RawBatch]:
        raise ConfigError("webhook_receipts is receiver-driven")
        yield RawBatch(records=[], checkpoint=checkpoint, complete=False)

    @mapper("webhook_receipts", version=1)
    def map_webhook_receipt(self, raw: dict[str, Any], ctx: MapContext) -> list[SourceRecord]:
        delivery_id = raw.get("delivery_id")
        if not isinstance(delivery_id, str):
            raise VendorContractError("webhook receipt delivery_id is required")
        return [
            SourceRecord(
                record_type="invicti_webhook_receipt",
                uid=delivery_id,
                revision=str(raw["configuration_revision"]),
                data={key: value for key, value in raw.items() if key != "raw_body_base64"},
            )
        ]

    @webhook(event_types=("issue", "issue_export", "vulnerability", "*"))
    def receive_event(self, delivery: WebhookDelivery) -> list[StreamRecord]:
        if len(delivery.body) > self._config().max_report_bytes:
            raise VendorContractError("webhook body exceeds configured byte limit")
        body_digest = hashlib.sha256(delivery.body).hexdigest()
        try:
            value = json.loads(delivery.body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise VendorContractError("Invicti webhook body must be JSON") from exc
        if not isinstance(value, dict):
            raise VendorContractError("Invicti webhook body must be an object")
        if "Vulnerabilities" in value:
            report = parse_report(delivery.body, max_bytes=self._config().max_report_bytes)
            issues = report.vulnerabilities
        else:
            issues = [parse_issue(value)]
        issue_ids = ",".join(sorted(issue.id for issue in issues))
        timestamps = [issue.last_seen for issue in issues if issue.last_seen is not None]
        updated = _timestamp(max(timestamps)) if timestamps else None
        integration = self._config().webhook_integration_id
        dedupe = hashlib.sha256(
            f"{issue_ids}\n{updated or ''}\n{integration}\n{body_digest}".encode()
        ).hexdigest()
        receipt = {
            "delivery_id": dedupe,
            "body_sha256": body_digest,
            "issue_ids": [issue.id for issue in issues],
            "updated": updated,
            "integration_id": integration,
            "configuration_revision": self._config().webhook_configuration_revision,
            "parser_version": "invicti-enterprise-webhook-json/1",
            "raw_body_base64": base64.b64encode(delivery.body).decode("ascii"),
        }
        return [
            StreamRecord(stream="webhook_receipts", raw=receipt),
            StreamRecord(stream="issues", raw={"delivery_id": dedupe}, reconcile="full"),
        ]

    def _public_issue(self, issue: Any) -> tuple[Any, Any]:
        evidence = sanitize_proof(issue.proof)

        def content(artifact: Any) -> str | None:
            return artifact.content if artifact is not None else None

        proof = InvictiProof(
            attack_detail=content(evidence.attack_detail),
            http_request=content(evidence.http_request),
            http_response=content(evidence.http_response),
            proof_of_concept=content(evidence.proof_of_concept),
        )
        return issue.model_copy(update={"proof": proof}), evidence

    async def _raw_issue(self, issue_id: str) -> dict[str, Any]:
        result = await self._request("GET", f"/issues/{issue_id}")
        return self._object(result)

    @operation("list_issues", input_model=ListIssuesArgs, output_model=IssueListOutput, capability=_CAPABILITY)
    async def list_issues(self, args: ListIssuesArgs) -> IssueListOutput:
        params = {
            "page": args.page,
            "pageSize": args.page_size,
            "lastSeenDateStart": _timestamp(args.last_seen_start),
            "lastSeenDateEnd": _timestamp(args.last_seen_end),
            "websiteId": args.website_id,
            "severity": args.severity,
            "sourceType": args.source_type,
            "sort": "LastSeenDate",
            "direction": args.sort,
        }
        result = await self._request("GET", "/issues/allissues", params={k: v for k, v in params.items() if v is not None}, pool="invicti-issues")
        values, has_next = self._page(self._object(result), args.page_size)
        issues = [self._public_issue(parse_issue(raw))[0] for raw in values]
        return IssueListOutput(issues=issues, page=args.page, has_next=has_next)

    @operation("list_scans", input_model=ListScansArgs, output_model=ScanListOutput, capability=_CAPABILITY)
    async def list_scans(self, args: ListScansArgs) -> ScanListOutput:
        windowed = args.state_changed_start is not None
        params = {
            "page": args.page,
            "pageSize": args.page_size,
            "initiatedDateStart": _timestamp(args.initiated_start),
            "initiatedDateEnd": _timestamp(args.initiated_end),
            "startDate": _timestamp(args.state_changed_start),
            "endDate": _timestamp(args.state_changed_end),
        }
        result = await self._request(
            "GET", "/scans/listbystatechanged" if windowed else "/scans/list", params={k: v for k, v in params.items() if v is not None}
        )
        values, has_next = self._page(self._object(result), args.page_size)
        return ScanListOutput(scans=[parse_scan(raw) for raw in values], page=args.page, has_next=has_next)

    @operation("get_issue", input_model=IssueArgs, output_model=IssueOutput, capability=_CAPABILITY)
    async def get_issue(self, args: IssueArgs) -> IssueOutput:
        issue, evidence = self._public_issue(parse_issue(await self._raw_issue(args.issue_id)))
        return IssueOutput(issue=issue, evidence=evidence)

    @operation("get_issue_history", input_model=IssueArgs, output_model=IssueHistoryOutput, capability=_CAPABILITY)
    async def get_issue_history(self, args: IssueArgs) -> IssueHistoryOutput:
        body = self._json(await self._request("GET", f"/issues/{args.issue_id}/history"))
        values = body.get("List", body.get("History")) if isinstance(body, dict) else body
        if not isinstance(values, list) or len(values) > 1000 or not all(isinstance(item, dict) for item in values):
            raise VendorContractError("issue history must be a bounded array of objects")
        return IssueHistoryOutput(history=values)

    @operation("get_website", input_model=WebsiteArgs, output_model=WebsiteOutput, capability=_CAPABILITY)
    async def get_website(self, args: WebsiteArgs) -> WebsiteOutput:
        body = self._object(await self._request("GET", f"/websites/{args.website_id}"))
        groups = body.get("Groups", [])
        if not isinstance(groups, list):
            raise VendorContractError("website Groups must be an array")
        names = [str(item.get("Name")) if isinstance(item, dict) else str(item) for item in groups]
        website = InvictiWebsite(
            id=str(body.get("Id", args.website_id)),
            name=body.get("Name") if isinstance(body.get("Name"), str) else None,
            root_url=(body.get("RootUrl") or body.get("Url")) if isinstance(body.get("RootUrl") or body.get("Url"), str) else None,
        )
        return WebsiteOutput(website=website, groups=names)

    @operation("get_scan", input_model=ScanArgs, output_model=ScanViewOutput, capability=_CAPABILITY)
    async def get_scan(self, args: ScanArgs) -> ScanViewOutput:
        return ScanViewOutput(scan=parse_scan(self._object(await self._request("GET", f"/scans/{args.scan_id}"))))

    @operation("get_scan_result", input_model=ScanArgs, output_model=ScanResultOutput, capability=_CAPABILITY)
    async def get_scan_result(self, args: ScanArgs) -> ScanResultOutput:
        target = Target(id=args.scan_id, source_uid=args.scan_id, kind="invicti_scan", display_name=args.scan_id, attributes={})
        records = await self._scan_result_records(target)
        results = [
            InvictiScanResult(
                scan_id=args.scan_id,
                issue_url=record["issue"].get("IssueUrl"),
                issue=self._public_issue(parse_issue(record["issue"], scan_id=args.scan_id))[0],
            )
            for record in records
        ]
        return ScanResultOutput(results=results)

    @operation("download_report", input_model=DownloadReportArgs, output_model=ReportOutput, capability=_CAPABILITY)
    async def download_report(self, args: DownloadReportArgs) -> ReportOutput:
        report = await self._download_report(args)
        public = []
        evidence = {}
        for issue in report.vulnerabilities:
            issue_public, issue_evidence = self._public_issue(issue)
            public.append(issue_public)
            evidence[issue.id] = issue_evidence
        return ReportOutput(report=report.model_copy(update={"vulnerabilities": public}), evidence=evidence)

    @operation("list_notifications", input_model=EmptyArgs, output_model=NotificationListOutput, capability=_CAPABILITY)
    async def list_notifications(self, args: EmptyArgs) -> NotificationListOutput:
        body = self._json(await self._request("GET", "/notifications"))
        values = body.get("List", body.get("Notifications")) if isinstance(body, dict) else body
        if not isinstance(values, list) or not all(isinstance(item, dict) for item in values):
            raise VendorContractError("notifications must be an array of objects")
        notifications = []
        for item in values:
            notification_id = item.get("Id", item.get("NotificationId"))
            if not isinstance(notification_id, str) or not notification_id:
                raise VendorContractError("notification Id is required")
            notifications.append(
                NotificationView(
                    id=notification_id,
                    name=item.get("Name") if isinstance(item.get("Name"), str) else None,
                    event=item.get("Event") if isinstance(item.get("Event"), str) else None,
                    scope=item.get("Scope") if isinstance(item.get("Scope"), str) else None,
                )
            )
        return NotificationListOutput(notifications=notifications)

    def _desired(self, args: UpdateIssueInput) -> dict[str, Any]:
        desired: dict[str, Any] = {}
        if args.state is not None:
            desired["State"] = args.state
        if args.assignee is not None:
            desired["Assignee"] = args.assignee
        if args.tags is not None:
            desired["Tags"] = args.tags
        return desired

    def _current(self, issue: Any) -> dict[str, Any]:
        return {"State": issue.state, "Assignee": issue.assignee, "Tags": issue.tags}

    def _assert_update_precondition(self, issue: Any, preconditions: dict[str, Any]) -> None:
        if issue.state != preconditions["state"] or _timestamp(issue.last_seen) != preconditions["last_seen"]:
            raise StalePlan("Invicti issue changed since the plan was made")

    @action("update_issue", classification="write", capability=_CAPABILITY, input_model=UpdateIssueInput, idempotency="natural_key")
    async def plan_update_issue(self, args: UpdateIssueInput) -> ActionPlan:
        issue = parse_issue(await self._raw_issue(args.issue_id))
        if issue.last_seen is None:
            raise StalePlan("Invicti issue has no LastSeenDate precondition")
        expected = {"state": args.expected_state, "last_seen": _timestamp(args.expected_last_seen)}
        self._assert_update_precondition(issue, expected)
        desired = self._desired(args)
        current = self._current(issue)
        changed = any(current.get(key) != value for key, value in desired.items())
        key = hashlib.sha256(
            f"{args.issue_id}\n{json.dumps(desired, sort_keys=True, separators=(',', ':'))}".encode()
        ).hexdigest()
        return ActionPlan(
            action="update_issue",
            target_ref=args.issue_id,
            diff={"before": current, "after": desired},
            preconditions=expected,
            idempotency_key=key,
            changed=changed,
            request={"issue_id": args.issue_id, "payload": desired},
        )

    @plan_update_issue.apply
    async def apply_update_issue(self, plan: ActionPlan) -> ActionOutcome:
        if not plan.changed:
            return ActionOutcome(status="no_op", vendor_ref=plan.target_ref)
        issue = parse_issue(await self._raw_issue(plan.request["issue_id"]))
        self._assert_update_precondition(issue, plan.preconditions)
        try:
            await self._request(
                "PUT",
                f"/issues/{plan.request['issue_id']}",
                json=plan.request["payload"],
                idempotency="non_idempotent",
                expected=(200, 204),
            )
        except (OutcomeUnknown, TransientVendorError):
            return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref)
        return await self.reconcile_update_issue(plan)

    @plan_update_issue.reconcile
    async def reconcile_update_issue(self, plan: ActionPlan) -> ActionOutcome:
        issue = parse_issue(await self._raw_issue(plan.request["issue_id"]))
        current = self._current(issue)
        if all(current.get(key) == value for key, value in plan.request["payload"].items()):
            public, _ = self._public_issue(issue)
            return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref, result={"issue": public.model_dump(mode="json")})
        return ActionOutcome(status="failed", vendor_ref=plan.target_ref, error="Invicti issue read-back does not match desired state")
