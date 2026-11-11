"""Invicti Standard local report and authenticated Send To Action ingestion."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any, ClassVar
from urllib.parse import urlsplit, urlunsplit

from icuhub.connectors._invicti import (
    InvictiReport,
    ReportSnapshot,
    map_report_to_findings,
    parse_issue,
    parse_report,
)
from icuhub.connectors.invicti_standard.models import InvictiStandardConfig, ParseReportArgs, ParseReportOutput
from icuhub.kit.connector import Connector, importer, mapper, operation, stream, webhook
from icuhub.kit.cursors import SequenceCursor, SnapshotCursor
from icuhub.kit.errors import ConfigError, VendorContractError
from icuhub.kit.types import (
    CapabilityHealth,
    HealthReport,
    ImportedFile,
    MapContext,
    RawBatch,
    StreamRecord,
    Target,
    WebhookDelivery,
)
from icuhub.kit.webhook import BasicAuthVerifier, SharedToken, WebhookVerifier

__all__ = ["InvictiStandard"]

_CAPABILITY = "FindingSource"


class _NoAuth:
    async def apply(self, request_headers: dict[str, str], method: str, url: str) -> None:
        return None

    async def refresh(self) -> bool:
        return False


def _decode_content(value: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ConfigError("content_base64 must be valid base64") from exc


class InvictiStandard(Connector):
    kind: ClassVar[str] = "invicti_standard"
    version: ClassVar[str] = "0.1.0"
    display_name: ClassVar[str] = "Invicti Standard"
    config_model: ClassVar[type[InvictiStandardConfig]] = InvictiStandardConfig
    uses_http: ClassVar[bool] = False
    auth_modes: ClassVar[tuple[str, ...]] = ()
    capabilities: ClassVar[tuple[str, ...]] = (_CAPABILITY,)
    flows: ClassVar[tuple[str, ...]] = ("F-218",)

    def _config(self) -> InvictiStandardConfig:
        if not isinstance(self.config, InvictiStandardConfig):
            raise ConfigError("invicti_standard requires InvictiStandardConfig")
        return self.config

    async def build_auth(self) -> _NoAuth:
        return _NoAuth()

    async def check(self) -> HealthReport:
        try:
            for filename in self._config().report_files:
                path = Path(filename)
                if path.stat().st_size > self._config().max_report_bytes:
                    raise OSError("report exceeds configured byte limit")
        except OSError as exc:
            return HealthReport(
                status="failing",
                capabilities={_CAPABILITY: CapabilityHealth(status="failing", reason=str(exc))},
            )
        return HealthReport(
            status="healthy",
            capabilities={_CAPABILITY: CapabilityHealth(status="healthy")},
            detail={"report_files": len(self._config().report_files), "remote_api": False},
        )

    def webhook_verifier(self, secret: bytes) -> WebhookVerifier | None:
        cfg = self._config()
        try:
            text = secret.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ConfigError("Invicti webhook credentials must be UTF-8") from exc
        if cfg.webhook_mode == "static_header":
            if len(text) < 16:
                raise ConfigError("Invicti static webhook token must contain at least 16 characters")
            return SharedToken(cfg.webhook_header, text)
        user, separator, password = text.partition(":")
        if not separator or not user or not password:
            raise ConfigError("Invicti Basic webhook secret must be username:password")
        return BasicAuthVerifier(user, password)

    def _parse(self, data: bytes, profile: str = "invicti_json") -> InvictiReport:
        cfg = self._config()
        kwargs = {
            "max_bytes": cfg.max_report_bytes,
            "website_id": cfg.website_id,
            "website_name": cfg.website_name,
        }
        if profile != "invicti_json":
            raise ConfigError(f"unsupported Invicti report profile {profile!r}")
        return parse_report(data, **kwargs)

    def _envelope(
        self,
        report: InvictiReport,
        *,
        raw_body: bytes | None = None,
        delivery_id: str | None = None,
    ) -> dict[str, Any]:
        result: dict[str, Any] = {"report": report.model_dump(mode="json")}
        if raw_body is not None:
            result["delivery"] = {
                "delivery_id": delivery_id,
                "parser_version": report.parser_version,
                "configuration_revision": self._config().webhook_configuration_revision,
                "raw_body_base64": base64.b64encode(raw_body).decode("ascii"),
            }
        return result

    def _load_report(self, filename: str) -> InvictiReport:
        path = Path(filename)
        try:
            size = path.stat().st_size
            if size > self._config().max_report_bytes:
                raise VendorContractError(f"report exceeds the {self._config().max_report_bytes} byte limit")
            data = path.read_bytes()
        except OSError as exc:
            raise VendorContractError(f"cannot read local Invicti report {path.name!r}") from exc
        return self._parse(data, "invicti_json")

    @stream(
        "report_issues",
        ocsf_class=2002,
        cursor=SnapshotCursor,
        modes=("full", "replay"),
        capability=_CAPABILITY,
        requires_target=False,
    )
    async def report_issues(
        self, target: Target | None, checkpoint: SnapshotCursor | None, mode: str
    ) -> AsyncIterator[RawBatch]:
        cfg = self._config()
        if not cfg.report_files:
            raise ConfigError("report_issues requires at least one configured report file")
        reports = [self._load_report(filename) for filename in cfg.report_files]
        combined = hashlib.sha256("\n".join(report.snapshot.snapshot_id for report in reports).encode()).hexdigest()
        cursor = SnapshotCursor(snapshot_id=f"invicti-standard-reports:{combined}", started_at=self.ctx.clock())
        done: list[str] = []
        for report in reports:
            done.append(report.snapshot.snapshot_id)
            batch_cursor = cursor.model_copy(update={"targets_done": list(done)})
            yield RawBatch(
                records=[self._envelope(report)],
                checkpoint=batch_cursor,
                complete=False,
            )
        yield RawBatch(records=[], checkpoint=cursor.model_copy(update={"targets_done": done}), complete=True)

    @stream(
        "webhook_issues",
        ocsf_class=2002,
        cursor=SequenceCursor,
        modes=("event",),
        capability=_CAPABILITY,
        requires_target=False,
    )
    async def webhook_issues(
        self, target: Target | None, checkpoint: SequenceCursor | None, mode: str
    ) -> AsyncIterator[RawBatch]:
        raise ConfigError("webhook_issues is receiver-driven; submit a verified Send To Action delivery")
        yield RawBatch(records=[], checkpoint=checkpoint, complete=False)

    def _map_envelope(self, raw: dict[str, Any], ctx: MapContext) -> list[Any]:
        if set(raw) - {"report", "delivery"}:
            raise VendorContractError("unknown Invicti envelope field")
        report = InvictiReport.model_validate(raw.get("report"))
        findings = map_report_to_findings(report, ctx)
        delivery = raw.get("delivery")
        if delivery is not None:
            if not isinstance(delivery, dict) or not isinstance(delivery.get("delivery_id"), str):
                raise VendorContractError("webhook delivery identity is required")
            public_delivery = {key: value for key, value in delivery.items() if key != "raw_body_base64"}
            for finding in findings:
                finding.metadata = finding.metadata.model_copy(update={"uid": delivery["delivery_id"]})
                fields = finding.unmapped.setdefault("invicti", {}) if finding.unmapped else {}
                fields["webhook"] = public_delivery
                finding.unmapped = {**(finding.unmapped or {}), "invicti": fields}
        return findings

    @mapper("report_issues", version=1)
    def map_report_issue(self, raw: dict[str, Any], ctx: MapContext) -> list[Any]:
        return self._map_envelope(raw, ctx)

    @mapper("webhook_issues", version=1)
    def map_webhook_issue(self, raw: dict[str, Any], ctx: MapContext) -> list[Any]:
        return self._map_envelope(raw, ctx)

    @operation(
        "parse_report",
        input_model=ParseReportArgs,
        output_model=ParseReportOutput,
        capability=_CAPABILITY,
        egress_class="internal",
    )
    async def parse_report_operation(self, args: ParseReportArgs) -> ParseReportOutput:
        report = self._parse(_decode_content(args.content_base64), args.profile)
        return ParseReportOutput(report=report)

    @importer(
        "invicti_json",
        stream="report_issues",
        media_types=("application/json",),
        extensions=(".json",),
    )
    async def import_json(self, imported: ImportedFile) -> AsyncIterator[dict[str, Any]]:
        yield self._envelope(self._parse(imported.data, "invicti_json"))

    @webhook(event_types=("issue", "issue_export", "vulnerability", "*"))
    def receive_event(self, delivery: WebhookDelivery) -> list[StreamRecord]:
        if len(delivery.body) > self._config().max_report_bytes:
            raise VendorContractError("webhook body exceeds configured byte limit")
        digest = hashlib.sha256(delivery.body).hexdigest()
        try:
            value = json.loads(delivery.body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise VendorContractError("Standard Send To Action body must be JSON") from exc
        if not isinstance(value, dict):
            raise VendorContractError("Standard Send To Action body must be an object")
        if "Vulnerabilities" in value:
            report = self._parse(delivery.body)
        else:
            issue = parse_issue(
                value,
                website_id=self._config().website_id,
                website_name=self._config().website_name,
                website_root_url=value.get("WebsiteRootUrl"),
            )
            root = issue.website.root_url
            if root is None:
                parsed = urlsplit(issue.location.url)
                root = urlunsplit((parsed.scheme, parsed.netloc, "/", "", ""))
            website = issue.website.model_copy(update={"root_url": root})
            issue = issue.model_copy(update={"website": website})
            snapshot = ReportSnapshot(
                snapshot_id=f"webhook:{digest}",
                file_sha256=digest,
                report_id=f"webhook:{digest}",
                scan_id=issue.scan_id,
                target_url=root,
            )
            report = InvictiReport(
                report_id=snapshot.report_id,
                scan_id=issue.scan_id,
                target_url=root,
                scan_date=None,
                file_sha256=digest,
                parser_version="invicti-webhook-json/1",
                snapshot=snapshot,
                vulnerabilities=[issue],
            )
        return [
            StreamRecord(
                stream="webhook_issues",
                raw=self._envelope(report, raw_body=delivery.body, delivery_id=digest),
            )
        ]
