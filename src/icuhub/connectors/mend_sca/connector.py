"""Mend SCA connector: Platform API 3.0 and legacy SCA API 2.0, polling only.

Platform 3.0 is the primary surface (security findings, legal violations,
libraries, activity, projects, reports). Legacy SCA 2.0 remains listed for
security alerts and legal alerts. HTTP API 1.3/1.4 is legacy and out of scope.
Mend exposes no webhooks in this connector; every stream is a poll.

Endpoints marked ``[UNVERIFIED]`` are not sourced from the vendor spec
(docs/VENDOR_CONNECTORS.md Mend SCA known gaps) and need a live check before
they are relied on.
"""

from __future__ import annotations

import base64
import hashlib
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any, ClassVar
from urllib.parse import urlsplit

from icuhub.kit.auth import SessionLogin
from icuhub.kit.connector import Connector, action, importer, mapper, operation, stream
from icuhub.kit.errors import (
    AuthFailed,
    BudgetExhausted,
    ConfigError,
    PermissionDenied,
    RateLimited,
    TransientVendorError,
    VendorContractError,
)
from icuhub.kit.mapping import epoch_ms
from icuhub.kit.types import (
    CapabilityHealth,
    HealthReport,
    ImportedFile,
    MapContext,
    RawBatch,
    Scope,
    SourceRecord,
    Target,
    TargetRecord,
)

from . import actions, mappers, reports
from .models import (
    DownloadReportArgs,
    FindingRefArgs,
    GetPermissionsArgs,
    GetPolicyArgs,
    ImportSbomArgs,
    LibraryRefArgs,
    ListSecurityAlertsArgs,
    ListSecurityFindingsArgs,
    MendDownload,
    MendListResult,
    MendReadResult,
    MendReportCursor,
    MendSCAConfig,
    MendSnapshotCursor,
    MendTimeCursor,
    ProjectRefArgs,
    RemediationArgs,
    ReportRefArgs,
    SetAlertStatusArgs,
    SetFindingStatusArgs,
    VulnerabilityRefArgs,
)

__all__ = ["MendSca"]

_FLOWS: tuple[str, ...] = ("F-217",)
_DEFAULT_TOKEN_TTL_S = 600
_PAGE_SIZE_V2 = 50
_PAGE_SIZE_V3 = 100
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def _alert_modified_at_or_none(item: dict[str, Any]) -> datetime | None:
    info = item.get("alertInfo")
    millis = epoch_ms(info.get("modifiedAt")) if isinstance(info, dict) else None
    return None if millis is None else _EPOCH + timedelta(milliseconds=millis)


def _alert_modified_at(item: dict[str, Any]) -> datetime:
    """Timestamp for a record already filtered to carry a parseable modifiedAt."""
    stamped = _alert_modified_at_or_none(item)
    if stamped is None:
        raise VendorContractError("alert record has no parseable alertInfo.modifiedAt")
    return stamped


def _alert_uuid(item: dict[str, Any]) -> str:
    """Alert identity: the top-level ``uuid`` the v2 pages carry, with ``alertInfo.uuid`` only as fallback."""
    top = item.get("uuid")
    info = item.get("alertInfo")
    nested = info.get("uuid") if isinstance(info, dict) else None
    if top is not None and nested is not None and top != nested:
        raise VendorContractError("alert record has conflicting uuid and alertInfo.uuid")
    uuid = top if top is not None else nested
    if not isinstance(uuid, str) or not uuid:
        raise VendorContractError("alert record has no uuid")
    return uuid


def _activity_occurred_at_or_none(item: dict[str, Any]) -> datetime | None:
    millis = epoch_ms(item.get("timestamp"))
    return None if millis is None else _EPOCH + timedelta(milliseconds=millis)


def _activity_occurred_at(item: dict[str, Any]) -> datetime:
    """Timestamp for a record already filtered to carry a parseable timestamp."""
    stamped = _activity_occurred_at_or_none(item)
    if stamped is None:
        raise VendorContractError("activity record has no parseable timestamp")
    return stamped


def _activity_uuid(item: dict[str, Any]) -> str:
    uuid = item.get("uuid")
    if not isinstance(uuid, str) or not uuid:
        raise VendorContractError("activity record has no uuid")
    return uuid


def _activity_is_new(cursor: MendTimeCursor, item: dict[str, Any]) -> bool:
    """Incremental replay filter: skip records older than the overlap window or already committed at the cursor.

    Untimed records cannot be placed against the window, so they are kept; they never advance the cursor.
    """
    occurred_at = _activity_occurred_at_or_none(item)
    if occurred_at is None:
        return True
    window_start = cursor.window_start()
    if window_start is not None and occurred_at < window_start:
        return False
    return not cursor.is_duplicate(occurred_at, _activity_uuid(item))


def _not_evaluated_batch(cursor: MendSnapshotCursor | MendTimeCursor) -> RawBatch:
    """Non-closing checkpoint for a denied scope: absence is never asserted, so ``complete`` stays False."""
    return RawBatch(
        records=[],
        checkpoint=cursor.model_copy(update={"coverage": "not_evaluated", "incomplete_reason": "PermissionDenied"}),
        complete=False,
    )


class MendSca(Connector):
    """Mend SCA connector (Platform 3.0 primary, legacy SCA 2.0 for alerts)."""

    kind: ClassVar[str] = "mend_sca"
    version: ClassVar[str] = "0.1.0"
    display_name: ClassVar[str] = "Mend SCA"
    owner: ClassVar[str] = "@icuhub/maintainers"
    config_model: ClassVar[type[MendSCAConfig]] = MendSCAConfig
    auth_modes: ClassVar[tuple[str, ...]] = ("SessionLogin",)
    capabilities: ClassVar[tuple[str, ...]] = ("FindingSource",)
    flows: ClassVar[tuple[str, ...]] = _FLOWS
    scopes: ClassVar[tuple[Scope, ...]] = (
        Scope(
            name="projects",
            probe="GET project listing (v3.0 orgs/projects or v2.0 projects) [UNVERIFIED]",
            required_by=("FindingSource",),
        ),
        Scope(
            name="security_findings",
            probe="GET /api/v3.0/projects/{uuid}/dependencies/findings/security [UNVERIFIED]",
            required_by=("FindingSource",),
        ),
        Scope(
            name="security_alerts",
            probe="GET /api/v2.0/projects/{token}/alerts/security",
            required_by=("FindingSource",),
        ),
        Scope(
            name="write",
            probe="PUT alert status / finding status / SBOM import (gated by write_enabled)",
            required_by=("FindingSource",),
        ),
    )

    # -- config, origin, and gates ---------------------------------------

    def _config(self) -> MendSCAConfig:
        if not isinstance(self.config, MendSCAConfig):
            raise ConfigError("Mend SCA connector requires MendSCAConfig")
        return self.config

    @property
    def _origin(self) -> str:
        parts = urlsplit(self._config().base_url)
        return f"{parts.scheme}://{parts.netloc}"

    # -- auth and transport ----------------------------------------------

    async def build_auth(self) -> SessionLogin:
        cfg = self._config()
        user_key = _decode(await self.ctx.secrets.resolve(cfg.user_key), "user_key")
        org_token = None
        if cfg.org_token is not None:
            org_token = _decode(await self.ctx.secrets.resolve(cfg.org_token), "org_token")

        async def login() -> tuple[str, str, Any]:
            # self.http is attached after build_auth returns; resolve it lazily.
            return await self._login(user_key, org_token)

        return SessionLogin(login, clock=self.ctx.clock)

    async def _login(self, user_key: str, org_token: str | None) -> tuple[str, str, Any]:
        cfg = self._config()
        body: dict[str, Any] = {"email": cfg.email, "userKey": user_key}
        if cfg.api_version == "2.0":
            body["orgToken"] = org_token
        else:
            # [UNVERIFIED] v3.0 login body key names; spec documents /login with org UUID.
            body["orgUuid"] = cfg.org_uuid
        result = await self.http.request(
            "POST", f"{cfg.base_url}/login", json=body, idempotency="non_idempotent", authenticate=False
        )
        payload = result.json()
        if cfg.api_version == "2.0":
            token = _dig(payload, "retVal", "jwtToken")
            ttl = None
        else:
            token = _dig(payload, "response", "jwtToken")
            ttl = _dig(payload, "response", "tokenTTL")
        if not isinstance(token, str) or not token:
            raise AuthFailed("Mend login returned no JWT")
        seconds = ttl if isinstance(ttl, int | float) and ttl > 0 else _DEFAULT_TOKEN_TTL_S
        return "Authorization", f"Bearer {token}", self.ctx.clock() + timedelta(seconds=seconds)

    async def call(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        body: Any = None,
        files: dict[str, Any] | None = None,
        expected: tuple[int, ...] = (200,),
    ) -> Any:
        """Issue one authenticated request. ``path`` is a full ``/api/vX/...`` path.

        ``resolve_request_url`` joins relative paths onto ``base_url``, which already
        ends in ``/api/vX``; the origin-absolute URL avoids a doubled version segment.
        """
        result = await self.http.request(
            method,
            f"{self._origin}{path}",
            params=params,
            json=body,
            files=files,
            expected=expected,
            idempotency="safe_read" if method == "GET" else "non_idempotent",
        )
        return result.json() if result.content else None

    # -- paging helpers --------------------------------------------------

    async def _v2_pages(
        self, path: str, *, page_size: int, max_pages: int, extra: dict[str, Any] | None = None
    ) -> AsyncIterator[tuple[int, list[dict[str, Any]], dict[str, Any]]]:
        """Zero-based ``page``/``pageSize`` pagination; envelope ``retVal`` list plus ``additionalData``."""
        page = 0
        while True:
            if page >= max_pages:
                raise BudgetExhausted("Mend v2.0 pagination exceeded max_pages")
            params = {"page": page, "pageSize": page_size, **(extra or {})}
            payload = await self.call("GET", path, params=params)
            items = payload.get("retVal") if isinstance(payload, dict) else None
            if not isinstance(items, list):
                raise VendorContractError("Mend v2.0 list response has no retVal list")
            additional = payload.get("additionalData") or {}
            yield page, [item for item in items if isinstance(item, dict)], additional
            if additional.get("isLastPage", True) or not items:
                return
            page += 1

    async def _v3_pages(
        self, path: str, *, limit: int, max_pages: int, extra: dict[str, Any] | None = None
    ) -> AsyncIterator[tuple[int, list[dict[str, Any]], dict[str, Any]]]:
        """Cursor/``limit`` pagination; envelope ``response`` list plus ``additionalData.next`` [UNVERIFIED]."""
        page = 0
        cursor: str | None = None
        while True:
            if page >= max_pages:
                raise BudgetExhausted("Mend v3.0 pagination exceeded max_pages")
            params: dict[str, Any] = {"limit": limit, **(extra or {})}
            if cursor is not None:
                params["cursor"] = cursor
            payload = await self.call("GET", path, params=params)
            items = payload.get("response") if isinstance(payload, dict) else None
            if not isinstance(items, list):
                raise VendorContractError("Mend v3.0 list response has no response list")
            additional = payload.get("additionalData") or {}
            yield page, [item for item in items if isinstance(item, dict)], additional
            cursor = additional.get("next")
            if not cursor or not items:
                return
            page += 1

    def _cfg_org(self) -> str:
        cfg = self._config()
        if cfg.org_uuid is None:
            raise ConfigError("Mend v3.0 requires org_uuid")
        return cfg.org_uuid

    def _organization_key(self) -> str:
        """Non-secret organization identity stamped on every record (never the org token).

        The org UUID when configured; a v2.0 token-only connection has no UUID, so its
        host (netloc of ``base_url``) identifies the Mend tenant.
        """
        cfg = self._config()
        return cfg.org_uuid or urlsplit(cfg.base_url).netloc

    def _snapshot_cursor(self, checkpoint: Any, stream_name: str, scope: str) -> MendSnapshotCursor:
        """Resume the snapshot in progress, or open a new one for this stream and scope."""
        if isinstance(checkpoint, MendSnapshotCursor):
            return checkpoint
        started_at = self.ctx.clock()
        material = f"{self.ctx.connection_id}\x1f{stream_name}\x1f{scope}\x1f{started_at.isoformat()}"
        return MendSnapshotCursor(
            snapshot_id=hashlib.sha256(material.encode("utf-8")).hexdigest()[:32],
            started_at=started_at,
            high_water_start=started_at,
            targets_done=[scope],
        )

    def _require_version(self, version: str) -> MendSCAConfig:
        cfg = self._config()
        if cfg.api_version != version:
            raise ConfigError(f"this operation requires Mend API {version}; connection is {cfg.api_version}")
        return cfg

    # -- health and discovery --------------------------------------------

    async def check(self) -> HealthReport:
        cfg = self._config()
        capabilities: dict[str, CapabilityHealth] = {}
        status = "healthy"
        try:
            if cfg.api_version == "3.0":
                probe = self._v3_pages(f"/api/v3.0/orgs/{self._cfg_org()}/projects", limit=1, max_pages=1)
            else:
                probe = self._v2_pages("/api/v2.0/projects", page_size=1, max_pages=1)
            try:
                await probe.__anext__()
            finally:
                await probe.aclose()
            capabilities["FindingSource"] = CapabilityHealth(status="healthy")
        except AuthFailed as exc:
            capabilities["FindingSource"] = CapabilityHealth(status="failing", reason=type(exc).__name__)
            status = "failing"
        except PermissionDenied as exc:
            # The refused listing was never evaluated, so the capability is not_evaluated, not healthy.
            # The failed listing still degrades the overall report rather than hiding behind it.
            capabilities["FindingSource"] = CapabilityHealth(status="not_evaluated", reason=type(exc).__name__)
            status = "degraded"
        except (RateLimited, TransientVendorError, VendorContractError) as exc:
            capabilities["FindingSource"] = CapabilityHealth(status="degraded", reason=type(exc).__name__)
            status = "degraded"
        return HealthReport(status=status, capabilities=capabilities, vendor_version=cfg.api_version)

    async def discover(self) -> AsyncIterator[TargetRecord]:
        cfg = self._config()
        selected = set(cfg.selected_projects)
        if cfg.api_version == "3.0":
            pages = self._v3_pages(
                f"/api/v3.0/orgs/{self._cfg_org()}/projects",
                limit=cfg.page_size,
                max_pages=cfg.max_pages,
            )
        else:
            pages = self._v2_pages("/api/v2.0/projects", page_size=cfg.page_size, max_pages=cfg.max_pages)
        async for _, items, _ in pages:
            for raw in items:
                uuid = raw.get("uuid") or raw.get("token")
                if not uuid or (selected and uuid not in selected):
                    continue
                yield TargetRecord(
                    source_uid=str(uuid),
                    kind="project",
                    display_name=str(raw.get("name") or f"project {uuid}"),
                    attributes={"path": raw.get("path"), "api_version": cfg.api_version},
                )

    # -- streams (v3.0 primary) ------------------------------------------

    @stream(
        "security_findings",
        cursor=MendSnapshotCursor,
        capability="FindingSource",
        ocsf_class=2002,
        modes=("full",),
        stability="beta",
        requires_target=True,
    )
    async def security_findings(
        self, target: Target | None, checkpoint: Any, mode: str
    ) -> AsyncIterator[RawBatch]:
        cfg = self._require_version("3.0")
        if target is None:
            raise ConfigError("security_findings requires a project target")
        organization = self._cfg_org()
        cursor = self._snapshot_cursor(checkpoint, "security_findings", target.source_uid)
        # [UNVERIFIED] Platform 3.0 project security findings path; spec lists it as a known gap.
        path = f"/api/v3.0/projects/{target.source_uid}/dependencies/findings/security"
        try:
            async for page, items, _ in self._v3_pages(
                path, limit=cfg.page_size or _PAGE_SIZE_V3, max_pages=cfg.max_pages
            ):
                for raw in items:
                    raw["_organization"] = organization
                cursor = cursor.model_copy(update={"page": page, "pages_fetched": page + 1})
                yield RawBatch(records=items, checkpoint=cursor, complete=False)
        except PermissionDenied:
            yield _not_evaluated_batch(cursor)
            raise
        cursor = cursor.model_copy(update={"coverage": "complete", "incomplete_reason": None})
        yield RawBatch(records=[], checkpoint=cursor, complete=True)

    @mapper("security_findings", version=1)
    def map_security_finding_record(self, raw: dict[str, Any], ctx: MapContext) -> list[Any]:
        return mappers.map_security_finding(raw, ctx)

    @stream(
        "legal_violations",
        cursor=MendSnapshotCursor,
        capability="FindingSource",
        ocsf_class=2003,
        modes=("full",),
        stability="beta",
        requires_target=True,
    )
    async def legal_violations(
        self, target: Target | None, checkpoint: Any, mode: str
    ) -> AsyncIterator[RawBatch]:
        cfg = self._require_version("3.0")
        if target is None:
            raise ConfigError("legal_violations requires a project target")
        organization = self._cfg_org()
        # [UNVERIFIED] Legal violations path; source ID not sourced (spec known gap).
        path = f"/api/v3.0/projects/{target.source_uid}/licenses/violations"
        cursor = self._snapshot_cursor(checkpoint, "legal_violations", target.source_uid)
        try:
            async for page, items, _ in self._v3_pages(
                path, limit=cfg.page_size or _PAGE_SIZE_V3, max_pages=cfg.max_pages
            ):
                for raw in items:
                    raw["_organization"] = organization
                cursor = cursor.model_copy(update={"page": page, "pages_fetched": page + 1})
                yield RawBatch(records=items, checkpoint=cursor, complete=False)
        except PermissionDenied:
            yield _not_evaluated_batch(cursor)
            raise
        cursor = cursor.model_copy(update={"coverage": "complete", "incomplete_reason": None})
        yield RawBatch(records=[], checkpoint=cursor, complete=True)

    @mapper("legal_violations", version=1)
    def map_legal_violation_record(self, raw: dict[str, Any], ctx: MapContext) -> list[Any]:
        return mappers.map_legal_violation(raw, ctx)

    @stream(
        "libraries",
        cursor=MendSnapshotCursor,
        capability="FindingSource",
        record_type="library",
        modes=("full",),
        stability="beta",
        requires_target=True,
    )
    async def libraries(self, target: Target | None, checkpoint: Any, mode: str) -> AsyncIterator[RawBatch]:
        cfg = self._require_version("3.0")
        if target is None:
            raise ConfigError("libraries requires a project target")
        organization = self._cfg_org()
        # [UNVERIFIED] Project libraries path.
        path = f"/api/v3.0/projects/{target.source_uid}/libraries"
        cursor = self._snapshot_cursor(checkpoint, "libraries", target.source_uid)
        try:
            async for page, items, _ in self._v3_pages(
                path, limit=cfg.page_size or _PAGE_SIZE_V3, max_pages=cfg.max_pages
            ):
                for raw in items:
                    raw["_organization"] = organization
                    raw["project"] = {"uuid": target.source_uid, "name": target.display_name}
                cursor = cursor.model_copy(update={"page": page, "pages_fetched": page + 1})
                yield RawBatch(records=items, checkpoint=cursor, complete=False)
        except PermissionDenied:
            yield _not_evaluated_batch(cursor)
            raise
        cursor = cursor.model_copy(update={"coverage": "complete", "incomplete_reason": None})
        yield RawBatch(records=[], checkpoint=cursor, complete=True)

    @mapper("libraries", version=1)
    def map_library_record(self, raw: dict[str, Any], ctx: MapContext) -> list[SourceRecord]:
        return mappers.map_library(raw, ctx)

    @stream(
        "activity",
        cursor=MendTimeCursor,
        capability="FindingSource",
        record_type="audit_event",
        modes=("incremental", "full"),
        stability="beta",
        requires_target=False,
    )
    async def activity(self, target: Target | None, checkpoint: Any, mode: str) -> AsyncIterator[RawBatch]:
        cfg = self._require_version("3.0")
        organization = self._cfg_org()
        # [UNVERIFIED] Organization activity/audit path.
        path = f"/api/v3.0/orgs/{organization}/activity"
        cursor = checkpoint if isinstance(checkpoint, MendTimeCursor) else MendTimeCursor(ts=None)
        try:
            async for page, items, _ in self._v3_pages(
                path, limit=cfg.page_size or _PAGE_SIZE_V3, max_pages=cfg.max_pages
            ):
                for raw in items:
                    raw["_organization"] = organization
                # Full mode replays the whole feed. Incremental mode replays the overlap window and drops
                # records already committed at the cursor timestamp. Only timestamped records advance the cursor.
                batch = items if mode == "full" else [raw for raw in items if _activity_is_new(cursor, raw)]
                stamped = [raw for raw in items if _activity_occurred_at_or_none(raw) is not None]
                if stamped:
                    cursor = cursor.advance(stamped, ts_of=_activity_occurred_at, id_of=_activity_uuid)
                cursor = cursor.model_copy(update={"page": page, "pages_fetched": page + 1})
                yield RawBatch(records=batch, checkpoint=cursor, complete=False)
        except PermissionDenied:
            yield _not_evaluated_batch(cursor)
            raise
        cursor = cursor.model_copy(update={"coverage": "complete", "incomplete_reason": None})
        yield RawBatch(records=[], checkpoint=cursor, complete=True)

    @mapper("activity", version=1)
    def map_activity_record(self, raw: dict[str, Any], ctx: MapContext) -> list[SourceRecord]:
        return mappers.map_activity(raw, ctx)

    @stream(
        "projects",
        cursor=MendSnapshotCursor,
        capability="FindingSource",
        record_type="project",
        modes=("full",),
        stability="beta",
        requires_target=False,
    )
    async def projects(self, target: Target | None, checkpoint: Any, mode: str) -> AsyncIterator[RawBatch]:
        cfg = self._config()
        organization = self._organization_key()
        if cfg.api_version == "3.0":
            pages = self._v3_pages(
                f"/api/v3.0/orgs/{self._cfg_org()}/projects",
                limit=cfg.page_size or _PAGE_SIZE_V3,
                max_pages=cfg.max_pages,
            )
        else:
            pages = self._v2_pages("/api/v2.0/projects", page_size=cfg.page_size or _PAGE_SIZE_V2, max_pages=cfg.max_pages)
        cursor = self._snapshot_cursor(checkpoint, "projects", organization)
        try:
            async for page, items, _ in pages:
                for raw in items:
                    raw["_organization"] = organization
                    raw["_stale_after_days"] = cfg.stale_after_days
                    raw.setdefault("_access", None)
                cursor = cursor.model_copy(update={"page": page, "pages_fetched": page + 1})
                yield RawBatch(records=items, checkpoint=cursor, complete=False)
        except PermissionDenied:
            yield _not_evaluated_batch(cursor)
            raise
        cursor = cursor.model_copy(update={"coverage": "complete", "incomplete_reason": None})
        yield RawBatch(records=[], checkpoint=cursor, complete=True)

    @mapper("projects", version=1)
    def map_project_record(self, raw: dict[str, Any], ctx: MapContext) -> list[SourceRecord]:
        return mappers.map_project(raw, ctx)

    # -- streams (v2.0 legacy alerts) ------------------------------------

    @stream(
        "security_alerts",
        cursor=MendTimeCursor,
        capability="FindingSource",
        ocsf_class=2002,
        modes=("incremental", "full"),
        stability="beta",
        requires_target=True,
    )
    async def security_alerts(self, target: Target | None, checkpoint: Any, mode: str) -> AsyncIterator[RawBatch]:
        cfg = self._require_version("2.0")
        if target is None:
            raise ConfigError("security_alerts requires a project target")
        organization = self._organization_key()
        cursor = checkpoint if isinstance(checkpoint, MendTimeCursor) else MendTimeCursor(ts=None)
        # [UNVERIFIED] v2.0 alerts path; spec lists list_security_alerts (2.0) as a known gap.
        path = f"/api/v2.0/projects/{target.source_uid}/alerts/security"
        pages = self._v2_pages(path, page_size=cfg.page_size or _PAGE_SIZE_V2, max_pages=cfg.max_pages)
        try:
            async for page, items, _ in pages:
                for raw in items:
                    raw["_organization"] = organization
                # Records without a parseable modifiedAt are yielded but never advance the cursor:
                # a fabricated timestamp would skip them on the next run.
                stamped = [raw for raw in items if _alert_modified_at_or_none(raw) is not None]
                if stamped:
                    advanced = cursor.advance(stamped, ts_of=_alert_modified_at, id_of=_alert_uuid)
                    cursor = cursor.model_copy(update={"ts": advanced.ts, "last_ids_at_ts": advanced.last_ids_at_ts})
                cursor = cursor.model_copy(update={"page": page, "pages_fetched": page + 1})
                yield RawBatch(records=items, checkpoint=cursor, complete=False)
        except PermissionDenied:
            yield _not_evaluated_batch(cursor)
            raise
        cursor = cursor.model_copy(update={"coverage": "complete", "incomplete_reason": None})
        yield RawBatch(records=[], checkpoint=cursor, complete=True)

    @mapper("security_alerts", version=1)
    def map_security_alert_record(self, raw: dict[str, Any], ctx: MapContext) -> list[Any]:
        return mappers.map_security_alert(raw, ctx)

    @stream(
        "legal_alerts",
        cursor=MendSnapshotCursor,
        capability="FindingSource",
        ocsf_class=2003,
        modes=("full",),
        stability="beta",
        requires_target=True,
    )
    async def legal_alerts(self, target: Target | None, checkpoint: Any, mode: str) -> AsyncIterator[RawBatch]:
        cfg = self._require_version("2.0")
        if target is None:
            raise ConfigError("legal_alerts requires a project target")
        # [UNVERIFIED] v2.0 legal alerts path.
        path = f"/api/v2.0/projects/{target.source_uid}/alerts/legal"
        cursor = self._snapshot_cursor(checkpoint, "legal_alerts", target.source_uid)
        try:
            async for page, items, _ in self._v2_pages(
                path, page_size=cfg.page_size or _PAGE_SIZE_V2, max_pages=cfg.max_pages
            ):
                for raw in items:
                    raw["_organization"] = self._organization_key()
                cursor = cursor.model_copy(update={"page": page, "pages_fetched": page + 1})
                yield RawBatch(records=items, checkpoint=cursor, complete=False)
        except PermissionDenied:
            yield _not_evaluated_batch(cursor)
            raise
        cursor = cursor.model_copy(update={"coverage": "complete", "incomplete_reason": None})
        yield RawBatch(records=[], checkpoint=cursor, complete=True)

    @mapper("legal_alerts", version=1)
    def map_legal_alert_record(self, raw: dict[str, Any], ctx: MapContext) -> list[Any]:
        return mappers.map_legal_alert(raw, ctx)

    # -- report ingestion (offline importer) -----------------------------

    @stream(
        "report_findings",
        cursor=MendReportCursor,
        capability="FindingSource",
        ocsf_class=2002,
        modes=("full",),
        stability="beta",
        requires_target=False,
    )
    async def report_findings(self, target: Target | None, checkpoint: Any, mode: str) -> AsyncIterator[RawBatch]:
        # Reports arrive only through the mend_report importer, which feeds report_findings' mapper directly.
        # Mend exposes no remote report listing in this connector, so a pull is refused explicitly.
        del target, checkpoint, mode
        raise ConfigError("report_findings is fed by the mend_report importer; Mend has no remote report pull")
        yield  # pragma: no cover - keeps this an async generator

    @mapper("report_findings", version=1)
    def map_report_finding_record(self, raw: dict[str, Any], ctx: MapContext) -> list[Any]:
        return mappers.map_report_finding(raw, ctx)

    @importer(
        "mend_report",
        stream="report_findings",
        media_types=("application/json",),
        extensions=(".json",),
    )
    async def import_report(self, imported: ImportedFile) -> AsyncIterator[dict[str, Any]]:
        cfg = self._config()
        organization = self._organization_key()
        parsed = reports.parse_report(imported.data, config=cfg, project_snapshot=imported.filename)
        for row in parsed.records:
            row["_organization"] = organization
            row["_report_sha256"] = parsed.identity.report_sha256
            yield row

    # -- read operations -------------------------------------------------

    @operation(
        "list_security_alerts",
        input_model=ListSecurityAlertsArgs,
        output_model=MendListResult,
        classification="read",
        capability="FindingSource",
    )
    async def list_security_alerts(self, args: ListSecurityAlertsArgs) -> MendListResult:
        cfg = self._require_version("2.0")
        items: list[dict[str, Any]] = []
        pages = 0
        async for page, batch, additional in self._v2_pages(
            f"/api/v2.0/projects/{args.project_token}/alerts/security",
            page_size=args.page_size or cfg.page_size or _PAGE_SIZE_V2,
            max_pages=args.max_pages or cfg.max_pages,
        ):
            items.extend(batch)
            pages = page + 1
        return MendListResult(items=items, complete=True, pages=pages, coverage="complete")

    @operation(
        "list_security_findings",
        input_model=ListSecurityFindingsArgs,
        output_model=MendListResult,
        classification="read",
        capability="FindingSource",
    )
    async def list_security_findings(self, args: ListSecurityFindingsArgs) -> MendListResult:
        cfg = self._require_version("3.0")
        if args.candidate_only or args.candidate_since is not None:
            raise ConfigError("candidate_only/candidate_since have no sourced vendor semantics")
        items: list[dict[str, Any]] = []
        pages = 0
        next_cursor: str | None = None
        async for page, batch, additional in self._v3_pages(
            f"/api/v3.0/projects/{args.project_uuid}/dependencies/findings/security",
            limit=args.limit or cfg.page_size or _PAGE_SIZE_V3,
            max_pages=args.max_pages or cfg.max_pages,
        ):
            items.extend(batch)
            pages = page + 1
            next_cursor = additional.get("next")
        return MendListResult(
            items=items,
            complete=next_cursor is None,
            pages=pages,
            next_cursor=next_cursor,
            coverage="complete" if next_cursor is None else "partial",
        )

    @operation(
        "get_project",
        input_model=ProjectRefArgs,
        output_model=MendReadResult,
        classification="read",
        capability="FindingSource",
    )
    async def get_project(self, args: ProjectRefArgs) -> MendReadResult:
        cfg = self._config()
        # [UNVERIFIED] project detail path (spec known gap).
        path = f"/api/v{cfg.api_version}/projects/{args.project_id}"
        payload = await self.call("GET", path)
        return MendReadResult(data=payload, api_version=cfg.api_version)

    @operation(
        "get_finding",
        input_model=FindingRefArgs,
        output_model=MendReadResult,
        classification="read",
        capability="FindingSource",
    )
    async def get_finding(self, args: FindingRefArgs) -> MendReadResult:
        cfg = self._require_version("3.0")
        # [UNVERIFIED] single security finding path (spec known gap).
        path = f"/api/v3.0/projects/{args.project_id}/dependencies/findings/security/{args.finding_uuid}"
        payload = await self.call("GET", path)
        return MendReadResult(data=payload, api_version=cfg.api_version)

    @operation(
        "get_library",
        input_model=LibraryRefArgs,
        output_model=MendReadResult,
        classification="read",
        capability="FindingSource",
    )
    async def get_library(self, args: LibraryRefArgs) -> MendReadResult:
        cfg = self._require_version("3.0")
        # [UNVERIFIED] library detail path (spec known gap).
        path = f"/api/v3.0/projects/{args.project_id}/libraries/{args.library_uuid}"
        payload = await self.call("GET", path)
        return MendReadResult(data=payload, api_version=cfg.api_version)

    @operation(
        "get_dependency_paths",
        input_model=FindingRefArgs,
        output_model=MendReadResult,
        classification="read",
        capability="FindingSource",
    )
    async def get_dependency_paths(self, args: FindingRefArgs) -> MendReadResult:
        cfg = self._require_version("3.0")
        # [UNVERIFIED] dependency paths for a finding (spec known gap).
        path = f"/api/v3.0/projects/{args.project_id}/dependencies/findings/security/{args.finding_uuid}/paths"
        payload = await self.call("GET", path)
        return MendReadResult(data=payload, api_version=cfg.api_version)

    @operation(
        "get_vulnerability_profile",
        input_model=VulnerabilityRefArgs,
        output_model=MendReadResult,
        classification="read",
        capability="FindingSource",
    )
    async def get_vulnerability_profile(self, args: VulnerabilityRefArgs) -> MendReadResult:
        cfg = self._require_version("3.0")
        # [UNVERIFIED] vulnerability profile path (spec known gap).
        path = f"/api/v3.0/vulnerabilities/{args.vulnerability_id}"
        payload = await self.call("GET", path)
        return MendReadResult(data=payload, api_version=cfg.api_version)

    @operation(
        "get_remediation",
        input_model=RemediationArgs,
        output_model=MendReadResult,
        classification="read",
        capability="FindingSource",
    )
    async def get_remediation(self, args: RemediationArgs) -> MendReadResult:
        cfg = self._require_version("3.0")
        # [UNVERIFIED] remediation guidance path (spec known gap).
        path = f"/api/v3.0/vulnerabilities/{args.vulnerability_id}/remediation"
        payload = await self.call("GET", path)
        return MendReadResult(data=payload, api_version=cfg.api_version)

    @operation(
        "get_policy",
        input_model=GetPolicyArgs,
        output_model=MendReadResult,
        classification="read",
        capability="FindingSource",
    )
    async def get_policy(self, args: GetPolicyArgs) -> MendReadResult:
        cfg = self._require_version("3.0")
        # [UNVERIFIED] policy detail path (spec known gap).
        path = f"/api/v3.0/{args.scope}/{args.scope_id}/policies/{args.policy_uuid}"
        payload = await self.call("GET", path)
        return MendReadResult(data=payload, api_version=cfg.api_version)

    @operation(
        "get_report_status",
        input_model=ReportRefArgs,
        output_model=MendReadResult,
        classification="read",
        capability="FindingSource",
    )
    async def get_report_status(self, args: ReportRefArgs) -> MendReadResult:
        cfg = self._require_version("3.0")
        path = f"/api/v3.0/orgs/{self._cfg_org()}/reports/{args.report_uuid}"
        result = await self.http.stream_download_result(
            "GET",
            f"{self._origin}{path}",
            max_bytes=self._config().max_report_bytes,
            expected=(200,),
        )
        return MendReadResult(data=result.json(), api_version=cfg.api_version)

    @operation(
        "download_report",
        input_model=DownloadReportArgs,
        output_model=MendDownload,
        classification="read",
        capability="FindingSource",
    )
    async def download_report(self, args: DownloadReportArgs) -> MendDownload:
        self._require_version("3.0")
        # [UNVERIFIED] report download path (spec known gap). HTTP 202 means the artifact is still
        # being generated; the caller polls get_report_status and retries. HTTP 200 returns the
        # bounded artifact base64-encoded so the operation output stays JSON-safe.
        path = f"/api/v3.0/orgs/{self._cfg_org()}/reports/{args.report_uuid}/download"
        result = await self.http.stream_download_result(
            "GET",
            f"{self._origin}{path}",
            max_bytes=self._config().max_report_bytes,
            expected=(200, 202),
        )
        if result.status == 202:
            return MendDownload(report_uuid=args.report_uuid, status="not_ready")
        return MendDownload(
            report_uuid=args.report_uuid,
            status="ready",
            size_bytes=len(result.content),
            sha256=hashlib.sha256(result.content).hexdigest(),
            media_type=result.headers.get("content-type"),
            content_base64=base64.b64encode(result.content).decode("ascii"),
        )

    @operation(
        "get_permissions",
        input_model=GetPermissionsArgs,
        output_model=MendReadResult,
        classification="read",
        capability="FindingSource",
    )
    async def get_permissions(self, args: GetPermissionsArgs) -> MendReadResult:
        cfg = self._require_version("2.0")
        if args.scope == "byRole":
            path = "/api/v2.0/permissions/byRole"
        else:
            if args.scope_id is None:
                raise ConfigError(f"get_permissions scope {args.scope!r} requires scope_id")
            # Spec: /orgs/{orgToken}, /products/{productToken}, /projects/{projectToken}/permissions.
            segment = {"org": "orgs", "product": "products", "project": "projects"}[args.scope]
            path = f"/api/v2.0/{segment}/{args.scope_id}/permissions"
        payload = await self.call("GET", path)
        return MendReadResult(data=payload, api_version=cfg.api_version)

    # -- write actions (gated by write_enabled; apply/reconcile in actions.py) --

    plan_set_alert_status = action(
        "set_alert_status",
        classification="write",
        capability="FindingSource",
        input_model=SetAlertStatusArgs,
        idempotency="natural_key",
    )(actions.plan_set_alert_status)
    set_alert_status_apply = plan_set_alert_status.apply(actions.set_alert_status_apply)
    set_alert_status_reconcile = plan_set_alert_status.reconcile(actions.set_alert_status_reconcile)

    plan_set_finding_status = action(
        "set_finding_status",
        classification="write",
        capability="FindingSource",
        input_model=SetFindingStatusArgs,
        idempotency="natural_key",
    )(actions.plan_set_finding_status)
    set_finding_status_apply = plan_set_finding_status.apply(actions.set_finding_status_apply)
    set_finding_status_reconcile = plan_set_finding_status.reconcile(actions.set_finding_status_reconcile)

    plan_import_sbom = action(
        "import_sbom",
        classification="write",
        capability="FindingSource",
        input_model=ImportSbomArgs,
        idempotency="natural_key",
    )(actions.plan_import_sbom)
    import_sbom_apply = plan_import_sbom.apply(actions.import_sbom_apply)
    import_sbom_reconcile = plan_import_sbom.reconcile(actions.import_sbom_reconcile)


def _decode(secret: bytes | str, label: str) -> str:
    if isinstance(secret, bytes):
        try:
            return secret.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ConfigError(f"Mend {label} secret is not UTF-8") from exc
    return str(secret)


def _dig(payload: Any, *keys: str) -> Any:
    node: Any = payload
    for key in keys:
        if not isinstance(node, dict):
            return None
        node = node.get(key)
    return node
