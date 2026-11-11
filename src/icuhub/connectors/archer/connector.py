"""Archer GRC connector: on-prem and SaaS, REST Content API plus SOAP Web Services.

Capabilities are RiskRegister for every stream: Archer is the system of record
for risks, exceptions, remediation plans, and assessment or scan findings. The
2002/2003 finding streams additionally emit OCSF findings; they do not declare
FindingSource because Archer is not the scanner of record. No webhooks exist on
either deployment model, so ``webhook_verifier`` returns None and notifications
use the ``none`` scheme.
"""

from collections.abc import AsyncIterator
from functools import cached_property
from typing import Any, ClassVar

from icuhub.kit import (
    AuthFailed,
    CapabilityHealth,
    ConfigError,
    Connector,
    ConnectorConfig,
    HealthReport,
    MapContext,
    PermissionDenied,
    RateLimited,
    Scope,
    SessionLogin,
    SnapshotCursor,
    TargetRecord,
    TimeIdCursor,
    TransientVendorError,
    VendorContractError,
    action,
    mapper,
    operation,
    stream,
)

from . import actions, mappers, operations, streams
from .client import ArcherClient, domain_login, rest_login
from .models import (
    ApplicationRef,
    ArcherConfig,
    AttachmentOutput,
    AttachmentRef,
    ContentOutput,
    ContentRef,
    CreateFindingOrExceptionInput,
    DataFeedHistoryInput,
    DataFeedHistoryOutput,
    DeleteContentInput,
    DiscoverOutput,
    EmptyInput,
    ExecuteDataFeedInput,
    HistoryOutput,
    ItemsOutput,
    LevelRef,
    SearchContentArgs,
    SearchContentOutput,
    UpdateFindingOrExceptionInput,
    UploadAttachmentInput,
    ValuesListRef,
    VersionOutput,
)

__all__ = ["Archer"]

_FLOWS: tuple[str, ...] = (
    "F-124", "F-125", "F-126", "F-127", "F-128", "F-129", "F-130",
    "F-230", "F-231", "F-232", "F-233", "F-234", "F-235", "F-236",
)


class Archer(Connector):
    """Archer GRC connector (REST Content API, SOAP Web Services, data feeds)."""

    kind: ClassVar[str] = "archer"
    version: ClassVar[str] = "0.1.0"
    display_name: ClassVar[str] = "Archer GRC"
    config_model: ClassVar[type[ConnectorConfig]] = ArcherConfig
    auth_modes: ClassVar[tuple[str, ...]] = ("SessionLogin",)
    capabilities: ClassVar[tuple[str, ...]] = ("RiskRegister",)
    flows: ClassVar[tuple[str, ...]] = _FLOWS
    plan_safe_post_paths: ClassVar[tuple[str, ...]] = (
        "/platformapi/core/security/login",
        "/platformapi/core/system/fielddefinition/level/",
        "/platformapi/core/system/valueslistvalue/valueslist/",
        "/platformapi/core/content/contentid",
        "/ws/general.asmx",
        "/ws/search.asmx",
    )
    scopes: ClassVar[tuple[Scope, ...]] = (
        # Custom role names vary per instance; probes prove the permission instead.
        Scope(
            name="version",
            probe="POST /platformapi/core/system/applicationinfo (X-Http-Method-Override: GET)",
            required_by=("RiskRegister",),
        ),
        Scope(
            name="metadata",
            probe="POST /platformapi/core/system/application (X-Http-Method-Override: GET)",
            required_by=("RiskRegister",),
        ),
        Scope(
            name="content_read",
            probe="SOAP ExecuteSearch on /ws/search.asmx",
            required_by=("RiskRegister",),
        ),
        Scope(
            name="content_write",
            probe="POST/PUT /platformapi/core/content",
            required_by=("RiskRegister",),
        ),
        Scope(
            name="data_feed_execute",
            probe="POST /platformapi/core/datafeed/execute",
            required_by=("RiskRegister",),
        ),
        Scope(name="content_api", probe="GET /contentapi/"),
    )

    def _cfg(self) -> ArcherConfig:
        if not isinstance(self.config, ArcherConfig):
            raise ConfigError("Archer connector requires ArcherConfig")
        return self.config

    # -- auth and client --------------------------------------------------

    async def build_auth(self) -> SessionLogin:
        cfg = self._cfg()
        secret = await self.ctx.secrets.resolve(cfg.password)
        password = secret.decode("utf-8") if isinstance(secret, bytes) else str(secret)

        async def login() -> tuple[str, str, None]:
            # self.http is attached after build_auth; resolve it lazily here.
            if cfg.auth_mode == "domain_session":
                return await domain_login(self.http, cfg, password)
            return await rest_login(self.http, cfg, password)

        self._session = SessionLogin(login, clock=self.ctx.clock)
        return self._session

    @cached_property
    def api(self) -> ArcherClient:
        session = getattr(self, "_session", None)
        if session is None:
            raise ConfigError("build_auth must run before Archer api access")
        return ArcherClient(lambda: self.http, self._cfg(), session)

    def map_context(self) -> MapContext:
        return MapContext(
            connection_id=self.ctx.connection_id,
            tenant_id=self.ctx.tenant_id,
            connector_kind=self.kind,
            received_at=self.ctx.clock(),
        )

    # -- health and discovery --------------------------------------------

    async def check(self) -> HealthReport:
        capabilities: dict[str, CapabilityHealth] = {}
        status = "healthy"
        vendor_version: str | None = None
        detail: dict[str, Any] = {}

        async def probe(name: str, fn) -> None:
            nonlocal status, vendor_version
            try:
                result = await fn()
                if name == "version":
                    vendor_version = result.version
                if name == "content_api":
                    available, http_status = result
                    detail["content_api_status"] = http_status
                    capabilities[name] = CapabilityHealth(
                        status="healthy" if available else "not_evaluated",
                        reason=None if available else f"HTTP {http_status}",
                    )
                    return
                capabilities[name] = CapabilityHealth(status="healthy")
            except AuthFailed as exc:
                capabilities[name] = CapabilityHealth(status="failing", reason=type(exc).__name__)
                status = "failing"
            except PermissionDenied as exc:
                # A 403 proves nothing about closure: the scope is not evaluable.
                capabilities[name] = CapabilityHealth(status="not_evaluated", reason=type(exc).__name__)
                if status == "healthy":
                    status = "degraded"
            except (RateLimited, TransientVendorError, VendorContractError) as exc:
                capabilities[name] = CapabilityHealth(status="degraded", reason=type(exc).__name__)
                if status == "healthy":
                    status = "degraded"

        await probe("version", self.api.version)
        if status != "failing":
            await probe("metadata", self.api.applications)
            await probe("content_api", self.api.content_api)
        aggregate = capabilities.get("metadata", capabilities.get("version"))
        capabilities["RiskRegister"] = aggregate or CapabilityHealth(status="failing", reason="AuthFailed")
        return HealthReport(
            status=status, capabilities=capabilities, vendor_version=vendor_version, detail=detail
        )

    async def discover(self) -> AsyncIterator[TargetRecord]:
        for app in await self.api.applications():
            app_id = app.get("Id")
            if app_id is None:
                continue
            yield TargetRecord(
                source_uid=str(app_id),
                kind="archer_application",
                display_name=str(app.get("Name") or f"application {app_id}"),
                attributes={"guid": app.get("Guid"), "status": app.get("Status"), "type": app.get("Type")},
            )

    def webhook_verifier(self, secret: bytes) -> None:
        return None

    # -- streams ----------------------------------------------------------

    @stream("vulnerability_scan_results", ocsf_class=2002, cursor=TimeIdCursor,
            modes=("incremental", "full"), capability="RiskRegister", requires_target=False)
    async def vulnerability_scan_results(self, target, checkpoint, mode):
        async for batch in streams.run_stream(self, "vulnerability_scan_results", target, checkpoint, mode):
            yield batch

    @stream("assessment_findings", ocsf_class=2003, cursor=TimeIdCursor,
            modes=("incremental", "full"), capability="RiskRegister", requires_target=False)
    async def assessment_findings(self, target, checkpoint, mode):
        async for batch in streams.run_stream(self, "assessment_findings", target, checkpoint, mode):
            yield batch

    @stream("risks", cursor=TimeIdCursor, modes=("incremental", "full"),
            capability="RiskRegister", requires_target=False)
    async def risks(self, target, checkpoint, mode):
        async for batch in streams.run_stream(self, "risks", target, checkpoint, mode):
            yield batch

    @stream("exception_requests", cursor=TimeIdCursor, modes=("incremental", "full"),
            capability="RiskRegister", requires_target=False)
    async def exception_requests(self, target, checkpoint, mode):
        async for batch in streams.run_stream(self, "exception_requests", target, checkpoint, mode):
            yield batch

    @stream("remediation_plans", cursor=TimeIdCursor, modes=("incremental", "full"),
            capability="RiskRegister", requires_target=False)
    async def remediation_plans(self, target, checkpoint, mode):
        async for batch in streams.run_stream(self, "remediation_plans", target, checkpoint, mode):
            yield batch

    @stream("applications_devices", cursor=TimeIdCursor, modes=("incremental", "full"),
            capability="RiskRegister", requires_target=False)
    async def applications_devices(self, target, checkpoint, mode):
        async for batch in streams.run_stream(self, "applications_devices", target, checkpoint, mode):
            yield batch

    @stream("vulnerability_library", cursor=TimeIdCursor, modes=("incremental", "full"),
            capability="RiskRegister", requires_target=False)
    async def vulnerability_library(self, target, checkpoint, mode):
        async for batch in streams.run_stream(self, "vulnerability_library", target, checkpoint, mode):
            yield batch

    @stream("attachments", cursor=SnapshotCursor, modes=("full",),
            capability="RiskRegister", requires_target=False)
    async def attachments(self, target, checkpoint, mode):
        async for batch in streams.run_stream(self, "attachments", target, checkpoint, mode):
            yield batch

    @stream("history", cursor=SnapshotCursor, modes=("full",),
            capability="RiskRegister", requires_target=False)
    async def history(self, target, checkpoint, mode):
        async for batch in streams.run_stream(self, "history", target, checkpoint, mode):
            yield batch

    @stream("data_feed_runs", cursor=SnapshotCursor, modes=("full",),
            capability="RiskRegister", requires_target=False)
    async def data_feed_runs(self, target, checkpoint, mode):
        async for batch in streams.run_stream(self, "data_feed_runs", target, checkpoint, mode):
            yield batch

    # -- mappers ----------------------------------------------------------

    @mapper("vulnerability_scan_results", version=1)
    def map_vulnerability_scan_results(self, raw, ctx):
        return mappers.map_record(self, "vulnerability_scan_results", raw, ctx)

    @mapper("assessment_findings", version=1)
    def map_assessment_findings(self, raw, ctx):
        return mappers.map_record(self, "assessment_findings", raw, ctx)

    @mapper("risks", version=1)
    def map_risks(self, raw, ctx):
        return mappers.map_record(self, "risks", raw, ctx)

    @mapper("exception_requests", version=1)
    def map_exception_requests(self, raw, ctx):
        return mappers.map_record(self, "exception_requests", raw, ctx)

    @mapper("remediation_plans", version=1)
    def map_remediation_plans(self, raw, ctx):
        return mappers.map_record(self, "remediation_plans", raw, ctx)

    @mapper("applications_devices", version=1)
    def map_applications_devices(self, raw, ctx):
        return mappers.map_record(self, "applications_devices", raw, ctx)

    @mapper("vulnerability_library", version=1)
    def map_vulnerability_library(self, raw, ctx):
        return mappers.map_record(self, "vulnerability_library", raw, ctx)

    @mapper("attachments", version=1)
    def map_attachments(self, raw, ctx):
        return mappers.map_record(self, "attachments", raw, ctx)

    @mapper("history", version=1)
    def map_history(self, raw, ctx):
        return mappers.map_record(self, "history", raw, ctx)

    @mapper("data_feed_runs", version=1)
    def map_data_feed_runs(self, raw, ctx):
        return mappers.map_record(self, "data_feed_runs", raw, ctx)

    # -- read operations --------------------------------------------------

    @operation("get_version", input_model=EmptyInput, output_model=VersionOutput,
               classification="read", capability="RiskRegister", egress_class="vendor_tenant")
    async def get_version(self, args: EmptyInput) -> VersionOutput:
        return await operations.get_version(self, args)

    @operation("list_applications", input_model=EmptyInput, output_model=ItemsOutput,
               classification="read", capability="RiskRegister", egress_class="vendor_tenant")
    async def list_applications(self, args: EmptyInput) -> ItemsOutput:
        return await operations.list_applications(self, args)

    @operation("list_levels", input_model=ApplicationRef, output_model=ItemsOutput,
               classification="read", capability="RiskRegister", egress_class="vendor_tenant")
    async def list_levels(self, args: ApplicationRef) -> ItemsOutput:
        return await operations.list_levels(self, args)

    @operation("list_fields", input_model=LevelRef, output_model=ItemsOutput,
               classification="read", capability="RiskRegister", egress_class="vendor_tenant")
    async def list_fields(self, args: LevelRef) -> ItemsOutput:
        return await operations.list_fields(self, args)

    @operation("list_values", input_model=ValuesListRef, output_model=ItemsOutput,
               classification="read", capability="RiskRegister", egress_class="vendor_tenant")
    async def list_values(self, args: ValuesListRef) -> ItemsOutput:
        return await operations.list_values(self, args)

    @operation("discover_content_api", input_model=EmptyInput, output_model=DiscoverOutput,
               classification="read", capability="RiskRegister", egress_class="vendor_tenant")
    async def discover_content_api(self, args: EmptyInput) -> DiscoverOutput:
        return await operations.discover_content_api(self, args)

    @operation("search_content", input_model=SearchContentArgs, output_model=SearchContentOutput,
               classification="read", capability="RiskRegister", egress_class="vendor_tenant")
    async def search_content(self, args: SearchContentArgs) -> SearchContentOutput:
        return await operations.search_content(self, args)

    @operation("get_content", input_model=ContentRef, output_model=ContentOutput,
               classification="read", capability="RiskRegister", egress_class="vendor_tenant")
    async def get_content(self, args: ContentRef) -> ContentOutput:
        return await operations.get_content(self, args)

    @operation("get_record_soap", input_model=ContentRef, output_model=ContentOutput,
               classification="read", capability="RiskRegister", egress_class="vendor_tenant")
    async def get_record_soap(self, args: ContentRef) -> ContentOutput:
        return await operations.get_record_soap(self, args)

    @operation("get_history", input_model=ContentRef, output_model=HistoryOutput,
               classification="read", capability="RiskRegister", egress_class="vendor_tenant")
    async def get_history(self, args: ContentRef) -> HistoryOutput:
        return await operations.get_history(self, args)

    @operation("get_attachment", input_model=AttachmentRef, output_model=AttachmentOutput,
               classification="read", capability="RiskRegister", egress_class="vendor_tenant")
    async def get_attachment(self, args: AttachmentRef) -> AttachmentOutput:
        return await operations.get_attachment(self, args)

    @operation("get_data_feed_history", input_model=DataFeedHistoryInput, output_model=DataFeedHistoryOutput,
               classification="read", capability="RiskRegister", egress_class="vendor_tenant")
    async def get_data_feed_history(self, args: DataFeedHistoryInput) -> DataFeedHistoryOutput:
        return await operations.get_data_feed_history(self, args)

    # -- actions ----------------------------------------------------------

    @action("create_finding_or_exception", classification="write", capability="RiskRegister",
            input_model=CreateFindingOrExceptionInput, idempotency="natural_key")
    async def create_finding_or_exception(self, args: CreateFindingOrExceptionInput):
        return await actions.plan_create(self, args)

    @create_finding_or_exception.apply
    async def _apply_create(self, plan):
        return await actions.apply_create(self, plan)

    @create_finding_or_exception.reconcile
    async def _reconcile_create(self, plan, outcome):
        return await actions.reconcile_create(self, plan, outcome)

    @action("update_finding_or_exception", classification="write", capability="RiskRegister",
            input_model=UpdateFindingOrExceptionInput, idempotency="natural_key")
    async def update_finding_or_exception(self, args: UpdateFindingOrExceptionInput):
        return await actions.plan_update(self, args)

    @update_finding_or_exception.apply
    async def _apply_update(self, plan):
        return await actions.apply_update(self, plan)

    @update_finding_or_exception.reconcile
    async def _reconcile_update(self, plan, outcome):
        return await actions.reconcile_update(self, plan, outcome)

    @action("upload_attachment", classification="write", capability="RiskRegister",
            input_model=UploadAttachmentInput, idempotency="natural_key")
    async def upload_attachment(self, args: UploadAttachmentInput):
        return await actions.plan_upload_attachment(self, args)

    @upload_attachment.apply
    async def _apply_upload_attachment(self, plan):
        return await actions.apply_upload_attachment(self, plan)

    @upload_attachment.reconcile
    async def _reconcile_upload_attachment(self, plan, outcome):
        return await actions.reconcile_upload_attachment(self, plan, outcome)

    @action("execute_data_feed", classification="write", capability="RiskRegister",
            input_model=ExecuteDataFeedInput, idempotency="natural_key")
    async def execute_data_feed(self, args: ExecuteDataFeedInput):
        return await actions.plan_execute_data_feed(self, args)

    @execute_data_feed.apply
    async def _apply_execute_data_feed(self, plan):
        return await actions.apply_execute_data_feed(self, plan)

    @execute_data_feed.reconcile
    async def _reconcile_execute_data_feed(self, plan, outcome):
        return await actions.reconcile_execute_data_feed(self, plan, outcome)

    @action("delete_content", classification="destructive", capability="RiskRegister",
            input_model=DeleteContentInput, idempotency="none")
    async def delete_content(self, args: DeleteContentInput):
        return await actions.plan_delete(self, args)

    @delete_content.apply
    async def _apply_delete(self, plan):
        return await actions.apply_delete(self, plan)

    @delete_content.reconcile
    async def _reconcile_delete(self, plan, outcome):
        return await actions.reconcile_delete(self, plan, outcome)
