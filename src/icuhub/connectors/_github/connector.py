"""Shared GitHub connector bindings, authentication, health, actions, and webhooks."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any, ClassVar, Literal

from pydantic import BaseModel

from icuhub.connectors._github import actions, mappers, operations, streams
from icuhub.connectors._github.base import GITHUB_EVENT_HEADER, GitHubBase
from icuhub.connectors._github.models import (
    CheckRunArgs,
    CreateCommitStatusArgs,
    CreatePrCommentArgs,
    CreatePullRequestArgs,
    CreateReviewArgs,
    GitHubConfig,
    MergePullRequestArgs,
    UpdateCodeScanningAlertArgs,
    UploadSarifArgs,
    VendorResult,
)
from icuhub.connectors._github.webhooks import GITHUB_WEBHOOK_EVENTS, hints_for_delivery
from icuhub.kit.auth import AuthStrategy, BearerToken, GitHubAppAuth
from icuhub.kit.connector import action, mapper, operation, stream, webhook
from icuhub.kit.cursors import SequenceCursor, SnapshotCursor, TimeIdCursor
from icuhub.kit.errors import AuthFailed, ConfigError, ConnectorError, NotFound, PermissionDenied, VendorContractError
from icuhub.kit.types import (
    CapabilityHealth,
    HealthReport,
    MapContext,
    RawBatch,
    Scope,
    StreamRecord,
    Target,
    WebhookDelivery,
)

__all__ = ["GitHubConnectorBase"]

_StreamOptions = dict[str, Any]

# Metadata lives here because the shared stream implementation is deliberately table-driven.
# Every name must match streams.run_stream; the import-time check below prevents silent drift.
_STREAM_SPECS: dict[str, _StreamOptions] = {
    "code_scanning_alerts": {
        "cursor": TimeIdCursor,
        "capability": "FindingSource",
        "ocsf_class": 2002,
        "modes": ("incremental", "full"),
    },
    "dependabot_alerts": {
        "cursor": TimeIdCursor,
        "capability": "FindingSource",
        "ocsf_class": 2002,
        "modes": ("incremental", "full"),
    },
    "secret_scanning_alerts": {
        "cursor": TimeIdCursor,
        "capability": "FindingSource",
        "ocsf_class": 2004,
        "modes": ("incremental", "full"),
    },
    "branch_protection": {
        "cursor": SnapshotCursor,
        "capability": "FindingSource",
        "ocsf_class": 2003,
    },
    "pull_requests": {
        "cursor": TimeIdCursor,
        "capability": "SourceControl",
        "modes": ("incremental", "full"),
        "record_type": "ticket",
    },
    "reviews": {
        "cursor": TimeIdCursor,
        "capability": "SourceControl",
        "modes": ("incremental", "full"),
        "record_type": "comment",
    },
    "review_comments": {
        "cursor": TimeIdCursor,
        "capability": "SourceControl",
        "modes": ("incremental", "full"),
        "record_type": "comment",
    },
    "audit_events": {
        "cursor": TimeIdCursor,
        "capability": "TelemetrySource",
        "ocsf_class": 6003,
        "modes": ("incremental", "full"),
        "requires_target": False,
    },
    "audit_stream_files": {
        "cursor": SequenceCursor,
        "capability": "TelemetrySource",
        "ocsf_class": 6003,
        "modes": ("incremental",),
    },
    "repositories": {"cursor": SnapshotCursor, "capability": "SourceControl", "requires_target": False},
    "organizations": {"cursor": SnapshotCursor, "capability": "SourceControl", "requires_target": False},
    "users": {"cursor": SnapshotCursor, "capability": "SourceControl", "requires_target": False},
    "teams": {"cursor": SnapshotCursor, "capability": "SourceControl", "requires_target": False},
    "team_members": {"cursor": SnapshotCursor, "capability": "SourceControl", "requires_target": False},
    "team_repositories": {"cursor": SnapshotCursor, "capability": "SourceControl", "requires_target": False},
    "collaborators": {"cursor": SnapshotCursor, "capability": "SourceControl"},
    "organization_external_identities": {
        "cursor": SnapshotCursor,
        "capability": "SourceControl",
        "requires_target": False,
    },
    "branches": {"cursor": SnapshotCursor, "capability": "SourceControl"},
    "tags": {"cursor": SnapshotCursor, "capability": "SourceControl"},
    "commits": {
        "cursor": TimeIdCursor,
        "capability": "SourceControl",
        "modes": ("incremental", "full"),
    },
    "repository_files": {"cursor": SnapshotCursor, "capability": "SourceControl"},
    "workflows": {
        "cursor": TimeIdCursor,
        "capability": "SourceControl",
        "modes": ("incremental", "full"),
    },
    "workflow_runs": {
        "cursor": TimeIdCursor,
        "capability": "SourceControl",
        "modes": ("incremental", "full"),
    },
    "workflow_jobs": {
        "cursor": TimeIdCursor,
        "capability": "SourceControl",
        "modes": ("incremental", "full"),
    },
    "workflow_artifacts": {"cursor": SnapshotCursor, "capability": "SourceControl"},
    "actions_caches": {"cursor": SnapshotCursor, "capability": "SourceControl"},
    "actions_runners": {"cursor": SnapshotCursor, "capability": "SourceControl", "requires_target": False},
    "commit_statuses": {"cursor": SnapshotCursor, "capability": "SourceControl", "modes": ("incremental", "full")},
    "check_runs": {"cursor": SnapshotCursor, "capability": "SourceControl", "modes": ("incremental", "full")},
}

if set(_STREAM_SPECS) != set(streams._STREAM_NAMES):  # noqa: SLF001 - same-family binding contract
    raise TypeError("GitHub stream bindings do not match the shared stream implementation")

_AUDIT_OPERATIONS = frozenset({"list_audit_events"})
_FINDING_OPERATIONS = frozenset(
    {
        "get_branch_protection",
        "get_ruleset",
        "list_code_scanning_alerts",
        "get_code_scanning_alert",
        "list_code_scanning_alert_instances",
        "get_code_scanning_analysis",
        "list_dependabot_alerts",
        "list_secret_scanning_alerts",
    }
)
_SECURITY_SINK_OPERATIONS = frozenset({"get_sarif_status"})


def _principal_id(body: Any, endpoint: str) -> int:
    """Return the integer ``id`` of an App or user response; anything else is a contract break."""
    value = body.get("id") if isinstance(body, dict) else None
    if not isinstance(value, int) or isinstance(value, bool):
        raise VendorContractError(f"GitHub {endpoint} response has no integer id")
    return value


def _operation_capability(name: str) -> str:
    if name in _AUDIT_OPERATIONS:
        return "TelemetrySource"
    if name in _FINDING_OPERATIONS:
        return "FindingSource"
    if name in _SECURITY_SINK_OPERATIONS:
        return "CodeScanningSink"
    return "SourceControl"


def _declare_stream(name: str, **options: Any):
    @stream(
        name,
        cursor=options["cursor"],
        capability=options["capability"],
        ocsf_class=options.get("ocsf_class"),
        record_type=options.get("record_type"),
        modes=options.get("modes", ("full",)),
        requires_target=options.get("requires_target", True),
    )
    async def read(
        connector: GitHubConnectorBase,
        target: Target | None,
        checkpoint: BaseModel | None,
        mode: str,
    ) -> AsyncIterator[RawBatch]:
        async for batch in streams.run_stream(connector, name, target, checkpoint, mode):
            yield batch

    return read


def _declare_mapper(name: str):
    @mapper(name, 1)
    def map_record(
        connector: GitHubConnectorBase, raw: dict[str, Any], ctx: MapContext
    ) -> list[BaseModel]:
        return mappers.map_stream_record(connector, name, raw, ctx)

    return map_record


def _declare_operation(name: str, input_model: type[BaseModel]):
    @operation(
        name,
        input_model=input_model,
        output_model=VendorResult,
        capability=_operation_capability(name),
    )
    async def execute(connector: GitHubConnectorBase, args: BaseModel) -> VendorResult:
        return await operations.execute_operation(connector, name, args)

    return execute


class GitHubConnectorBase(GitHubBase):
    """GitHub REST and webhook behavior shared by github.com and GHES editions."""

    version: ClassVar[str] = "0.1.0"
    auth_modes: ClassVar[tuple[str, ...]] = ("GitHubAppAuth", "BearerToken")
    capabilities: ClassVar[tuple[str, ...]] = (
        "SourceControl",
        "CodeScanningSink",
        "FindingSource",
        "TelemetrySource",
    )
    scopes: ClassVar[tuple[Scope, ...]] = (
        Scope(name="metadata", probe="GET /rate_limit", required_by=("SourceControl",)),
        Scope(
            name="installation_repositories",
            probe="GET /installation/repositories",
            required_by=("SourceControl",),
        ),
        Scope(
            name="code_scanning_read",
            probe="GET /repos/{owner}/{repo}/code-scanning/alerts",
            required_by=("FindingSource",),
        ),
        Scope(
            name="code_scanning_write",
            probe="Approved SARIF upload or alert update with read-back",
            required_by=("CodeScanningSink",),
        ),
        Scope(
            name="administration_read",
            probe="GET /repos/{owner}/{repo}/branches/{branch}/protection",
            required_by=("FindingSource",),
        ),
        Scope(
            name="enterprise_audit_read",
            probe="GET /enterprises/{enterprise}/audit-log",
            required_by=("TelemetrySource",),
        ),
    )

    # Bind the table-driven shared implementations into the kit's per-class registry.
    for _name, _options in _STREAM_SPECS.items():
        locals()[f"stream_{_name}"] = _declare_stream(_name, **_options)
        locals()[f"map_{_name}"] = _declare_mapper(_name)
    del _name, _options

    # The operation table owns each typed input model; bindings never duplicate that contract.
    for _name, (_input_model, _handler) in operations._OPERATIONS.items():  # noqa: SLF001 - binding contract
        locals()[f"operation_{_name}"] = _declare_operation(_name, _input_model)
    del _name, _input_model, _handler

    def _config(self) -> GitHubConfig:
        config = self.config
        assert isinstance(config, GitHubConfig)
        return config

    def api_root(self) -> str:
        return self._config().base_url.rstrip("/")

    def installation_id(self) -> str:
        return self._config().installation_id or self.ctx.connection_id

    async def build_auth(self) -> AuthStrategy:
        config = self._config()
        if config.personal_access_token is not None:
            raw = await self.ctx.secrets.resolve(config.personal_access_token)
            try:
                token = raw.decode("ascii")
            except UnicodeDecodeError as exc:
                raise ConfigError("GitHub personal access token must be ASCII") from exc
            if not token:
                raise ConfigError("GitHub personal access token must not be empty")
            return BearerToken(token)

        # GitHubConfig validates that all three App fields are present together.
        assert config.app_id is not None
        assert config.app_private_key is not None
        assert config.installation_id is not None
        private_key = await self.ctx.secrets.resolve(config.app_private_key)
        return GitHubAppAuth(
            app_id=config.app_id,
            private_key_pem=private_key,
            installation_id=config.installation_id,
            api_base=self.api_root(),
            clock=self.ctx.clock,
        )

    @staticmethod
    def _not_evaluated(reason: str) -> CapabilityHealth:
        return CapabilityHealth(status="not_evaluated", reason=reason)

    async def _optional_probe(
        self,
        path: str,
        capability_names: tuple[str, ...],
        capabilities: dict[str, CapabilityHealth],
    ) -> Literal["healthy", "degraded"]:
        try:
            response = await self.request("GET", path, params={"per_page": 1})
            body = response.json()
            if not isinstance(body, (dict, list)):
                raise VendorContractError(f"GitHub probe {path} must return a JSON object or array")
        except (PermissionDenied, NotFound) as exc:
            for name in capability_names:
                capabilities[name] = self._not_evaluated(type(exc).__name__)
            return "healthy"
        except (ConnectorError, OSError, TimeoutError, RuntimeError) as exc:
            for name in capability_names:
                capabilities[name] = CapabilityHealth(status="degraded", reason=type(exc).__name__)
            return "degraded"
        for name in capability_names:
            capabilities[name] = CapabilityHealth(status="healthy")
        return "healthy"

    @staticmethod
    def _degrade(current: Literal["healthy", "degraded"], probe: Literal["healthy", "degraded"]) -> Literal[
        "healthy", "degraded"
    ]:
        return "degraded" if "degraded" in (current, probe) else "healthy"

    async def _verify_identity(self) -> None:
        """Prove the configured credential belongs to the configured identity.

        App auth calls ``GET /app`` with an App JWT (installation tokens cannot read it) and
        requires the returned App id to equal ``app_id``. PAT auth calls ``GET /user``.
        """
        config = self._config()
        if config.app_id is not None:
            auth = await self.build_auth()
            if not isinstance(auth, GitHubAppAuth):
                raise ConfigError("App configuration must resolve to GitHubAppAuth")
            response = await self.http.request(
                "GET",
                self.rest_url("/app"),
                headers={**self.api_headers(), "Authorization": f"Bearer {auth.app_jwt()}"},
                authenticate=False,
            )
            value = _principal_id(response.json(), "/app")
            if str(value) != str(config.app_id):
                raise AuthFailed(f"GitHub App id {value} does not match configured app_id")
            return
        _principal_id((await self.request("GET", "/user")).json(), "/user")

    async def check(self) -> HealthReport:
        detail = {
            "edition": self.kind,
            "api_root": self.api_root(),
            "api_version": self._config().api_version,
            "installation_id": self.installation_id(),
        }
        try:
            body = (await self.request("GET", "/rate_limit")).json()
            if not isinstance(body, dict):
                raise VendorContractError("GitHub /rate_limit response must be a JSON object")
            await self._verify_identity()
        except AuthFailed as exc:
            capabilities = {
                name: CapabilityHealth(status="failing", reason=type(exc).__name__)
                if name == "SourceControl"
                else self._not_evaluated(type(exc).__name__)
                for name in self.capabilities
            }
            return HealthReport(status="failing", capabilities=capabilities, detail=detail)
        except PermissionDenied as exc:
            capabilities = {
                name: CapabilityHealth(status="degraded", reason=type(exc).__name__)
                if name == "SourceControl"
                else self._not_evaluated(type(exc).__name__)
                for name in self.capabilities
            }
            return HealthReport(status="degraded", capabilities=capabilities, detail=detail)
        except (ConnectorError, OSError, TimeoutError, RuntimeError) as exc:
            capabilities = {
                name: CapabilityHealth(status="degraded", reason=type(exc).__name__)
                if name == "SourceControl"
                else self._not_evaluated(type(exc).__name__)
                for name in self.capabilities
            }
            return HealthReport(status="degraded", capabilities=capabilities, detail=detail)

        capabilities = {
            "SourceControl": CapabilityHealth(status="healthy"),
            "CodeScanningSink": self._not_evaluated("write scope requires an approved action with read-back"),
            "FindingSource": self._not_evaluated("probe_repository is not configured"),
            "TelemetrySource": self._not_evaluated("enterprise is not configured"),
        }
        status: Literal["healthy", "degraded"] = "healthy"
        config = self._config()
        if config.app_id is not None:
            probe = await self._optional_probe("/installation/repositories", ("SourceControl",), capabilities)
            status = self._degrade(status, probe)
        if config.probe_repository is not None:
            probe = await self._optional_probe(
                f"/repos/{config.probe_repository}/code-scanning/alerts",
                ("FindingSource",),
                capabilities,
            )
            status = self._degrade(status, probe)
        if config.enterprise is not None:
            probe = await self._optional_probe(
                f"/enterprises/{config.enterprise}/audit-log",
                ("TelemetrySource",),
                capabilities,
            )
            status = self._degrade(status, probe)
        return HealthReport(status=status, capabilities=capabilities, detail=detail)

    @webhook(event_types=GITHUB_WEBHOOK_EVENTS, header_event=GITHUB_EVENT_HEADER)
    def receive_event(self, delivery: WebhookDelivery) -> list[StreamRecord]:
        event = delivery.headers.get(GITHUB_EVENT_HEADER, "")
        return hints_for_delivery(event, delivery, app_id=self._config().app_id)

    # --- governed actions ---------------------------------------------------------------------

    @action(
        "upload_code_scanning_sarif",
        classification="write",
        capability="CodeScanningSink",
        input_model=UploadSarifArgs,
        idempotency="natural_key",
    )
    async def action_upload_code_scanning_sarif(self, args: UploadSarifArgs):
        return await actions.plan_upload_code_scanning_sarif(self, args)

    @action_upload_code_scanning_sarif.apply
    async def _apply_upload_code_scanning_sarif(self, plan):
        return await actions.apply_upload_code_scanning_sarif(self, plan)

    @action_upload_code_scanning_sarif.reconcile
    async def _reconcile_upload_code_scanning_sarif(self, plan, outcome):
        return await actions.reconcile_upload_code_scanning_sarif(self, plan, outcome)

    @action(
        "update_code_scanning_alert",
        classification="write",
        capability="FindingSource",
        input_model=UpdateCodeScanningAlertArgs,
        idempotency="natural_key",
    )
    async def action_update_code_scanning_alert(self, args: UpdateCodeScanningAlertArgs):
        return await actions.plan_update_code_scanning_alert(self, args)

    @action_update_code_scanning_alert.apply
    async def _apply_update_code_scanning_alert(self, plan):
        return await actions.apply_update_code_scanning_alert(self, plan)

    @action_update_code_scanning_alert.reconcile
    async def _reconcile_update_code_scanning_alert(self, plan, outcome):
        return await actions.reconcile_update_code_scanning_alert(self, plan, outcome)

    @action(
        "create_pr_comment",
        classification="write",
        capability="SourceControl",
        input_model=CreatePrCommentArgs,
        idempotency="key",
    )
    async def action_create_pr_comment(self, args: CreatePrCommentArgs):
        return await actions.plan_create_pr_comment(self, args)

    @action_create_pr_comment.apply
    async def _apply_create_pr_comment(self, plan):
        return await actions.apply_create_pr_comment(self, plan)

    @action_create_pr_comment.reconcile
    async def _reconcile_create_pr_comment(self, plan, outcome):
        return await actions.reconcile_create_pr_comment(self, plan, outcome)

    @action(
        "create_review",
        classification="write",
        capability="SourceControl",
        input_model=CreateReviewArgs,
        idempotency="natural_key",
    )
    async def action_create_review(self, args: CreateReviewArgs):
        return await actions.plan_create_review(self, args)

    @action_create_review.apply
    async def _apply_create_review(self, plan):
        return await actions.apply_create_review(self, plan)

    @action_create_review.reconcile
    async def _reconcile_create_review(self, plan, outcome):
        return await actions.reconcile_create_review(self, plan, outcome)

    @action(
        "create_pull_request",
        classification="write",
        capability="SourceControl",
        input_model=CreatePullRequestArgs,
        idempotency="natural_key",
    )
    async def action_create_pull_request(self, args: CreatePullRequestArgs):
        return await actions.plan_create_pull_request(self, args)

    @action_create_pull_request.apply
    async def _apply_create_pull_request(self, plan):
        return await actions.apply_create_pull_request(self, plan)

    @action_create_pull_request.reconcile
    async def _reconcile_create_pull_request(self, plan, outcome):
        return await actions.reconcile_create_pull_request(self, plan, outcome)

    @action(
        "create_commit_status",
        classification="write",
        capability="SourceControl",
        input_model=CreateCommitStatusArgs,
        idempotency="natural_key",
    )
    async def action_create_commit_status(self, args: CreateCommitStatusArgs):
        return await actions.plan_create_commit_status(self, args)

    @action_create_commit_status.apply
    async def _apply_create_commit_status(self, plan):
        return await actions.apply_create_commit_status(self, plan)

    @action_create_commit_status.reconcile
    async def _reconcile_create_commit_status(self, plan, outcome):
        return await actions.reconcile_create_commit_status(self, plan, outcome)

    @action(
        "create_or_update_check_run",
        classification="write",
        capability="SourceControl",
        input_model=CheckRunArgs,
        idempotency="key",
    )
    async def action_create_or_update_check_run(self, args: CheckRunArgs):
        return await actions.plan_create_or_update_check_run(self, args)

    @action_create_or_update_check_run.apply
    async def _apply_create_or_update_check_run(self, plan):
        return await actions.apply_create_or_update_check_run(self, plan)

    @action_create_or_update_check_run.reconcile
    async def _reconcile_create_or_update_check_run(self, plan, outcome):
        return await actions.reconcile_create_or_update_check_run(self, plan, outcome)

    @action(
        "merge_pull_request",
        classification="destructive",
        capability="SourceControl",
        input_model=MergePullRequestArgs,
        idempotency="natural_key",
    )
    async def action_merge_pull_request(self, args: MergePullRequestArgs):
        return await actions.plan_merge_pull_request(self, args)

    @action_merge_pull_request.apply
    async def _apply_merge_pull_request(self, plan):
        return await actions.apply_merge_pull_request(self, plan)

    @action_merge_pull_request.reconcile
    async def _reconcile_merge_pull_request(self, plan, outcome):
        return await actions.reconcile_merge_pull_request(self, plan, outcome)
