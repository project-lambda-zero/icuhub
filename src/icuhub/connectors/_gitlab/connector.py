"""Shared GitLab connector: auth, REST client, governed actions, and Standard Webhooks.

GitLab.com and GitLab Self-Managed share this base. Edition packages add ``kind``,
``display_name``, and ``config_model``. Ultimate-only publication fails closed: ``require_ultimate``
raises ``PermissionDenied`` unless the host reports the Ultimate plan.
"""

from __future__ import annotations

import io
import zipfile
from typing import Any, ClassVar, Literal

from pydantic import BaseModel

from icuhub.connectors._gitlab import actions, exports, mappers, operations, streams
from icuhub.connectors._gitlab.graphql import traverse_vulnerabilities
from icuhub.connectors._gitlab.models import (
    ApproveMergeRequestArgs,
    ChangeVulnerabilityStateArgs,
    ControlJobArgs,
    ControlPipelineArgs,
    CreateMergeRequestArgs,
    CreateMrNoteOrDiscussionArgs,
    CreateVulnerabilityExportInput,
    GitLabConfig,
    MergeMergeRequestArgs,
    PublishSecurityReportArtifactArgs,
    VendorResult,
)
from icuhub.connectors._gitlab.webhooks import RotatingStandardWebhooks
from icuhub.kit import (
    AuthStrategy,
    BearerToken,
    CapabilityHealth,
    ConfigError,
    Connector,
    HeaderToken,
    HealthReport,
    NotFound,
    VendorContractError,
    WebhookVerifier,
    action,
    operation,
)
from icuhub.kit.errors import BudgetExhausted, ConnectorError, PermissionDenied
from icuhub.kit.paginate import link_header_pages

__all__ = ["GitLabConnectorBase"]

_FINDING_OPERATIONS = frozenset(
    {"list_vulnerabilities", "get_vulnerability_detail", "get_vulnerability_export", "download_vulnerability_export"}
)


def _operation_capability(name: str) -> str:
    return "FindingSource" if name in _FINDING_OPERATIONS else "SourceControl"


def _declare_operation(name: str, input_model: type[BaseModel]):
    @operation(
        name,
        input_model=input_model,
        output_model=VendorResult,
        capability=_operation_capability(name),
    )
    async def execute(connector: GitLabConnectorBase, args: BaseModel) -> VendorResult:
        return await operations.execute_operation(connector, name, args)

    return execute


# GitLab's REST vulnerability state endpoints. The docs mark these deprecated and unstable, so
# they are used as-is and never replaced with an invented GraphQL mutation.
_VULNERABILITY_VERBS: dict[str, str] = {
    "confirmed": "confirm",
    "resolved": "resolve",
    "dismissed": "dismiss",
    "detected": "revert",
}
_SARIF_SUFFIXES = (".sarif", ".sarif.json")
_ULTIMATE_PLAN = "ultimate"


def _list_items(body: Any) -> list[dict[str, Any]]:
    if not isinstance(body, list):
        raise VendorContractError("GitLab list response is not a JSON array")
    return body


class GitLabConnectorBase(Connector):
    """GitLab REST, governed actions, and Standard Webhooks shared by both editions."""

    version: ClassVar[str] = "0.1.0"
    auth_modes: ClassVar[tuple[str, ...]] = ("HeaderToken", "BearerToken")
    capabilities: ClassVar[tuple[str, ...]] = ("SourceControl", "CodeScanningSink", "FindingSource")

    _current_user_id: int | None = None

    # Stream declarations. Each name is the stream's registered name; mappers bind by the same name.
    vulnerabilities = streams.vulnerabilities
    merge_requests = streams.merge_requests
    audit_events = streams.audit_events
    group_audit_events = streams.group_audit_events
    projects = streams.projects
    groups = streams.groups
    group_members = streams.group_members
    project_members = streams.project_members
    labels = streams.labels
    milestones = streams.milestones
    branches = streams.branches
    tags = streams.tags
    commits = streams.commits
    repository_tree = streams.repository_tree
    pipelines = streams.pipelines
    jobs = streams.jobs
    pipeline_bridges = streams.pipeline_bridges
    pipeline_test_reports = streams.pipeline_test_reports
    pipeline_variables = streams.pipeline_variables
    mr_diffs = streams.mr_diffs
    mr_versions = streams.mr_versions
    mr_commits = streams.mr_commits
    mr_pipelines = streams.mr_pipelines
    mr_approval_rules = streams.mr_approval_rules
    mr_approval_state = streams.mr_approval_state
    commit_diffs = streams.commit_diffs
    repository_files = streams.repository_files
    file_blame = streams.file_blame
    job_logs = streams.job_logs
    job_artifacts = streams.job_artifacts

    # Record mappers, one per stream, in the same order.
    map_vulnerability = mappers.map_vulnerability
    map_merge_request = mappers.map_merge_request
    map_audit_event = mappers.map_audit_event
    map_group_audit_event = mappers.map_group_audit_event
    map_project = mappers.map_project
    map_group = mappers.map_group
    map_group_member = mappers.map_group_member
    map_project_member = mappers.map_project_member
    map_label = mappers.map_label
    map_milestone = mappers.map_milestone
    map_branch = mappers.map_branch
    map_tag = mappers.map_tag
    map_commit = mappers.map_commit
    map_repository_tree = mappers.map_repository_tree
    map_pipeline = mappers.map_pipeline
    map_job = mappers.map_job
    map_pipeline_bridge = mappers.map_pipeline_bridge
    map_pipeline_test_report = mappers.map_pipeline_test_report
    map_pipeline_variable = mappers.map_pipeline_variable
    map_mr_diff = mappers.map_mr_diff
    map_mr_version = mappers.map_mr_version
    map_mr_commit = mappers.map_mr_commit
    map_mr_pipeline = mappers.map_mr_pipeline
    map_mr_approval_rule = mappers.map_mr_approval_rule
    map_mr_approval_state = mappers.map_mr_approval_state
    map_commit_diffs = mappers.map_commit_diffs
    map_repository_files = mappers.map_repository_files
    map_file_blame = mappers.map_file_blame
    map_job_logs = mappers.map_job_logs
    map_job_artifacts = mappers.map_job_artifacts

    # The operation table owns each typed input model; bindings never duplicate that contract.
    for _name, (_input_model, _handler) in operations._OPERATIONS.items():  # noqa: SLF001 - binding contract
        locals()[f"operation_{_name}"] = _declare_operation(_name, _input_model)
    del _name, _input_model, _handler

    def _config(self) -> GitLabConfig:
        config = self.config
        assert isinstance(config, GitLabConfig)
        return config

    async def build_auth(self) -> AuthStrategy:
        config = self._config()
        raw = await self.ctx.secrets.resolve(config.access_token)
        try:
            value = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ConfigError("GitLab access token must be UTF-8") from exc
        if not value:
            raise ConfigError("GitLab access token must not be empty")
        if config.auth_method == "oauth_bearer":
            return BearerToken(value)
        header = "JOB-TOKEN" if config.auth_method == "job_token" else "PRIVATE-TOKEN"
        return HeaderToken(header, value)

    async def check(self) -> HealthReport:
        capabilities: dict[str, CapabilityHealth] = {}
        status: Literal["healthy", "degraded"] = "healthy"
        try:
            await self._user_id()
            capabilities["SourceControl"] = CapabilityHealth(status="healthy")
        except PermissionDenied as exc:
            capabilities["SourceControl"] = CapabilityHealth(status="not_evaluated", reason=type(exc).__name__)
        except (ConnectorError, OSError, TimeoutError, RuntimeError) as exc:
            capabilities["SourceControl"] = CapabilityHealth(status="degraded", reason=type(exc).__name__)
            status = "degraded"
        try:
            await self.require_ultimate()
            for name in ("CodeScanningSink", "FindingSource"):
                capabilities[name] = CapabilityHealth(status="healthy")
        except PermissionDenied as exc:
            for name in ("CodeScanningSink", "FindingSource"):
                capabilities[name] = CapabilityHealth(status="not_evaluated", reason=type(exc).__name__)
        except (ConnectorError, OSError, TimeoutError, RuntimeError) as exc:
            for name in ("CodeScanningSink", "FindingSource"):
                capabilities[name] = CapabilityHealth(status="degraded", reason=type(exc).__name__)
            status = "degraded"
        return HealthReport(status=status, capabilities=capabilities, vendor_version=None)

    def webhook_verifier(self, secret: bytes) -> WebhookVerifier | None:
        if not secret:
            raise ConfigError("GitLab webhook secret must not be empty")
        try:
            text = secret.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ConfigError("GitLab webhook secret must be UTF-8") from exc
        return RotatingStandardWebhooks([text], tolerance_s=float(self._config().webhook_tolerance_s))

    # --- REST helpers -------------------------------------------------------------------------

    async def _get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        return (await self.http.request("GET", path, params=params)).json()

    async def _send(
        self,
        method: Literal["POST", "PUT"],
        path: str,
        *,
        body: dict[str, Any] | None,
        idempotency: Literal["idempotent_write", "non_idempotent"],
        expected: tuple[int, ...] = (200, 201),
    ) -> Any:
        result = await self.http.request(method, path, json=body, idempotency=idempotency, expected=expected)
        return result.json()

    async def _collect_partial(
        self, path: str, params: dict[str, Any] | None = None
    ) -> tuple[list[dict[str, Any]], bool]:
        """Return every page read before pagination ended, and whether it ended without exhausting the budget.

        ``complete`` is False only when ``BudgetExhausted`` stopped pagination; the records read so far are kept
        so callers can report them as a partial view. Nothing is closed or checkpointed from an incomplete read.
        """
        config = self._config()
        query = {"per_page": config.page_size, **(params or {})}
        items: list[dict[str, Any]] = []
        try:
            async for page, _ in link_header_pages(
                self.http, path, query, items=_list_items, max_pages=config.max_pages
            ):
                items.extend(page)
        except BudgetExhausted:
            return items, False
        return items, True

    async def _collect(self, path: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        items, complete = await self._collect_partial(path, params)
        if not complete:
            raise BudgetExhausted(f"GitLab pagination of {path} exceeded the page budget")
        return items

    async def _user_id(self) -> int:
        if self._current_user_id is None:
            self._current_user_id = int((await self._get("/user"))["id"])
        return self._current_user_id

    # --- probes -------------------------------------------------------------------------------

    async def require_ultimate(self) -> None:
        """Fail closed unless the host reports the Ultimate plan through ``GET /license``.

        ``GET /license`` is documented for Self-Managed and Dedicated instances and needs an
        administrator token. GitLab.com does not expose its plan at this path, so publication
        is refused there until a live probe is confirmed under ``ICUHUB_ACC=1``.
        A 403 or 404 maps to ``PermissionDenied`` so the health report shows ``not_evaluated``.
        """
        try:
            body = await self._get("/license")
        except NotFound as exc:
            raise PermissionDenied("GitLab license endpoint is unavailable; Ultimate cannot be verified") from exc
        plan = body.get("plan")
        if plan != _ULTIMATE_PLAN:
            raise PermissionDenied(f"GitLab plan {plan!r} does not include Ultimate security features")

    # --- merge requests and discussions -------------------------------------------------------

    async def get_merge_request(self, project_id: int, iid: int) -> dict[str, Any]:
        return await self._get(f"/projects/{project_id}/merge_requests/{iid}")

    async def find_open_merge_request(
        self, project_id: int, source_branch: str, target_branch: str
    ) -> dict[str, Any] | None:
        items = await self._collect(
            f"/projects/{project_id}/merge_requests",
            {"state": "opened", "source_branch": source_branch, "target_branch": target_branch},
        )
        return items[0] if items else None

    async def create_merge_request(
        self, *, project_id: int, source_branch: str, target_branch: str, title: str, description: str | None
    ) -> dict[str, Any]:
        body = {
            "source_branch": source_branch,
            "target_branch": target_branch,
            "title": title,
            "description": description or "",
        }
        return await self._send(
            "POST", f"/projects/{project_id}/merge_requests", body=body, idempotency="non_idempotent"
        )

    async def find_discussion(self, project_id: int, iid: int, action_key: str) -> dict[str, Any] | None:
        """Find the discussion whose note by the integration user has the exact action-key marker line."""
        marker = f"<!-- {actions._ACTION_KEY_MARKER}{action_key} -->"  # noqa: SLF001 -- same marker format
        user_id = await self._user_id()
        for discussion in await self._collect(f"/projects/{project_id}/merge_requests/{iid}/discussions"):
            for note in discussion.get("notes") or []:
                author = note.get("author") or {}
                if author.get("id") == user_id and marker in str(note.get("body", "")).splitlines():
                    return discussion
        return None

    async def create_discussion(
        self, project_id: int, iid: int, body: str, position: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"body": body}
        if position is not None:
            payload["position"] = position
        return await self._send(
            "POST",
            f"/projects/{project_id}/merge_requests/{iid}/discussions",
            body=payload,
            idempotency="non_idempotent",
        )

    async def get_merge_approvals(self, project_id: int, iid: int) -> dict[str, Any]:
        return await self._get(f"/projects/{project_id}/merge_requests/{iid}/approvals")

    async def approve_merge_request(self, project_id: int, iid: int, sha: str) -> dict[str, Any]:
        return await self._send(
            "POST",
            f"/projects/{project_id}/merge_requests/{iid}/approve",
            body={"sha": sha},
            idempotency="idempotent_write",
        )

    async def merge_merge_request(self, project_id: int, iid: int, sha: str) -> dict[str, Any]:
        result = await self.http.request(
            "PUT",
            f"/projects/{project_id}/merge_requests/{iid}/merge",
            json={"sha": sha},
            idempotency="idempotent_write",
            expected=(200,),
        )
        return result.json()

    # --- vulnerabilities and native ingestion -------------------------------------------------

    async def get_vulnerability(self, vulnerability_id: int) -> dict[str, Any]:
        return await self._get(f"/vulnerabilities/{vulnerability_id}")

    async def set_vulnerability_state(self, vulnerability_id: int, state: str) -> dict[str, Any]:
        """Move a vulnerability to ``state`` through the deprecated REST state endpoints."""
        verb = _VULNERABILITY_VERBS.get(state)
        if verb is None:
            raise ConfigError(f"vulnerability state {state!r} has no GitLab REST transition")
        return await self._send(
            "POST",
            f"/vulnerabilities/{vulnerability_id}/{verb}",
            body=None,
            idempotency="idempotent_write",
        )

    async def reconcile_native_vulnerabilities(self, project_id: int, uids: list[str]) -> dict[str, Any]:
        """Report which of ``uids`` the project's native vulnerability findings contain.

        ``complete`` is False when the findings scan exhausts the page budget, so the caller
        reports ``accepted_async`` instead of treating absent UIDs as missing.
        """
        wanted = set(uids)
        findings, complete = await traverse_vulnerabilities(self, project_id)
        found = sorted({finding["uuid"] for finding in findings if finding["uuid"] in wanted})
        return {"complete": complete, "found": found}

    async def download_sarif_artifact(self, project_id: int, job_id: int) -> bytes:
        """Return the single ``.sarif`` or ``.sarif.json`` member of a job artifact archive.

        The compressed archive and the declared and actual uncompressed member sizes are each
        bounded by ``max_artifact_bytes``, so a zip bomb fails before it is fully inflated.
        Raises ``NotFound`` when the archive has no SARIF member.
        """
        config = self._config()
        result = await self.http.request("GET", f"/projects/{project_id}/jobs/{job_id}/artifacts")
        archive = result.content
        if len(archive) > config.max_artifact_bytes:
            raise VendorContractError("artifact archive exceeds max_artifact_bytes")
        try:
            zf = zipfile.ZipFile(io.BytesIO(archive))
        except zipfile.BadZipFile as exc:
            raise VendorContractError("job artifact is not a ZIP archive") from exc
        with zf:
            members = [info for info in zf.infolist() if info.filename.lower().endswith(_SARIF_SUFFIXES)]
            if not members:
                raise NotFound(f"job {job_id} artifacts contain no SARIF member")
            if len(members) > 1:
                raise VendorContractError("job artifacts contain more than one SARIF member")
            member = members[0]
            if member.file_size > config.max_artifact_bytes:
                raise VendorContractError("SARIF member declares a size above max_artifact_bytes")
            with zf.open(member) as handle:
                data = handle.read(config.max_artifact_bytes + 1)
        if len(data) > config.max_artifact_bytes:
            raise VendorContractError("SARIF member inflates above max_artifact_bytes")
        return data

    # --- pipelines and jobs -------------------------------------------------------------------

    async def get_pipeline(self, project_id: int, pipeline_id: int) -> dict[str, Any]:
        return await self._get(f"/projects/{project_id}/pipelines/{pipeline_id}")

    async def control_pipeline(
        self, project_id: int, pipeline_id: int, operation: Literal["retry", "cancel"]
    ) -> dict[str, Any]:
        return await self._send(
            "POST",
            f"/projects/{project_id}/pipelines/{pipeline_id}/{operation}",
            body=None,
            idempotency="non_idempotent",
            expected=(200, 201, 202),
        )

    async def get_job(self, project_id: int, job_id: int) -> dict[str, Any]:
        return await self._get(f"/projects/{project_id}/jobs/{job_id}")

    async def control_job(
        self, project_id: int, job_id: int, operation: Literal["play", "retry", "cancel"]
    ) -> dict[str, Any]:
        return await self._send(
            "POST",
            f"/projects/{project_id}/jobs/{job_id}/{operation}",
            body=None,
            idempotency="non_idempotent",
            expected=(200, 201, 202),
        )

    # --- governed actions ---------------------------------------------------------------------
    # Action wrappers use ``action_<name>`` attributes so they do not shadow the vendor client
    # methods above, which ``actions.py`` calls by bare name. Kit dispatch uses the action string.

    @action(
        "create_merge_request",
        classification="write",
        capability="SourceControl",
        input_model=CreateMergeRequestArgs,
        idempotency="natural_key",
    )
    async def action_create_merge_request(self, args: CreateMergeRequestArgs):
        return await actions.plan_create_merge_request(self, args)

    @action_create_merge_request.apply
    async def _apply_create_merge_request(self, plan):
        return await actions.apply_create_merge_request(self, plan)

    @action_create_merge_request.reconcile
    async def _reconcile_create_merge_request(self, plan, outcome):
        return await actions.reconcile_create_merge_request(self, plan, outcome)

    @action(
        "create_mr_note_or_discussion",
        classification="write",
        capability="SourceControl",
        input_model=CreateMrNoteOrDiscussionArgs,
        idempotency="key",
    )
    async def action_create_mr_note_or_discussion(self, args: CreateMrNoteOrDiscussionArgs):
        return await actions.plan_create_mr_note_or_discussion(self, args)

    @action_create_mr_note_or_discussion.apply
    async def _apply_create_mr_note_or_discussion(self, plan):
        return await actions.apply_create_mr_note_or_discussion(self, plan)

    @action_create_mr_note_or_discussion.reconcile
    async def _reconcile_create_mr_note_or_discussion(self, plan, outcome):
        return await actions.reconcile_create_mr_note_or_discussion(self, plan, outcome)

    @action(
        "approve_merge_request",
        classification="write",
        capability="SourceControl",
        input_model=ApproveMergeRequestArgs,
        idempotency="natural_key",
    )
    async def action_approve_merge_request(self, args: ApproveMergeRequestArgs):
        return await actions.plan_approve_merge_request(self, args)

    @action_approve_merge_request.apply
    async def _apply_approve_merge_request(self, plan):
        return await actions.apply_approve_merge_request(self, plan)

    @action_approve_merge_request.reconcile
    async def _reconcile_approve_merge_request(self, plan, outcome):
        return await actions.reconcile_approve_merge_request(self, plan, outcome)

    @action(
        "change_vulnerability_state",
        classification="write",
        capability="FindingSource",
        input_model=ChangeVulnerabilityStateArgs,
        idempotency="natural_key",
    )
    async def action_change_vulnerability_state(self, args: ChangeVulnerabilityStateArgs):
        return await actions.plan_change_vulnerability_state(self, args)

    @action_change_vulnerability_state.apply
    async def _apply_change_vulnerability_state(self, plan):
        return await actions.apply_change_vulnerability_state(self, plan)

    @action_change_vulnerability_state.reconcile
    async def _reconcile_change_vulnerability_state(self, plan, outcome):
        return await actions.reconcile_change_vulnerability_state(self, plan, outcome)

    @action(
        "create_vulnerability_export",
        classification="write",
        capability="FindingSource",
        input_model=CreateVulnerabilityExportInput,
        idempotency="none",
    )
    async def action_create_vulnerability_export(self, args: CreateVulnerabilityExportInput):
        return await exports.plan_create_vulnerability_export(self, args)

    @action_create_vulnerability_export.apply
    async def _apply_create_vulnerability_export(self, plan):
        return await exports.apply_create_vulnerability_export(self, plan)

    @action_create_vulnerability_export.reconcile
    async def _reconcile_create_vulnerability_export(self, plan, outcome):
        return await exports.reconcile_create_vulnerability_export(self, plan, outcome)

    @action(
        "merge_merge_request",
        classification="destructive",
        capability="SourceControl",
        input_model=MergeMergeRequestArgs,
        idempotency="natural_key",
    )
    async def action_merge_merge_request(self, args: MergeMergeRequestArgs):
        return await actions.plan_merge_merge_request(self, args)

    @action_merge_merge_request.apply
    async def _apply_merge_merge_request(self, plan):
        return await actions.apply_merge_merge_request(self, plan)

    @action_merge_merge_request.reconcile
    async def _reconcile_merge_merge_request(self, plan, outcome):
        return await actions.reconcile_merge_merge_request(self, plan, outcome)

    @action(
        "publish_security_report_artifact",
        classification="write",
        capability="CodeScanningSink",
        input_model=PublishSecurityReportArtifactArgs,
        idempotency="natural_key",
    )
    async def action_publish_security_report_artifact(self, args: PublishSecurityReportArtifactArgs):
        return await actions.plan_publish_security_report_artifact(self, args)

    @action_publish_security_report_artifact.apply
    async def _apply_publish_security_report_artifact(self, plan):
        return await actions.apply_publish_security_report_artifact(self, plan)

    @action_publish_security_report_artifact.reconcile
    async def _reconcile_publish_security_report_artifact(self, plan, outcome):
        return await actions.reconcile_publish_security_report_artifact(self, plan, outcome)

    @action(
        "control_pipeline",
        classification="write",
        capability="SourceControl",
        input_model=ControlPipelineArgs,
        idempotency="natural_key",
    )
    async def action_control_pipeline(self, args: ControlPipelineArgs):
        return await actions.plan_control_pipeline(self, args)

    @action_control_pipeline.apply
    async def _apply_control_pipeline(self, plan):
        return await actions.apply_control_pipeline(self, plan)

    @action_control_pipeline.reconcile
    async def _reconcile_control_pipeline(self, plan, outcome):
        return await actions.reconcile_control_pipeline(self, plan, outcome)

    @action(
        "control_job",
        classification="write",
        capability="SourceControl",
        input_model=ControlJobArgs,
        idempotency="natural_key",
    )
    async def action_control_job(self, args: ControlJobArgs):
        return await actions.plan_control_job(self, args)

    @action_control_job.apply
    async def _apply_control_job(self, plan):
        return await actions.apply_control_job(self, plan)

    @action_control_job.reconcile
    async def _reconcile_control_job(self, plan, outcome):
        return await actions.reconcile_control_job(self, plan, outcome)
