"""GitHub operations: typed REST reads shared by github.com and GHES.

Each entry in ``_OPERATIONS`` pairs a read operation name with the input model it accepts and the handler
that performs the REST call. Handlers return ``VendorResult`` objects that retain the vendor JSON.
Governed writes are owned by the action layer and are not dispatched here.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from typing import Any
from urllib.parse import quote

from pydantic import BaseModel

from icuhub.connectors._github.base import GitHubBase
from icuhub.connectors._github.models import (
    AlertInstancesRef,
    AlertRef,
    AnalysisRef,
    ArtifactRef,
    BranchRef,
    CheckRunRef,
    CollaboratorRef,
    CommitRef,
    EmptyArgs,
    EnterpriseRef,
    FileRef,
    MembershipRef,
    OrgRef,
    PullRef,
    RepoRef,
    ReviewCommentRef,
    ReviewRef,
    RulesetRef,
    SarifStatusRef,
    TagRef,
    TeamRef,
    TreeRef,
    UserRef,
    VendorResult,
    WebhookDeliveryRef,
    WebhookRef,
    WorkflowJobRef,
    WorkflowRef,
    WorkflowRunRef,
)
from icuhub.kit.errors import BudgetExhausted, ConfigError, VendorContractError
from icuhub.kit.http import HttpResult

__all__ = ["execute_operation"]

_Handler = Callable[[GitHubBase, Any], Awaitable[VendorResult]]


def _path(*segments: object) -> str:
    """Join URL path segments, percent-encoding each one and refusing dot segments."""
    encoded: list[str] = []
    for segment in segments:
        text = str(segment)
        if text in (".", ".."):
            raise ConfigError("GitHub path segments may not be '.' or '..'")
        encoded.append(quote(text, safe=""))
    return "/" + "/".join(encoded)


def _file_path(path: str) -> str:
    """Encode a repository-relative file path, keeping its slashes as separators."""
    parts = path.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise ConfigError("GitHub file paths must be normalized repository-relative paths")
    return "/".join(quote(part, safe="") for part in parts)


def _compact(values: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in values.items() if value is not None}


def _object(response: HttpResult) -> VendorResult:
    body = response.json()
    if not isinstance(body, dict):
        raise VendorContractError("GitHub returned a non-object JSON body where an object was expected")
    return VendorResult(data=body, status_code=response.status)


async def _get(connector: GitHubBase, path: str, params: Mapping[str, Any] | None = None) -> VendorResult:
    return _object(await connector.request("GET", path, params=params))


async def _collect(
    connector: GitHubBase,
    path: str,
    params: Mapping[str, Any] | None = None,
    items_key: str | None = None,
) -> VendorResult:
    items: list[dict[str, Any]] = []
    status = 200
    async for page_items, response in connector.pages(path, params, items_key):
        items.extend(page_items)
        status = response.status
    return VendorResult(data={"items": items}, status_code=status)


# -- reads: identity, organization, and repository inventory ----------------------------------


async def _list_installation_repositories(connector: GitHubBase, _args: EmptyArgs) -> VendorResult:
    return await _collect(connector, "/installation/repositories", items_key="repositories")


async def _get_rate_limit(connector: GitHubBase, _args: EmptyArgs) -> VendorResult:
    return await _get(connector, "/rate_limit")


async def _get_repository(connector: GitHubBase, args: RepoRef) -> VendorResult:
    return await _get(connector, _path("repos", args.owner, args.repo))


async def _get_organization(connector: GitHubBase, args: OrgRef) -> VendorResult:
    return await _get(connector, _path("orgs", args.organization))


async def _get_team(connector: GitHubBase, args: TeamRef) -> VendorResult:
    return await _get(connector, _path("orgs", args.organization, "teams", args.team_slug))


async def _get_membership(connector: GitHubBase, args: MembershipRef) -> VendorResult:
    return await _get(connector, _path("orgs", args.organization, "memberships", args.username))


async def _get_collaborator_permission(connector: GitHubBase, args: CollaboratorRef) -> VendorResult:
    return await _get(
        connector,
        _path("repos", args.owner, args.repo, "collaborators", args.username, "permission"),
    )


async def _get_user(connector: GitHubBase, args: UserRef) -> VendorResult:
    return await _get(connector, _path("users", args.username))


async def _list_audit_events(connector: GitHubBase, args: EnterpriseRef) -> VendorResult:
    return await _collect(
        connector,
        _path("enterprises", args.enterprise, "audit-log"),
        params=_compact({"phrase": args.phrase}),
    )


# -- reads: git data, branches, and repository content ----------------------------------------


async def _list_branches(connector: GitHubBase, args: RepoRef) -> VendorResult:
    return await _collect(connector, _path("repos", args.owner, args.repo, "branches"))


async def _get_branch_protection(connector: GitHubBase, args: BranchRef) -> VendorResult:
    return await _get(
        connector,
        _path("repos", args.owner, args.repo, "branches", args.branch, "protection"),
    )


async def _get_tag(connector: GitHubBase, args: TagRef) -> VendorResult:
    return await _get(connector, _path("repos", args.owner, args.repo, "git", "ref", "tags", args.tag))


async def _get_commit(connector: GitHubBase, args: CommitRef) -> VendorResult:
    return await _get(connector, _path("repos", args.owner, args.repo, "commits", args.sha))


async def _get_tree(connector: GitHubBase, args: TreeRef) -> VendorResult:
    params = {"recursive": "1"} if args.recursive else None
    return await _get(connector, _path("repos", args.owner, args.repo, "git", "trees", args.tree_sha), params)


async def _get_file(connector: GitHubBase, args: FileRef) -> VendorResult:
    path = _path("repos", args.owner, args.repo, "contents") + "/" + _file_path(args.path)
    result = await _get(connector, path, _compact({"ref": args.ref}))
    size = result.data.get("size")
    if isinstance(size, int) and size > connector.config.max_file_bytes:
        raise BudgetExhausted(
            f"file {args.path!r} is {size} bytes, above the {connector.config.max_file_bytes} byte cap"
        )
    return result


async def _get_ruleset(connector: GitHubBase, args: RulesetRef) -> VendorResult:
    return await _get(connector, _path("repos", args.owner, args.repo, "rulesets", args.ruleset_id))


async def _get_workflow(connector: GitHubBase, args: WorkflowRef) -> VendorResult:
    return await _get(connector, _path("repos", args.owner, args.repo, "actions", "workflows", args.workflow_id))


async def _get_workflow_run(connector: GitHubBase, args: WorkflowRunRef) -> VendorResult:
    return await _get(connector, _path("repos", args.owner, args.repo, "actions", "runs", args.run_id))


async def _get_workflow_job(connector: GitHubBase, args: WorkflowJobRef) -> VendorResult:
    return await _get(connector, _path("repos", args.owner, args.repo, "actions", "jobs", args.job_id))


async def _get_artifact(connector: GitHubBase, args: ArtifactRef) -> VendorResult:
    return await _get(connector, _path("repos", args.owner, args.repo, "actions", "artifacts", args.artifact_id))


async def _list_webhooks(connector: GitHubBase, args: RepoRef) -> VendorResult:
    return await _collect(connector, _path("repos", args.owner, args.repo, "hooks"))


async def _get_webhook(connector: GitHubBase, args: WebhookRef) -> VendorResult:
    return await _get(connector, _path("repos", args.owner, args.repo, "hooks", args.hook_id))


async def _get_webhook_delivery(connector: GitHubBase, args: WebhookDeliveryRef) -> VendorResult:
    return await _get(
        connector,
        _path("repos", args.owner, args.repo, "hooks", args.hook_id, "deliveries", args.delivery_id),
    )


async def _get_check_run(connector: GitHubBase, args: CheckRunRef) -> VendorResult:
    return await _get(connector, _path("repos", args.owner, args.repo, "check-runs", args.check_run_id))


# -- reads: code scanning, Dependabot, and secret scanning ------------------------------------


async def _list_code_scanning_alerts(connector: GitHubBase, args: RepoRef) -> VendorResult:
    # Ascending update order lets the caller keep an (updated_at, alert_number) high-water mark.
    return await _collect(
        connector,
        _path("repos", args.owner, args.repo, "code-scanning", "alerts"),
        params={"sort": "updated", "direction": "asc"},
    )


async def _get_code_scanning_alert(connector: GitHubBase, args: AlertRef) -> VendorResult:
    return await _get(
        connector,
        _path("repos", args.owner, args.repo, "code-scanning", "alerts", args.alert_number),
    )


async def _list_code_scanning_alert_instances(connector: GitHubBase, args: AlertInstancesRef) -> VendorResult:
    return await _collect(
        connector,
        _path("repos", args.owner, args.repo, "code-scanning", "alerts", args.alert_number, "instances"),
        params=_compact({"ref": args.ref}),
    )


async def _get_code_scanning_analysis(connector: GitHubBase, args: AnalysisRef) -> VendorResult:
    return await _get(
        connector,
        _path("repos", args.owner, args.repo, "code-scanning", "analyses", args.analysis_id),
    )


async def _get_sarif_status(connector: GitHubBase, args: SarifStatusRef) -> VendorResult:
    return await _get(connector, _path("repos", args.owner, args.repo, "code-scanning", "sarifs", args.sarif_id))


async def _list_dependabot_alerts(connector: GitHubBase, args: RepoRef) -> VendorResult:
    return await _collect(connector, _path("repos", args.owner, args.repo, "dependabot", "alerts"))


async def _list_secret_scanning_alerts(connector: GitHubBase, args: RepoRef) -> VendorResult:
    return await _collect(connector, _path("repos", args.owner, args.repo, "secret-scanning", "alerts"))


# -- reads: pull requests, reviews, and review comments ---------------------------------------


async def _get_pull_request(connector: GitHubBase, args: PullRef) -> VendorResult:
    return await _get(connector, _path("repos", args.owner, args.repo, "pulls", args.pull_number))


async def _list_pull_request_reviews(connector: GitHubBase, args: PullRef) -> VendorResult:
    return await _collect(connector, _path("repos", args.owner, args.repo, "pulls", args.pull_number, "reviews"))


async def _get_review(connector: GitHubBase, args: ReviewRef) -> VendorResult:
    return await _get(
        connector,
        _path("repos", args.owner, args.repo, "pulls", args.pull_number, "reviews", args.review_id),
    )


async def _list_review_comments(connector: GitHubBase, args: PullRef) -> VendorResult:
    return await _collect(connector, _path("repos", args.owner, args.repo, "pulls", args.pull_number, "comments"))


async def _get_review_comment(connector: GitHubBase, args: ReviewCommentRef) -> VendorResult:
    return await _get(connector, _path("repos", args.owner, args.repo, "pulls", "comments", args.comment_id))


_OPERATIONS: dict[str, tuple[type[BaseModel], _Handler]] = {
    "get_rate_limit": (EmptyArgs, _get_rate_limit),
    "list_installation_repositories": (EmptyArgs, _list_installation_repositories),
    "list_audit_events": (EnterpriseRef, _list_audit_events),
    "get_repository": (RepoRef, _get_repository),
    "get_organization": (OrgRef, _get_organization),
    "get_team": (TeamRef, _get_team),
    "get_membership": (MembershipRef, _get_membership),
    "get_collaborator_permission": (CollaboratorRef, _get_collaborator_permission),
    "get_user": (UserRef, _get_user),
    "list_branches": (RepoRef, _list_branches),
    "get_branch_protection": (BranchRef, _get_branch_protection),
    "get_tag": (TagRef, _get_tag),
    "get_commit": (CommitRef, _get_commit),
    "get_tree": (TreeRef, _get_tree),
    "get_file": (FileRef, _get_file),
    "get_ruleset": (RulesetRef, _get_ruleset),
    "get_workflow": (WorkflowRef, _get_workflow),
    "get_workflow_run": (WorkflowRunRef, _get_workflow_run),
    "get_workflow_job": (WorkflowJobRef, _get_workflow_job),
    "get_artifact": (ArtifactRef, _get_artifact),
    "list_webhooks": (RepoRef, _list_webhooks),
    "get_webhook": (WebhookRef, _get_webhook),
    "get_webhook_delivery": (WebhookDeliveryRef, _get_webhook_delivery),
    "get_check_run": (CheckRunRef, _get_check_run),
    "list_code_scanning_alerts": (RepoRef, _list_code_scanning_alerts),
    "get_code_scanning_alert": (AlertRef, _get_code_scanning_alert),
    "list_code_scanning_alert_instances": (AlertInstancesRef, _list_code_scanning_alert_instances),
    "get_code_scanning_analysis": (AnalysisRef, _get_code_scanning_analysis),
    "get_sarif_status": (SarifStatusRef, _get_sarif_status),
    "list_dependabot_alerts": (RepoRef, _list_dependabot_alerts),
    "list_secret_scanning_alerts": (RepoRef, _list_secret_scanning_alerts),
    "get_pull_request": (PullRef, _get_pull_request),
    "list_pull_request_reviews": (PullRef, _list_pull_request_reviews),
    "get_review": (ReviewRef, _get_review),
    "list_review_comments": (PullRef, _list_review_comments),
    "get_review_comment": (ReviewCommentRef, _get_review_comment),
}


async def execute_operation(connector: GitHubBase, name: str, args: BaseModel) -> VendorResult:
    """Run the named GitHub operation after checking that ``args`` has the operation's input model."""
    entry = _OPERATIONS.get(name)
    if entry is None:
        raise ConfigError(f"unknown GitHub operation {name!r}")
    input_model, handler = entry
    if not isinstance(args, input_model):
        raise ConfigError(f"GitHub operation {name!r} expects {input_model.__name__}")
    return await handler(connector, args)
