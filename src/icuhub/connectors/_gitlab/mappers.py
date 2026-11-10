"""GitLab stream mappers: OCSF findings for native vulnerabilities, a ticket for merge requests, an
API activity for audit events, and kit source records for every other stream.

Each mapper is a pure function of one raw record. Stream fetchers annotate records with the
numeric project or group id they were read under (``_project_id`` / ``_group_id``) and, for
pipeline and merge request children, with the parent identity, so every uid is scoped without
guessing from payload fields.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel

from icuhub.connectors._gitlab.mapping import NoIdentifierError, map_native_finding, parse_time
from icuhub.connectors._gitlab.support import checked, data, links, required, revision, source, uid
from icuhub.kit.connector import mapper
from icuhub.kit.errors import VendorContractError
from icuhub.kit.mapping import bounded_raw, epoch_ms, product
from icuhub.kit.types import MapContext, TicketRecord
from icuhub_schemas.ocsf import Actor, Api, ApiActivity, Cloud, Metadata, NetworkEndpoint, Product, User

if TYPE_CHECKING:
    from icuhub.connectors._gitlab.connector import GitLabConnectorBase

__all__ = [
    "map_audit_event",
    "map_audit_stream_object",
    "map_branch",
    "map_commit",
    "map_commit_diffs",
    "map_file_blame",
    "map_group",
    "map_group_audit_event",
    "map_group_member",
    "map_job",
    "map_job_artifacts",
    "map_job_logs",
    "map_label",
    "map_merge_request",
    "map_milestone",
    "map_mr_approval_rule",
    "map_mr_approval_state",
    "map_mr_commit",
    "map_mr_diff",
    "map_mr_pipeline",
    "map_mr_version",
    "map_pipeline",
    "map_pipeline_bridge",
    "map_pipeline_test_report",
    "map_pipeline_variable",
    "map_project",
    "map_project_member",
    "map_repository_files",
    "map_repository_tree",
    "map_tag",
    "map_vulnerability",
]

_PROVIDER = "GitLab"
_ACTIVITY_OTHER = 99
_MR_STATUS_CATEGORY: dict[str, Literal["open", "in_progress", "done", "unknown"]] = {
    "opened": "open",
    "locked": "open",
    "merged": "done",
    "closed": "done",
}


@mapper("vulnerabilities", version=1)
def map_vulnerability(_connector: GitLabConnectorBase, raw: dict[str, Any], ctx: MapContext) -> list[BaseModel]:
    """OCSF vulnerability finding; a finding with no CVE or CWE stays a source record instead of being dropped."""
    try:
        return [checked(map_native_finding(raw, ctx))]
    except NoIdentifierError:
        return [source("vulnerabilities", uid("project", raw["_project_id"], "vulnerability", required(raw, "id")), raw)]


@mapper("merge_requests", version=1)
def map_merge_request(_connector: GitLabConnectorBase, raw: dict[str, Any], _ctx: MapContext) -> list[BaseModel]:
    project_id = raw["_project_id"]
    iid = required(raw, "iid")
    state = required(raw, "state")
    return [
        TicketRecord(
            uid=uid("project", project_id, "merge_request", iid),
            revision=revision(raw),
            key=f"!{iid}",
            status=state,
            status_category=_MR_STATUS_CATEGORY.get(state, "unknown"),
            resolution=state if state in ("merged", "closed") else None,
            url=raw.get("web_url") if isinstance(raw.get("web_url"), str) else None,
            updated_at=parse_time(raw.get("updated_at"), "updated_at"),
            labels=[str(label) for label in raw.get("labels") or []],
            fingerprint_links=[],
            links=links(raw),
            data=data("merge_requests", raw),
        )
    ]


@mapper("audit_events", version=1)
def map_audit_event(_connector: GitLabConnectorBase, raw: dict[str, Any], _ctx: MapContext) -> list[BaseModel]:
    """OCSF API activity for a project audit event; an event without an operation stays a source record."""
    operation = raw.get("event_name")
    if not isinstance(operation, str) or not operation:
        return [source("audit_events", uid("project", raw["_project_id"], "audit_event", required(raw, "id")), raw)]
    return [_api_activity(raw, operation)]


@mapper("group_audit_events", version=1)
def map_group_audit_event(_connector: GitLabConnectorBase, raw: dict[str, Any], _ctx: MapContext) -> list[BaseModel]:
    """OCSF API activity for a group audit event; an event without an operation stays a source record."""
    operation = raw.get("event_name")
    if not isinstance(operation, str) or not operation:
        return [source("group_audit_events", uid("group", raw["_group_id"], "audit_event", required(raw, "id")), raw)]
    return [_api_activity(raw, operation)]


@mapper("audit_stream_objects", version=1)
def map_audit_stream_object(_connector: GitLabConnectorBase, raw: dict[str, Any], _ctx: MapContext) -> list[BaseModel]:
    """OCSF API activity for an event read from a GitLab.com batched audit object.

    A partial-coverage marker or stream error stays a source record so the gap is visible. An event
    without an operation also stays a source record, keyed by its object and event id.
    """
    object_key = raw["_audit_object_key"]
    if raw.get("_partial_coverage") is True or "_stream_error" in raw:
        return [source("audit_stream_objects", uid("audit_stream_object", object_key, "partial"), raw)]
    operation = raw.get("event_name")
    if not isinstance(operation, str) or not operation:
        return [
            source(
                "audit_stream_objects",
                uid("audit_stream_object", object_key, "audit_event", required(raw, "id")),
                raw,
            )
        ]
    return [_api_activity(raw, operation)]


def _api_activity(raw: dict[str, Any], operation: str) -> BaseModel:
    """OCSF API activity for one audit event whose operation name is already known to be present."""
    raw_details = raw.get("details")
    details: Mapping[str, Any] = raw_details if isinstance(raw_details, dict) else {}
    actor_name = details.get("author_name")
    actor_id = raw.get("author_id")
    actor = None
    if actor_name is not None or actor_id is not None:
        actor = Actor(
            user=User(
                name=str(actor_name) if actor_name is not None else None,
                uid=str(actor_id) if actor_id is not None else None,
            )
        )
    ip = raw.get("ip_address")
    created = epoch_ms(raw.get("created_at"))
    if created is None:
        raise VendorContractError("audit event created_at must be a timestamp")
    return checked(
        ApiActivity(
            type_uid=ApiActivity.CLASS_UID * 100 + _ACTIVITY_OTHER,
            activity_id=_ACTIVITY_OTHER,
            severity_id=0,
            time=created,
            metadata=Metadata(product=Product(**product(_PROVIDER, _PROVIDER)), uid=required(raw, "id")),
            cloud=Cloud(provider=_PROVIDER),
            osint=[],
            actor=actor,
            api=Api(operation=operation),
            src_endpoint=NetworkEndpoint(ip=ip) if isinstance(ip, str) else None,
            raw_data=bounded_raw(dict(raw)),
        )
    )


@mapper("projects", version=1)
def map_project(_connector: GitLabConnectorBase, raw: dict[str, Any], _ctx: MapContext) -> list[BaseModel]:
    return [source("projects", uid("project", required(raw, "id")), raw)]


@mapper("groups", version=1)
def map_group(_connector: GitLabConnectorBase, raw: dict[str, Any], _ctx: MapContext) -> list[BaseModel]:
    return [source("groups", uid("group", required(raw, "id")), raw)]


@mapper("group_members", version=1)
def map_group_member(_connector: GitLabConnectorBase, raw: dict[str, Any], _ctx: MapContext) -> list[BaseModel]:
    return [source("group_members", uid("group", raw["_group_id"], "member", required(raw, "id")), raw)]


@mapper("project_members", version=1)
def map_project_member(_connector: GitLabConnectorBase, raw: dict[str, Any], _ctx: MapContext) -> list[BaseModel]:
    return [source("project_members", uid("project", raw["_project_id"], "member", required(raw, "id")), raw)]


@mapper("labels", version=1)
def map_label(_connector: GitLabConnectorBase, raw: dict[str, Any], _ctx: MapContext) -> list[BaseModel]:
    return [source("labels", uid("project", raw["_project_id"], "label", required(raw, "id")), raw)]


@mapper("milestones", version=1)
def map_milestone(_connector: GitLabConnectorBase, raw: dict[str, Any], _ctx: MapContext) -> list[BaseModel]:
    return [source("milestones", uid("project", raw["_project_id"], "milestone", required(raw, "id")), raw)]


@mapper("branches", version=1)
def map_branch(_connector: GitLabConnectorBase, raw: dict[str, Any], _ctx: MapContext) -> list[BaseModel]:
    return [source("branches", uid("project", raw["_project_id"], "branch", required(raw, "name")), raw)]


@mapper("tags", version=1)
def map_tag(_connector: GitLabConnectorBase, raw: dict[str, Any], _ctx: MapContext) -> list[BaseModel]:
    return [source("tags", uid("project", raw["_project_id"], "tag", required(raw, "name")), raw)]


@mapper("commits", version=1)
def map_commit(_connector: GitLabConnectorBase, raw: dict[str, Any], _ctx: MapContext) -> list[BaseModel]:
    return [source("commits", uid("project", raw["_project_id"], "commit", required(raw, "id")), raw)]


@mapper("commit_diffs", version=1)
def map_commit_diffs(_connector: GitLabConnectorBase, raw: dict[str, Any], _ctx: MapContext) -> list[BaseModel]:
    path = raw.get("new_path") or raw.get("old_path")
    if not isinstance(path, str) or not path:
        raise VendorContractError("GitLab commit diff record has no file path")
    return [
        source(
            "commit_diffs",
            uid("project", raw["_project_id"], "commit", raw["_commit_sha"], "diff", path),
            raw,
        )
    ]


@mapper("repository_tree", version=1)
def map_repository_tree(_connector: GitLabConnectorBase, raw: dict[str, Any], _ctx: MapContext) -> list[BaseModel]:
    return [source("repository_tree", uid("project", raw["_project_id"], "tree", required(raw, "path")), raw)]


@mapper("repository_files", version=1)
def map_repository_files(_connector: GitLabConnectorBase, raw: dict[str, Any], _ctx: MapContext) -> list[BaseModel]:
    return [source("repository_files", uid("project", raw["_project_id"], "file", required(raw, "path")), raw)]


@mapper("file_blame", version=1)
def map_file_blame(_connector: GitLabConnectorBase, raw: dict[str, Any], _ctx: MapContext) -> list[BaseModel]:
    return [
        source(
            "file_blame",
            uid(
                "project",
                raw["_project_id"],
                "file",
                raw["_file_path"],
                "blame",
                required(raw, "_commit_sha"),
                raw.get("start", 0),
            ),
            raw,
        )
    ]


@mapper("pipelines", version=1)
def map_pipeline(_connector: GitLabConnectorBase, raw: dict[str, Any], _ctx: MapContext) -> list[BaseModel]:
    return [source("pipelines", uid("project", raw["_project_id"], "pipeline", required(raw, "id")), raw)]


@mapper("jobs", version=1)
def map_job(_connector: GitLabConnectorBase, raw: dict[str, Any], _ctx: MapContext) -> list[BaseModel]:
    return [source("jobs", uid("project", raw["_project_id"], "job", required(raw, "id")), raw)]


@mapper("job_logs", version=1)
def map_job_logs(_connector: GitLabConnectorBase, raw: dict[str, Any], _ctx: MapContext) -> list[BaseModel]:
    return [source("job_logs", uid("project", raw["_project_id"], "job", required(raw, "job_id"), "log"), raw)]


@mapper("job_artifacts", version=1)
def map_job_artifacts(_connector: GitLabConnectorBase, raw: dict[str, Any], _ctx: MapContext) -> list[BaseModel]:
    return [
        source("job_artifacts", uid("project", raw["_project_id"], "job", required(raw, "job_id"), "artifacts"), raw)
    ]


@mapper("pipeline_bridges", version=1)
def map_pipeline_bridge(_connector: GitLabConnectorBase, raw: dict[str, Any], _ctx: MapContext) -> list[BaseModel]:
    return [source("pipeline_bridges", uid("project", raw["_project_id"], "bridge", required(raw, "id")), raw)]


@mapper("pipeline_test_reports", version=1)
def map_pipeline_test_report(
    _connector: GitLabConnectorBase, raw: dict[str, Any], _ctx: MapContext
) -> list[BaseModel]:
    return [
        source(
            "pipeline_test_reports",
            uid("project", raw["_project_id"], "pipeline", raw["_pipeline_id"], "test_report"),
            raw,
        )
    ]


@mapper("pipeline_variables", version=1)
def map_pipeline_variable(_connector: GitLabConnectorBase, raw: dict[str, Any], _ctx: MapContext) -> list[BaseModel]:
    """Variable metadata only: the fetcher drops values before records reach the mapper."""
    return [
        source(
            "pipeline_variables",
            uid("project", raw["_project_id"], "pipeline", raw["_pipeline_id"], "variable", required(raw, "key")),
            raw,
        )
    ]


@mapper("mr_diffs", version=1)
def map_mr_diff(_connector: GitLabConnectorBase, raw: dict[str, Any], _ctx: MapContext) -> list[BaseModel]:
    path = raw.get("new_path") or raw.get("old_path")
    if not isinstance(path, str) or not path:
        raise VendorContractError("GitLab MR diff record has no file path")
    return [
        source(
            "mr_diffs",
            uid("project", raw["_project_id"], "mr", raw["_merge_request_iid"], "diff", path),
            raw,
        )
    ]


@mapper("mr_versions", version=1)
def map_mr_version(_connector: GitLabConnectorBase, raw: dict[str, Any], _ctx: MapContext) -> list[BaseModel]:
    return [
        source(
            "mr_versions",
            uid("project", raw["_project_id"], "mr", raw["_merge_request_iid"], "version", required(raw, "id")),
            raw,
        )
    ]


@mapper("mr_commits", version=1)
def map_mr_commit(_connector: GitLabConnectorBase, raw: dict[str, Any], _ctx: MapContext) -> list[BaseModel]:
    return [
        source(
            "mr_commits",
            uid("project", raw["_project_id"], "mr", raw["_merge_request_iid"], "commit", required(raw, "id")),
            raw,
        )
    ]


@mapper("mr_pipelines", version=1)
def map_mr_pipeline(_connector: GitLabConnectorBase, raw: dict[str, Any], _ctx: MapContext) -> list[BaseModel]:
    return [
        source(
            "mr_pipelines",
            uid("project", raw["_project_id"], "mr", raw["_merge_request_iid"], "pipeline", required(raw, "id")),
            raw,
        )
    ]


@mapper("mr_approval_rules", version=1)
def map_mr_approval_rule(_connector: GitLabConnectorBase, raw: dict[str, Any], _ctx: MapContext) -> list[BaseModel]:
    return [
        source(
            "mr_approval_rules",
            uid("project", raw["_project_id"], "mr", raw["_merge_request_iid"], "approval_rule", required(raw, "id")),
            raw,
        )
    ]


@mapper("mr_approval_state", version=1)
def map_mr_approval_state(_connector: GitLabConnectorBase, raw: dict[str, Any], _ctx: MapContext) -> list[BaseModel]:
    return [
        source(
            "mr_approval_state",
            uid("project", raw["_project_id"], "mr", raw["_merge_request_iid"], "approval_state"),
            raw,
        )
    ]
