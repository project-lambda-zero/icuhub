"""GitLab stream declarations.

Every stream is an explicit async generator bound on ``GitLabConnectorBase``. Snapshot streams yield
all pages before a final ``complete=True`` batch, so only a complete snapshot authorizes absence
closure. Time-id streams advance their cursor only across a complete read. ``BudgetExhausted``
marks a run incomplete; ``PermissionDenied`` and tier failures propagate, so a gated endpoint is
never reported as zero records.

Streams call the connector's own ``_collect``/``_get`` helpers. This package owns both sides of
that boundary, so the access is intentional.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import AsyncIterator
from datetime import datetime
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

from icuhub.connectors._gitlab.graphql import traverse_vulnerabilities
from icuhub.connectors._gitlab.mapping import parse_time
from icuhub.connectors._gitlab.support import (
    Fetch,
    annotate,
    gather,
    gather_each,
    numeric_id,
    snapshot_batches,
    time_id_batches,
    window_query,
)
from icuhub.kit.connector import stream
from icuhub.kit.cursors import SequenceCursor, SnapshotCursor, TimeIdCursor
from icuhub.kit.errors import BudgetExhausted, ConfigError, NotFound, VendorContractError
from icuhub.kit.types import RawBatch, Target

if TYPE_CHECKING:
    from icuhub.connectors._gitlab.connector import GitLabConnectorBase

__all__ = [
    "audit_events",
    "audit_stream_objects",
    "branches",
    "commits",
    "commit_diffs",
    "file_blame",
    "group_audit_events",
    "group_members",
    "groups",
    "jobs",
    "job_artifacts",
    "job_logs",
    "labels",
    "merge_requests",
    "milestones",
    "mr_approval_rules",
    "mr_approval_state",
    "mr_commits",
    "mr_diffs",
    "mr_pipelines",
    "mr_versions",
    "pipeline_bridges",
    "pipeline_test_reports",
    "pipeline_variables",
    "pipelines",
    "project_members",
    "projects",
    "repository_files",
    "repository_tree",
    "tags",
    "vulnerabilities",
]

def _updated_at(raw: dict[str, Any]) -> datetime:
    return parse_time(raw.get("updated_at"), "updated_at")


def _created_at(raw: dict[str, Any]) -> datetime:
    return parse_time(raw.get("created_at"), "created_at")


def _committed_at(raw: dict[str, Any]) -> datetime:
    return parse_time(raw.get("committed_date"), "committed_date")


def _pipeline_updated_at(raw: dict[str, Any]) -> datetime:
    return parse_time(raw.get("_pipeline_updated_at"), "updated_at")


def _project_key(raw: dict[str, Any]) -> str:
    return f"{raw['_project_id']}:{raw['id']}"


def _group_key(raw: dict[str, Any]) -> str:
    return f"{raw['_group_id']}:{raw['id']}"


def _merge_request_key(raw: dict[str, Any]) -> str:
    return f"{raw['_project_id']}:{raw['iid']}"


def _test_report_key(raw: dict[str, Any]) -> str:
    return f"{raw['_project_id']}:{raw['_pipeline_id']}"


def _variable_key(raw: dict[str, Any]) -> str:
    return f"{raw['_project_id']}:{raw['_pipeline_id']}:{raw['key']}"


def _pipeline_query(checkpoint: TimeIdCursor | None, mode: str) -> dict[str, str]:
    return {"order_by": "updated_at", "sort": "asc", **window_query(checkpoint, mode, "updated_after")}


def _pipeline_fields(project_id: int, pipeline: dict[str, Any]) -> dict[str, Any]:
    return {
        "_project_id": project_id,
        "_pipeline_id": pipeline["id"],
        "_pipeline_updated_at": pipeline.get("updated_at"),
    }


async def _pipeline_children(
    connector: GitLabConnectorBase,
    project_id: int,
    checkpoint: TimeIdCursor | None,
    mode: str,
    fetch: Fetch,
) -> tuple[list[dict[str, Any]], bool]:
    pipelines, complete = await gather(connector, f"/projects/{project_id}/pipelines", _pipeline_query(checkpoint, mode))
    records, children_complete = await gather_each(pipelines, fetch)
    return records, complete and children_complete


def _pipeline_child_fetch(connector: GitLabConnectorBase, project_id: int, suffix: str) -> Fetch:
    async def fetch(pipeline: dict[str, Any]) -> list[dict[str, Any]]:
        items = await connector._collect(f"/projects/{project_id}/pipelines/{pipeline['id']}/{suffix}")
        return annotate(items, **_pipeline_fields(project_id, pipeline))

    return fetch


def _test_report_fetch(connector: GitLabConnectorBase, project_id: int) -> Fetch:
    async def fetch(pipeline: dict[str, Any]) -> list[dict[str, Any]]:
        try:
            report = await connector._get(f"/projects/{project_id}/pipelines/{pipeline['id']}/test_report")
        except NotFound:
            return []
        return annotate([report], **_pipeline_fields(project_id, pipeline))

    return fetch


def _variable_fetch(connector: GitLabConnectorBase, project_id: int) -> Fetch:
    async def fetch(pipeline: dict[str, Any]) -> list[dict[str, Any]]:
        items = await connector._collect(f"/projects/{project_id}/pipelines/{pipeline['id']}/variables")
        # Values are secrets-bearing and never leave the fetcher: only key and type are kept.
        metadata = [{"key": item.get("key"), "variable_type": item.get("variable_type")} for item in items]
        return annotate(metadata, **_pipeline_fields(project_id, pipeline))

    return fetch


def _mr_fields(project_id: int, merge_request: dict[str, Any]) -> dict[str, Any]:
    return {"_project_id": project_id, "_merge_request_iid": merge_request["iid"]}


def _mr_child_fetch(connector: GitLabConnectorBase, project_id: int, suffix: str) -> Fetch:
    async def fetch(merge_request: dict[str, Any]) -> list[dict[str, Any]]:
        items = await connector._collect(f"/projects/{project_id}/merge_requests/{merge_request['iid']}/{suffix}")
        return annotate(items, **_mr_fields(project_id, merge_request))

    return fetch


def _mr_state_fetch(connector: GitLabConnectorBase, project_id: int) -> Fetch:
    async def fetch(merge_request: dict[str, Any]) -> list[dict[str, Any]]:
        body = await connector._get(f"/projects/{project_id}/merge_requests/{merge_request['iid']}/approval_state")
        return annotate([body], **_mr_fields(project_id, merge_request))

    return fetch


async def _merge_request_snapshot(
    connector: GitLabConnectorBase, project_id: int, fetch: Fetch
) -> tuple[list[dict[str, Any]], bool]:
    merge_requests, complete = await gather(
        connector, f"/projects/{project_id}/merge_requests", {"state": "all", "scope": "all"}
    )
    records, children_complete = await gather_each(merge_requests, fetch)
    return records, complete and children_complete


@stream("vulnerabilities", cursor=SnapshotCursor, capability="FindingSource", ocsf_class=2002, modes=("full",))
async def vulnerabilities(
    connector: GitLabConnectorBase, target: Target | None, _checkpoint: SnapshotCursor | None, _mode: str
) -> AsyncIterator[RawBatch]:
    """Native vulnerability findings from a full GraphQL traversal of the project connection.

    The connection has no server-side ``updatedAfter`` filter, so only full snapshots are declared.
    A complete traversal is the only input that authorizes absence closure.
    """
    project_id = numeric_id(target, "project")
    findings, complete = await traverse_vulnerabilities(connector, project_id)
    async for batch in snapshot_batches(
        connector,
        "vulnerabilities",
        f"project:{project_id}",
        annotate(findings, _project_id=project_id),
        complete=complete,
    ):
        yield batch


@stream("merge_requests", cursor=TimeIdCursor, capability="SourceControl")
async def merge_requests(
    connector: GitLabConnectorBase, target: Target | None, checkpoint: TimeIdCursor | None, mode: str
) -> AsyncIterator[RawBatch]:
    project_id = numeric_id(target, "project")
    params = {"scope": "all", **_pipeline_query(checkpoint, mode)}
    records, complete = await gather(connector, f"/projects/{project_id}/merge_requests", params)
    async for batch in time_id_batches(
        annotate(records, _project_id=project_id),
        checkpoint,
        mode,
        complete=complete,
        time_of=_updated_at,
        id_of=_merge_request_key,
    ):
        yield batch


@stream("audit_events", cursor=TimeIdCursor, capability="SourceControl", ocsf_class=6003)
async def audit_events(
    connector: GitLabConnectorBase, target: Target | None, checkpoint: TimeIdCursor | None, mode: str
) -> AsyncIterator[RawBatch]:
    project_id = numeric_id(target, "project")
    records, complete = await gather(
        connector, f"/projects/{project_id}/audit_events", window_query(checkpoint, mode, "created_after")
    )
    async for batch in time_id_batches(
        annotate(records, _project_id=project_id),
        checkpoint,
        mode,
        complete=complete,
        time_of=_created_at,
        id_of=_project_key,
    ):
        yield batch


@stream("group_audit_events", cursor=TimeIdCursor, capability="SourceControl", ocsf_class=6003)
async def group_audit_events(
    connector: GitLabConnectorBase, target: Target | None, checkpoint: TimeIdCursor | None, mode: str
) -> AsyncIterator[RawBatch]:
    group_id = numeric_id(target, "group")
    records, complete = await gather(
        connector, f"/groups/{group_id}/audit_events", window_query(checkpoint, mode, "created_after")
    )
    async for batch in time_id_batches(
        annotate(records, _group_id=group_id),
        checkpoint,
        mode,
        complete=complete,
        time_of=_created_at,
        id_of=_group_key,
    ):
        yield batch


# Upper bound for one GitLab.com batched audit object, applied to the download itself.
_AUDIT_OBJECT_MAX_BYTES = 8 * 1024 * 1024


def _audit_objects(target: Target | None) -> tuple[list[dict[str, str]], bool]:
    """Read the batched object list the destination supplies: ``{"objects": [{"key", "url"}, ...]}``."""
    if target is None:
        raise ConfigError("GitLab audit_stream_objects requires a destination target")
    attributes = target.attributes
    supplied = attributes.get("objects")
    if not isinstance(supplied, list):
        raise ConfigError("GitLab audit destination target must supply an objects array")
    objects: list[dict[str, str]] = []
    for item in supplied:
        if not isinstance(item, dict):
            raise ConfigError("GitLab audit destination objects must be objects")
        key = item.get("key")
        url = item.get("url")
        if not isinstance(key, str) or not key or not isinstance(url, str) or not url:
            raise ConfigError("Each GitLab audit destination object needs a key and URL")
        objects.append({"key": key, "url": url})
    objects.sort(key=lambda item: item["key"])
    complete = attributes.get("complete", True) is not False and attributes.get("truncated", False) is not True
    return objects, complete


def _audit_payload(content: bytes, key: str, max_bytes: int) -> list[dict[str, Any]]:
    """Parse one batched object as a JSON document (array or object) or as JSON Lines.

    [UNVERIFIED] GitLab.com's batched object payload format. Compressed or non-UTF-8 content fails closed.
    """
    if len(content) > max_bytes:
        raise BudgetExhausted(f"GitLab audit object exceeded {max_bytes} bytes")
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise VendorContractError(f"GitLab audit object {key!r} is not UTF-8") from exc
    values: list[Any]
    try:
        document: Any = json.loads(text)
    except ValueError:
        values = []
        for line_number, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                values.append(json.loads(line))
            except ValueError as exc:
                raise VendorContractError(
                    f"GitLab audit object {key!r} has invalid JSON on line {line_number}"
                ) from exc
    else:
        values = document if isinstance(document, list) else [document]
    events: list[dict[str, Any]] = []
    for value in values:
        if not isinstance(value, dict):
            raise VendorContractError(f"GitLab audit object {key!r} contains a non-object event")
        events.append(value)
    return events


@stream(
    "audit_stream_objects",
    cursor=SequenceCursor,
    capability="SourceControl",
    ocsf_class=6003,
    modes=("incremental",),
)
async def audit_stream_objects(
    connector: GitLabConnectorBase, target: Target | None, checkpoint: SequenceCursor | None, _mode: str
) -> AsyncIterator[RawBatch]:
    """GitLab.com batched audit objects in key order; the checkpoint is the last fully read object key.

    Presigned download URLs are used for the fetch only and never reach the evidence record.
    """
    objects, complete = _audit_objects(target)
    current = checkpoint if isinstance(checkpoint, SequenceCursor) else SequenceCursor(seq="")
    previous = str(current.seq)
    seen_event_ids: set[str] = set()
    for item in objects:
        key = item["key"]
        if previous and key <= previous:
            continue
        try:
            content = await connector.http.stream_download("GET", item["url"], max_bytes=_AUDIT_OBJECT_MAX_BYTES)
            events = _audit_payload(content, key, _AUDIT_OBJECT_MAX_BYTES)
        except BudgetExhausted as exc:
            error = {
                "_audit_object_key": key,
                "_partial_coverage": True,
                "_stream_error": {"kind": "budget_exhausted", "message": str(exc)},
            }
            yield RawBatch(records=[error], checkpoint=current, complete=False)
            complete = False
            break
        records: list[dict[str, Any]] = []
        for event in events:
            event_id = event.get("id")
            if event_id is not None:
                if str(event_id) in seen_event_ids:
                    continue
                seen_event_ids.add(str(event_id))
            records.append({**event, "_audit_object_key": key})
        current = current.advance(key)
        yield RawBatch(records=records, checkpoint=current, complete=False)
    yield RawBatch(records=[], checkpoint=current, complete=complete)


@stream("projects", cursor=SnapshotCursor, capability="SourceControl", modes=("full",))
async def projects(
    connector: GitLabConnectorBase, target: Target | None, _checkpoint: SnapshotCursor | None, _mode: str
) -> AsyncIterator[RawBatch]:
    group_id = numeric_id(target, "group")
    records, complete = await gather(connector, f"/groups/{group_id}/projects", {"include_subgroups": "true"})
    async for batch in snapshot_batches(
        connector, "projects", f"group:{group_id}", annotate(records, _group_id=group_id), complete=complete
    ):
        yield batch


@stream("groups", cursor=SnapshotCursor, capability="SourceControl", modes=("full",))
async def groups(
    connector: GitLabConnectorBase, target: Target | None, _checkpoint: SnapshotCursor | None, _mode: str
) -> AsyncIterator[RawBatch]:
    group_id = numeric_id(target, "group")
    root = await connector._get(f"/groups/{group_id}")
    descendants, complete = await gather(connector, f"/groups/{group_id}/descendant_groups")
    async for batch in snapshot_batches(
        connector,
        "groups",
        f"group:{group_id}",
        annotate([root, *descendants], _group_id=group_id),
        complete=complete,
    ):
        yield batch


@stream("group_members", cursor=SnapshotCursor, capability="SourceControl", modes=("full",))
async def group_members(
    connector: GitLabConnectorBase, target: Target | None, _checkpoint: SnapshotCursor | None, _mode: str
) -> AsyncIterator[RawBatch]:
    group_id = numeric_id(target, "group")
    records, complete = await gather(connector, f"/groups/{group_id}/members/all")
    async for batch in snapshot_batches(
        connector, "group_members", f"group:{group_id}", annotate(records, _group_id=group_id), complete=complete
    ):
        yield batch


@stream("project_members", cursor=SnapshotCursor, capability="SourceControl", modes=("full",))
async def project_members(
    connector: GitLabConnectorBase, target: Target | None, _checkpoint: SnapshotCursor | None, _mode: str
) -> AsyncIterator[RawBatch]:
    project_id = numeric_id(target, "project")
    records, complete = await gather(connector, f"/projects/{project_id}/members/all")
    async for batch in snapshot_batches(
        connector,
        "project_members",
        f"project:{project_id}",
        annotate(records, _project_id=project_id),
        complete=complete,
    ):
        yield batch


@stream("labels", cursor=SnapshotCursor, capability="SourceControl", modes=("full",))
async def labels(
    connector: GitLabConnectorBase, target: Target | None, _checkpoint: SnapshotCursor | None, _mode: str
) -> AsyncIterator[RawBatch]:
    project_id = numeric_id(target, "project")
    records, complete = await gather(connector, f"/projects/{project_id}/labels")
    async for batch in snapshot_batches(
        connector, "labels", f"project:{project_id}", annotate(records, _project_id=project_id), complete=complete
    ):
        yield batch


@stream("milestones", cursor=SnapshotCursor, capability="SourceControl", modes=("full",))
async def milestones(
    connector: GitLabConnectorBase, target: Target | None, _checkpoint: SnapshotCursor | None, _mode: str
) -> AsyncIterator[RawBatch]:
    project_id = numeric_id(target, "project")
    records, complete = await gather(connector, f"/projects/{project_id}/milestones")
    async for batch in snapshot_batches(
        connector,
        "milestones",
        f"project:{project_id}",
        annotate(records, _project_id=project_id),
        complete=complete,
    ):
        yield batch


@stream("branches", cursor=SnapshotCursor, capability="SourceControl", modes=("full",))
async def branches(
    connector: GitLabConnectorBase, target: Target | None, _checkpoint: SnapshotCursor | None, _mode: str
) -> AsyncIterator[RawBatch]:
    project_id = numeric_id(target, "project")
    records, complete = await gather(connector, f"/projects/{project_id}/repository/branches")
    async for batch in snapshot_batches(
        connector, "branches", f"project:{project_id}", annotate(records, _project_id=project_id), complete=complete
    ):
        yield batch


@stream("tags", cursor=SnapshotCursor, capability="SourceControl", modes=("full",))
async def tags(
    connector: GitLabConnectorBase, target: Target | None, _checkpoint: SnapshotCursor | None, _mode: str
) -> AsyncIterator[RawBatch]:
    project_id = numeric_id(target, "project")
    records, complete = await gather(connector, f"/projects/{project_id}/repository/tags")
    async for batch in snapshot_batches(
        connector, "tags", f"project:{project_id}", annotate(records, _project_id=project_id), complete=complete
    ):
        yield batch


@stream("commits", cursor=TimeIdCursor, capability="SourceControl")
async def commits(
    connector: GitLabConnectorBase, target: Target | None, checkpoint: TimeIdCursor | None, mode: str
) -> AsyncIterator[RawBatch]:
    project_id = numeric_id(target, "project")
    params = {"all": "true", **window_query(checkpoint, mode, "since")}
    records, complete = await gather(connector, f"/projects/{project_id}/repository/commits", params)
    async for batch in time_id_batches(
        annotate(records, _project_id=project_id),
        checkpoint,
        mode,
        complete=complete,
        time_of=_committed_at,
        id_of=_project_key,
    ):
        yield batch


@stream("repository_tree", cursor=SnapshotCursor, capability="SourceControl", modes=("full",))
async def repository_tree(
    connector: GitLabConnectorBase, target: Target | None, _checkpoint: SnapshotCursor | None, _mode: str
) -> AsyncIterator[RawBatch]:
    project_id = numeric_id(target, "project")
    records, complete = await gather(connector, f"/projects/{project_id}/repository/tree", {"recursive": "true"})
    async for batch in snapshot_batches(
        connector,
        "repository_tree",
        f"project:{project_id}",
        annotate(records, _project_id=project_id),
        complete=complete,
    ):
        yield batch


_REPOSITORY_FILE_MAX_BYTES = 1024 * 1024
_JOB_LOG_MAX_BYTES = 8 * 1024 * 1024
_ARTIFACT_MAX_BYTES = 32 * 1024 * 1024


def _repository_ref(target: Target | None) -> str:
    ref = target.attributes.get("ref", "HEAD") if target is not None else "HEAD"
    if not isinstance(ref, str) or not ref:
        raise ConfigError("GitLab repository ref must be a non-empty string")
    return ref


def _download_metadata(content: bytes) -> dict[str, Any]:
    return {"bytes": len(content), "sha256": hashlib.sha256(content).hexdigest(), "truncated": False}


def _truncated_download_metadata() -> dict[str, Any]:
    return {"bytes": 0, "sha256": None, "truncated": True}


def _download_durable(raw: dict[str, Any]) -> bool:
    """A job whose download was capped is not captured; the time-id cursor must not advance past it."""
    return raw.get("truncated") is not True


def _job_time(raw: dict[str, Any]) -> datetime:
    return parse_time(raw.get("_job_updated_at"), "job updated_at")


def _job_key(raw: dict[str, Any]) -> str:
    return f"{raw['_project_id']}:{raw['job_id']}"


def _job_fields(project_id: int, job: dict[str, Any]) -> dict[str, Any]:
    pipeline = job.get("pipeline")
    return {
        "_project_id": project_id,
        "_job_updated_at": job.get("finished_at") or job.get("updated_at"),
        "job_id": job["id"],
        "pipeline_id": pipeline.get("id") if isinstance(pipeline, dict) else None,
    }


@stream("commit_diffs", cursor=SnapshotCursor, capability="SourceControl", modes=("full",))
async def commit_diffs(
    connector: GitLabConnectorBase, target: Target | None, _checkpoint: SnapshotCursor | None, _mode: str
) -> AsyncIterator[RawBatch]:
    project_id = numeric_id(target, "project")
    commits, complete = await gather(connector, f"/projects/{project_id}/repository/commits", {"all": "true"})
    records: list[dict[str, Any]] = []
    for commit in commits:
        sha = str(commit["id"])
        diffs, read_complete = await gather(
            connector, f"/projects/{project_id}/repository/commits/{quote(sha, safe='')}/diff"
        )
        for diff in diffs:
            metadata = {
                key: diff.get(key)
                for key in ("old_path", "new_path", "new_file", "renamed_file", "deleted_file", "generated_file")
            }
            records.append({**metadata, "_project_id": project_id, "_commit_sha": sha})
        if not read_complete:
            complete = False
            break
    async for batch in snapshot_batches(connector, "commit_diffs", f"project:{project_id}", records, complete=complete):
        yield batch


@stream("repository_files", cursor=SnapshotCursor, capability="SourceControl", modes=("full",))
async def repository_files(
    connector: GitLabConnectorBase, target: Target | None, _checkpoint: SnapshotCursor | None, _mode: str
) -> AsyncIterator[RawBatch]:
    project_id = numeric_id(target, "project")
    ref = _repository_ref(target)
    entries, complete = await gather(
        connector, f"/projects/{project_id}/repository/tree", {"recursive": "true", "ref": ref}
    )
    records: list[dict[str, Any]] = []
    for entry in entries:
        if entry.get("type") != "blob":
            continue
        path = entry.get("path")
        if not isinstance(path, str) or not path:
            raise VendorContractError("GitLab repository blob has no path")
        metadata = {key: entry.get(key) for key in ("path", "id", "mode", "size")}
        size = entry.get("size")
        if isinstance(size, int) and size > _REPOSITORY_FILE_MAX_BYTES:
            download = _truncated_download_metadata()
        else:
            try:
                response = await connector.http.stream_download_result(
                    "GET",
                    f"/projects/{project_id}/repository/files/{quote(path, safe='')}",
                    params={"ref": ref},
                    max_bytes=_REPOSITORY_FILE_MAX_BYTES,
                    expected=(200,),
                )
            except BudgetExhausted:
                download = _truncated_download_metadata()
            else:
                download = _download_metadata(response.content)
        records.append({**metadata, **download, "_project_id": project_id, "_ref": ref})
    async for batch in snapshot_batches(
        connector, "repository_files", f"project:{project_id}", records, complete=complete
    ):
        yield batch


@stream("file_blame", cursor=SnapshotCursor, capability="SourceControl", modes=("full",))
async def file_blame(
    connector: GitLabConnectorBase, target: Target | None, _checkpoint: SnapshotCursor | None, _mode: str
) -> AsyncIterator[RawBatch]:
    project_id = numeric_id(target, "project")
    ref = _repository_ref(target)
    entries, complete = await gather(
        connector, f"/projects/{project_id}/repository/tree", {"recursive": "true", "ref": ref}
    )
    blobs = [entry for entry in entries if entry.get("type") == "blob"]

    async def fetch(entry: dict[str, Any]) -> list[dict[str, Any]]:
        path = entry.get("path")
        if not isinstance(path, str) or not path:
            raise VendorContractError("GitLab repository blob has no path")
        ranges = await connector._collect(
            f"/projects/{project_id}/repository/files/{quote(path, safe='')}/blame", {"ref": ref}
        )
        records: list[dict[str, Any]] = []
        for blame in ranges:
            commit = blame.get("commit")
            commit_sha = commit.get("id") if isinstance(commit, dict) else None
            records.append(
                {
                    "start": blame.get("start"),
                    "end": blame.get("end"),
                    "commit": commit,
                    "_project_id": project_id,
                    "_file_path": path,
                    "_commit_sha": commit_sha,
                    "_ref": ref,
                }
            )
        return records

    records, children_complete = await gather_each(blobs, fetch)
    async for batch in snapshot_batches(
        connector, "file_blame", f"project:{project_id}", records, complete=complete and children_complete
    ):
        yield batch


@stream("job_logs", cursor=TimeIdCursor, capability="SourceControl", modes=("incremental",))
async def job_logs(
    connector: GitLabConnectorBase, target: Target | None, checkpoint: TimeIdCursor | None, mode: str
) -> AsyncIterator[RawBatch]:
    project_id = numeric_id(target, "project")
    jobs, complete = await gather(connector, f"/projects/{project_id}/jobs")
    records: list[dict[str, Any]] = []
    for job in jobs:
        fields = _job_fields(project_id, job)
        try:
            response = await connector.http.stream_download_result(
                "GET",
                f"/projects/{project_id}/jobs/{fields['job_id']}/trace",
                max_bytes=_JOB_LOG_MAX_BYTES,
                expected=(200,),
            )
        except BudgetExhausted:
            download = _truncated_download_metadata()
        else:
            download = _download_metadata(response.content)
        records.append({**fields, **download})
    async for batch in time_id_batches(
        records, checkpoint, mode, complete=complete, time_of=_job_time, id_of=_job_key, durable=_download_durable
    ):
        yield batch


@stream("job_artifacts", cursor=TimeIdCursor, capability="SourceControl", modes=("incremental",))
async def job_artifacts(
    connector: GitLabConnectorBase, target: Target | None, checkpoint: TimeIdCursor | None, mode: str
) -> AsyncIterator[RawBatch]:
    project_id = numeric_id(target, "project")
    jobs, complete = await gather(connector, f"/projects/{project_id}/jobs")
    records: list[dict[str, Any]] = []
    for job in jobs:
        artifacts = job.get("artifacts")
        if not isinstance(artifacts, list) or not artifacts:
            continue
        names = sorted(
            str(artifact["filename"]) for artifact in artifacts if isinstance(artifact, dict) and artifact.get("filename")
        )
        fields = _job_fields(project_id, job)
        try:
            response = await connector.http.stream_download_result(
                "GET",
                f"/projects/{project_id}/jobs/{fields['job_id']}/artifacts",
                max_bytes=_ARTIFACT_MAX_BYTES,
                expected=(200,),
            )
        except BudgetExhausted:
            download = _truncated_download_metadata()
        else:
            download = _download_metadata(response.content)
        records.append({**fields, **download, "artifact_names": names})
    async for batch in time_id_batches(
        records, checkpoint, mode, complete=complete, time_of=_job_time, id_of=_job_key, durable=_download_durable
    ):
        yield batch


@stream("pipelines", cursor=TimeIdCursor, capability="SourceControl")
async def pipelines(
    connector: GitLabConnectorBase, target: Target | None, checkpoint: TimeIdCursor | None, mode: str
) -> AsyncIterator[RawBatch]:
    project_id = numeric_id(target, "project")
    records, complete = await gather(
        connector, f"/projects/{project_id}/pipelines", _pipeline_query(checkpoint, mode)
    )
    async for batch in time_id_batches(
        annotate(records, _project_id=project_id),
        checkpoint,
        mode,
        complete=complete,
        time_of=_updated_at,
        id_of=_project_key,
    ):
        yield batch


@stream("jobs", cursor=TimeIdCursor, capability="SourceControl")
async def jobs(
    connector: GitLabConnectorBase, target: Target | None, checkpoint: TimeIdCursor | None, mode: str
) -> AsyncIterator[RawBatch]:
    """Jobs of every pipeline updated inside the window; the pipeline update time bounds the selection."""
    project_id = numeric_id(target, "project")
    records, complete = await _pipeline_children(
        connector, project_id, checkpoint, mode, _pipeline_child_fetch(connector, project_id, "jobs")
    )
    async for batch in time_id_batches(
        records,
        checkpoint,
        mode,
        complete=complete,
        time_of=_pipeline_updated_at,
        id_of=_project_key,
    ):
        yield batch


@stream("pipeline_bridges", cursor=TimeIdCursor, capability="SourceControl")
async def pipeline_bridges(
    connector: GitLabConnectorBase, target: Target | None, checkpoint: TimeIdCursor | None, mode: str
) -> AsyncIterator[RawBatch]:
    project_id = numeric_id(target, "project")
    records, complete = await _pipeline_children(
        connector, project_id, checkpoint, mode, _pipeline_child_fetch(connector, project_id, "bridges")
    )
    async for batch in time_id_batches(
        records,
        checkpoint,
        mode,
        complete=complete,
        time_of=_pipeline_updated_at,
        id_of=_project_key,
    ):
        yield batch


@stream("pipeline_test_reports", cursor=TimeIdCursor, capability="SourceControl")
async def pipeline_test_reports(
    connector: GitLabConnectorBase, target: Target | None, checkpoint: TimeIdCursor | None, mode: str
) -> AsyncIterator[RawBatch]:
    project_id = numeric_id(target, "project")
    records, complete = await _pipeline_children(
        connector, project_id, checkpoint, mode, _test_report_fetch(connector, project_id)
    )
    async for batch in time_id_batches(
        records,
        checkpoint,
        mode,
        complete=complete,
        time_of=_pipeline_updated_at,
        id_of=_test_report_key,
    ):
        yield batch


@stream("pipeline_variables", cursor=TimeIdCursor, capability="SourceControl")
async def pipeline_variables(
    connector: GitLabConnectorBase, target: Target | None, checkpoint: TimeIdCursor | None, mode: str
) -> AsyncIterator[RawBatch]:
    """Variable keys and types only; values are never fetched into a record."""
    project_id = numeric_id(target, "project")
    records, complete = await _pipeline_children(
        connector, project_id, checkpoint, mode, _variable_fetch(connector, project_id)
    )
    async for batch in time_id_batches(
        records,
        checkpoint,
        mode,
        complete=complete,
        time_of=_pipeline_updated_at,
        id_of=_variable_key,
    ):
        yield batch


@stream("mr_diffs", cursor=SnapshotCursor, capability="SourceControl", modes=("full",))
async def mr_diffs(
    connector: GitLabConnectorBase, target: Target | None, _checkpoint: SnapshotCursor | None, _mode: str
) -> AsyncIterator[RawBatch]:
    project_id = numeric_id(target, "project")
    records, complete = await _merge_request_snapshot(
        connector, project_id, _mr_child_fetch(connector, project_id, "diffs")
    )
    async for batch in snapshot_batches(connector, "mr_diffs", f"project:{project_id}", records, complete=complete):
        yield batch


@stream("mr_versions", cursor=SnapshotCursor, capability="SourceControl", modes=("full",))
async def mr_versions(
    connector: GitLabConnectorBase, target: Target | None, _checkpoint: SnapshotCursor | None, _mode: str
) -> AsyncIterator[RawBatch]:
    project_id = numeric_id(target, "project")
    records, complete = await _merge_request_snapshot(
        connector, project_id, _mr_child_fetch(connector, project_id, "versions")
    )
    async for batch in snapshot_batches(
        connector, "mr_versions", f"project:{project_id}", records, complete=complete
    ):
        yield batch


@stream("mr_commits", cursor=SnapshotCursor, capability="SourceControl", modes=("full",))
async def mr_commits(
    connector: GitLabConnectorBase, target: Target | None, _checkpoint: SnapshotCursor | None, _mode: str
) -> AsyncIterator[RawBatch]:
    project_id = numeric_id(target, "project")
    records, complete = await _merge_request_snapshot(
        connector, project_id, _mr_child_fetch(connector, project_id, "commits")
    )
    async for batch in snapshot_batches(
        connector, "mr_commits", f"project:{project_id}", records, complete=complete
    ):
        yield batch


@stream("mr_pipelines", cursor=SnapshotCursor, capability="SourceControl", modes=("full",))
async def mr_pipelines(
    connector: GitLabConnectorBase, target: Target | None, _checkpoint: SnapshotCursor | None, _mode: str
) -> AsyncIterator[RawBatch]:
    project_id = numeric_id(target, "project")
    records, complete = await _merge_request_snapshot(
        connector, project_id, _mr_child_fetch(connector, project_id, "pipelines")
    )
    async for batch in snapshot_batches(
        connector, "mr_pipelines", f"project:{project_id}", records, complete=complete
    ):
        yield batch


@stream("mr_approval_rules", cursor=SnapshotCursor, capability="SourceControl", modes=("full",))
async def mr_approval_rules(
    connector: GitLabConnectorBase, target: Target | None, _checkpoint: SnapshotCursor | None, _mode: str
) -> AsyncIterator[RawBatch]:
    project_id = numeric_id(target, "project")
    records, complete = await _merge_request_snapshot(
        connector, project_id, _mr_child_fetch(connector, project_id, "approval_rules")
    )
    async for batch in snapshot_batches(
        connector, "mr_approval_rules", f"project:{project_id}", records, complete=complete
    ):
        yield batch


@stream("mr_approval_state", cursor=SnapshotCursor, capability="SourceControl", modes=("full",))
async def mr_approval_state(
    connector: GitLabConnectorBase, target: Target | None, _checkpoint: SnapshotCursor | None, _mode: str
) -> AsyncIterator[RawBatch]:
    project_id = numeric_id(target, "project")
    records, complete = await _merge_request_snapshot(connector, project_id, _mr_state_fetch(connector, project_id))
    async for batch in snapshot_batches(
        connector, "mr_approval_state", f"project:{project_id}", records, complete=complete
    ):
        yield batch
