"""Read-only GitLab operations for vulnerability findings, exports, repositories, pipelines, and merge requests.

Operations here only read from GitLab; none create, update, or delete objects.
Bounded downloads (job logs, job artifacts, repository files) return digests and sizes only,
never the downloaded bytes or text.
"""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Awaitable, Callable
from datetime import datetime
from typing import Any
from urllib.parse import quote

from pydantic import BaseModel

from icuhub.kit import ConfigError
from icuhub.kit.errors import BudgetExhausted, VendorContractError

from .exports import download_vulnerability_export, get_vulnerability_export
from .graphql import traverse_vulnerabilities
from .models import (
    ArtifactRef,
    CommitRef,
    DownloadVulnerabilityExportInput,
    ExportRef,
    GroupRef,
    JobRef,
    ListAuditEventsInput,
    ListMergeRequestsInput,
    ListVulnerabilitiesInput,
    MergeRequestRef,
    PipelineRef,
    ProjectRef,
    RepositoryPathRef,
    VendorResult,
    VulnerabilityRef,
)
from .support import gather

__all__ = ["execute_operation"]

_Handler = Callable[[Any, Any], Awaitable[VendorResult]]

# Byte caps for bounded downloads. The repository file and blame caps apply to the JSON response body.
_JOB_LOG_MAX_BYTES = 8 * 1024 * 1024
_JOB_ARTIFACT_MAX_BYTES = 32 * 1024 * 1024
_REPOSITORY_FILE_MAX_BYTES = 1024 * 1024


def _paged(records: list[dict[str, Any]], complete: bool) -> VendorResult:
    return VendorResult(data=records, coverage="complete" if complete else "partial")


def _json_object(body: Any, what: str) -> dict[str, Any]:
    if not isinstance(body, dict):
        raise VendorContractError(f"GitLab {what} response is not a JSON object")
    return body


def _iso(value: datetime | None) -> str | None:
    return None if value is None else value.isoformat()


def _query(**fields: str | None) -> dict[str, str]:
    return {key: value for key, value in fields.items() if value is not None}


def _digest(content: bytes) -> dict[str, Any]:
    return {"sha256": hashlib.sha256(content).hexdigest(), "bytes": len(content), "truncated": False}


def _truncated_digest() -> dict[str, Any]:
    return {"sha256": None, "bytes": 0, "truncated": True}


async def _get_object(connector: Any, path: str, what: str) -> VendorResult:
    response = await connector.http.request("GET", path)
    return VendorResult(data=_json_object(response.json(), what))


def _commit_path(args: CommitRef) -> str:
    return f"/projects/{args.project_id}/repository/commits/{quote(args.sha, safe='')}"


def _job_path(args: JobRef) -> str:
    return f"/projects/{args.project_id}/jobs/{args.job_id}"


def _file_path(args: RepositoryPathRef, suffix: str = "") -> str:
    return f"/projects/{args.project_id}/repository/files/{quote(args.path, safe='')}{suffix}"


def _artifact_path(job_path: str, artifact_path: str | None) -> str:
    if artifact_path is None:
        return f"{job_path}/artifacts"
    if any(segment in ("", ".", "..") for segment in artifact_path.split("/")):
        raise ConfigError("artifact_path must not contain empty, '.', or '..' segments")
    return f"{job_path}/artifacts/{quote(artifact_path, safe='/')}"


def _blame_range(item: Any) -> dict[str, Any]:
    """Keep the blame commit metadata and line count; the blamed source lines are never returned."""
    if not isinstance(item, dict):
        raise VendorContractError("GitLab blame range is not a JSON object")
    lines = item.get("lines")
    if not isinstance(lines, list):
        raise VendorContractError("GitLab blame range has no lines list")
    return {**{key: value for key, value in item.items() if key != "lines"}, "line_count": len(lines)}


async def _list_vulnerabilities(connector: Any, args: ListVulnerabilitiesInput) -> VendorResult:
    findings, complete = await traverse_vulnerabilities(connector, args.project_id)
    return VendorResult(
        data={"vulnerabilities": findings, "count": len(findings), "complete": complete},
        coverage="complete" if complete else "partial",
    )


async def _get_project(connector: Any, args: ProjectRef) -> VendorResult:
    return await _get_object(connector, f"/projects/{args.project_id}", "project")


async def _get_group(connector: Any, args: GroupRef) -> VendorResult:
    return await _get_object(connector, f"/groups/{args.group_id}", "group")


async def _get_vulnerability_detail(connector: Any, args: VulnerabilityRef) -> VendorResult:
    """The REST vulnerability object; it carries ``id``, ``state``, and ``severity`` among its fields."""
    return await _get_object(connector, f"/vulnerabilities/{args.vulnerability_id}", "vulnerability")


async def _get_commit(connector: Any, args: CommitRef) -> VendorResult:
    return await _get_object(connector, _commit_path(args), "commit")


async def _list_commit_diffs(connector: Any, args: CommitRef) -> VendorResult:
    records, complete = await gather(connector, f"{_commit_path(args)}/diff")
    return _paged(records, complete)


async def _get_repository_file(connector: Any, args: RepositoryPathRef) -> VendorResult:
    """File metadata plus the SHA-256 and size of the decoded content; the content itself is not returned."""
    ref = args.ref or "HEAD"
    try:
        response = await connector.http.stream_download_result(
            "GET",
            _file_path(args),
            max_bytes=_REPOSITORY_FILE_MAX_BYTES,
            params={"ref": ref},
            expected=(200,),
        )
    except BudgetExhausted:
        return VendorResult(data={"file_path": args.path, "ref": ref, **_truncated_digest()}, coverage="partial")
    body = _json_object(response.json(), "repository file")
    content = body.get("content")
    if body.get("encoding") != "base64" or not isinstance(content, str):
        raise VendorContractError("GitLab repository file response has no base64 content")
    try:
        decoded = base64.b64decode(content)
    except ValueError as exc:
        raise VendorContractError("GitLab repository file content is not valid base64") from exc
    metadata = {key: value for key, value in body.items() if key != "content"}
    return VendorResult(data={**metadata, "ref": ref, **_digest(decoded)})


async def _get_file_blame(connector: Any, args: RepositoryPathRef) -> VendorResult:
    ref = args.ref or "HEAD"
    try:
        response = await connector.http.stream_download_result(
            "GET",
            _file_path(args, "/blame"),
            max_bytes=_REPOSITORY_FILE_MAX_BYTES,
            params={"ref": ref},
            expected=(200,),
        )
    except BudgetExhausted:
        return VendorResult(data=[], coverage="partial")
    body = response.json()
    if not isinstance(body, list):
        raise VendorContractError("GitLab blame response is not a JSON array")
    return VendorResult(data=[_blame_range(item) for item in body])


async def _list_pipelines(connector: Any, args: ProjectRef) -> VendorResult:
    records, complete = await gather(connector, f"/projects/{args.project_id}/pipelines")
    return _paged(records, complete)


async def _list_pipeline_jobs(connector: Any, args: PipelineRef) -> VendorResult:
    records, complete = await gather(connector, f"/projects/{args.project_id}/pipelines/{args.pipeline_id}/jobs")
    return _paged(records, complete)


async def _get_job(connector: Any, args: JobRef) -> VendorResult:
    return await _get_object(connector, _job_path(args), "job")


async def _download_job_log(connector: Any, args: JobRef) -> VendorResult:
    try:
        response = await connector.http.stream_download_result(
            "GET",
            f"{_job_path(args)}/trace",
            max_bytes=_JOB_LOG_MAX_BYTES,
            expected=(200,),
        )
    except BudgetExhausted:
        return VendorResult(data=_truncated_digest(), coverage="partial")
    return VendorResult(data=_digest(response.content))


async def _download_job_artifact(connector: Any, args: ArtifactRef) -> VendorResult:
    try:
        response = await connector.http.stream_download_result(
            "GET",
            _artifact_path(_job_path(args), args.artifact_path),
            max_bytes=_JOB_ARTIFACT_MAX_BYTES,
            expected=(200,),
        )
    except BudgetExhausted:
        return VendorResult(data=_truncated_digest(), coverage="partial")
    return VendorResult(data=_digest(response.content))


async def _list_audit_events(connector: Any, args: ListAuditEventsInput) -> VendorResult:
    if (args.project_id is None) == (args.group_id is None):
        raise ConfigError("list_audit_events requires exactly one of project_id or group_id")
    scope = f"/projects/{args.project_id}" if args.project_id is not None else f"/groups/{args.group_id}"
    params = _query(created_after=_iso(args.created_after), created_before=_iso(args.created_before))
    records, complete = await gather(connector, f"{scope}/audit_events", params)
    return _paged(records, complete)


async def _list_merge_requests(connector: Any, args: ListMergeRequestsInput) -> VendorResult:
    """``page`` is the first page read; later pages are followed through the Link header.

    Without ``project_id`` the read spans every merge request the token can see (global ``/merge_requests``).
    """
    params = _query(
        page=str(args.page),
        state=args.state,
        updated_after=_iso(args.updated_after),
        updated_before=_iso(args.updated_before),
    )
    path = "/merge_requests" if args.project_id is None else f"/projects/{args.project_id}/merge_requests"
    records, complete = await gather(connector, path, params)
    return _paged(records, complete)


async def _list_mr_child(connector: Any, args: MergeRequestRef, suffix: str) -> VendorResult:
    records, complete = await gather(connector, f"/projects/{args.project_id}/merge_requests/{args.iid}/{suffix}")
    return _paged(records, complete)


async def _list_mr_diffs(connector: Any, args: MergeRequestRef) -> VendorResult:
    return await _list_mr_child(connector, args, "diffs")


async def _list_mr_versions(connector: Any, args: MergeRequestRef) -> VendorResult:
    return await _list_mr_child(connector, args, "versions")


async def _list_mr_commits(connector: Any, args: MergeRequestRef) -> VendorResult:
    return await _list_mr_child(connector, args, "commits")


async def _list_mr_pipelines(connector: Any, args: MergeRequestRef) -> VendorResult:
    return await _list_mr_child(connector, args, "pipelines")


_OPERATIONS: dict[str, tuple[type[BaseModel], _Handler]] = {
    "list_vulnerabilities": (ListVulnerabilitiesInput, _list_vulnerabilities),
    "get_vulnerability_export": (ExportRef, get_vulnerability_export),
    "download_vulnerability_export": (DownloadVulnerabilityExportInput, download_vulnerability_export),
    "get_project": (ProjectRef, _get_project),
    "get_group": (GroupRef, _get_group),
    "get_vulnerability_detail": (VulnerabilityRef, _get_vulnerability_detail),
    "get_commit": (CommitRef, _get_commit),
    "list_commit_diffs": (CommitRef, _list_commit_diffs),
    "get_repository_file": (RepositoryPathRef, _get_repository_file),
    "get_file_blame": (RepositoryPathRef, _get_file_blame),
    "list_pipelines": (ProjectRef, _list_pipelines),
    "list_pipeline_jobs": (PipelineRef, _list_pipeline_jobs),
    "get_job": (JobRef, _get_job),
    "download_job_log": (JobRef, _download_job_log),
    "download_job_artifact": (ArtifactRef, _download_job_artifact),
    "list_audit_events": (ListAuditEventsInput, _list_audit_events),
    "list_merge_requests": (ListMergeRequestsInput, _list_merge_requests),
    "list_mr_diffs": (MergeRequestRef, _list_mr_diffs),
    "list_mr_versions": (MergeRequestRef, _list_mr_versions),
    "list_mr_commits": (MergeRequestRef, _list_mr_commits),
    "list_mr_pipelines": (MergeRequestRef, _list_mr_pipelines),
}


async def execute_operation(connector: Any, name: str, args: BaseModel) -> VendorResult:
    """Run the named GitLab operation after checking that ``args`` has the operation's input model."""
    entry = _OPERATIONS.get(name)
    if entry is None:
        raise ConfigError(f"unknown GitLab operation {name!r}")
    input_model, handler = entry
    if not isinstance(args, input_model):
        raise ConfigError(f"GitLab operation {name!r} expects {input_model.__name__}")
    return await handler(connector, args)
