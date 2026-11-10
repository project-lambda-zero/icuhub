"""Live GitLab self-managed acceptance: health, identity, vulnerabilities, exports, repository, jobs, audit, and gated writes."""

from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, cast

import httpx2
import pytest

from icuhub.connectors._gitlab.models import (
    ApproveMergeRequestArgs,
    ArtifactRef,
    ChangeVulnerabilityStateArgs,
    CommitRef,
    ControlJobArgs,
    ControlPipelineArgs,
    CreateMergeRequestArgs,
    CreateMrNoteOrDiscussionArgs,
    CreateVulnerabilityExportInput,
    DownloadVulnerabilityExportInput,
    ExportRef,
    GroupRef,
    JobRef,
    ListAuditEventsInput,
    ListMergeRequestsInput,
    ListVulnerabilitiesInput,
    MergeMergeRequestArgs,
    MergeRequestRef,
    PipelineRef,
    ProjectRef,
    PublishSecurityReportArtifactArgs,
    RepositoryPathRef,
    VulnerabilityRef,
)
from icuhub.connectors.gitlab_self_managed import GitLabSelfManaged
from icuhub.kit.testing import collect_stream, make_connector
from icuhub.kit.types import Target

ACCEPTANCE_KIND = "gitlab_self_managed"

_PLACEHOLDER_HASH = "0" * 64
_EXPORT_TERMINAL = ("finished", "failed", "expired")
_EXPORT_POLL_ATTEMPTS = 30
_EXPORT_POLL_SECONDS = 5.0
_SUCCESS = ("succeeded", "no_op")
_SUCCESS_OR_ASYNC = ("succeeded", "no_op", "accepted_async")


def _connector(acceptance) -> GitLabSelfManaged:
    return make_connector(  # type: ignore[return-value]
        GitLabSelfManaged, acceptance.config, httpx2.AsyncHTTPTransport(), acceptance.secrets
    )


def _write_connector(acceptance) -> GitLabSelfManaged:
    config = {
        **acceptance.config,
        "write_enabled": acceptance.allow_writes,
        "destructive_enabled": bool(acceptance.params.get("allow_destructive", False)),
    }
    return make_connector(  # type: ignore[return-value]
        GitLabSelfManaged, config, httpx2.AsyncHTTPTransport(), acceptance.secrets
    )


def _required_param(acceptance, name: str) -> str:
    if name not in acceptance.params:
        pytest.skip(f"{ACCEPTANCE_KIND}: params.{name} is required")
    return str(acceptance.params[name])


def _int_param(acceptance, name: str) -> int:
    return int(_required_param(acceptance, name))


def _optional(acceptance, name: str) -> str | None:
    value = acceptance.params.get(name)
    return None if value in (None, "") else str(value)


def _optional_int(acceptance, name: str) -> int | None:
    value = _optional(acceptance, name)
    return None if value is None else int(value)


def _optional_datetime(acceptance, name: str) -> datetime | None:
    value = _optional(acceptance, name)
    if value is None:
        return None
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        pytest.fail(f"{ACCEPTANCE_KIND}: params.{name} must carry a timezone offset")
    return parsed


def _call(connector: GitLabSelfManaged, name: str, args: Any) -> Any:
    return asyncio.run(connector.operations()[name].fn(connector, args))


def _project_target(project_id: int) -> Target:
    return Target(
        id=str(project_id),
        source_uid=str(project_id),
        kind="project",
        display_name=f"Project {project_id}",
        attributes={},
    )


def _action_key(name: str) -> str:
    return f"icuhub-acc-{name.replace('_', '-')}"


def _run_action(connector: GitLabSelfManaged, name: str, probe: Any) -> tuple[Any, Any]:
    """Plan, bind the approval hash to the plan when the action takes one, apply, then reconcile if required."""
    spec = connector.actions()[name]
    plan = asyncio.run(spec.plan(connector, probe))
    if "approved_plan_hash" in type(probe).model_fields:
        approved = probe.model_copy(update={"approved_plan_hash": plan.plan_hash})
        replanned = asyncio.run(spec.plan(connector, approved))
        assert replanned.plan_hash == plan.plan_hash, "plan changed between approval rounds"
        plan = replanned
    outcome = asyncio.run(spec.apply(connector, plan))
    if outcome.status in ("accepted_async", "outcome_unknown"):
        assert spec.reconcile is not None
        outcome = asyncio.run(spec.reconcile(connector, plan, outcome))
    return plan, outcome


def _metadata_ok(data: dict[str, Any]) -> bool:
    digest = data.get("sha256")
    size = data.get("bytes")
    return isinstance(digest, str) and len(digest) == 64 and isinstance(size, int) and size >= 0


def _head_sha(connector: GitLabSelfManaged, project_id: int, iid: int) -> str:
    return str(asyncio.run(connector.get_merge_request(project_id, iid))["sha"])


def test_server_version_and_discovery(acceptance) -> None:
    report = asyncio.run(_connector(acceptance).check())
    healthy = report.status in ("healthy", "degraded") and report.vendor_version is not None
    acceptance.record(
        "server_version_and_discovery",
        healthy,
        report.status,
        version=report.vendor_version,
        capabilities=sorted(report.capabilities),
    )
    assert healthy


def test_get_merge_request(acceptance) -> None:
    project_id = int(_required_param(acceptance, "project_id"))
    iid = int(_required_param(acceptance, "merge_request_iid"))
    merge_request = asyncio.run(_connector(acceptance).get_merge_request(project_id, iid))
    found = merge_request.get("iid") == iid
    acceptance.record("get_merge_request", found, "merge request read", iid=iid)
    assert found


def test_project_and_group_identity(acceptance) -> None:
    connector = _connector(acceptance)
    project_id = _optional_int(acceptance, "project_id")
    group_id = _optional_int(acceptance, "group_id")
    if project_id is None and group_id is None:
        pytest.skip(f"{ACCEPTANCE_KIND}: params.project_id or params.group_id is required for identity reads")
    if project_id is not None:
        project = _call(connector, "get_project", ProjectRef(project_id=project_id))
        project_ok = project.coverage == "complete" and bool(project.data)
        acceptance.record("get_project", project_ok, project.coverage, project_id=project_id)
        assert project_ok
    if group_id is not None:
        group = _call(connector, "get_group", GroupRef(group_id=group_id))
        group_ok = group.coverage == "complete" and bool(group.data)
        acceptance.record("get_group", group_ok, group.coverage, group_id=group_id)
        assert group_ok


def test_vulnerability_operation_traversal(acceptance) -> None:
    connector = _connector(acceptance)
    project_id = _int_param(acceptance, "project_id")
    result = _call(connector, "list_vulnerabilities", ListVulnerabilitiesInput(project_id=project_id))
    vulnerabilities = result.data["vulnerabilities"]
    complete = result.data["complete"] is True and result.coverage == "complete" and not result.dropped
    counted = result.data["count"] == len(vulnerabilities)
    acceptance.record(
        "list_vulnerabilities",
        complete and counted,
        "complete traversal" if complete and counted else "traversal incomplete or count mismatch",
        count=len(vulnerabilities),
        coverage=result.coverage,
    )
    assert complete and counted


def test_vulnerability_full_stream_traversal(acceptance) -> None:
    connector = _connector(acceptance)
    project_id = _int_param(acceptance, "project_id")
    assert "full" in connector.streams()["vulnerabilities"].modes
    batches = collect_stream(connector, "vulnerabilities", target=_project_target(project_id), mode="full")
    complete = bool(batches) and batches[-1].complete
    records = sum(len(batch.records) for batch in batches)
    acceptance.record(
        "vulnerability_full_traversal",
        complete,
        "complete" if complete else "incomplete",
        batches=len(batches),
        records=records,
    )
    assert complete


def test_vulnerability_detail_read(acceptance) -> None:
    vulnerability_id = _optional_int(acceptance, "vulnerability_id")
    if vulnerability_id is None:
        pytest.skip(f"{ACCEPTANCE_KIND}: params.vulnerability_id is required")
    detail = _call(_connector(acceptance), "get_vulnerability_detail", VulnerabilityRef(vulnerability_id=vulnerability_id))
    detail_ok = detail.coverage == "complete" and bool(detail.data)
    acceptance.record("get_vulnerability_detail", detail_ok, detail.coverage)
    assert detail_ok


def _export_scope(acceptance) -> dict[str, Any]:
    scope = _optional(acceptance, "vulnerability_export_scope")
    if scope == "project":
        return {"project_id": _int_param(acceptance, "project_id")}
    if scope == "group":
        return {"group_id": _int_param(acceptance, "group_id")}
    if scope == "instance":
        return {"authorized_instance": True}
    pytest.skip(f"{ACCEPTANCE_KIND}: params.vulnerability_export_scope must be project, group, or instance")


def _poll_export(connector: GitLabSelfManaged, export_id: int) -> str:
    for _ in range(_EXPORT_POLL_ATTEMPTS):
        status = str(_call(connector, "get_vulnerability_export", ExportRef(export_id=export_id)).data["status"])
        if status in _EXPORT_TERMINAL:
            return status
        time.sleep(_EXPORT_POLL_SECONDS)
    return "timeout"


def test_vulnerability_export_create_poll_download(acceptance) -> None:
    acceptance.require_writes()
    scope = _export_scope(acceptance)
    _, created = _run_action(
        _write_connector(acceptance),
        "create_vulnerability_export",
        CreateVulnerabilityExportInput(**scope),
    )
    acceptance.record("create_vulnerability_export", created.status == "accepted_async", created.status)
    assert created.status == "accepted_async"
    export_id = int(created.result["export_id"])
    connector = _connector(acceptance)
    status = _poll_export(connector, export_id)
    acceptance.record("vulnerability_export_status", status == "finished", status)
    assert status == "finished"
    download = _call(
        connector,
        "download_vulnerability_export",
        DownloadVulnerabilityExportInput(export_id=export_id),
    ).data
    bounded = _metadata_ok(download)
    acceptance.record("vulnerability_export_download", bounded, "download metadata", size_bytes=download.get("bytes"))
    assert bounded


def test_commit_and_diff_reads(acceptance) -> None:
    sha = _optional(acceptance, "commit_sha")
    if sha is None:
        pytest.skip(f"{ACCEPTANCE_KIND}: params.commit_sha is required for commit reads")
    connector = _connector(acceptance)
    commit_ref = CommitRef(project_id=_int_param(acceptance, "project_id"), sha=sha)
    commit = _call(connector, "get_commit", commit_ref)
    commit_ok = commit.coverage == "complete" and bool(commit.data)
    acceptance.record("get_commit", commit_ok, commit.coverage)
    diffs = _call(connector, "list_commit_diffs", commit_ref)
    diffs_ok = diffs.coverage == "complete" and not diffs.dropped
    acceptance.record("list_commit_diffs", diffs_ok, diffs.coverage, dropped=len(diffs.dropped))
    assert commit_ok and diffs_ok


def test_repository_file_and_blame(acceptance) -> None:
    path = _optional(acceptance, "repository_path")
    if path is None:
        pytest.skip(f"{ACCEPTANCE_KIND}: params.repository_path is required for file and blame reads")
    connector = _connector(acceptance)
    file_ref = RepositoryPathRef(
        project_id=_int_param(acceptance, "project_id"),
        path=path,
        ref=_optional(acceptance, "repository_ref"),
    )
    file_result = _call(connector, "get_repository_file", file_ref)
    file_ok = file_result.coverage == "complete" and _metadata_ok(file_result.data)
    acceptance.record(
        "get_repository_file", file_ok, file_result.coverage, truncated=file_result.data.get("truncated")
    )
    blame = _call(connector, "get_file_blame", file_ref)
    blame_ok = blame.coverage == "complete" and isinstance(blame.data, list)
    acceptance.record("get_file_blame", blame_ok, blame.coverage)
    assert file_ok and blame_ok


def test_pipeline_and_job_reads(acceptance) -> None:
    project_id = _int_param(acceptance, "project_id")
    pipeline_id = _optional_int(acceptance, "pipeline_id")
    job_id = _optional_int(acceptance, "job_id")
    connector = _connector(acceptance)
    pipelines = _call(connector, "list_pipelines", ProjectRef(project_id=project_id))
    pipelines_ok = pipelines.coverage == "complete" and isinstance(pipelines.data, list)
    acceptance.record("list_pipelines", pipelines_ok, pipelines.coverage)
    assert pipelines_ok
    if pipeline_id is not None:
        jobs = _call(connector, "list_pipeline_jobs", PipelineRef(project_id=project_id, pipeline_id=pipeline_id))
        jobs_ok = jobs.coverage == "complete" and isinstance(jobs.data, list)
        acceptance.record("list_pipeline_jobs", jobs_ok, jobs.coverage)
        assert jobs_ok
    if job_id is not None:
        job = _call(connector, "get_job", JobRef(project_id=project_id, job_id=job_id))
        job_ok = job.coverage == "complete" and bool(job.data)
        acceptance.record("get_job", job_ok, job.coverage)
        assert job_ok


def test_merge_request_reads(acceptance) -> None:
    project_id = _int_param(acceptance, "project_id")
    iid = _optional_int(acceptance, "merge_request_iid")
    connector = _connector(acceptance)
    listed = _call(connector, "list_merge_requests", ListMergeRequestsInput(project_id=project_id))
    listed_ok = listed.coverage == "complete" and isinstance(listed.data, list)
    acceptance.record("list_merge_requests", listed_ok, listed.coverage)
    assert listed_ok
    if iid is not None:
        mr_ref = MergeRequestRef(project_id=project_id, iid=iid)
        for name in ("list_mr_diffs", "list_mr_versions", "list_mr_commits", "list_mr_pipelines"):
            child = _call(connector, name, mr_ref)
            child_ok = child.coverage == "complete" and isinstance(child.data, list)
            acceptance.record(name, child_ok, child.coverage)
            assert child_ok


def test_bounded_job_log(acceptance) -> None:
    job_id = _optional_int(acceptance, "job_id")
    if job_id is None:
        pytest.skip(f"{ACCEPTANCE_KIND}: params.job_id is required for job log reads")
    connector = _connector(acceptance)
    log = _call(connector, "download_job_log", JobRef(project_id=_int_param(acceptance, "project_id"), job_id=job_id))
    bounded = _metadata_ok(log.data) and isinstance(log.data.get("truncated"), bool)
    acceptance.record("download_job_log", bounded, "job log metadata", truncated=log.data.get("truncated"))
    assert bounded


def test_bounded_job_artifact(acceptance) -> None:
    job_id = _optional_int(acceptance, "job_id")
    artifact_path = _optional(acceptance, "artifact_path")
    if job_id is None or artifact_path is None:
        pytest.skip(f"{ACCEPTANCE_KIND}: params.job_id and params.artifact_path are required for artifact reads")
    connector = _connector(acceptance)
    artifact = ArtifactRef(
        project_id=_int_param(acceptance, "project_id"),
        job_id=job_id,
        artifact_path=artifact_path,
    )
    result = _call(connector, "download_job_artifact", artifact)
    bounded = _metadata_ok(result.data) and isinstance(result.data.get("truncated"), bool)
    acceptance.record("download_job_artifact", bounded, "artifact metadata", truncated=result.data.get("truncated"))
    assert bounded


def test_audit_events(acceptance) -> None:
    project_id = _optional_int(acceptance, "project_id")
    group_id = _optional_int(acceptance, "group_id")
    if project_id is None and group_id is None:
        pytest.skip(f"{ACCEPTANCE_KIND}: params.project_id or params.group_id is required for audit reads")
    connector = _connector(acceptance)
    args = ListAuditEventsInput(
        project_id=project_id,
        group_id=group_id,
        created_after=_optional_datetime(acceptance, "audit_created_after"),
        created_before=_optional_datetime(acceptance, "audit_created_before"),
    )
    result = _call(connector, "list_audit_events", args)
    complete = result.coverage == "complete" and not result.dropped and isinstance(result.data, list)
    acceptance.record("list_audit_events", complete, result.coverage, dropped=len(result.dropped))
    assert complete


def test_gated_create_merge_request(acceptance) -> None:
    acceptance.require_writes()
    project_id = _int_param(acceptance, "project_id")
    probe = CreateMergeRequestArgs(
        project_id=project_id,
        source_branch=_required_param(acceptance, "source_branch"),
        target_branch=_required_param(acceptance, "target_branch"),
        title=str(acceptance.params.get("merge_request_title", "ICUHUB acceptance merge request")),
        action_key=_action_key("create_merge_request"),
        approved_plan_hash=_PLACEHOLDER_HASH,
    )
    plan, outcome = _run_action(_write_connector(acceptance), "create_merge_request", probe)
    acceptance.record("create_merge_request", outcome.status in _SUCCESS, outcome.status, changed=plan.changed)
    assert outcome.status in _SUCCESS


def test_gated_mr_note_or_discussion(acceptance) -> None:
    acceptance.require_writes()
    probe = CreateMrNoteOrDiscussionArgs(
        project_id=_int_param(acceptance, "project_id"),
        iid=_int_param(acceptance, "merge_request_iid"),
        body=str(acceptance.params.get("note_body", "ICUHUB acceptance note")),
        action_key=_action_key("create_mr_note_or_discussion"),
        approved_plan_hash=_PLACEHOLDER_HASH,
    )
    plan, outcome = _run_action(_write_connector(acceptance), "create_mr_note_or_discussion", probe)
    acceptance.record("create_mr_note_or_discussion", outcome.status in _SUCCESS, outcome.status, changed=plan.changed)
    assert outcome.status in _SUCCESS


def test_gated_approve_merge_request(acceptance) -> None:
    acceptance.require_writes()
    project_id = _int_param(acceptance, "project_id")
    iid = _int_param(acceptance, "merge_request_iid")
    connector = _write_connector(acceptance)
    probe = ApproveMergeRequestArgs(
        project_id=project_id,
        iid=iid,
        sha=_head_sha(connector, project_id, iid),
        action_key=_action_key("approve_merge_request"),
        approved_plan_hash=_PLACEHOLDER_HASH,
    )
    plan, outcome = _run_action(connector, "approve_merge_request", probe)
    acceptance.record("approve_merge_request", outcome.status in _SUCCESS, outcome.status, changed=plan.changed)
    assert outcome.status in _SUCCESS


def test_gated_change_vulnerability_state(acceptance) -> None:
    acceptance.require_writes()
    vulnerability_id = _optional_int(acceptance, "vulnerability_id")
    target_state = _optional(acceptance, "vulnerability_target_state")
    if vulnerability_id is None or target_state is None:
        pytest.skip(f"{ACCEPTANCE_KIND}: params.vulnerability_id and params.vulnerability_target_state are required")
    connector = _write_connector(acceptance)
    observed = str(asyncio.run(connector.get_vulnerability(vulnerability_id))["state"])
    probe = ChangeVulnerabilityStateArgs(
        vulnerability_id=vulnerability_id,
        expected_state=observed,
        state=target_state,
        action_key=_action_key("change_vulnerability_state"),
        approved_plan_hash=_PLACEHOLDER_HASH,
    )
    plan, outcome = _run_action(connector, "change_vulnerability_state", probe)
    acceptance.record("change_vulnerability_state", outcome.status in _SUCCESS, outcome.status, changed=plan.changed)
    assert outcome.status in _SUCCESS


def test_gated_merge_request_merge(acceptance) -> None:
    acceptance.require_writes()
    if not acceptance.params.get("allow_destructive"):
        pytest.skip(f"{ACCEPTANCE_KIND}: params.allow_destructive is required for merge")
    project_id = _int_param(acceptance, "project_id")
    iid = _int_param(acceptance, "merge_request_iid")
    connector = _write_connector(acceptance)
    probe = MergeMergeRequestArgs(
        project_id=project_id,
        iid=iid,
        sha=_head_sha(connector, project_id, iid),
        action_key=_action_key("merge_merge_request"),
        approved_plan_hash=_PLACEHOLDER_HASH,
    )
    plan, outcome = _run_action(connector, "merge_merge_request", probe)
    acceptance.record("merge_merge_request", outcome.status in _SUCCESS, outcome.status, changed=plan.changed)
    assert outcome.status in _SUCCESS


def test_gated_security_report_publication(acceptance) -> None:
    acceptance.require_writes()
    sarif_path = _optional(acceptance, "sarif_path")
    publish_job_id = _optional_int(acceptance, "publish_job_id")
    uids = acceptance.params.get("native_finding_uids")
    if sarif_path is None or publish_job_id is None or not uids:
        pytest.skip(
            f"{ACCEPTANCE_KIND}: params.sarif_path, params.publish_job_id, and params.native_finding_uids are required"
        )
    project_id = _int_param(acceptance, "project_id")
    iid = _int_param(acceptance, "merge_request_iid")
    connector = _write_connector(acceptance)
    probe = PublishSecurityReportArtifactArgs(
        project_id=project_id,
        iid=iid,
        job_id=publish_job_id,
        expected_head_sha=_head_sha(connector, project_id, iid),
        sarif=json.loads(Path(sarif_path).read_text(encoding="utf-8")),
        native_finding_uids=[str(uid) for uid in uids],
        action_key=_action_key("publish_security_report_artifact"),
    )
    plan, outcome = _run_action(connector, "publish_security_report_artifact", probe)
    acceptance.record(
        "publish_security_report_artifact", outcome.status in _SUCCESS_OR_ASYNC, outcome.status, changed=plan.changed
    )
    assert outcome.status in _SUCCESS_OR_ASYNC


def test_gated_pipeline_control(acceptance) -> None:
    acceptance.require_writes()
    pipeline_id = _optional_int(acceptance, "pipeline_id")
    operation = _optional(acceptance, "pipeline_operation")
    if pipeline_id is None or operation not in ("retry", "cancel"):
        pytest.skip(f"{ACCEPTANCE_KIND}: params.pipeline_id and params.pipeline_operation (retry|cancel) are required")
    pipeline_operation = cast(Literal["retry", "cancel"], operation)
    project_id = _int_param(acceptance, "project_id")
    connector = _write_connector(acceptance)
    observed = str(asyncio.run(connector.get_pipeline(project_id, pipeline_id))["status"])
    probe = ControlPipelineArgs(
        project_id=project_id,
        pipeline_id=pipeline_id,
        operation=pipeline_operation,
        expected_status=observed,
        action_key=_action_key("control_pipeline"),
    )
    plan, outcome = _run_action(connector, "control_pipeline", probe)
    acceptance.record("control_pipeline", outcome.status in _SUCCESS_OR_ASYNC, outcome.status, changed=plan.changed)
    assert outcome.status in _SUCCESS_OR_ASYNC


def test_gated_job_control(acceptance) -> None:
    acceptance.require_writes()
    job_id = _optional_int(acceptance, "control_job_id")
    operation = _optional(acceptance, "control_job_operation")
    if job_id is None or operation not in ("play", "retry", "cancel"):
        pytest.skip(
            f"{ACCEPTANCE_KIND}: params.control_job_id and params.control_job_operation (play|retry|cancel) are required"
        )
    job_operation = cast(Literal["play", "retry", "cancel"], operation)
    project_id = _int_param(acceptance, "project_id")
    connector = _write_connector(acceptance)
    observed = str(asyncio.run(connector.get_job(project_id, job_id))["status"])
    probe = ControlJobArgs(
        project_id=project_id,
        job_id=job_id,
        operation=job_operation,
        expected_status=observed,
        action_key=_action_key("control_job"),
    )
    plan, outcome = _run_action(connector, "control_job", probe)
    acceptance.record("control_job", outcome.status in _SUCCESS_OR_ASYNC, outcome.status, changed=plan.changed)
    assert outcome.status in _SUCCESS_OR_ASYNC
