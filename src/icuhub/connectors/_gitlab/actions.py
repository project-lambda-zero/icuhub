"""GitLab governed write actions: plan, apply, and reconcile for each action.

Every write follows plan -> apply -> reconcile. Plans read vendor state and never write.
Apply and reconcile take only the plan: every input is read from ``plan.request`` and
``plan.preconditions``, which the kit hashes into ``plan_hash``. The kit binds approval to that
hash and re-plans before apply, refusing a stale plan. Apply re-checks preconditions, sends at
most once, and reads back the vendor result. An ambiguous send returns ``outcome_unknown``;
reconcile resolves it from vendor state and never resends. Rejections (``Conflict``,
``VendorContractError``) are definitive and map to ``failed`` unless the action has a documented
read-back rule.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from icuhub.kit import (
    ActionOutcome,
    ActionPlan,
    ConfigError,
    Conflict,
    NotFound,
    OutcomeUnknown,
    StalePlan,
    TransientVendorError,
    VendorContractError,
)

from .models import (
    ApproveMergeRequestArgs,
    ChangeVulnerabilityStateArgs,
    ControlJobArgs,
    ControlPipelineArgs,
    CreateMergeRequestArgs,
    CreateMrNoteOrDiscussionArgs,
    MergeMergeRequestArgs,
    PublishSecurityReportArtifactArgs,
)
from .sarif import parse_publish_sarif

__all__ = [
    "action_identity",
    "apply_approve_merge_request",
    "apply_change_vulnerability_state",
    "apply_control_job",
    "apply_control_pipeline",
    "apply_create_merge_request",
    "apply_create_mr_note_or_discussion",
    "apply_merge_merge_request",
    "apply_publish_security_report_artifact",
    "plan_approve_merge_request",
    "plan_change_vulnerability_state",
    "plan_control_job",
    "plan_control_pipeline",
    "plan_create_merge_request",
    "plan_create_mr_note_or_discussion",
    "plan_merge_merge_request",
    "plan_publish_security_report_artifact",
    "reconcile_approve_merge_request",
    "reconcile_change_vulnerability_state",
    "reconcile_control_job",
    "reconcile_control_pipeline",
    "reconcile_create_merge_request",
    "reconcile_create_mr_note_or_discussion",
    "reconcile_merge_merge_request",
    "reconcile_publish_security_report_artifact",
]

_MAX_SARIF_BYTES = 10 * 1024 * 1024
_ACTION_KEY_MARKER = "icuhub-action-key:"
_IN_FLIGHT_JOB_STATUSES = frozenset({"created", "pending", "preparing", "running", "scheduled", "waiting_for_resource"})
_FAILED_JOB_STATUSES = frozenset({"failed", "canceled", "skipped"})
_AMBIGUOUS = (OutcomeUnknown, TransientVendorError)
_REJECTED = (Conflict, VendorContractError)


def action_identity(connector: Any, action: str, key: str) -> str:
    """Idempotency key scoped to the tenant, the action, and its natural key."""
    raw = f"{connector.ctx.tenant_id}\x1f{action}\x1f{key}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _require_write(connector: Any) -> None:
    if not connector._config().write_enabled:  # noqa: SLF001 -- connector owns its typed config
        raise ConfigError("gitlab writes are disabled for this connector")


def _require_destructive(connector: Any) -> None:
    if not connector._config().destructive_enabled:  # noqa: SLF001 -- connector owns its typed config
        raise ConfigError("gitlab destructive actions are disabled for this connector")


def _sarif_limits(connector: Any) -> dict[str, int]:
    config = connector._config()  # noqa: SLF001 -- connector owns its typed config
    return {
        "max_bytes": _MAX_SARIF_BYTES,
        "max_runs": config.max_sarif_runs,
        "max_results_per_run": config.max_sarif_results_per_run,
    }


def _request(args: Any) -> dict[str, Any]:
    """Serialized args without the approval hash, so plan_hash never depends on itself."""
    return args.model_dump(mode="json", exclude={"approved_plan_hash"})


def _same_sha(observed: str, planned: str) -> bool:
    return observed.lower() == planned.lower()


async def _require_head(connector: Any, project_id: int, iid: int, sha: str) -> dict[str, Any]:
    mr = await connector.get_merge_request(project_id, iid)
    if not _same_sha(str(mr["sha"]), sha):
        raise StalePlan("merge request head moved since the plan was made")
    return mr


async def _require_open_head(connector: Any, project_id: int, iid: int, sha: str) -> dict[str, Any]:
    mr = await _require_head(connector, project_id, iid, sha)
    if mr["state"] != "opened":
        raise StalePlan("merge request is no longer open")
    return mr


def _marked_body(body: str, action_key: str) -> str:
    if _ACTION_KEY_MARKER in body:
        raise ConfigError("note body must not contain the icuhub action-key marker")
    return f"{body.rstrip()}\n\n<!-- {_ACTION_KEY_MARKER}{action_key} -->"


def _sarif_digest(document: Any) -> str:
    """Digest of the normalized SARIF document, so plan and artifact compare on equal footing."""
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _sarif_counts(document: dict[str, Any]) -> tuple[int, int]:
    runs = document["runs"]
    return len(runs), sum(len(run.get("results", [])) for run in runs)


def _mr_result(project_id: int, mr: dict[str, Any]) -> dict[str, Any]:
    return {"id": mr["id"], "iid": mr["iid"], "project_id": project_id}


def _approval_result(request: dict[str, Any]) -> dict[str, Any]:
    return {"project_id": request["project_id"], "iid": request["iid"], "sha": request["sha"]}


# --- create_merge_request -------------------------------------------------------------------


async def plan_create_merge_request(connector: Any, args: CreateMergeRequestArgs) -> ActionPlan:
    open_mr = await connector.find_open_merge_request(args.project_id, args.source_branch, args.target_branch)
    changed = open_mr is None
    key = f"{args.project_id}:{args.source_branch}:{args.target_branch}"
    diff = (
        {
            "source_branch": args.source_branch,
            "target_branch": args.target_branch,
            "title": args.title,
            "description": args.description,
        }
        if changed
        else {}
    )
    return ActionPlan(
        action="create_merge_request",
        target_ref=f"gitlab:project:{args.project_id}",
        diff=diff,
        preconditions={"open_merge_request_iid": None if open_mr is None else open_mr["iid"]},
        idempotency_key=action_identity(connector, "create_merge_request", key),
        changed=changed,
        request=_request(args),
    )


async def apply_create_merge_request(connector: Any, plan: ActionPlan) -> ActionOutcome:
    _require_write(connector)
    request = plan.request
    project_id = request["project_id"]
    open_mr = await connector.find_open_merge_request(project_id, request["source_branch"], request["target_branch"])
    observed_iid = None if open_mr is None else open_mr["iid"]
    if observed_iid != plan.preconditions["open_merge_request_iid"]:
        raise StalePlan("open merge request for these branches changed since the plan was made")
    if not plan.changed:
        assert open_mr is not None
        return ActionOutcome(
            status="no_op",
            vendor_ref=str(open_mr["id"]),
            result=_mr_result(project_id, open_mr),
        )
    try:
        created = await connector.create_merge_request(
            project_id=project_id,
            source_branch=request["source_branch"],
            target_branch=request["target_branch"],
            title=request["title"],
            description=request["description"],
        )
    except _AMBIGUOUS as exc:
        return ActionOutcome(status="outcome_unknown", error=str(exc))
    except _REJECTED as exc:
        return ActionOutcome(status="failed", error=str(exc))
    readback = await connector.get_merge_request(project_id, created["iid"])
    if (
        readback["id"] != created["id"]
        or readback["source_branch"] != request["source_branch"]
        or readback["target_branch"] != request["target_branch"]
    ):
        return ActionOutcome(
            status="outcome_unknown",
            vendor_ref=str(created["id"]),
            error="read-back does not match the created merge request",
        )
    return ActionOutcome(
        status="succeeded",
        vendor_ref=str(created["id"]),
        result=_mr_result(project_id, readback),
    )


async def reconcile_create_merge_request(connector: Any, plan: ActionPlan, outcome: ActionOutcome) -> ActionOutcome:
    request = plan.request
    project_id = request["project_id"]
    open_mr = await connector.find_open_merge_request(project_id, request["source_branch"], request["target_branch"])
    if open_mr is None:
        return ActionOutcome(status="outcome_unknown", error="no open merge request exists for these branches")
    return ActionOutcome(
        status="succeeded",
        vendor_ref=str(open_mr["id"]),
        result=_mr_result(project_id, open_mr),
    )


# --- create_mr_note_or_discussion -----------------------------------------------------------


async def plan_create_mr_note_or_discussion(connector: Any, args: CreateMrNoteOrDiscussionArgs) -> ActionPlan:
    body = _marked_body(args.body, args.action_key)
    existing = await connector.find_discussion(args.project_id, args.iid, args.action_key)
    changed = existing is None
    preconditions: dict[str, Any] = {"discussion_id": None if existing is None else existing["id"]}
    position = None if args.position is None else args.position.model_dump(mode="json")
    if changed and args.position is not None:
        mr = await connector.get_merge_request(args.project_id, args.iid)
        if not _same_sha(str(mr["sha"]), args.position.head_sha):
            raise StalePlan("diff position was computed against a head that is no longer current")
        preconditions["head_sha"] = mr["sha"]
    return ActionPlan(
        action="create_mr_note_or_discussion",
        target_ref=f"gitlab:project:{args.project_id}:mr:{args.iid}",
        diff={"body": body, "position": position} if changed else {},
        preconditions=preconditions,
        idempotency_key=action_identity(
            connector, "create_mr_note_or_discussion", f"{args.project_id}:{args.iid}:{args.action_key}"
        ),
        changed=changed,
        request=_request(args),
    )


async def apply_create_mr_note_or_discussion(connector: Any, plan: ActionPlan) -> ActionOutcome:
    _require_write(connector)
    request = plan.request
    project_id = request["project_id"]
    iid = request["iid"]
    action_key = request["action_key"]
    existing = await connector.find_discussion(project_id, iid, action_key)
    if existing is not None:
        return ActionOutcome(
            status="no_op",
            vendor_ref=str(existing["id"]),
            result={"discussion_id": existing["id"], "iid": iid, "project_id": project_id},
        )
    if not plan.changed:
        raise StalePlan("discussion for this action key disappeared since the plan was made")
    if request["position"] is not None:
        mr = await connector.get_merge_request(project_id, iid)
        if not _same_sha(str(mr["sha"]), str(plan.preconditions["head_sha"])):
            raise StalePlan("merge request head moved since the plan was made")
    body = _marked_body(request["body"], action_key)
    try:
        created = await connector.create_discussion(project_id, iid, body, position=request["position"])
    except _AMBIGUOUS as exc:
        return ActionOutcome(status="outcome_unknown", error=str(exc))
    except _REJECTED as exc:
        return ActionOutcome(status="failed", error=str(exc))
    readback = await connector.find_discussion(project_id, iid, action_key)
    if readback is None or readback["id"] != created["id"]:
        return ActionOutcome(
            status="outcome_unknown",
            vendor_ref=str(created["id"]),
            error="read-back did not find the posted discussion",
        )
    return ActionOutcome(
        status="succeeded",
        vendor_ref=str(created["id"]),
        result={"discussion_id": created["id"], "iid": iid, "project_id": project_id},
    )


async def reconcile_create_mr_note_or_discussion(connector: Any, plan: ActionPlan, outcome: ActionOutcome) -> ActionOutcome:
    request = plan.request
    project_id = request["project_id"]
    iid = request["iid"]
    existing = await connector.find_discussion(project_id, iid, request["action_key"])
    if existing is None:
        return ActionOutcome(status="outcome_unknown", error="no discussion carries this action key")
    return ActionOutcome(
        status="succeeded",
        vendor_ref=str(existing["id"]),
        result={"discussion_id": existing["id"], "iid": iid, "project_id": project_id},
    )


# --- approve_merge_request ------------------------------------------------------------------


async def _approval_held(connector: Any, project_id: int, iid: int, sha: str) -> bool:
    approvals = await connector.get_merge_approvals(project_id, iid)
    if not approvals["approved"]:
        return False
    mr = await connector.get_merge_request(project_id, iid)
    return _same_sha(str(mr["sha"]), sha)


async def plan_approve_merge_request(connector: Any, args: ApproveMergeRequestArgs) -> ActionPlan:
    mr = await _require_open_head(connector, args.project_id, args.iid, args.sha)
    approvals = await connector.get_merge_approvals(args.project_id, args.iid)
    changed = not approvals["approved"]
    return ActionPlan(
        action="approve_merge_request",
        target_ref=f"gitlab:project:{args.project_id}:mr:{args.iid}",
        diff={"sha": args.sha} if changed else {},
        preconditions={"head_sha": mr["sha"], "approved": bool(approvals["approved"])},
        idempotency_key=action_identity(
            connector, "approve_merge_request", f"{args.project_id}:{args.iid}:{args.sha}"
        ),
        changed=changed,
        request=_request(args),
    )


async def apply_approve_merge_request(connector: Any, plan: ActionPlan) -> ActionOutcome:
    _require_write(connector)
    request = plan.request
    project_id = request["project_id"]
    iid = request["iid"]
    sha = request["sha"]
    await _require_open_head(connector, project_id, iid, sha)
    if not plan.changed:
        return ActionOutcome(status="no_op", vendor_ref=plan.target_ref, result=_approval_result(request))
    try:
        await connector.approve_merge_request(project_id, iid, sha)
    except _AMBIGUOUS as exc:
        return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))
    except Conflict as exc:
        if await _approval_held(connector, project_id, iid, sha):
            return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref, result=_approval_result(request))
        return ActionOutcome(status="failed", vendor_ref=plan.target_ref, error=str(exc))
    except VendorContractError as exc:
        return ActionOutcome(status="failed", vendor_ref=plan.target_ref, error=str(exc))
    if await _approval_held(connector, project_id, iid, sha):
        return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref, result=_approval_result(request))
    return ActionOutcome(
        status="outcome_unknown",
        vendor_ref=plan.target_ref,
        error="approval is not visible on read-back at the planned head",
    )


async def reconcile_approve_merge_request(connector: Any, plan: ActionPlan, outcome: ActionOutcome) -> ActionOutcome:
    request = plan.request
    if await _approval_held(connector, request["project_id"], request["iid"], request["sha"]):
        return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref, result=_approval_result(request))
    return ActionOutcome(
        status="outcome_unknown",
        vendor_ref=plan.target_ref,
        error="approval is not visible on read-back at the planned head",
    )


# --- change_vulnerability_state -------------------------------------------------------------


async def plan_change_vulnerability_state(connector: Any, args: ChangeVulnerabilityStateArgs) -> ActionPlan:
    vulnerability = await connector.get_vulnerability(args.vulnerability_id)
    observed = str(vulnerability["state"])
    if observed == args.state:
        changed = False
    elif observed == args.expected_state:
        changed = True
    else:
        raise StalePlan(f"vulnerability is {observed}, expected {args.expected_state}")
    return ActionPlan(
        action="change_vulnerability_state",
        target_ref=f"gitlab:vulnerability:{args.vulnerability_id}",
        diff={"state": {"from": observed, "to": args.state}} if changed else {},
        preconditions={"expected_state": args.expected_state, "observed_state": observed},
        idempotency_key=action_identity(
            connector, "change_vulnerability_state", f"{args.vulnerability_id}:{args.state}"
        ),
        changed=changed,
        request=_request(args),
    )


async def apply_change_vulnerability_state(connector: Any, plan: ActionPlan) -> ActionOutcome:
    _require_write(connector)
    request = plan.request
    vulnerability_id = request["vulnerability_id"]
    target = request["state"]
    observed = str((await connector.get_vulnerability(vulnerability_id))["state"])
    if observed != plan.preconditions["observed_state"]:
        raise StalePlan("vulnerability state changed since the plan was made")
    if not plan.changed:
        return ActionOutcome(
            status="no_op",
            vendor_ref=plan.target_ref,
            result={"vulnerability_id": vulnerability_id, "state": observed},
        )
    try:
        await connector.set_vulnerability_state(vulnerability_id, target)
    except _AMBIGUOUS as exc:
        return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))
    except _REJECTED as exc:
        return ActionOutcome(status="failed", vendor_ref=plan.target_ref, error=str(exc))
    readback = str((await connector.get_vulnerability(vulnerability_id))["state"])
    if readback == target:
        return ActionOutcome(
            status="succeeded",
            vendor_ref=plan.target_ref,
            result={"vulnerability_id": vulnerability_id, "state": readback},
        )
    return ActionOutcome(
        status="outcome_unknown",
        vendor_ref=plan.target_ref,
        error=f"read-back state is {readback}, expected {target}",
    )


async def reconcile_change_vulnerability_state(connector: Any, plan: ActionPlan, outcome: ActionOutcome) -> ActionOutcome:
    request = plan.request
    vulnerability_id = request["vulnerability_id"]
    target = request["state"]
    state = str((await connector.get_vulnerability(vulnerability_id))["state"])
    if state == target:
        return ActionOutcome(
            status="succeeded",
            vendor_ref=plan.target_ref,
            result={"vulnerability_id": vulnerability_id, "state": state},
        )
    return ActionOutcome(
        status="outcome_unknown",
        vendor_ref=plan.target_ref,
        error=f"state is {state}, expected {target}",
    )


# --- merge_merge_request (destructive) ------------------------------------------------------


async def _merge_readback(connector: Any, request: dict[str, Any], rejected: str | None) -> ActionOutcome:
    project_id = request["project_id"]
    iid = request["iid"]
    sha = request["sha"]
    mr = await connector.get_merge_request(project_id, iid)
    result: dict[str, Any] = {"project_id": project_id, "iid": iid, "sha": sha, "id": mr["id"]}
    if mr["state"] == "merged":
        if not _same_sha(str(mr["sha"]), sha):
            return ActionOutcome(
                status="failed",
                vendor_ref=str(mr["id"]),
                result=result,
                error="merge request was merged at a head other than the planned one",
            )
        result["merge_commit_sha"] = mr.get("merge_commit_sha")
        return ActionOutcome(status="succeeded", vendor_ref=str(mr["id"]), result=result)
    if rejected is not None and mr["state"] == "opened" and _same_sha(str(mr["sha"]), sha):
        return ActionOutcome(status="failed", vendor_ref=str(mr["id"]), result=result, error=rejected)
    return ActionOutcome(
        status="outcome_unknown",
        vendor_ref=str(mr["id"]),
        result=result,
        error="merge request is neither merged nor rejected at the planned head",
    )


async def plan_merge_merge_request(connector: Any, args: MergeMergeRequestArgs) -> ActionPlan:
    mr = await _require_open_head(connector, args.project_id, args.iid, args.sha)
    return ActionPlan(
        action="merge_merge_request",
        target_ref=f"gitlab:project:{args.project_id}:mr:{args.iid}",
        diff={"sha": args.sha, "source_branch": mr["source_branch"], "target_branch": mr["target_branch"]},
        preconditions={"head_sha": mr["sha"]},
        idempotency_key=action_identity(connector, "merge_merge_request", f"{args.project_id}:{args.iid}:{args.sha}"),
        changed=True,
        request=_request(args),
    )


async def apply_merge_merge_request(connector: Any, plan: ActionPlan) -> ActionOutcome:
    _require_destructive(connector)
    _require_write(connector)
    request = plan.request
    project_id = request["project_id"]
    iid = request["iid"]
    sha = request["sha"]
    await _require_open_head(connector, project_id, iid, sha)
    try:
        await connector.merge_merge_request(project_id, iid, sha)
    except _AMBIGUOUS:
        return await _merge_readback(connector, request, rejected=None)
    except _REJECTED as exc:
        return await _merge_readback(connector, request, rejected=str(exc))
    return await _merge_readback(connector, request, rejected=None)


async def reconcile_merge_merge_request(connector: Any, plan: ActionPlan, outcome: ActionOutcome) -> ActionOutcome:
    return await _merge_readback(connector, plan.request, rejected=None)


# --- publish_security_report_artifact -------------------------------------------------------


def _publication_operation(job_status: str) -> str | None:
    if job_status == "manual":
        return "play"
    if job_status in {"failed", "canceled"}:
        return "retry"
    return None


def _publication_result(plan: ActionPlan, job_id: int | None, job_status: str) -> dict[str, Any]:
    return {
        "job_id": job_id,
        "job_status": job_status,
        "sarif_sha256": plan.request["sarif_sha256"],
        "run_count": plan.request["run_count"],
        "result_count": plan.request["result_count"],
        "dropped": plan.request["dropped"],
    }


async def plan_publish_security_report_artifact(
    connector: Any, args: PublishSecurityReportArtifactArgs
) -> ActionPlan:
    await connector.require_ultimate()
    await _require_head(connector, args.project_id, args.iid, args.expected_head_sha)
    job = await connector.get_job(args.project_id, args.job_id)
    if not _same_sha(str(job["commit"]["id"]), args.expected_head_sha):
        raise StalePlan("artifact job ran against a commit other than the expected head")
    parsed = parse_publish_sarif(args.sarif, **_sarif_limits(connector))
    run_count, result_count = _sarif_counts(parsed.data)
    digest = _sarif_digest(parsed.data)
    operation = _publication_operation(str(job["status"]))
    changed = operation is not None
    request = {
        "project_id": args.project_id,
        "iid": args.iid,
        "job_id": args.job_id,
        "operation": operation,
        "expected_head_sha": args.expected_head_sha,
        "sarif_sha256": digest,
        "run_count": run_count,
        "result_count": result_count,
        "dropped": parsed.dropped,
        "native_finding_uids": args.native_finding_uids,
        "action_key": args.action_key,
    }
    return ActionPlan(
        action="publish_security_report_artifact",
        target_ref=f"gitlab:project:{args.project_id}:job:{args.job_id}",
        diff={"job_id": args.job_id, "operation": operation, "sarif_sha256": digest} if changed else {},
        preconditions={"head_sha": args.expected_head_sha, "job_id": args.job_id, "job_status": job["status"]},
        idempotency_key=action_identity(connector, "publish_security_report_artifact", args.action_key),
        changed=changed,
        request=request,
    )


async def _publication_outcome(connector: Any, plan: ActionPlan, project_id: int, job_id: int) -> ActionOutcome:
    job = await connector.get_job(project_id, job_id)
    status = str(job["status"])
    result = _publication_result(plan, job_id, status)
    if status in _IN_FLIGHT_JOB_STATUSES:
        return ActionOutcome(status="accepted_async", vendor_ref=str(job_id), result=result)
    if status in _FAILED_JOB_STATUSES:
        return ActionOutcome(
            status="failed",
            vendor_ref=str(job_id),
            result=result,
            error=f"artifact job ended with status {status}",
        )
    if status != "success":
        return ActionOutcome(
            status="outcome_unknown",
            vendor_ref=str(job_id),
            result=result,
            error=f"artifact job is in status {status}",
        )
    try:
        content = await connector.download_sarif_artifact(project_id, job_id)
    except NotFound:
        return ActionOutcome(
            status="failed",
            vendor_ref=str(job_id),
            result=result,
            error="artifact job has no SARIF artifact",
        )
    except VendorContractError as exc:
        return ActionOutcome(
            status="failed",
            vendor_ref=str(job_id),
            result=result,
            error=f"artifact archive is not a valid publish SARIF: {exc}",
        )
    except TransientVendorError as exc:
        return ActionOutcome(status="outcome_unknown", vendor_ref=str(job_id), result=result, error=str(exc))
    try:
        artifact = parse_publish_sarif(content, **_sarif_limits(connector))
    except VendorContractError as exc:
        return ActionOutcome(
            status="failed",
            vendor_ref=str(job_id),
            result=result,
            error=f"artifact is not a valid publish SARIF: {exc}",
        )
    result["artifact_sha256"] = _sarif_digest(artifact.data)
    if result["artifact_sha256"] != plan.request["sarif_sha256"]:
        return ActionOutcome(
            status="failed",
            vendor_ref=str(job_id),
            result=result,
            error="artifact digest differs from the planned SARIF",
        )
    uids: list[str] = plan.request["native_finding_uids"]
    try:
        reconciled = await connector.reconcile_native_vulnerabilities(project_id, uids)
    except TransientVendorError as exc:
        return ActionOutcome(status="outcome_unknown", vendor_ref=str(job_id), result=result, error=str(exc))
    if not reconciled["complete"]:
        return ActionOutcome(status="accepted_async", vendor_ref=str(job_id), result=result)
    found = set(reconciled["found"])
    missing = [uid for uid in uids if uid not in found]
    if missing:
        result["native_missing"] = missing
        return ActionOutcome(
            status="failed",
            vendor_ref=str(job_id),
            result=result,
            error="native findings are missing for artifact UIDs",
        )
    return ActionOutcome(status="succeeded", vendor_ref=str(job_id), result=result)


async def apply_publish_security_report_artifact(connector: Any, plan: ActionPlan) -> ActionOutcome:
    _require_write(connector)
    request = plan.request
    project_id = request["project_id"]
    job_id = request["job_id"]
    await connector.require_ultimate()
    await _require_head(connector, project_id, request["iid"], request["expected_head_sha"])
    job = await connector.get_job(project_id, job_id)
    if str(job["status"]) != plan.preconditions["job_status"]:
        raise StalePlan("artifact job status changed since the plan was made")
    if not plan.changed:
        return await _publication_outcome(connector, plan, project_id, job_id)
    operation = str(request["operation"])
    try:
        response = await connector.control_job(project_id, job_id, operation)
    except _AMBIGUOUS as exc:
        target = None if operation == "retry" else job_id
        return ActionOutcome(
            status="outcome_unknown",
            vendor_ref=plan.target_ref,
            result=_publication_result(plan, target, str(job["status"])),
            error=str(exc),
        )
    except _REJECTED as exc:
        return ActionOutcome(
            status="failed",
            vendor_ref=plan.target_ref,
            result=_publication_result(plan, job_id, str(job["status"])),
            error=str(exc),
        )
    if operation == "retry":
        new_id = response.get("id")
        if new_id is None:
            return ActionOutcome(
                status="outcome_unknown",
                vendor_ref=plan.target_ref,
                result=_publication_result(plan, None, str(job["status"])),
                error="retry response carried no job id",
            )
        target_job = int(new_id)
    else:
        target_job = job_id
    return await _publication_outcome(connector, plan, project_id, target_job)


async def reconcile_publish_security_report_artifact(
    connector: Any, plan: ActionPlan, outcome: ActionOutcome
) -> ActionOutcome:
    job_id = outcome.result.get("job_id")
    if job_id is None:
        return ActionOutcome(
            status="outcome_unknown",
            vendor_ref=plan.target_ref,
            error="retry job id was not recorded",
        )
    return await _publication_outcome(connector, plan, plan.request["project_id"], int(job_id))


# --- control_pipeline -----------------------------------------------------------------------


async def _pipeline_outcome(connector: Any, plan: ActionPlan) -> ActionOutcome:
    request = plan.request
    status = str((await connector.get_pipeline(request["project_id"], request["pipeline_id"]))["status"])
    expected = plan.preconditions["status"]
    result = {"pipeline_id": request["pipeline_id"], "pipeline_status": status}
    if request["operation"] == "retry":
        if status != expected:
            return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref, result=result)
        return ActionOutcome(status="accepted_async", vendor_ref=plan.target_ref, result=result)
    if status == "canceled":
        return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref, result=result)
    if status == "canceling" or status == expected:
        return ActionOutcome(status="accepted_async", vendor_ref=plan.target_ref, result=result)
    return ActionOutcome(
        status="failed",
        vendor_ref=plan.target_ref,
        result=result,
        error=f"pipeline is {status} after cancel",
    )


async def plan_control_pipeline(connector: Any, args: ControlPipelineArgs) -> ActionPlan:
    pipeline = await connector.get_pipeline(args.project_id, args.pipeline_id)
    observed = str(pipeline["status"])
    if observed != args.expected_status:
        raise StalePlan(f"pipeline is {observed}, expected {args.expected_status}")
    return ActionPlan(
        action="control_pipeline",
        target_ref=f"gitlab:project:{args.project_id}:pipeline:{args.pipeline_id}",
        diff={"operation": args.operation},
        preconditions={"status": observed},
        idempotency_key=action_identity(
            connector, "control_pipeline", f"pipeline:{args.project_id}:{args.pipeline_id}:{args.operation}"
        ),
        changed=True,
        request=_request(args),
    )


async def apply_control_pipeline(connector: Any, plan: ActionPlan) -> ActionOutcome:
    _require_write(connector)
    request = plan.request
    project_id = request["project_id"]
    pipeline_id = request["pipeline_id"]
    observed = str((await connector.get_pipeline(project_id, pipeline_id))["status"])
    if observed != plan.preconditions["status"]:
        raise StalePlan("pipeline status changed since the plan was made")
    try:
        await connector.control_pipeline(project_id, pipeline_id, request["operation"])
    except _AMBIGUOUS as exc:
        return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))
    except _REJECTED as exc:
        return ActionOutcome(status="failed", vendor_ref=plan.target_ref, error=str(exc))
    return await _pipeline_outcome(connector, plan)


async def reconcile_control_pipeline(connector: Any, plan: ActionPlan, outcome: ActionOutcome) -> ActionOutcome:
    return await _pipeline_outcome(connector, plan)


# --- control_job ----------------------------------------------------------------------------


async def _job_control_outcome(connector: Any, plan: ActionPlan, job_id: int) -> ActionOutcome:
    request = plan.request
    job = await connector.get_job(request["project_id"], job_id)
    status = str(job["status"])
    result = {"job_id": job_id, "job_status": status}
    if request["operation"] == "retry":
        if int(job["id"]) != job_id:
            return ActionOutcome(
                status="outcome_unknown",
                vendor_ref=str(job_id),
                result=result,
                error="retry read-back returned a different job",
            )
        return ActionOutcome(status="succeeded", vendor_ref=str(job_id), result=result)
    expected = plan.preconditions["status"]
    if request["operation"] == "cancel":
        if status == "canceled":
            return ActionOutcome(status="succeeded", vendor_ref=str(job_id), result=result)
        if status == "canceling" or status == expected:
            return ActionOutcome(status="accepted_async", vendor_ref=str(job_id), result=result)
        return ActionOutcome(
            status="failed",
            vendor_ref=str(job_id),
            result=result,
            error=f"job is {status} after cancel",
        )
    if status != expected:
        return ActionOutcome(status="succeeded", vendor_ref=str(job_id), result=result)
    return ActionOutcome(status="accepted_async", vendor_ref=str(job_id), result=result)


async def plan_control_job(connector: Any, args: ControlJobArgs) -> ActionPlan:
    job = await connector.get_job(args.project_id, args.job_id)
    observed = str(job["status"])
    if observed != args.expected_status:
        raise StalePlan(f"job is {observed}, expected {args.expected_status}")
    return ActionPlan(
        action="control_job",
        target_ref=f"gitlab:project:{args.project_id}:job:{args.job_id}",
        diff={"operation": args.operation},
        preconditions={"status": observed},
        idempotency_key=action_identity(
            connector, "control_job", f"job:{args.project_id}:{args.job_id}:{args.operation}"
        ),
        changed=True,
        request=_request(args),
    )


async def apply_control_job(connector: Any, plan: ActionPlan) -> ActionOutcome:
    _require_write(connector)
    request = plan.request
    project_id = request["project_id"]
    job_id = request["job_id"]
    operation = request["operation"]
    observed = str((await connector.get_job(project_id, job_id))["status"])
    if observed != plan.preconditions["status"]:
        raise StalePlan("job status changed since the plan was made")
    target: int | None = None if operation == "retry" else job_id
    try:
        response = await connector.control_job(project_id, job_id, operation)
    except _AMBIGUOUS as exc:
        return ActionOutcome(
            status="outcome_unknown",
            vendor_ref=plan.target_ref,
            result={"job_id": target},
            error=str(exc),
        )
    except _REJECTED as exc:
        return ActionOutcome(
            status="failed",
            vendor_ref=plan.target_ref,
            result={"job_id": target},
            error=str(exc),
        )
    if operation == "retry":
        new_id = response.get("id")
        if new_id is None:
            return ActionOutcome(
                status="outcome_unknown",
                vendor_ref=plan.target_ref,
                result={"job_id": None},
                error="retry response carried no job id",
            )
        target = int(new_id)
    assert target is not None
    return await _job_control_outcome(connector, plan, target)


async def reconcile_control_job(connector: Any, plan: ActionPlan, outcome: ActionOutcome) -> ActionOutcome:
    request = plan.request
    if request["operation"] == "retry":
        job_id = outcome.result.get("job_id")
        if job_id is None:
            return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error="retry job id was not recorded")
        return await _job_control_outcome(connector, plan, int(job_id))
    return await _job_control_outcome(connector, plan, int(request["job_id"]))
