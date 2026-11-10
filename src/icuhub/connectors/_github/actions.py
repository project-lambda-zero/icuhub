"""Explicit, read-back-verified GitHub and GHES action workflows."""

from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import re
from collections.abc import Iterable, Mapping
from copy import deepcopy
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

from icuhub.kit.errors import (
    BudgetExhausted,
    ConfigError,
    Conflict,
    OutcomeUnknown,
    StalePlan,
    VendorContractError,
)
from icuhub.kit.http import IdempotencyMode
from icuhub.kit.types import ActionOutcome, ActionPlan, SourceRecord
from icuhub_schemas.ocsf import (
    ApplicationSecurityPostureFinding,
    DetectionFinding,
    VulnerabilityFinding,
)
from icuhub_schemas.sarif import (
    Result,
    Run,
    SarifLog,
    Tool,
    ToolComponent,
    dump_sarif,
    findings_to_sarif,
    parse_sarif,
)

from .models import (
    CheckRunArgs,
    CreateCommitStatusArgs,
    CreatePrCommentArgs,
    CreatePullRequestArgs,
    CreateReviewArgs,
    MergePullRequestArgs,
    PullRef,
    RepoRef,
    UpdateCodeScanningAlertArgs,
    UploadSarifArgs,
)

__all__ = [
    "apply_create_commit_status",
    "apply_create_or_update_check_run",
    "apply_create_pr_comment",
    "apply_create_pull_request",
    "apply_create_review",
    "apply_merge_pull_request",
    "apply_update_code_scanning_alert",
    "apply_upload_code_scanning_sarif",
    "plan_create_commit_status",
    "plan_create_or_update_check_run",
    "plan_create_pr_comment",
    "plan_create_pull_request",
    "plan_create_review",
    "plan_merge_pull_request",
    "plan_update_code_scanning_alert",
    "plan_upload_code_scanning_sarif",
    "prepare_pull_request_sarif",
    "reconcile_create_commit_status",
    "reconcile_create_or_update_check_run",
    "reconcile_create_pr_comment",
    "reconcile_create_pull_request",
    "reconcile_create_review",
    "reconcile_merge_pull_request",
    "reconcile_update_code_scanning_alert",
    "reconcile_upload_code_scanning_sarif",
]

_MAX_SARIF_RESULTS = 25_000
_COMMENT_MARKER = "<!-- icuhub-action-key:{} -->"
_REVIEW_STATES = {
    "APPROVE": "APPROVED",
    "REQUEST_CHANGES": "CHANGES_REQUESTED",
    "COMMENT": "COMMENTED",
}
_HUNK_HEADER = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def _segment(value: str) -> str:
    return quote(value, safe="")


def _require_write(connector: Any) -> None:
    if not connector.config.write_enabled:
        raise ConfigError("GitHub writes are disabled by write_enabled=False")


def _require_destructive(connector: Any) -> None:
    if not connector.config.destructive_enabled:
        raise ConfigError("GitHub destructive actions are disabled by destructive_enabled=False")


def _repo_path(owner: str, repo: str) -> str:
    return f"/repos/{_segment(owner)}/{_segment(repo)}"


def _args_repo_path(args: RepoRef) -> str:
    return _repo_path(args.owner, args.repo)


def _plan_repo_path(plan: ActionPlan) -> str:
    return _repo_path(str(plan.preconditions["owner"]), str(plan.preconditions["repo"]))


def _repo_preconditions(args: RepoRef) -> dict[str, Any]:
    return {"owner": args.owner, "repo": args.repo}


def _make_plan(
    connector: Any,
    action: str,
    *,
    target_ref: str,
    route_key: str,
    diff: dict[str, Any],
    preconditions: dict[str, Any],
    request: dict[str, Any],
    changed: bool = True,
) -> ActionPlan:
    return ActionPlan(
        action=action,
        target_ref=target_ref,
        diff=diff,
        preconditions=preconditions,
        idempotency_key=connector.action_identity(action, route_key),
        changed=changed,
        request=request,
    )


def _no_op(plan: ActionPlan, result: dict[str, Any] | None = None) -> ActionOutcome:
    return ActionOutcome(status="no_op", vendor_ref=plan.target_ref, result=result or {})


def _unknown(plan: ActionPlan, error: OutcomeUnknown | str) -> ActionOutcome:
    return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(error))


def _object(result: Any) -> dict[str, Any]:
    body = result.json()
    if not isinstance(body, dict):
        raise VendorContractError("GitHub response must be a JSON object")
    return body


async def _get_object(connector: Any, path: str) -> dict[str, Any]:
    return _object(await connector.request("GET", path))


async def _all_pages(
    connector: Any,
    path: str,
    *,
    params: Mapping[str, Any] | None = None,
    items_key: str | None = None,
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    query = {"per_page": 100, **(params or {})}
    async for page, _result in connector.pages(path, params=query, items_key=items_key):
        items.extend(page)
    return items


async def _mutation(
    connector: Any,
    plan: ActionPlan,
    *,
    idempotency: IdempotencyMode,
    expected: tuple[int, ...],
) -> Any:
    return await connector.request(
        str(plan.request["method"]),
        str(plan.request["path"]),
        json=plan.request.get("json"),
        headers={"Idempotency-Key": plan.idempotency_key},
        idempotency=idempotency,
        expected=expected,
    )


def _required_id(body: Mapping[str, Any], field: str = "id") -> int:
    value = body.get(field)
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise VendorContractError(f"GitHub response requires a positive integer {field}")
    return value


def _optional_analysis_id(body: Mapping[str, Any]) -> int | None:
    value = body.get("analysis_id")
    if value is None and isinstance(body.get("analysis"), Mapping):
        value = body["analysis"].get("id")
    if value is None:
        return None
    if isinstance(value, str) and value.isdigit():
        value = int(value)
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise VendorContractError("GitHub analysis_id must be a positive integer")
    return value


def _sha(value: Any, field: str = "sha") -> str:
    if not isinstance(value, str) or not value:
        raise VendorContractError(f"GitHub response requires a non-empty {field}")
    return value


def _same_sha(left: Any, right: Any) -> bool:
    return isinstance(left, str) and isinstance(right, str) and left.casefold() == right.casefold()


def _ref_path(repo_path: str, ref: str) -> str:
    normalized = ref[5:] if ref.startswith("refs/") else ref
    if not normalized or normalized.startswith("/") or any(
        part in ("", ".", "..") for part in normalized.split("/")
    ):
        raise ConfigError("GitHub ref must be a normalized fully qualified ref")
    return f"{repo_path}/git/ref/{quote(normalized, safe='/')}"


async def _ref_head(connector: Any, repo_path: str, ref: str) -> str:
    body = await _get_object(connector, _ref_path(repo_path, ref))
    reference = body.get("object")
    if not isinstance(reference, Mapping):
        raise VendorContractError("GitHub ref response requires an object")
    return _sha(reference.get("sha"), "object.sha")


async def _assert_ref_head(connector: Any, repo_path: str, ref: str, expected: str) -> str:
    actual = await _ref_head(connector, repo_path, ref)
    if not _same_sha(actual, expected):
        raise StalePlan(f"GitHub ref {ref} is at {actual}, not planned commit {expected}")
    return actual


@dataclass(frozen=True)
class _CanonicalSarif:
    document: dict[str, Any]
    content: bytes
    skipped: list[dict[str, Any]]
    result_count: int
    sha256: str


def _canonical_bytes(document: Mapping[str, Any]) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _gzip_bytes(content: bytes) -> bytes:
    buffer = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=buffer, compresslevel=9, mtime=0) as compressed:
        compressed.write(content)
    return buffer.getvalue()


def _result_has_location(result: Mapping[str, Any]) -> bool:
    locations = result.get("locations")
    if not isinstance(locations, list):
        return False
    for location in locations:
        if not isinstance(location, Mapping):
            continue
        physical = location.get("physicalLocation")
        if not isinstance(physical, Mapping):
            continue
        artifact = physical.get("artifactLocation")
        if isinstance(artifact, Mapping) and isinstance(artifact.get("uri"), str) and artifact["uri"]:
            return True
    return False


def _canonical_sarif(connector: Any, source: SarifLog | Mapping[str, Any]) -> _CanonicalSarif:
    log = source if isinstance(source, SarifLog) else parse_sarif(source)
    parsed = dump_sarif(log)
    runs = parsed.get("runs")
    if not isinstance(runs, list):
        raise VendorContractError("SARIF runs must be a list")

    limit = min(int(connector.config.max_sarif_results), _MAX_SARIF_RESULTS)
    retained_by_run: list[list[dict[str, Any]]] = [[] for _run in runs]
    entries: list[tuple[int, int, dict[str, Any]]] = []
    skipped: list[dict[str, Any]] = []
    for run_index, run in enumerate(runs):
        results = run.get("results") or []
        if not isinstance(results, list):
            raise VendorContractError("SARIF run results must be a list")
        for result_index, result in enumerate(results):
            identity = {"run_index": run_index, "result_index": result_index}
            rule_id = result.get("ruleId") if isinstance(result, Mapping) else None
            if not isinstance(rule_id, str) or not rule_id:
                skipped.append({**identity, "reason": "missing_ruleId"})
                continue
            if not _result_has_location(result):
                skipped.append({**identity, "reason": "missing_location", "ruleId": rule_id})
                continue
            if len(entries) >= limit:
                skipped.append({**identity, "reason": "result_limit_exceeded", "ruleId": rule_id})
                continue
            copied = deepcopy(dict(result))
            retained_by_run[run_index].append(copied)
            entries.append((run_index, result_index, copied))

    def with_prefix(count: int) -> dict[str, Any]:
        remaining = count
        output_runs: list[dict[str, Any]] = []
        for run, retained in zip(runs, retained_by_run, strict=True):
            take = min(len(retained), remaining)
            remaining -= take
            copied_run = {key: deepcopy(value) for key, value in run.items() if key != "results"}
            copied_run["results"] = deepcopy(retained[:take])
            output_runs.append(copied_run)
        return {"version": "2.1.0", **({"$schema": parsed["$schema"]} if "$schema" in parsed else {}), "runs": output_runs}

    max_bytes = int(connector.config.max_sarif_bytes)
    full_document = with_prefix(len(entries))
    content = _canonical_bytes(full_document)
    retained_count = len(entries)
    if len(content) > max_bytes:
        low = 0
        high = len(entries)
        while low < high:
            middle = (low + high + 1) // 2
            if len(_canonical_bytes(with_prefix(middle))) <= max_bytes:
                low = middle
            else:
                high = middle - 1
        retained_count = low
        document = with_prefix(retained_count)
        content = _canonical_bytes(document)
        if len(content) > max_bytes:
            raise BudgetExhausted("SARIF tool metadata alone exceeds max_sarif_bytes")
        for run_index, result_index, result in entries[retained_count:]:
            skipped.append(
                {
                    "run_index": run_index,
                    "result_index": result_index,
                    "reason": "sarif_byte_limit_exceeded",
                    "ruleId": result.get("ruleId"),
                }
            )
        full_document = document
    skipped.sort(key=lambda item: (item.get("run_index", -1), item.get("result_index", -1)))
    return _CanonicalSarif(
        document=full_document,
        content=content,
        skipped=skipped,
        result_count=retained_count,
        sha256=hashlib.sha256(content).hexdigest(),
    )


def _skip_report(_connector: Any, skipped: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "skipped": skipped,
        "skipped_total": len(skipped),
        "skipped_details_omitted": 0,
    }


# ---------------------------------------------------------------------------
# upload_code_scanning_sarif


async def plan_upload_code_scanning_sarif(connector: Any, args: UploadSarifArgs) -> ActionPlan:
    canonical = _canonical_sarif(connector, args.sarif)
    repo_path = _args_repo_path(args)
    head_sha = await _assert_ref_head(connector, repo_path, args.ref, args.commit_sha)
    compressed = _gzip_bytes(canonical.content)
    payload: dict[str, Any] = {
        "commit_sha": head_sha,
        "ref": args.ref,
        "sarif": base64.b64encode(compressed).decode("ascii"),
    }
    for name in ("checkout_uri", "started_at", "tool_name"):
        value = getattr(args, name)
        if value is not None:
            payload[name] = value
    report = _skip_report(connector, canonical.skipped)
    document_tool_names = sorted(
        {
            run["tool"]["driver"]["name"]
            for run in canonical.document["runs"]
            if isinstance(run.get("tool"), Mapping)
            and isinstance(run["tool"].get("driver"), Mapping)
            and isinstance(run["tool"]["driver"].get("name"), str)
        }
    )
    tool_names = [args.tool_name] if args.tool_name is not None else document_tool_names
    preconditions = {
        **_repo_preconditions(args),
        "ref": args.ref,
        "head_sha": head_sha,
        "started_at": args.started_at,
        "sarif_sha256": canonical.sha256,
    }
    request = {
        "method": "POST",
        "path": f"{repo_path}/code-scanning/sarifs",
        "json": payload,
        "sarif_id": None,
        "analysis_id": None,
        "analysis_created_at": None,
        "tool_names": tool_names,
        "processing_status": None,
        "result_count": canonical.result_count,
        **report,
    }
    return _make_plan(
        connector,
        "upload_code_scanning_sarif",
        target_ref=f"github:sarif:{args.owner}/{args.repo}:{head_sha}:{args.ref}",
        route_key=f"{args.owner}/{args.repo}:{head_sha}:{args.ref}:{canonical.sha256}",
        diff={
            "upload": {
                "commit_sha": head_sha,
                "ref": args.ref,
                "result_count": canonical.result_count,
                "sarif_bytes": len(canonical.content),
                "sarif_gzip_bytes": len(compressed),
                "sarif_sha256": canonical.sha256,
                **report,
            }
        },
        preconditions=preconditions,
        request=request,
    )


def _sarif_ids(plan: ActionPlan, outcome: ActionOutcome | None = None) -> tuple[str | None, int | None]:
    sarif_id = plan.request.get("sarif_id")
    analysis_id = plan.request.get("analysis_id")
    if outcome is not None:
        sarif_id = sarif_id or outcome.result.get("sarif_id")
        if sarif_id is None and outcome.status in ("accepted_async", "succeeded"):
            sarif_id = outcome.vendor_ref
        analysis_id = analysis_id or outcome.result.get("analysis_id")
    if sarif_id is not None:
        sarif_id = str(sarif_id)
    if analysis_id is not None:
        analysis_id = int(analysis_id)
    return sarif_id, analysis_id


def _analysis_created_at(body: Mapping[str, Any]) -> str | None:
    value = body.get("created_at")
    if value is None and isinstance(body.get("analysis"), Mapping):
        value = body["analysis"].get("created_at")
    if value is not None and not isinstance(value, str):
        raise VendorContractError("GitHub analysis created_at must be a string")
    return value


def _analysis_matches(analysis: Mapping[str, Any], plan: ActionPlan, sarif_id: str) -> bool:
    if not _same_sha(analysis.get("commit_sha"), plan.preconditions["head_sha"]):
        return False
    if analysis.get("ref") != plan.preconditions["ref"]:
        return False
    native_sarif_id = analysis.get("sarif_id")
    if native_sarif_id is not None and str(native_sarif_id) != sarif_id:
        return False
    expected_tools = plan.request.get("tool_names") or []
    tool = analysis.get("tool")
    tool_name = tool.get("name") if isinstance(tool, Mapping) else None
    if expected_tools and tool_name not in expected_tools:
        return False
    expected_created_at = plan.request.get("analysis_created_at") or plan.preconditions.get("started_at")
    return expected_created_at is None or analysis.get("created_at") == expected_created_at


async def _native_analysis(
    connector: Any,
    plan: ActionPlan,
    sarif_id: str,
    analysis_id: int | None,
) -> dict[str, Any] | None:
    repo_path = _plan_repo_path(plan)
    if analysis_id is not None:
        analysis = await _get_object(connector, f"{repo_path}/code-scanning/analyses/{analysis_id}")
        if _required_id(analysis) != analysis_id:
            raise VendorContractError("GitHub analysis read-back returned a different id")
        return analysis if _analysis_matches(analysis, plan, sarif_id) else None
    analyses = await _all_pages(
        connector,
        f"{repo_path}/code-scanning/analyses",
        params={"ref": plan.preconditions["ref"], "sarif_id": sarif_id},
    )
    matches = [analysis for analysis in analyses if _analysis_matches(analysis, plan, sarif_id)]
    if not matches:
        return None
    matches.sort(key=lambda item: (str(item.get("created_at") or ""), int(item.get("id") or 0)), reverse=True)
    return matches[0]


async def apply_upload_code_scanning_sarif(connector: Any, plan: ActionPlan) -> ActionOutcome:
    _require_write(connector)
    if not plan.changed:
        return _no_op(plan)
    sarif_id, analysis_id = _sarif_ids(plan)
    if sarif_id is not None:
        return await reconcile_upload_code_scanning_sarif(
            connector,
            plan,
            ActionOutcome(
                status="accepted_async",
                vendor_ref=sarif_id,
                result={"sarif_id": sarif_id, "analysis_id": analysis_id},
            ),
        )
    await _assert_ref_head(
        connector,
        _plan_repo_path(plan),
        str(plan.preconditions["ref"]),
        str(plan.preconditions["head_sha"]),
    )
    try:
        response = _object(await _mutation(connector, plan, idempotency="non_idempotent", expected=(202,)))
    except OutcomeUnknown as exc:
        return _unknown(plan, exc)
    raw_sarif_id = response.get("id")
    if raw_sarif_id is None or not str(raw_sarif_id):
        raise VendorContractError("GitHub SARIF acceptance response requires id")
    sarif_id = str(raw_sarif_id)
    analysis_id = _optional_analysis_id(response)
    analysis_created_at = _analysis_created_at(response)
    plan.request["sarif_id"] = sarif_id
    plan.request["analysis_id"] = analysis_id
    plan.request["analysis_created_at"] = analysis_created_at
    plan.request["processing_status"] = "pending"
    result = {
        "sarif_id": sarif_id,
        "analysis_id": analysis_id,
        "analysis_created_at": analysis_created_at,
        "result_count": plan.request["result_count"],
        "skipped": plan.request["skipped"],
        "skipped_total": plan.request["skipped_total"],
        "response": response,
    }
    return ActionOutcome(status="accepted_async", vendor_ref=sarif_id, result=result)


async def reconcile_upload_code_scanning_sarif(
    connector: Any,
    plan: ActionPlan,
    prior_outcome: ActionOutcome,
) -> ActionOutcome:
    if prior_outcome.status == "failed":
        plan.request["processing_status"] = "failed"
        return prior_outcome
    if plan.request.get("processing_status") == "failed":
        return ActionOutcome(
            status="failed",
            vendor_ref=plan.request.get("sarif_id"),
            error="GitHub SARIF processing previously failed",
            result=plan.request.get("processing_errors") or {},
        )
    sarif_id, analysis_id = _sarif_ids(plan, prior_outcome)
    if sarif_id is None:
        return _unknown(plan, "SARIF acceptance id is unavailable; upload cannot be reconciled safely")
    repo_path = _plan_repo_path(plan)
    processing = await _get_object(connector, f"{repo_path}/code-scanning/sarifs/{_segment(sarif_id)}")
    status = processing.get("processing_status")
    if status not in ("pending", "complete", "failed"):
        raise VendorContractError("GitHub SARIF processing_status must be pending, complete, or failed")
    plan.request["sarif_id"] = sarif_id
    plan.request["processing_status"] = status
    processing_analysis_id = _optional_analysis_id(processing)
    if processing_analysis_id is not None and analysis_id is not None and processing_analysis_id != analysis_id:
        return ActionOutcome(
            status="failed",
            vendor_ref=sarif_id,
            error="GitHub SARIF processing changed the associated analysis id",
        )
    analysis_id = processing_analysis_id or analysis_id
    analysis_created_at = _analysis_created_at(processing) or plan.request.get("analysis_created_at")
    plan.request["analysis_id"] = analysis_id
    plan.request["analysis_created_at"] = analysis_created_at
    base_result = {
        "sarif_id": sarif_id,
        "analysis_id": analysis_id,
        "analysis_created_at": analysis_created_at,
        "processing_status": status,
    }
    if status == "pending":
        return ActionOutcome(status="accepted_async", vendor_ref=sarif_id, result=base_result)
    if status == "failed":
        errors = processing.get("errors")
        plan.request["processing_errors"] = {"errors": errors}
        return ActionOutcome(
            status="failed",
            vendor_ref=sarif_id,
            result={**base_result, "errors": errors},
            error=f"GitHub SARIF processing failed: {errors!r}",
        )
    analysis = await _native_analysis(connector, plan, sarif_id, analysis_id)
    if analysis is None:
        return ActionOutcome(
            status="accepted_async",
            vendor_ref=sarif_id,
            result=base_result,
            error="SARIF processing completed but no matching native analysis is visible yet",
        )
    native_id = _required_id(analysis)
    plan.request["analysis_id"] = native_id
    plan.request["analysis_created_at"] = analysis.get("created_at")
    return ActionOutcome(
        status="succeeded",
        vendor_ref=str(native_id),
        result={**base_result, "analysis_id": native_id, "analysis_created_at": analysis.get("created_at"), "analysis": analysis},
    )


# ---------------------------------------------------------------------------
# update_code_scanning_alert


def _alert_converged(current: Mapping[str, Any], desired: Mapping[str, Any]) -> bool:
    if current.get("state") != desired.get("state"):
        return False
    if desired.get("state") != "dismissed":
        return True
    if "dismissed_reason" in desired and current.get("dismissed_reason") != desired["dismissed_reason"]:
        return False
    return "dismissed_comment" not in desired or current.get("dismissed_comment") == desired["dismissed_comment"]


def _assert_alert_preconditions(current: Mapping[str, Any], plan: ActionPlan) -> None:
    if current.get("state") != plan.preconditions["state"] or current.get("updated_at") != plan.preconditions["updated_at"]:
        raise StalePlan("GitHub code scanning alert changed after planning")


async def plan_update_code_scanning_alert(connector: Any, args: UpdateCodeScanningAlertArgs) -> ActionPlan:
    path = f"{_args_repo_path(args)}/code-scanning/alerts/{args.alert_number}"
    current = await _get_object(connector, path)
    payload = args.model_dump(mode="json", include={"state", "dismissed_reason", "dismissed_comment"}, exclude_none=True)
    changed = not _alert_converged(current, payload)
    return _make_plan(
        connector,
        "update_code_scanning_alert",
        target_ref=f"github:code-scanning-alert:{args.owner}/{args.repo}:{args.alert_number}",
        route_key=f"{args.owner}/{args.repo}:{args.alert_number}:{args.state}:{args.dismissed_reason}:{args.dismissed_comment}",
        diff={} if not changed else {"state": {"from": current.get("state"), "to": args.state}, "fields": payload},
        preconditions={
            **_repo_preconditions(args),
            "alert_number": args.alert_number,
            "state": current.get("state"),
            "updated_at": current.get("updated_at"),
        },
        request={"method": "PATCH", "path": path, "json": payload},
        changed=changed,
    )


async def apply_update_code_scanning_alert(connector: Any, plan: ActionPlan) -> ActionOutcome:
    _require_write(connector)
    if not plan.changed:
        return _no_op(plan)
    current = await _get_object(connector, str(plan.request["path"]))
    if _alert_converged(current, plan.request["json"]):
        return _no_op(plan, {"alert": current})
    _assert_alert_preconditions(current, plan)
    try:
        response = _object(await _mutation(connector, plan, idempotency="idempotent_write", expected=(200,)))
    except OutcomeUnknown as exc:
        unknown = ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))
        reconciled = await reconcile_update_code_scanning_alert(connector, plan, unknown)
        return reconciled if reconciled.status == "succeeded" else _unknown(plan, exc)
    if not _alert_converged(response, plan.request["json"]):
        raise VendorContractError("GitHub alert mutation response does not match the requested state")
    accepted = ActionOutcome(status="succeeded", vendor_ref=plan.target_ref, result={"alert": response})
    return await reconcile_update_code_scanning_alert(connector, plan, accepted)


async def reconcile_update_code_scanning_alert(
    connector: Any,
    plan: ActionPlan,
    prior_outcome: ActionOutcome,
) -> ActionOutcome:
    current = await _get_object(connector, str(plan.request["path"]))
    if _alert_converged(current, plan.request["json"]):
        return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref, result={"alert": current})
    return ActionOutcome(
        status="failed",
        vendor_ref=plan.target_ref,
        result={"alert": current},
        error="GitHub alert read-back does not match the requested state",
    )


# ---------------------------------------------------------------------------
# create_pr_comment


def _comment_marker(action_key: str) -> str:
    return _COMMENT_MARKER.format(action_key)


def _marked_comment(comment: Mapping[str, Any], marker: str) -> bool:
    body = comment.get("body")
    return isinstance(body, str) and marker in body.splitlines()


async def _find_comment(connector: Any, plan_or_path: ActionPlan | str, marker: str) -> dict[str, Any] | None:
    path = plan_or_path if isinstance(plan_or_path, str) else str(plan_or_path.request["list_path"])
    comments = await _all_pages(connector, path)
    matches = [comment for comment in comments if _marked_comment(comment, marker)]
    if not matches:
        return None
    matches.sort(key=lambda item: int(item.get("id") or 0))
    return matches[0]


async def plan_create_pr_comment(connector: Any, args: CreatePrCommentArgs) -> ActionPlan:
    repo_path = _args_repo_path(args)
    path = f"{repo_path}/issues/{args.pull_number}/comments"
    marker = _comment_marker(args.action_key)
    comments = await _all_pages(connector, path)
    existing = next((item for item in sorted(comments, key=lambda value: int(value.get("id") or 0)) if _marked_comment(item, marker)), None)
    body = f"{args.body}\n\n{marker}"
    preconditions = {**_repo_preconditions(args), "pull_number": args.pull_number, "action_key": args.action_key, "marker": marker}
    request = {"method": "POST", "path": path, "list_path": path, "json": {"body": body}, "comment_id": None}
    changed = existing is None
    if existing is not None:
        request["comment_id"] = _required_id(existing)
    return _make_plan(
        connector,
        "create_pr_comment",
        target_ref=(str(existing.get("url")) if existing else f"github:comment:{args.owner}/{args.repo}:{args.pull_number}:{args.action_key}"),
        route_key=f"{args.owner}/{args.repo}:{args.pull_number}:{args.action_key}",
        diff={"comment": {"added": body}} if changed else {},
        preconditions=preconditions,
        request=request,
        changed=changed,
    )


async def apply_create_pr_comment(connector: Any, plan: ActionPlan) -> ActionOutcome:
    _require_write(connector)
    if not plan.changed:
        return _no_op(plan)
    existing = await _find_comment(connector, plan, str(plan.preconditions["marker"]))
    if existing is not None:
        plan.request["comment_id"] = _required_id(existing)
        return _no_op(plan, {"comment": existing})
    try:
        response = _object(await _mutation(connector, plan, idempotency="non_idempotent", expected=(201,)))
    except OutcomeUnknown as exc:
        existing = await _find_comment(connector, plan, str(plan.preconditions["marker"]))
        if existing is not None:
            comment_id = _required_id(existing)
            plan.request["comment_id"] = comment_id
            return ActionOutcome(status="succeeded", vendor_ref=str(comment_id), result={"comment": existing})
        return _unknown(plan, exc)
    comment_id = _required_id(response)
    plan.request["comment_id"] = comment_id
    read_path = f"{_plan_repo_path(plan)}/issues/comments/{comment_id}"
    current = await _get_object(connector, read_path)
    if _required_id(current) != comment_id or not _marked_comment(current, str(plan.preconditions["marker"])):
        return ActionOutcome(status="failed", vendor_ref=str(comment_id), error="GitHub comment read-back lacks the exact action marker")
    return ActionOutcome(status="succeeded", vendor_ref=str(comment_id), result={"comment": current})


async def reconcile_create_pr_comment(
    connector: Any,
    plan: ActionPlan,
    prior_outcome: ActionOutcome,
) -> ActionOutcome:
    existing = await _find_comment(connector, plan, str(plan.preconditions["marker"]))
    if existing is not None:
        comment_id = _required_id(existing)
        plan.request["comment_id"] = comment_id
        return ActionOutcome(status="succeeded", vendor_ref=str(comment_id), result={"comment": existing})
    status = "outcome_unknown" if prior_outcome.status == "outcome_unknown" else "failed"
    return ActionOutcome(status=status, vendor_ref=plan.target_ref, error="GitHub comment marker was not found in any comment page")


# ---------------------------------------------------------------------------
# create_review


def _review_matches(review: Mapping[str, Any], head_sha: str, event: str) -> bool:
    return _same_sha(review.get("commit_id"), head_sha) and review.get("state") in (event, _REVIEW_STATES[event])


async def _find_review(connector: Any, plan: ActionPlan) -> dict[str, Any] | None:
    reviews = await _all_pages(connector, str(plan.request["list_path"]))
    matches = [
        review
        for review in reviews
        if _review_matches(review, str(plan.preconditions["head_sha"]), str(plan.request["json"]["event"]))
    ]
    if not matches:
        return None
    matches.sort(key=lambda item: int(item.get("id") or 0))
    return matches[0]


async def _pull_request(connector: Any, repo_path: str, number: int) -> dict[str, Any]:
    return await _get_object(connector, f"{repo_path}/pulls/{number}")


def _pull_head(pull: Mapping[str, Any]) -> str:
    head = pull.get("head")
    if not isinstance(head, Mapping):
        raise VendorContractError("GitHub pull request requires head")
    return _sha(head.get("sha"), "head.sha")


async def plan_create_review(connector: Any, args: CreateReviewArgs) -> ActionPlan:
    repo_path = _args_repo_path(args)
    pull_path = f"{repo_path}/pulls/{args.pull_number}"
    pull = await _get_object(connector, pull_path)
    head_sha = _pull_head(pull)
    payload: dict[str, Any] = {
        "commit_id": head_sha,
        "event": args.event,
        "comments": [comment.model_dump(mode="json", exclude_none=True) for comment in args.comments],
    }
    if args.body is not None:
        payload["body"] = args.body
    list_path = f"{pull_path}/reviews"
    preconditions = {**_repo_preconditions(args), "pull_number": args.pull_number, "head_sha": head_sha}
    plan = _make_plan(
        connector,
        "create_review",
        target_ref=f"github:review:{args.owner}/{args.repo}:{args.pull_number}:{head_sha}:{args.event}",
        route_key=f"{args.owner}/{args.repo}:{args.pull_number}:{head_sha}:{args.event}",
        diff={"review": {"head_sha": head_sha, "event": args.event}},
        preconditions=preconditions,
        request={"method": "POST", "path": list_path, "list_path": list_path, "json": payload, "review_id": None},
    )
    existing = await _find_review(connector, plan)
    if existing is not None:
        review_id = _required_id(existing)
        plan.request["review_id"] = review_id
        plan.changed = False
        plan.diff = {}
        plan.target_ref = str(review_id)
    return plan


async def apply_create_review(connector: Any, plan: ActionPlan) -> ActionOutcome:
    _require_write(connector)
    if not plan.changed:
        return _no_op(plan)
    repo_path = _plan_repo_path(plan)
    pull = await _pull_request(connector, repo_path, int(plan.preconditions["pull_number"]))
    if not _same_sha(_pull_head(pull), plan.preconditions["head_sha"]):
        raise StalePlan("GitHub pull request head changed after review planning")
    existing = await _find_review(connector, plan)
    if existing is not None:
        plan.request["review_id"] = _required_id(existing)
        return _no_op(plan, {"review": existing})
    try:
        response = _object(await _mutation(connector, plan, idempotency="non_idempotent", expected=(201,)))
    except OutcomeUnknown as exc:
        existing = await _find_review(connector, plan)
        if existing is not None:
            review_id = _required_id(existing)
            plan.request["review_id"] = review_id
            return ActionOutcome(status="succeeded", vendor_ref=str(review_id), result={"review": existing})
        return _unknown(plan, exc)
    review_id = _required_id(response)
    plan.request["review_id"] = review_id
    current = await _get_object(connector, f"{str(plan.request['list_path'])}/{review_id}")
    if _required_id(current) != review_id or not _review_matches(
        current, str(plan.preconditions["head_sha"]), str(plan.request["json"]["event"])
    ):
        return ActionOutcome(status="failed", vendor_ref=str(review_id), error="GitHub review read-back does not match PR head and event")
    return ActionOutcome(status="succeeded", vendor_ref=str(review_id), result={"review": current})


async def reconcile_create_review(
    connector: Any,
    plan: ActionPlan,
    prior_outcome: ActionOutcome,
) -> ActionOutcome:
    existing = await _find_review(connector, plan)
    if existing is not None:
        review_id = _required_id(existing)
        plan.request["review_id"] = review_id
        return ActionOutcome(status="succeeded", vendor_ref=str(review_id), result={"review": existing})
    status = "outcome_unknown" if prior_outcome.status == "outcome_unknown" else "failed"
    return ActionOutcome(status=status, vendor_ref=plan.target_ref, error="No review matches the planned PR head and event")


# ---------------------------------------------------------------------------
# create_pull_request


def _desired_head(plan: ActionPlan) -> tuple[str, str]:
    value = str(plan.request["json"]["head"])
    if ":" in value:
        owner, branch = value.split(":", 1)
        return owner, branch
    return str(plan.preconditions["owner"]), value


def _pull_matches(pull: Mapping[str, Any], plan: ActionPlan) -> bool:
    if pull.get("state") != "open":
        return False
    head = pull.get("head")
    base = pull.get("base")
    if not isinstance(head, Mapping) or not isinstance(base, Mapping):
        return False
    expected_owner, expected_branch = _desired_head(plan)
    head_repo = head.get("repo")
    head_user = head.get("user")
    actual_owner: Any = None
    if isinstance(head_repo, Mapping):
        owner = head_repo.get("owner")
        if isinstance(owner, Mapping):
            actual_owner = owner.get("login")
        if actual_owner is None:
            full_name = head_repo.get("full_name")
            if isinstance(full_name, str) and "/" in full_name:
                actual_owner = full_name.split("/", 1)[0]
    if actual_owner is None and isinstance(head_user, Mapping):
        actual_owner = head_user.get("login")
    if actual_owner is None and isinstance(head.get("label"), str) and ":" in head["label"]:
        actual_owner = head["label"].split(":", 1)[0]
    if actual_owner != expected_owner or head.get("ref") != expected_branch or base.get("ref") != plan.request["json"]["base"]:
        return False
    base_repo = base.get("repo")
    if isinstance(base_repo, Mapping):
        if base_repo.get("name") not in (None, plan.preconditions["repo"]):
            return False
        owner = base_repo.get("owner")
        if isinstance(owner, Mapping) and owner.get("login") not in (None, plan.preconditions["owner"]):
            return False
    return True


async def _find_open_pull(connector: Any, plan: ActionPlan) -> dict[str, Any] | None:
    pulls = await _all_pages(
        connector,
        str(plan.request["list_path"]),
        params={"state": "open", "base": plan.request["json"]["base"]},
    )
    matches = [pull for pull in pulls if _pull_matches(pull, plan)]
    if not matches:
        return None
    matches.sort(key=lambda item: int(item.get("number") or 0))
    return matches[0]


async def plan_create_pull_request(connector: Any, args: CreatePullRequestArgs) -> ActionPlan:
    repo_path = _args_repo_path(args)
    payload = args.model_dump(mode="json", include={"title", "head", "base", "body", "draft", "maintainer_can_modify"}, exclude_none=True)
    path = f"{repo_path}/pulls"
    plan = _make_plan(
        connector,
        "create_pull_request",
        target_ref=f"github:pull:{args.owner}/{args.repo}:{args.head}:{args.base}",
        route_key=f"{args.owner}/{args.repo}:{args.head}:{args.base}",
        diff={"pull_request": {"head": args.head, "base": args.base, "title": args.title}},
        preconditions={**_repo_preconditions(args), "head": args.head, "base": args.base},
        request={"method": "POST", "path": path, "list_path": path, "json": payload, "pull_number": None},
    )
    existing = await _find_open_pull(connector, plan)
    if existing is not None:
        number = _required_id(existing, "number")
        plan.request["pull_number"] = number
        plan.changed = False
        plan.diff = {}
        plan.target_ref = str(number)
    return plan


async def apply_create_pull_request(connector: Any, plan: ActionPlan) -> ActionOutcome:
    _require_write(connector)
    if not plan.changed:
        return _no_op(plan)
    existing = await _find_open_pull(connector, plan)
    if existing is not None:
        number = _required_id(existing, "number")
        plan.request["pull_number"] = number
        return _no_op(plan, {"pull_request": existing})
    try:
        response = _object(await _mutation(connector, plan, idempotency="non_idempotent", expected=(201,)))
    except OutcomeUnknown as exc:
        existing = await _find_open_pull(connector, plan)
        if existing is not None:
            number = _required_id(existing, "number")
            plan.request["pull_number"] = number
            return ActionOutcome(status="succeeded", vendor_ref=str(number), result={"pull_request": existing})
        return _unknown(plan, exc)
    number = _required_id(response, "number")
    plan.request["pull_number"] = number
    current = await _pull_request(connector, _plan_repo_path(plan), number)
    if _required_id(current, "number") != number or not _pull_matches(current, plan):
        return ActionOutcome(status="failed", vendor_ref=str(number), error="GitHub pull request read-back does not match source and target")
    if current.get("title") != plan.request["json"]["title"]:
        return ActionOutcome(status="failed", vendor_ref=str(number), error="GitHub pull request read-back returned a different title")
    return ActionOutcome(status="succeeded", vendor_ref=str(number), result={"pull_request": current})


async def reconcile_create_pull_request(
    connector: Any,
    plan: ActionPlan,
    prior_outcome: ActionOutcome,
) -> ActionOutcome:
    existing = await _find_open_pull(connector, plan)
    if existing is not None:
        number = _required_id(existing, "number")
        plan.request["pull_number"] = number
        return ActionOutcome(status="succeeded", vendor_ref=str(number), result={"pull_request": existing})
    status = "outcome_unknown" if prior_outcome.status == "outcome_unknown" else "failed"
    return ActionOutcome(status=status, vendor_ref=plan.target_ref, error="No open pull request matches the planned source owner, branch, and target")


# ---------------------------------------------------------------------------
# create_commit_status


def _latest_status(statuses: Iterable[Mapping[str, Any]], context: str) -> dict[str, Any] | None:
    matching = [dict(status) for status in statuses if status.get("context") == context]
    if not matching:
        return None
    matching.sort(key=lambda item: (str(item.get("created_at") or ""), int(item.get("id") or 0)))
    return matching[-1]


def _status_converged(status: Mapping[str, Any] | None, desired: Mapping[str, Any]) -> bool:
    if status is None or status.get("state") != desired.get("state"):
        return False
    return all(status.get(name) == desired.get(name) for name in ("description", "target_url"))


def _status_signature(status: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if status is None:
        return None
    return {name: status.get(name) for name in ("id", "state", "context", "description", "target_url", "created_at", "updated_at")}


async def _current_status(connector: Any, plan: ActionPlan) -> dict[str, Any] | None:
    statuses = await _all_pages(connector, str(plan.request["list_path"]))
    return _latest_status(statuses, str(plan.request["json"]["context"]))


async def plan_create_commit_status(connector: Any, args: CreateCommitStatusArgs) -> ActionPlan:
    repo_path = _args_repo_path(args)
    list_path = f"{repo_path}/commits/{_segment(args.sha)}/statuses"
    statuses = await _all_pages(connector, list_path)
    current = _latest_status(statuses, args.context)
    payload = args.model_dump(mode="json", include={"state", "context", "description", "target_url"}, exclude_none=True)
    changed = not _status_converged(current, payload)
    return _make_plan(
        connector,
        "create_commit_status",
        target_ref=f"github:status:{args.owner}/{args.repo}:{args.sha}:{args.context}",
        route_key=f"{args.owner}/{args.repo}:{args.sha}:{args.context}",
        diff={"status": {"from": _status_signature(current), "to": payload}} if changed else {},
        preconditions={**_repo_preconditions(args), "sha": args.sha, "context": args.context, "current": _status_signature(current)},
        request={
            "method": "POST",
            "path": f"{repo_path}/statuses/{_segment(args.sha)}",
            "list_path": list_path,
            "json": payload,
            "status_id": None,
        },
        changed=changed,
    )


async def apply_create_commit_status(connector: Any, plan: ActionPlan) -> ActionOutcome:
    _require_write(connector)
    if not plan.changed:
        return _no_op(plan)
    current = await _current_status(connector, plan)
    if _status_converged(current, plan.request["json"]):
        if current is not None:
            plan.request["status_id"] = current.get("id")
        return _no_op(plan, {"status": current})
    if _status_signature(current) != plan.preconditions["current"]:
        raise StalePlan("GitHub commit status context changed after planning")
    try:
        response = _object(await _mutation(connector, plan, idempotency="non_idempotent", expected=(201,)))
    except OutcomeUnknown as exc:
        current = await _current_status(connector, plan)
        if _status_converged(current, plan.request["json"]):
            plan.request["status_id"] = current.get("id") if current else None
            return ActionOutcome(status="succeeded", vendor_ref=str(plan.request["status_id"]), result={"status": current})
        return _unknown(plan, exc)
    status_id = _required_id(response)
    plan.request["status_id"] = status_id
    current = await _current_status(connector, plan)
    if current is None or current.get("id") != status_id or not _status_converged(current, plan.request["json"]):
        return ActionOutcome(status="failed", vendor_ref=str(status_id), error="GitHub commit status read-back is not current for the exact SHA and context")
    return ActionOutcome(status="succeeded", vendor_ref=str(status_id), result={"status": current})


async def reconcile_create_commit_status(
    connector: Any,
    plan: ActionPlan,
    prior_outcome: ActionOutcome,
) -> ActionOutcome:
    current = await _current_status(connector, plan)
    if _status_converged(current, plan.request["json"]):
        status_id = current.get("id") if current else None
        plan.request["status_id"] = status_id
        return ActionOutcome(status="succeeded", vendor_ref=str(status_id), result={"status": current})
    status = "outcome_unknown" if prior_outcome.status == "outcome_unknown" else "failed"
    return ActionOutcome(status=status, vendor_ref=plan.target_ref, error="Current GitHub commit status does not match the exact SHA, context, and value")


# ---------------------------------------------------------------------------
# create_or_update_check_run


def _require_check_app_auth(connector: Any) -> None:
    if connector.config.personal_access_token is not None:
        raise ConfigError("GitHub check runs require GitHub App authentication; use create_commit_status with PAT/BearerToken")


def _terminal_analysis(analysis: Mapping[str, Any], head_sha: str) -> None:
    if not _same_sha(analysis.get("commit_sha"), head_sha):
        raise StalePlan("GitHub native analysis commit does not match the check head SHA")
    status = analysis.get("processing_status") or analysis.get("status")
    if status is not None and status not in ("complete", "completed", "success", "succeeded"):
        raise StalePlan(f"GitHub native analysis is not terminal: {status}")
    if analysis.get("error"):
        raise StalePlan(f"GitHub native analysis failed: {analysis['error']}")
    results_count = analysis.get("results_count")
    if isinstance(results_count, bool) or not isinstance(results_count, int) or results_count < 0:
        raise StalePlan("GitHub native analysis has no terminal results_count")


def _analysis_preconditions(analysis: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "analysis_id": analysis.get("id"),
        "analysis_commit_sha": analysis.get("commit_sha"),
        "analysis_ref": analysis.get("ref"),
        "analysis_created_at": analysis.get("created_at"),
        "analysis_results_count": analysis.get("results_count"),
        "analysis_rules_count": analysis.get("rules_count"),
    }


def _assert_analysis_preconditions(analysis: Mapping[str, Any], plan: ActionPlan) -> None:
    for key, value in _analysis_preconditions(analysis).items():
        if key == "analysis_commit_sha":
            if not _same_sha(value, plan.preconditions[key]):
                raise StalePlan("GitHub native analysis commit changed after check planning")
        elif value != plan.preconditions[key]:
            raise StalePlan(f"GitHub native analysis precondition {key} changed after check planning")


def _check_payload(args: CheckRunArgs) -> dict[str, Any]:
    output: dict[str, Any] = {"title": args.title, "summary": args.summary}
    if args.text is not None:
        output["text"] = args.text
    if args.annotations:
        output["annotations"] = [annotation.model_dump(mode="json", exclude_none=True) for annotation in args.annotations]
    payload: dict[str, Any] = {
        "name": args.name,
        "head_sha": args.sha,
        "external_id": args.action_key,
        "status": args.status,
        "output": output,
    }
    if args.conclusion is not None:
        payload["conclusion"] = args.conclusion
    if args.details_url is not None:
        payload["details_url"] = args.details_url
    return payload


def _check_identity(check: Mapping[str, Any], plan: ActionPlan) -> bool:
    return (
        check.get("name") == plan.request["name"]
        and check.get("external_id") == plan.request["external_id"]
        and _same_sha(check.get("head_sha"), plan.request["head_sha"])
    )


def _output_matches(current: Any, desired: Any) -> bool:
    if not isinstance(current, Mapping) or not isinstance(desired, Mapping):
        return False
    for key, value in desired.items():
        if key == "annotations":
            current_annotations = current.get(key) or []
            if not isinstance(current_annotations, list) or len(current_annotations) != len(value):
                return False
            for actual_item, desired_item in zip(current_annotations, value, strict=True):
                if not isinstance(actual_item, Mapping) or any(actual_item.get(field) != item for field, item in desired_item.items()):
                    return False
        elif current.get(key) != value:
            return False
    return True


def _check_converged(check: Mapping[str, Any], plan: ActionPlan) -> bool:
    if not _check_identity(check, plan):
        return False
    desired = plan.request["json"]
    for key in ("status", "conclusion", "details_url"):
        if key in desired and check.get(key) != desired[key]:
            return False
    return "output" not in desired or _output_matches(check.get("output"), desired["output"])


def _check_signature(check: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if check is None:
        return None
    return {
        "id": check.get("id"),
        "status": check.get("status"),
        "conclusion": check.get("conclusion"),
        "details_url": check.get("details_url"),
        "output": deepcopy(check.get("output")),
    }


async def _find_check(connector: Any, plan: ActionPlan) -> dict[str, Any] | None:
    checks = await _all_pages(
        connector,
        str(plan.request["list_path"]),
        params={"check_name": plan.request["name"]},
        items_key="check_runs",
    )
    matches = [check for check in checks if _check_identity(check, plan)]
    if not matches:
        return None
    matches.sort(key=lambda item: int(item.get("id") or 0))
    return matches[0]


async def plan_create_or_update_check_run(connector: Any, args: CheckRunArgs) -> ActionPlan:
    _require_check_app_auth(connector)
    repo_path = _args_repo_path(args)
    analysis_path = f"{repo_path}/code-scanning/analyses/{args.analysis_id}"
    analysis = await _get_object(connector, analysis_path)
    if _required_id(analysis) != args.analysis_id:
        raise VendorContractError("GitHub native analysis read returned a different id")
    _terminal_analysis(analysis, args.sha)
    payload = _check_payload(args)
    list_path = f"{repo_path}/commits/{_segment(args.sha)}/check-runs"
    plan = _make_plan(
        connector,
        "create_or_update_check_run",
        target_ref=f"github:check:{args.owner}/{args.repo}:{args.sha}:{args.name}:{args.action_key}",
        route_key=f"{args.owner}/{args.repo}:{args.sha}:{args.name}:{args.action_key}",
        diff={"check_run": {"from": None, "to": payload, "analysis_id": args.analysis_id}},
        preconditions={
            **_repo_preconditions(args),
            "head_sha": args.sha,
            **_analysis_preconditions(analysis),
        },
        request={
            "method": "POST",
            "path": f"{repo_path}/check-runs",
            "list_path": list_path,
            "analysis_path": analysis_path,
            "json": payload,
            "name": args.name,
            "head_sha": args.sha,
            "external_id": args.action_key,
            "check_id": None,
        },
    )
    existing = await _find_check(connector, plan)
    plan.preconditions["current_check"] = _check_signature(existing)
    if existing is not None:
        check_id = _required_id(existing)
        plan.request["check_id"] = check_id
        plan.request["method"] = "PATCH"
        plan.request["path"] = f"{repo_path}/check-runs/{check_id}"
        mutation = dict(payload)
        mutation.pop("head_sha", None)
        plan.request["json"] = mutation
        plan.diff = {"check_run": {"from": _check_signature(existing), "to": payload, "analysis_id": args.analysis_id}}
        if _check_converged(existing, plan):
            plan.changed = False
            plan.diff = {}
            plan.target_ref = str(check_id)
    return plan


async def apply_create_or_update_check_run(connector: Any, plan: ActionPlan) -> ActionOutcome:
    _require_write(connector)
    _require_check_app_auth(connector)
    if not plan.changed:
        return _no_op(plan)
    analysis = await _get_object(connector, str(plan.request["analysis_path"]))
    _terminal_analysis(analysis, str(plan.request["head_sha"]))
    _assert_analysis_preconditions(analysis, plan)
    existing = await _find_check(connector, plan)
    planned_id = plan.request.get("check_id")
    if existing is not None and _check_converged(existing, plan):
        plan.request["check_id"] = _required_id(existing)
        return _no_op(plan, {"check_run": existing, "analysis": analysis})
    if planned_id is None and existing is not None:
        raise StalePlan("A matching GitHub check run appeared after create planning; replan as an update")
    if planned_id is not None and (existing is None or _required_id(existing) != int(planned_id)):
        raise StalePlan("The planned GitHub check run no longer exists")
    if _check_signature(existing) != plan.preconditions["current_check"]:
        raise StalePlan("The planned GitHub check run changed after planning")
    try:
        response = _object(
            await _mutation(
                connector,
                plan,
                idempotency="non_idempotent",
                expected=(201,) if plan.request["method"] == "POST" else (200,),
            )
        )
    except OutcomeUnknown as exc:
        unknown = ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))
        reconciled = await reconcile_create_or_update_check_run(connector, plan, unknown)
        return reconciled if reconciled.status == "succeeded" else _unknown(plan, exc)
    check_id = _required_id(response)
    if planned_id is not None and check_id != int(planned_id):
        raise VendorContractError("GitHub check update returned a different check id")
    plan.request["check_id"] = check_id
    current = await _get_object(connector, f"{_plan_repo_path(plan)}/check-runs/{check_id}")
    if _required_id(current) != check_id or not _check_converged(current, plan):
        return ActionOutcome(status="failed", vendor_ref=str(check_id), error="GitHub check run read-back does not match head, name, external_id, or output")
    return ActionOutcome(
        status="succeeded",
        vendor_ref=str(check_id),
        result={"check_run": current, "analysis": analysis, "analysis_id": analysis.get("id")},
    )


async def reconcile_create_or_update_check_run(
    connector: Any,
    plan: ActionPlan,
    prior_outcome: ActionOutcome,
) -> ActionOutcome:
    _require_check_app_auth(connector)
    analysis = await _get_object(connector, str(plan.request["analysis_path"]))
    try:
        _terminal_analysis(analysis, str(plan.request["head_sha"]))
        _assert_analysis_preconditions(analysis, plan)
    except StalePlan as exc:
        return ActionOutcome(status="failed", vendor_ref=plan.target_ref, error=str(exc))
    check_id = plan.request.get("check_id")
    if check_id is not None:
        current = await _get_object(connector, f"{_plan_repo_path(plan)}/check-runs/{int(check_id)}")
    else:
        current = await _find_check(connector, plan)
    if current is not None and _check_converged(current, plan):
        current_id = _required_id(current)
        plan.request["check_id"] = current_id
        return ActionOutcome(
            status="succeeded",
            vendor_ref=str(current_id),
            result={"check_run": current, "analysis": analysis, "analysis_id": analysis.get("id")},
        )
    status = "outcome_unknown" if prior_outcome.status == "outcome_unknown" else "failed"
    return ActionOutcome(status=status, vendor_ref=plan.target_ref, error="GitHub check run does not match the reconciled analysis and planned head")


# ---------------------------------------------------------------------------
# merge_pull_request


async def plan_merge_pull_request(connector: Any, args: MergePullRequestArgs) -> ActionPlan:
    repo_path = _args_repo_path(args)
    pull_path = f"{repo_path}/pulls/{args.pull_number}"
    pull = await _get_object(connector, pull_path)
    merged = bool(pull.get("merged", False))
    head_sha = _pull_head(pull)
    if not merged and pull.get("state") != "open":
        raise Conflict("GitHub pull request is closed and not merged")
    if not merged and args.expected_head_sha is not None and not _same_sha(head_sha, args.expected_head_sha):
        raise StalePlan("GitHub pull request head does not match expected_head_sha")
    payload = args.model_dump(mode="json", include={"merge_method", "commit_title", "commit_message"}, exclude_none=True)
    payload["sha"] = head_sha
    return _make_plan(
        connector,
        "merge_pull_request",
        target_ref=f"github:pull:{args.owner}/{args.repo}:{args.pull_number}",
        route_key=f"{args.owner}/{args.repo}:{args.pull_number}:{head_sha}:{args.merge_method}",
        diff={} if merged else {"merge": {"head_sha": head_sha, "merge_method": args.merge_method}},
        preconditions={
            **_repo_preconditions(args),
            "pull_number": args.pull_number,
            "head_sha": head_sha,
            "state": pull.get("state"),
            "merged": merged,
        },
        request={"method": "PUT", "path": f"{pull_path}/merge", "pull_path": pull_path, "json": payload},
        changed=not merged,
    )


async def apply_merge_pull_request(connector: Any, plan: ActionPlan) -> ActionOutcome:
    _require_destructive(connector)
    _require_write(connector)
    if not plan.changed:
        return _no_op(plan)
    pull = await _get_object(connector, str(plan.request["pull_path"]))
    if pull.get("merged") is True:
        return _no_op(plan, {"pull_request": pull})
    if pull.get("state") != "open" or not _same_sha(_pull_head(pull), plan.preconditions["head_sha"]):
        raise StalePlan("GitHub pull request state or actual head changed before merge")
    try:
        response = _object(await _mutation(connector, plan, idempotency="non_idempotent", expected=(200,)))
    except OutcomeUnknown as exc:
        current = await _get_object(connector, str(plan.request["pull_path"]))
        if current.get("merged") is True and _same_sha(_pull_head(current), plan.preconditions["head_sha"]):
            return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref, result={"pull_request": current})
        return _unknown(plan, exc)
    if response.get("merged") is not True:
        return ActionOutcome(
            status="failed",
            vendor_ref=plan.target_ref,
            result={"merge": response},
            error=str(response.get("message") or "GitHub did not merge the pull request"),
        )
    current = await _get_object(connector, str(plan.request["pull_path"]))
    if current.get("merged") is not True or not _same_sha(_pull_head(current), plan.preconditions["head_sha"]):
        return ActionOutcome(status="failed", vendor_ref=plan.target_ref, error="GitHub pull request read-back is not merged at the planned head")
    response_sha = response.get("sha")
    if response_sha is not None and current.get("merge_commit_sha") is not None and not _same_sha(response_sha, current["merge_commit_sha"]):
        return ActionOutcome(status="failed", vendor_ref=plan.target_ref, error="GitHub merge commit read-back differs from the merge response")
    return ActionOutcome(status="succeeded", vendor_ref=str(response_sha or current.get("merge_commit_sha") or plan.target_ref), result={"merge": response, "pull_request": current})


async def reconcile_merge_pull_request(
    connector: Any,
    plan: ActionPlan,
    prior_outcome: ActionOutcome,
) -> ActionOutcome:
    current = await _get_object(connector, str(plan.request["pull_path"]))
    if current.get("merged") is True and _same_sha(_pull_head(current), plan.preconditions["head_sha"]):
        return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref, result={"pull_request": current})
    if current.get("merged") is True:
        return ActionOutcome(status="failed", vendor_ref=plan.target_ref, error="Pull request merged at a different head than planned")
    status = "outcome_unknown" if prior_outcome.status == "outcome_unknown" else "failed"
    return ActionOutcome(status=status, vendor_ref=plan.target_ref, error="GitHub pull request is not merged at the planned head")


# ---------------------------------------------------------------------------
# F4 PR-to-SARIF preparation


def _changed_lines(patch: Any) -> list[tuple[int, int]] | None:
    if not isinstance(patch, str):
        return None
    lines: list[int] = []
    new_line: int | None = None
    for line in patch.splitlines():
        match = _HUNK_HEADER.match(line)
        if match is not None:
            new_line = int(match.group(1))
            continue
        if new_line is None or line.startswith("\\"):
            continue
        if line.startswith("+") and not line.startswith("+++"):
            lines.append(new_line)
            new_line += 1
        elif line.startswith("-") and not line.startswith("---"):
            continue
        else:
            new_line += 1
    ranges: list[tuple[int, int]] = []
    for line in sorted(set(lines)):
        if ranges and line == ranges[-1][1] + 1:
            ranges[-1] = (ranges[-1][0], line)
        else:
            ranges.append((line, line))
    return ranges


def _normal_code_path(path: Any) -> str | None:
    if not isinstance(path, str) or not path or path.startswith("/") or "\\" in path:
        return None
    if any(part in ("", ".", "..") for part in path.split("/")):
        return None
    return path


def _location_in_diff(location: Any, changed: Mapping[str, list[tuple[int, int]] | None]) -> tuple[bool, str, str | None]:
    if not isinstance(location, Mapping):
        return False, "invalid_code_location", None
    physical = location.get("physicalLocation")
    if not isinstance(physical, Mapping):
        return False, "no_code_location", None
    artifact = physical.get("artifactLocation")
    if not isinstance(artifact, Mapping):
        return False, "no_code_location", None
    path = _normal_code_path(artifact.get("uri"))
    if path is None:
        return False, "invalid_code_location", None
    if path not in changed:
        return False, "outside_current_diff", path
    region = physical.get("region")
    if not isinstance(region, Mapping) or region.get("startLine") is None:
        return True, "", path
    ranges = changed[path]
    if ranges is None:
        return False, "diff_unavailable", path
    start = region.get("startLine")
    end = region.get("endLine") or start
    if isinstance(start, bool) or isinstance(end, bool) or not isinstance(start, int) or not isinstance(end, int):
        return False, "invalid_code_location", path
    if end < start or not any(start <= range_end and end >= range_start for range_start, range_end in ranges):
        return False, "outside_current_diff", path
    return True, "", path


def _typed_finding(item: Any) -> tuple[Any | None, str, str | None]:
    if isinstance(item, VulnerabilityFinding | DetectionFinding | ApplicationSecurityPostureFinding):
        return item, item.finding_info.uid, None
    if isinstance(item, SourceRecord):
        document = item.data
        uid = item.uid
    elif isinstance(item, Mapping):
        document = dict(item)
        finding_info = document.get("finding_info")
        uid = str(finding_info.get("uid")) if isinstance(finding_info, Mapping) and finding_info.get("uid") is not None else "unknown"
    else:
        return None, "unknown", "invalid_finding"
    classes = {
        2002: VulnerabilityFinding,
        2004: DetectionFinding,
        2007: ApplicationSecurityPostureFinding,
    }
    class_uid = document.get("class_uid")
    finding_class = classes.get(class_uid) if isinstance(class_uid, int) and not isinstance(class_uid, bool) else None
    if finding_class is None:
        return None, uid, "unsupported_ocsf_class"
    try:
        finding = finding_class.from_ocsf(document)
    except (TypeError, ValueError):
        return None, uid, "invalid_finding"
    return finding, finding.finding_info.uid, None


async def prepare_pull_request_sarif(
    connector: Any,
    pull: PullRef,
    findings: Iterable[Any],
    tool_name: str,
) -> dict[str, Any]:
    """Prepare bounded, head-bound SARIF without publishing an unreconciled check."""

    if not tool_name:
        raise ConfigError("tool_name must not be empty")
    repo_path = _args_repo_path(pull)
    pull_path = f"{repo_path}/pulls/{pull.pull_number}"
    current = await _get_object(connector, pull_path)
    if current.get("state") != "open":
        raise StalePlan("GitHub pull request is not open for SARIF preparation")
    head_sha = _pull_head(current)
    head = current.get("head")
    base = current.get("base")
    if not isinstance(head, Mapping) or not isinstance(base, Mapping):
        raise VendorContractError("GitHub pull request requires head and base")
    files = await _all_pages(connector, f"{pull_path}/files")
    changed: dict[str, list[tuple[int, int]] | None] = {}
    for file in files:
        path = _normal_code_path(file.get("filename"))
        if path is not None:
            changed[path] = _changed_lines(file.get("patch"))

    skipped: list[dict[str, Any]] = []
    results: list[Result] = []
    for finding_index, item in enumerate(findings):
        finding, finding_uid, invalid_reason = _typed_finding(item)
        if finding is None:
            skipped.append({"finding_index": finding_index, "finding_uid": finding_uid, "reason": invalid_reason})
            continue
        conversion = findings_to_sarif([finding], tool_name)
        if conversion.skipped:
            skipped.append({"finding_index": finding_index, "finding_uid": finding_uid, "reason": "no_code_location"})
            continue
        for result in conversion.log.runs[0].results or []:
            valid_locations: list[Any] = []
            for location in result.locations or []:
                location_document = location.model_dump(mode="json", by_alias=True, exclude_none=True)
                valid, reason, path = _location_in_diff(location_document, changed)
                if valid:
                    valid_locations.append(location)
                else:
                    region = location_document.get("physicalLocation", {}).get("region", {})
                    skipped.append(
                        {
                            "finding_index": finding_index,
                            "finding_uid": finding_uid,
                            "ruleId": result.rule_id,
                            "reason": reason,
                            "path": path,
                            "start_line": region.get("startLine"),
                        }
                    )
            if valid_locations:
                results.append(result.model_copy(update={"locations": valid_locations}))

    log = SarifLog(runs=[Run(tool=Tool(driver=ToolComponent(name=tool_name)), results=results)])
    canonical = _canonical_sarif(connector, log)
    skipped.extend(canonical.skipped)
    report = _skip_report(connector, skipped)
    upload_ref = f"refs/pull/{pull.pull_number}/head"
    upload_args = {
        "owner": pull.owner,
        "repo": pull.repo,
        "commit_sha": head_sha,
        "ref": upload_ref,
        "sarif": canonical.document,
        "tool_name": tool_name,
    }
    metadata = {
        "owner": pull.owner,
        "repo": pull.repo,
        "pull_number": pull.pull_number,
        "head_sha": head_sha,
        "head_ref": head.get("ref"),
        "base_sha": base.get("sha"),
        "base_ref": base.get("ref"),
        "ref": upload_ref,
        "changed_paths": sorted(changed),
        "result_count": canonical.result_count,
        "sarif_bytes": len(canonical.content),
        "sarif_sha256": canonical.sha256,
        "skipped_total": report["skipped_total"],
        "skipped_details_omitted": report["skipped_details_omitted"],
    }
    return {"upload_args": upload_args, "metadata": metadata, "skipped": report["skipped"]}
