"""Live GitHub.com acceptance: health and scopes, identity, pagination, overlap sync, throttling, and gated writes."""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any

import httpx2
import pytest

from icuhub.connectors._github.models import CheckRunArgs, CreateCommitStatusArgs
from icuhub.connectors.github import GitHub
from icuhub.kit.cursors import TimeIdCursor
from icuhub.kit.errors import RateLimited
from icuhub.kit.testing import collect_stream, make_connector
from icuhub.kit.types import Target

ACCEPTANCE_KIND = "github"

_SUCCESS = ("succeeded", "no_op")
_NOT_EXERCISED = "NOT EXERCISED: operator must run manually"


def _connector(acceptance) -> GitHub:
    return make_connector(  # type: ignore[return-value]
        GitHub, acceptance.config, httpx2.AsyncHTTPTransport(), acceptance.secrets
    )


def _write_connector(acceptance) -> GitHub:
    config = {
        **acceptance.config,
        "write_enabled": acceptance.allow_writes,
        "destructive_enabled": bool(acceptance.params.get("allow_destructive", False)),
    }
    return make_connector(  # type: ignore[return-value]
        GitHub, config, httpx2.AsyncHTTPTransport(), acceptance.secrets
    )


def _required_param(acceptance, name: str) -> str:
    if name not in acceptance.params:
        pytest.skip(f"{ACCEPTANCE_KIND}: params.{name} is required")
    return str(acceptance.params[name])


def _app_auth_configured(acceptance) -> bool:
    return all(acceptance.config.get(key) for key in ("app_id", "app_private_key", "installation_id"))


def _action_key(name: str) -> str:
    return f"icuhub-acc-{name.replace('_', '-')}"


def _repository_target(acceptance) -> Target:
    owner = _required_param(acceptance, "owner")
    repo = _required_param(acceptance, "repo")
    repository_id = _required_param(acceptance, "repository_id")
    return Target(
        id=repository_id,
        source_uid=f"github:repository:{repository_id}",
        kind="repository",
        display_name=f"{owner}/{repo}",
        attributes={"owner": owner, "repo": repo},
    )


def _run_write(connector: GitHub, name: str, args: Any) -> tuple[Any, Any]:
    """Plan, re-plan to confirm the plan is not stale, apply, then reconcile when the outcome is ambiguous."""
    spec = connector.actions()[name]
    plan = asyncio.run(spec.plan(connector, args))
    replanned = asyncio.run(spec.plan(connector, args))
    assert replanned.plan_hash == plan.plan_hash
    outcome = asyncio.run(spec.apply(connector, plan))
    if outcome.status in ("accepted_async", "outcome_unknown"):
        if spec.reconcile is None:
            raise AssertionError(f"{name} returned {outcome.status} but declares no reconcile")
        outcome = asyncio.run(spec.reconcile(connector, plan, outcome))
    return plan, outcome


async def _listing_pages(connector: GitHub, path: str, items_key: str | None) -> tuple[int, int]:
    pages = 0
    items = 0
    async for page_items, _ in connector.pages(path, {"per_page": 1}, items_key=items_key):
        pages += 1
        items += len(page_items)
    return pages, items


def test_health_reports_capability_scopes(acceptance) -> None:
    report = asyncio.run(_connector(acceptance).check())
    capabilities = {name: health.status for name, health in report.capabilities.items()}
    reasons = {name: health.reason for name, health in report.capabilities.items() if health.status != "healthy"}
    healthy = report.status in ("healthy", "degraded") and capabilities.get("SourceControl") == "healthy"
    acceptance.record(
        "health_and_scopes",
        healthy,
        report.status,
        capabilities=capabilities,
        reasons=reasons,
        api_version=report.detail.get("api_version"),
    )
    assert healthy


def test_identity_api_version_and_selection(acceptance) -> None:
    connector = _connector(acceptance)
    api_version = connector.config.api_version
    response = asyncio.run(connector.request("GET", "/rate_limit"))
    selected = response.headers.get("x-github-api-version-selected")
    version_ok = selected == api_version
    acceptance.record(
        "api_version_honored",
        version_ok,
        f"configured={api_version} selected={selected}",
        configured=api_version,
        selected=selected,
    )
    assert version_ok

    if _app_auth_configured(acceptance):
        pages, count = asyncio.run(_listing_pages(connector, "/installation/repositories", "repositories"))
        identity_ok = count > 0
        acceptance.record(
            "installation_selection",
            identity_ok,
            "installation repositories listed",
            auth_mode="github_app",
            pages=pages,
            selected_repositories=count,
        )
    else:
        user = asyncio.run(connector.request("GET", "/user")).json()
        identity_ok = isinstance(user, dict) and isinstance(user.get("id"), int)
        acceptance.record("identity", identity_ok, "authenticated user resolved", auth_mode="personal_access_token")
    assert identity_ok


def test_link_pages_are_traversed(acceptance) -> None:
    connector = _connector(acceptance)
    if _app_auth_configured(acceptance):
        path, items_key = "/installation/repositories", "repositories"
    else:
        path, items_key = "/user/repos", None
    pages, count = asyncio.run(_listing_pages(connector, path, items_key))
    traversed = pages >= 2
    acceptance.record(
        "link_pagination",
        traversed,
        f"pages={pages} items={count}",
        path=path,
        pages=pages,
        items=count,
    )
    assert traversed


def test_overlapping_incremental_sync_suppresses_boundary_duplicates(acceptance) -> None:
    connector = _connector(acceptance)
    target = _repository_target(acceptance)
    full = collect_stream(connector, "code_scanning_alerts", target=target, mode="full")
    assert full, "full sync returned no batches"
    checkpoint = full[-1].checkpoint
    if not isinstance(checkpoint, TimeIdCursor) or checkpoint.ts is None:
        acceptance.record("full_sync_checkpoint", False, "last full batch lacks a timestamp checkpoint")
        pytest.fail("full sync did not produce a time/id checkpoint")
    acceptance.record("full_sync_checkpoint", True, "last full batch carries a timestamp checkpoint")

    incremental = collect_stream(
        connector, "code_scanning_alerts", target=target, checkpoint=checkpoint, mode="incremental"
    )
    incremental_records = [raw for batch in incremental for raw in batch.records]
    duplicates = [
        raw
        for raw in incremental_records
        if checkpoint.is_duplicate(
            datetime.fromisoformat(str(raw["updated_at"]).replace("Z", "+00:00")),
            str(raw["number"]),
        )
    ]
    suppressed = not duplicates
    acceptance.record(
        "overlap_sync",
        suppressed,
        f"incremental_records={len(incremental_records)} boundary_duplicates={len(duplicates)}",
        full_records=sum(len(batch.records) for batch in full),
        incremental_records=len(incremental_records),
    )
    assert suppressed


def test_secondary_throttling_is_handled_without_sleep(acceptance) -> None:
    connector = _connector(acceptance)
    try:
        response = asyncio.run(connector.request("GET", "/rate_limit"))
    except RateLimited as exc:
        acceptance.record(
            "secondary_throttling",
            True,
            "rate limit persisted; bounded retries ended with RateLimited",
            throttled=True,
            retry_after_s=exc.retry_after_s,
        )
        return
    remaining = response.headers.get("x-ratelimit-remaining")
    quota_visible = remaining is not None and remaining.isdigit()
    acceptance.record(
        "secondary_throttling",
        quota_visible,
        "no throttle on sample; quota headers parsed",
        throttled=False,
        ratelimit_remaining=remaining,
        retry_after_present=response.headers.get("retry-after") is not None,
    )
    assert quota_visible


def test_gated_commit_status_write_and_readback(acceptance) -> None:
    acceptance.require_writes()
    owner = _required_param(acceptance, "owner")
    repo = _required_param(acceptance, "repo")
    sha = _required_param(acceptance, "commit_sha")
    context = _required_param(acceptance, "status_context")
    connector = _write_connector(acceptance)
    args = CreateCommitStatusArgs(
        owner=owner,
        repo=repo,
        sha=sha,
        state="success",
        context=context,
        description="icuhub acceptance",
    )
    plan, outcome = _run_write(connector, "create_commit_status", args)
    statuses = asyncio.run(connector.request("GET", f"/repos/{owner}/{repo}/commits/{sha}/statuses")).json()
    latest = next((status for status in statuses if status.get("context") == context), None)
    matched = latest is not None and latest.get("state") == "success"
    passed = outcome.status in _SUCCESS and matched
    acceptance.record(
        "commit_status_write_readback",
        passed,
        f"outcome={outcome.status} changed={plan.changed}",
        context=context,
        state="success",
    )
    assert passed


def test_gated_check_run_write_requires_app_auth(acceptance) -> None:
    acceptance.require_writes()
    if not _app_auth_configured(acceptance):
        pytest.skip(
            f"{ACCEPTANCE_KIND}: check-run writes require GitHub App auth (app_id, app_private_key, installation_id)"
        )
    owner = _required_param(acceptance, "owner")
    repo = _required_param(acceptance, "repo")
    sha = _required_param(acceptance, "commit_sha")
    check_name = _required_param(acceptance, "check_name")
    analysis_id = int(_required_param(acceptance, "analysis_id"))
    connector = _write_connector(acceptance)
    args = CheckRunArgs(
        owner=owner,
        repo=repo,
        sha=sha,
        name=check_name,
        action_key=_action_key("create_or_update_check_run"),
        analysis_id=analysis_id,
        status="completed",
        conclusion="success",
        title="icuhub acceptance",
        summary="icuhub acceptance check run",
    )
    plan, outcome = _run_write(connector, "create_or_update_check_run", args)
    runs = asyncio.run(connector.request("GET", f"/repos/{owner}/{repo}/commits/{sha}/check-runs")).json()
    matched = any(
        run.get("name") == check_name and run.get("status") == "completed" for run in runs.get("check_runs", [])
    )
    passed = outcome.status in _SUCCESS and matched
    acceptance.record(
        "check_run_write_readback",
        passed,
        f"outcome={outcome.status} changed={plan.changed}",
        check_name=check_name,
    )
    assert passed


def test_update_code_scanning_alert_manual_only(acceptance) -> None:
    acceptance.record("update_code_scanning_alert", False, _NOT_EXERCISED, manual_only=True)
    pytest.skip(_NOT_EXERCISED)


def test_merge_pull_request_manual_only(acceptance) -> None:
    acceptance.record("merge_pull_request", False, _NOT_EXERCISED, manual_only=True)
    pytest.skip(_NOT_EXERCISED)
