"""Edition-level tests for the github.com connector.

Covers the ``GitHubComConfig`` API-root pin, the ``repositories`` stream over two ``Link``-header
pages with typed contract violations, partial-scope health when code scanning is forbidden,
the ``create_commit_status`` action (single write across a retried apply, write gate), the
destructive gate on ``merge_pull_request``, and secret redaction in health reports and errors.
Requests are answered by ``RouteTransport`` from the synthetic fixtures in ``tests/fixtures/github/``.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, cast

import httpx2
import pytest

from icuhub.connectors._github.models import CheckRunArgs, CreateCommitStatusArgs, MergePullRequestArgs
from icuhub.connectors.github import GitHub
from icuhub.connectors.github.models import GitHubComConfig
from icuhub.kit.errors import AuthFailed, ConfigError, VendorContractError
from icuhub.kit.testing import RouteTransport, collect_stream, conformance_problems, make_connector

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "github"
BASE = "https://api.github.com"
PAT_REF = "github-pat"
PAT_VALUE = "synthetic-pat"
SECRETS = {PAT_REF: PAT_VALUE.encode()}
REPO_PATH = "/repos/example-org/example-repo"
REPOS_PATH = "/orgs/example-org/repos"
ALERTS_PATH = f"{REPO_PATH}/code-scanning/alerts"
PULL_PATH = f"{REPO_PATH}/pulls/7"
HEAD_SHA = "a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4"
STATUSES_PATH = f"{REPO_PATH}/commits/{HEAD_SHA}/statuses"
STATUS_POST_PATH = f"{REPO_PATH}/statuses/{HEAD_SHA}"


def _load(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _config(**extra: Any) -> dict[str, Any]:
    return {"base_url": BASE, "personal_access_token": {"ref": PAT_REF}, **extra}


def _build(transport: RouteTransport, **config_extra: Any) -> GitHub:
    return cast(GitHub, make_connector(GitHub, _config(**config_extra), transport, SECRETS))


def _status_args() -> CreateCommitStatusArgs:
    return CreateCommitStatusArgs(
        owner="example-org",
        repo="example-repo",
        sha=HEAD_SHA,
        state="success",
        context="icuhub/ci",
        description="Synthetic checks passed",
        target_url="https://ci.example.test/runs/91",
    )


# --- configuration -----------------------------------------------------------


@pytest.mark.parametrize("base_url", ["https://api.github.test", "https://api.github.com/api/v3"])
def test_github_com_config_rejects_other_api_roots(base_url: str) -> None:
    with pytest.raises(ValueError):
        GitHubComConfig.model_validate(_config(base_url=base_url))


@pytest.mark.parametrize("base_url", ["https://api.github.com", "https://api.github.com/"])
def test_github_com_config_accepts_public_api_root(base_url: str) -> None:
    config = GitHubComConfig.model_validate(_config(base_url=base_url))

    assert config.base_url.rstrip("/") == "https://api.github.com"


def test_github_com_edition_conforms() -> None:
    assert conformance_problems(GitHub) == []


# --- repositories stream -----------------------------------------------------


def _paged_repositories(requests: list[httpx2.Request]) -> Any:
    def handler(request: httpx2.Request) -> dict[str, Any]:
        requests.append(request)
        if request.url.params.get("page") == "2":
            return {"status": 200, "json": _load("repositories_page2.json")}
        next_url = f"{BASE}{REPOS_PATH}?type=all&sort=full_name&direction=asc&per_page=100&page=2"
        return {
            "status": 200,
            "json": _load("repositories_page1.json"),
            "headers": {"link": f'<{next_url}>; rel="next"'},
        }

    return handler


def test_repositories_stream_follows_link_header_across_two_pages() -> None:
    requests: list[httpx2.Request] = []
    connector = _build(
        RouteTransport({("GET", REPOS_PATH): _paged_repositories(requests)}),
        organization="example-org",
    )

    batches = collect_stream(connector, "repositories", mode="full")

    names = [record["name"] for batch in batches for record in batch.records]
    assert names == ["example-repo", "example-repo-two"]
    assert batches[-1].complete is True
    assert requests[1].url.params.get("page") == "2"


def test_repositories_stream_tolerates_unknown_fields() -> None:
    requests: list[httpx2.Request] = []
    connector = _build(
        RouteTransport({("GET", REPOS_PATH): _paged_repositories(requests)}),
        organization="example-org",
    )

    batches = collect_stream(connector, "repositories", mode="full")

    records = {record["name"]: record for batch in batches for record in batch.records}
    assert records["example-repo-two"]["synthetic_unknown_field"] == "tolerated"


def test_non_object_repository_record_is_a_typed_contract_violation() -> None:
    connector = _build(
        RouteTransport({("GET", REPOS_PATH): {"status": 200, "json": _load("repository_malformed.json")}}),
        organization="example-org",
    )

    with pytest.raises(VendorContractError, match="non-object record"):
        collect_stream(connector, "repositories", mode="full")


# --- health -------------------------------------------------------------------


def test_forbidden_code_scanning_probe_marks_finding_source_not_evaluated() -> None:
    connector = _build(
        RouteTransport(
            {
                ("GET", "/rate_limit"): {"status": 200, "json": _load("rate_limit.json")},
                ("GET", ALERTS_PATH): {"status": 403, "json": _load("probe_forbidden.json")},
            }
        ),
        probe_repository="example-org/example-repo",
    )

    report = asyncio.run(connector.check())

    assert report.capabilities["FindingSource"].status == "not_evaluated"


# --- commit status action ------------------------------------------------------


def test_commit_status_apply_posts_once_and_retried_apply_is_no_op() -> None:
    posted: list[bool] = []
    status = _load("commit_status_success.json")

    def list_statuses(_request: httpx2.Request) -> dict[str, Any]:
        return {"status": 200, "json": [status] if posted else []}

    def create_status(_request: httpx2.Request) -> dict[str, Any]:
        posted.append(True)
        return {"status": 201, "json": status}

    transport = RouteTransport({("GET", STATUSES_PATH): list_statuses, ("POST", STATUS_POST_PATH): create_status})
    connector = _build(transport, write_enabled=True)
    spec = GitHub.actions()["create_commit_status"]

    plan = asyncio.run(spec.plan(connector, _status_args()))
    first = asyncio.run(spec.apply(connector, plan))
    second = asyncio.run(spec.apply(connector, plan))

    assert first.status == "succeeded"
    assert second.status == "no_op"
    assert [request.method for request in transport.requests].count("POST") == 1


def test_commit_status_apply_is_refused_before_any_write_when_writes_disabled() -> None:
    transport = RouteTransport({("GET", STATUSES_PATH): {"status": 200, "json": []}})
    connector = _build(transport)
    spec = GitHub.actions()["create_commit_status"]

    plan = asyncio.run(spec.plan(connector, _status_args()))
    with pytest.raises(ConfigError):
        asyncio.run(spec.apply(connector, plan))

    assert {request.method for request in transport.requests} == {"GET"}


def test_check_run_plan_is_refused_with_personal_access_token_before_any_request() -> None:
    transport = RouteTransport({})
    connector = _build(transport)
    args = CheckRunArgs(
        owner="example-org",
        repo="example-repo",
        sha=HEAD_SHA,
        name="icuhub",
        action_key="icuhub:check-1",
        analysis_id=5,
        status="completed",
        conclusion="success",
        title="Scan",
        summary="Done",
    )

    with pytest.raises(ConfigError):
        asyncio.run(GitHub.actions()["create_or_update_check_run"].plan(connector, args))

    assert transport.requests == []


# --- destructive gate ----------------------------------------------------------


def test_merge_apply_is_refused_before_any_write_without_destructive_enabled() -> None:
    transport = RouteTransport({("GET", PULL_PATH): {"status": 200, "json": _load("pull_request_open.json")}})
    connector = _build(transport, write_enabled=True)
    spec = GitHub.actions()["merge_pull_request"]
    args = MergePullRequestArgs(owner="example-org", repo="example-repo", pull_number=7)

    plan = asyncio.run(spec.plan(connector, args))
    assert plan.changed is True
    with pytest.raises(ConfigError):
        asyncio.run(spec.apply(connector, plan))

    assert {request.method for request in transport.requests} == {"GET"}


# --- secret redaction ----------------------------------------------------------


def test_health_reports_and_errors_never_carry_the_personal_access_token() -> None:
    healthy = _build(RouteTransport({("GET", "/rate_limit"): {"status": 200, "json": _load("rate_limit.json")}}))
    report = asyncio.run(healthy.check())
    assert PAT_VALUE not in json.dumps(report.model_dump(mode="json"))

    rejected = _build(
        RouteTransport(
            {
                ("GET", "/rate_limit"): {"status": 401, "json": {"message": "Bad credentials"}},
                ("GET", REPOS_PATH): {"status": 401, "json": {"message": "Bad credentials"}},
            }
        ),
        organization="example-org",
    )
    report = asyncio.run(rejected.check())
    assert report.status == "failing"
    assert PAT_VALUE not in json.dumps(report.model_dump(mode="json"))

    with pytest.raises(AuthFailed) as excinfo:
        collect_stream(rejected, "repositories", mode="full")
    assert PAT_VALUE not in str(excinfo.value)
