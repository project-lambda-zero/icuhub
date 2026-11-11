"""Behavior tests for the GitLab stream declarations: pagination, cursors, gating, and secret handling."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar, cast

import pytest

from icuhub.connectors._gitlab.connector import GitLabConnectorBase
from icuhub.connectors._gitlab.models import GitLabConfig
from icuhub.kit import ConnectorConfig
from icuhub.kit.cursors import TimeIdCursor
from icuhub.kit.errors import ConfigError, NotFound, PermissionDenied, VendorContractError
from icuhub.kit.testing import RouteTransport, collect_stream, make_connector, map_all
from icuhub.kit.types import SourceRecord, Target
from icuhub_schemas.ocsf import ApiActivity, VulnerabilityFinding, validate_ocsf

PROJECT_ID = 42
API = "/api/v4"
# Host-root GraphQL endpoint, built by graphql_url() in graphql.py (not under the REST /api/v4 prefix).
GRAPHQL_PATH = "/api/graphql"
TOKEN_REF = "gitlab-token"
SECRETS = {TOKEN_REF: b"glpat-synthetic"}
FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "gitlab"


class _StreamGitLab(GitLabConnectorBase):
    """Concrete test connector: the shared GitLab base plus the class attributes an edition package supplies."""

    kind: ClassVar[str] = "gitlab"
    display_name: ClassVar[str] = "GitLab (stream test)"
    config_model: ClassVar[type[ConnectorConfig]] = GitLabConfig
    flows: ClassVar[tuple[str, ...]] = ()


def _connector(routes: dict[tuple[str, str], Any], **config_extra: Any) -> _StreamGitLab:
    config: dict[str, Any] = {"access_token": {"ref": TOKEN_REF}, **config_extra}
    return cast(_StreamGitLab, make_connector(_StreamGitLab, config, RouteTransport(routes), SECRETS))


def _project_target() -> Target:
    return Target(
        id=str(PROJECT_ID),
        source_uid=f"gitlab:project:{PROJECT_ID}",
        kind="project",
        display_name="demo",
        attributes={},
    )


def _group_target(group_id: int = 7) -> Target:
    return Target(
        id=str(group_id),
        source_uid=f"gitlab:group:{group_id}",
        kind="group",
        display_name="demo-group",
        attributes={},
    )


def _finding(native_id: int, identifiers: list[dict[str, str]]) -> dict[str, Any]:
    """A record in the shape ``normalize_vulnerability`` emits."""
    return {
        "id": native_id,
        "gid": f"gid://gitlab/Vulnerability/{native_id}",
        "uuid": f"uuid-{native_id}",
        "state": "confirmed",
        "report_type": "sast",
        "severity": "high",
        "updated_at": "2026-11-09T10:00:00Z",
        "identifiers": identifiers,
        "location": {"file": "src/parser/read.c", "start_line": 14, "end_line": 16},
    }


def _records(batches: list[Any]) -> list[dict[str, Any]]:
    return [record for batch in batches for record in batch.records]


def _fixture(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _project_route() -> tuple[tuple[str, str], dict[str, Any]]:
    return ("GET", f"{API}/projects/{PROJECT_ID}"), {"status": 200, "json": _fixture("project_42.json")}


def _graphql_pages(variables_log: list[dict[str, Any]]) -> Any:
    """Serve the two fixture pages keyed by the ``after`` cursor the traversal sends."""
    pages = {
        None: _fixture("graphql_vulnerabilities_page1.json"),
        "cursor-page-2": _fixture("graphql_vulnerabilities_page2.json"),
    }

    def respond(request: Any) -> dict[str, Any]:
        variables = json.loads(request.content)["variables"]
        variables_log.append(variables)
        return {"status": 200, "json": pages[variables["after"]]}

    return respond


def test_vulnerabilities_traverses_every_graphql_page_and_completes() -> None:
    variables: list[dict[str, Any]] = []
    project_path, project_response = _project_route()
    connector = _connector({project_path: project_response, ("POST", GRAPHQL_PATH): _graphql_pages(variables)})

    batches = collect_stream(connector, "vulnerabilities", _project_target(), mode="full")

    assert batches[-1].complete is True
    assert [record["id"] for record in _records(batches)] == [7001, 7002]
    assert [sent["after"] for sent in variables] == [None, "cursor-page-2"]
    assert all(sent["fullPath"] == "example-group/demo-service" for sent in variables)
    mapped = map_all(connector, "vulnerabilities", _records(batches), _project_target())
    assert len(mapped) == 2
    assert all(isinstance(item, VulnerabilityFinding) for item in mapped)


def test_vulnerabilities_exhausted_page_budget_never_claims_complete() -> None:
    variables: list[dict[str, Any]] = []
    project_path, project_response = _project_route()
    connector = _connector(
        {project_path: project_response, ("POST", GRAPHQL_PATH): _graphql_pages(variables)}, max_pages=1
    )

    batches = collect_stream(connector, "vulnerabilities", _project_target(), mode="full")

    assert [sent["after"] for sent in variables] == [None]
    assert [record["id"] for record in _records(batches)] == [7001]
    assert all(batch.complete is False for batch in batches)


def test_vulnerabilities_graphql_errors_raise_vendor_contract_error() -> None:
    project_path, project_response = _project_route()
    graphql_error = {"status": 200, "json": _fixture("graphql_error.json")}
    connector = _connector({project_path: project_response, ("POST", GRAPHQL_PATH): graphql_error})

    with pytest.raises(VendorContractError):
        collect_stream(connector, "vulnerabilities", _project_target(), mode="full")


def test_vulnerabilities_null_project_raises_not_found() -> None:
    project_path, project_response = _project_route()
    null_project = {"status": 200, "json": _fixture("graphql_null_project.json")}
    connector = _connector({project_path: project_response, ("POST", GRAPHQL_PATH): null_project})

    with pytest.raises(NotFound):
        collect_stream(connector, "vulnerabilities", _project_target(), mode="full")


def test_merge_requests_incremental_sends_window_and_suppresses_duplicates() -> None:
    cursor = TimeIdCursor(
        ts=datetime(2026, 11, 9, 10, 0, tzinfo=UTC),
        last_ids_at_ts=[f"{PROJECT_ID}:7"],
    )
    window_params: list[str | None] = []

    def merge_requests(request: Any) -> dict[str, Any]:
        window_params.append(request.url.params.get("updated_after"))
        merge_request_rows = [
            {"id": 1007, "iid": 7, "state": "opened", "updated_at": "2026-11-09T10:00:00Z"},
            {"id": 1008, "iid": 8, "state": "opened", "updated_at": "2026-11-09T10:03:00Z"},
            {"id": 1008, "iid": 8, "state": "merged", "updated_at": "2026-11-09T10:05:00Z"},
        ]
        return {"status": 200, "json": merge_request_rows}

    connector = _connector({("GET", f"{API}/projects/{PROJECT_ID}/merge_requests"): merge_requests})

    batches = collect_stream(connector, "merge_requests", _project_target(), cursor, mode="incremental")

    assert window_params and window_params[0] is not None
    emitted = _records(batches)
    assert [(record["iid"], record["state"]) for record in emitted] == [(8, "merged")]
    final = batches[-1]
    assert final.complete is True
    assert isinstance(final.checkpoint, TimeIdCursor)
    assert final.checkpoint.ts == datetime(2026, 11, 9, 10, 5, tzinfo=UTC)
    assert f"{PROJECT_ID}:8" in final.checkpoint.last_ids_at_ts


def test_audit_events_map_to_api_activity_that_validates() -> None:
    events = [
        {
            "id": 501,
            "event_name": "project_updated",
            "author_id": 5,
            "ip_address": "203.0.113.9",
            "created_at": "2026-11-09T10:00:00Z",
            "details": {"author_name": "alice"},
        }
    ]
    connector = _connector({("GET", f"{API}/projects/{PROJECT_ID}/audit_events"): {"status": 200, "json": events}})

    batches = collect_stream(connector, "audit_events", _project_target(), mode="full")
    mapped = map_all(connector, "audit_events", _records(batches), _project_target())

    assert len(mapped) == 1
    assert isinstance(mapped[0], ApiActivity)
    validate_ocsf(mapped[0].model_dump(mode="json", exclude_none=True))


def test_group_audit_events_map_to_api_activity_that_validates() -> None:
    events = [
        {
            "id": 601,
            "event_name": "group_updated",
            "author_id": 5,
            "ip_address": "203.0.113.9",
            "created_at": "2026-11-09T10:00:00Z",
            "details": {"author_name": "alice"},
        }
    ]
    connector = _connector({("GET", f"{API}/groups/7/audit_events"): {"status": 200, "json": events}})

    batches = collect_stream(connector, "group_audit_events", _group_target(), mode="full")
    mapped = map_all(connector, "group_audit_events", _records(batches), _group_target())

    assert len(mapped) == 1
    assert isinstance(mapped[0], ApiActivity)
    validate_ocsf(mapped[0].model_dump(mode="json", exclude_none=True))


def test_pipeline_variables_never_carry_values() -> None:
    pipelines = [{"id": 9001, "updated_at": "2026-11-09T10:00:00Z"}]
    variables = [{"key": "DEPLOY_TOKEN", "value": "s3cr3t-value", "variable_type": "env_var"}]
    connector = _connector(
        {
            ("GET", f"{API}/projects/{PROJECT_ID}/pipelines"): {"status": 200, "json": pipelines},
            ("GET", f"{API}/projects/{PROJECT_ID}/pipelines/9001/variables"): {"status": 200, "json": variables},
        }
    )

    batches = collect_stream(connector, "pipeline_variables", _project_target(), mode="full")

    emitted = _records(batches)
    assert [record["key"] for record in emitted] == ["DEPLOY_TOKEN"]
    assert all("value" not in record for record in emitted)
    assert "s3cr3t-value" not in json.dumps(emitted, default=str)


def test_mr_approval_state_permission_denied_propagates() -> None:
    merge_requests = [{"id": 1007, "iid": 7, "state": "opened", "updated_at": "2026-11-09T10:00:00Z"}]
    connector = _connector(
        {
            ("GET", f"{API}/projects/{PROJECT_ID}/merge_requests"): {"status": 200, "json": merge_requests},
            ("GET", f"{API}/projects/{PROJECT_ID}/merge_requests/7/approval_state"): {
                "status": 403,
                "json": {"message": "403 Forbidden"},
            },
        }
    )

    with pytest.raises(PermissionDenied):
        collect_stream(connector, "mr_approval_state", _project_target(), mode="full")


def test_non_numeric_project_target_raises_config_error_before_any_request() -> None:
    connector = _connector({})
    target = Target(id="group/project", source_uid="gitlab:project:group/project", kind="project", display_name="x", attributes={})

    with pytest.raises(ConfigError):
        collect_stream(connector, "merge_requests", target, mode="incremental")


def test_finding_without_identifiers_maps_to_source_record_not_dropped() -> None:
    connector = _connector({})
    raw = {**_finding(7002, []), "_project_id": PROJECT_ID}

    mapped = map_all(connector, "vulnerabilities", [raw], _project_target())

    assert len(mapped) == 1
    assert isinstance(mapped[0], SourceRecord)
    assert mapped[0].uid == f"gitlab:project:{PROJECT_ID}:vulnerability:7002"
