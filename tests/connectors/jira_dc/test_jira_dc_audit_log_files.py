"""Offline tests for the ``audit_log_files`` stream: collector transport, resume, recovery, caps, and mapping.

The collector client is built by ``open_audit_collector``, which calls ``build_http`` without a transport.
Each test routes that client through the same ``RouteTransport`` the Jira client uses, so requests are
answered offline and their headers can be inspected.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any, cast

import httpx2
import pytest

from icuhub.connectors.jira_dc import audit_collector
from icuhub.connectors.jira_dc import connector as jira_dc_connector
from icuhub.connectors.jira_dc.connector import JiraDataCenter
from icuhub.kit.errors import BudgetExhausted, VendorContractError
from icuhub.kit.testing import RouteTransport, collect_stream, make_connector, map_all
from icuhub.kit.types import RawBatch
from icuhub_schemas.ocsf import ApiActivity

BASE = "https://jira.example.test"
PAT_REF = "jira-pat"
COLLECTOR_TOKEN_REF = "audit-collector-token"
COLLECTOR = "https://collector.example.test"
COLLECTOR_PATH = "/audit/node-a.jsonl"
COLLECTOR_URL = f"{COLLECTOR}{COLLECTOR_PATH}"
COLLECTOR_TOKEN = "synthetic-collector-token"
JIRA_PAT = "synthetic-pat"
SECRETS = {PAT_REF: JIRA_PAT.encode(), COLLECTOR_TOKEN_REF: COLLECTOR_TOKEN.encode()}
NODE = "node-a"
PATH = "/var/atlassian/audit/audit-1.jsonl"

FIRST = {"id": 1, "created": "2026-11-09T10:00:00Z", "summary": "Created group"}
SECOND = {"id": 2, "created": "2026-11-09T10:05:00Z", "summary": "Updated user"}
THIRD = {"id": 3, "created": "2026-11-09T10:06:00Z", "summary": "Deleted user"}
FOURTH = {"id": 4, "created": "2026-11-09T11:00:00Z", "summary": "New file"}


def _line(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"


def _jira_config(**extra: Any) -> dict[str, Any]:
    return {"base_url": BASE, "personal_access_token": {"ref": PAT_REF}, **extra}


def _audit_config(**extra: Any) -> dict[str, Any]:
    return _jira_config(
        audit_files=[{"node": NODE, "path": PATH, "url": COLLECTOR_URL}],
        audit_collector_token={"ref": COLLECTOR_TOKEN_REF},
        **extra,
    )


def _route_collector_through(monkeypatch: pytest.MonkeyPatch, transport: httpx2.AsyncBaseTransport) -> None:
    """Make ``open_audit_collector`` build its client on ``transport`` instead of a live network transport."""
    real_build_http = audit_collector.build_http

    def build_on_transport(config: Any, auth: Any, **kwargs: Any) -> Any:
        return real_build_http(config, auth, transport=transport, **kwargs)

    monkeypatch.setattr(audit_collector, "build_http", build_on_transport)


def _audit_connector(
    monkeypatch: pytest.MonkeyPatch,
    files: dict[str, bytes],
    requests: list[httpx2.Request] | None = None,
    **config_extra: Any,
) -> JiraDataCenter:
    """Build the connector with a collector that serves ``files`` by path; mutate ``files`` between runs."""

    def serve(request: httpx2.Request) -> httpx2.Response:
        if requests is not None:
            requests.append(request)
        body = files.get(request.url.path)
        if body is None:
            return httpx2.Response(404, request=request)
        return httpx2.Response(200, content=body, request=request)

    transport = RouteTransport({("GET", COLLECTOR_PATH): cast(Callable[[httpx2.Request], Any], serve)})
    _route_collector_through(monkeypatch, transport)
    return cast(
        JiraDataCenter,
        make_connector(JiraDataCenter, _audit_config(**config_extra), transport, SECRETS),
    )


def _run(connector: JiraDataCenter, checkpoint: Any = None) -> list[RawBatch]:
    return collect_stream(connector, "audit_log_files", checkpoint=checkpoint, mode="incremental")


def _records(batches: list[RawBatch]) -> list[dict[str, Any]]:
    return [record for batch in batches for record in batch.records]


def test_without_audit_files_yields_one_complete_empty_batch_and_builds_no_collector(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_if_built(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("open_audit_collector must not run without audit_files")

    monkeypatch.setattr(jira_dc_connector, "open_audit_collector", fail_if_built)
    connector = cast(
        JiraDataCenter,
        make_connector(JiraDataCenter, _jira_config(), RouteTransport({}), SECRETS),
    )

    batches = _run(connector)

    assert len(batches) == 1
    assert batches[0].records == []
    assert batches[0].complete is True


def test_first_batch_reads_from_byte_zero_then_a_complete_marker(monkeypatch: pytest.MonkeyPatch) -> None:
    content = _line(FIRST) + _line(SECOND)
    connector = _audit_connector(monkeypatch, {COLLECTOR_PATH: content})

    batches = _run(connector)

    assert [batch.complete for batch in batches] == [False, True]
    records = _records(batches)
    assert [record["id"] for record in records] == [1, 2]
    assert records[0]["_jira_file_offset"] == 0
    assert records[0]["_jira_node"] == NODE
    assert records[0]["_jira_file"] == PATH


def test_append_resume_emits_only_records_after_the_committed_offset(monkeypatch: pytest.MonkeyPatch) -> None:
    files = {COLLECTOR_PATH: _line(FIRST)}
    connector = _audit_connector(monkeypatch, files)
    first_batches = _run(connector)
    checkpoint = first_batches[-1].checkpoint

    files[COLLECTOR_PATH] = _line(FIRST) + _line(SECOND)
    second_batches = _run(connector, checkpoint)

    records = _records(second_batches)
    assert [record["id"] for record in records] == [2]
    assert records[0]["_jira_file_offset"] == len(_line(FIRST))
    assert records[0]["_jira_recovery"] == "none"


def test_same_path_rotation_restarts_from_byte_zero_with_rotation_recovery(monkeypatch: pytest.MonkeyPatch) -> None:
    # The replacement file must be longer than the committed offset, otherwise it reads as truncation.
    files = {COLLECTOR_PATH: _line(FIRST)}
    connector = _audit_connector(monkeypatch, files)
    first_batches = _run(connector)
    checkpoint = first_batches[-1].checkpoint

    files[COLLECTOR_PATH] = _line(THIRD) + _line(FOURTH)
    records = _records(_run(connector, checkpoint))

    assert [record["id"] for record in records] == [3, 4]
    assert all(record["_jira_recovery"] == "rotation" for record in records)
    assert records[0]["_jira_file_offset"] == 0


def test_truncation_restarts_from_byte_zero_with_truncation_recovery(monkeypatch: pytest.MonkeyPatch) -> None:
    files = {COLLECTOR_PATH: _line(FIRST) + _line(SECOND)}
    connector = _audit_connector(monkeypatch, files)
    first_batches = _run(connector)
    checkpoint = first_batches[-1].checkpoint

    files[COLLECTOR_PATH] = _line(THIRD)
    records = _records(_run(connector, checkpoint))

    assert [record["id"] for record in records] == [3]
    assert records[0]["_jira_recovery"] == "truncation"
    assert records[0]["_jira_file_offset"] == 0


def test_incomplete_trailing_line_is_not_emitted_until_it_is_completed(monkeypatch: pytest.MonkeyPatch) -> None:
    complete = _line(FIRST)
    partial = b'{"id":2,"created":"2026-11-09T10:05:00Z",'
    tail = b'"summary":"Updated user"}\n'
    files = {COLLECTOR_PATH: complete + partial}
    connector = _audit_connector(monkeypatch, files)
    first_batches = _run(connector)

    assert [record["id"] for record in _records(first_batches)] == [1]

    files[COLLECTOR_PATH] = complete + partial + tail
    second_batches = _run(connector, first_batches[-1].checkpoint)

    records = _records(second_batches)
    assert [record["id"] for record in records] == [2]
    assert records[0]["summary"] == "Updated user"


def test_collector_request_carries_the_collector_bearer_token_and_never_the_jira_pat(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[httpx2.Request] = []
    connector = _audit_connector(monkeypatch, {COLLECTOR_PATH: _line(FIRST)}, requests=requests)

    _run(connector)

    assert len(requests) == 1
    assert requests[0].headers["authorization"] == f"Bearer {COLLECTOR_TOKEN}"
    assert all(JIRA_PAT not in value for value in requests[0].headers.values())


def test_audit_max_bytes_caps_the_collector_download(monkeypatch: pytest.MonkeyPatch) -> None:
    connector = _audit_connector(monkeypatch, {COLLECTOR_PATH: _line(FIRST)}, audit_max_bytes=16)

    with pytest.raises(BudgetExhausted, match="byte cap"):
        _run(connector)


def test_invalid_json_in_the_collected_file_surfaces_as_a_vendor_contract_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connector = _audit_connector(monkeypatch, {COLLECTOR_PATH: _line(FIRST) + b"not json\n"})

    with pytest.raises(VendorContractError, match="not valid JSON"):
        _run(connector)


def test_float_record_id_is_scoped_by_node_and_stringified_by_the_mapper(monkeypatch: pytest.MonkeyPatch) -> None:
    float_id = {"id": 40001.0, "created": "2026-11-09T10:00:00Z", "summary": "Created group"}
    connector = _audit_connector(monkeypatch, {COLLECTOR_PATH: _line(float_id)})

    records = _records(_run(connector))
    (activity,) = map_all(connector, "audit_log_files", records)

    resources = cast(ApiActivity, activity).resources or []
    assert len(resources) == 1
    assert (resources[0].uid or "").endswith(f"{NODE}/40001.0")
