"""DB-backed REST tests: real Postgres, real auth rows, recorded vendor transport."""

from __future__ import annotations

import asyncio
import json
import uuid
from types import SimpleNamespace
from typing import Any

import pytest

from icuhub.api.app import create_app
from icuhub.api.auth import api_key_hash
from icuhub.api.mcp import _list_tools
from icuhub.connectors import CONNECTORS
from icuhub.core.sync import run_import_job
from icuhub.storage.db import session_scope
from icuhub.storage.models import ServiceAccount, Tenant
from icuhub.workers.main import run_once
from tests.core.helpers import REGISTRY, finding, make_services, vendor_transport

ADMIN_TOKEN = "icuhub_abcdefghi_adminsecret"
APPROVER_TOKEN = "icuhub_jklmnopqr_approversecret"


def _json(data: Any) -> tuple[dict[str, str], bytes]:
    return {"content-type": "application/json"}, json.dumps(data).encode()


def _auth(token: str, **headers: str) -> dict[str, str]:
    return {"authorization": f"Bearer {token}", **headers}


def _account(tenant_id: uuid.UUID, name: str, token: str, roles: list[str]) -> ServiceAccount:
    return ServiceAccount(
        tenant_id=tenant_id,
        name=name,
        key_prefix=token[:16],
        key_hash=api_key_hash(token),
        roles=roles,
        groups=["secops"],
    )


@pytest.fixture
def api_env(tmp_path: Any, clean_database: None, monkeypatch: Any) -> Any:
    state: dict[str, Any] = {"issues": [], "findings": [finding("api-1")]}
    services = make_services(vendor_transport(state), tmp_path / "kek")
    for kind, cls in REGISTRY.items():
        monkeypatch.setitem(CONNECTORS, kind, cls)
    tenant_id = uuid.uuid4()

    async def seed() -> None:
        async with session_scope(tenant_id) as session:
            session.add(Tenant(id=tenant_id, slug=f"t-{tenant_id.hex[:8]}", display_name="T"))
            await session.flush()
            session.add(_account(tenant_id, "admin", ADMIN_TOKEN, ["admin"]))
            session.add(_account(tenant_id, "approver", APPROVER_TOKEN, ["approver"]))

    asyncio.run(seed())
    return {"services": services, "tenant_id": tenant_id, "state": state, "app": create_app()}


def _connection_body(kind: str, slug: str) -> dict[str, Any]:
    return {
        "kind": kind,
        "slug": slug,
        "display_name": "Sample",
        "config": {"base_url": "http://127.0.0.1:9", "allow_plain_http_loopback": True},
        "secrets": {"api_token": "test-token"},
    }


def test_connection_action_approval_and_audit(asgi: Any, api_env: Any) -> None:
    call = asgi(api_env["app"])
    headers, payload = _json(_connection_body("sample_tracker_core", "tracker-api"))
    status, _, body = call("POST", "/v1/connections", _auth(ADMIN_TOKEN, **headers), payload)
    assert status == 201, body
    connection = json.loads(body)
    status, _, body = call("GET", "/v1/connections", _auth(ADMIN_TOKEN))
    assert status == 200 and len(json.loads(body)) == 1
    status, _, body = call("GET", "/v1/connectors", _auth(ADMIN_TOKEN))
    assert status == 200
    assert any(row["kind"] == "sample_tracker_core" for row in json.loads(body))
    status, _, body = call("GET", f"/v1/connections/{connection['id']}/operations", _auth(ADMIN_TOKEN))
    assert status == 200
    names = {row["name"] for row in json.loads(body)}
    assert "create_issue" in names and "ping" in names
    headers, payload = _json({"args": {"summary": "from api", "icuhub_route_key": "api-rk"}})
    status, _, body = call(
        "POST",
        f"/v1/connections/{connection['id']}/operations/create_issue",
        _auth(ADMIN_TOKEN, **headers, **{"x-correlation-id": "corr-1", "idempotency-key": "api-key-1"}),
        payload,
    )
    assert status == 200, body
    action = json.loads(body)
    assert action["state"] == "pending_approval"
    status, _, body = call("GET", f"/v1/actions/{action['action_id']}", _auth(ADMIN_TOKEN))
    assert status == 200 and json.loads(body)["state"] == "pending_approval"
    status, _, body = call("GET", "/v1/approvals", _auth(APPROVER_TOKEN))
    approvals = json.loads(body)
    assert len(approvals) == 1
    approval_id = approvals[0]["id"]
    headers, payload = _json({"reason": "looks right"})
    status, _, body = call("POST", f"/v1/approvals/{approval_id}/approve", _auth(APPROVER_TOKEN, **headers), payload)
    assert status == 200, body
    assert json.loads(body)["state"] == "approved"
    assert asyncio.run(run_once(queues=("actions",), max_jobs=5)) == 1
    status, _, body = call("GET", f"/v1/actions/{action['action_id']}", _auth(ADMIN_TOKEN))
    assert json.loads(body)["state"] == "succeeded"
    assert api_env["state"]["issues"][0]["summary"] == "from api"
    status, _, body = call("GET", "/v1/audit/verify", _auth(ADMIN_TOKEN))
    assert status == 200 and json.loads(body)["ok"] is True


def test_sync_report_routes_policy_and_webhook_endpoints(asgi: Any, api_env: Any) -> None:
    call = asgi(api_env["app"])
    headers, payload = _json(_connection_body("sample_scanner", "scanner-api"))
    status, _, body = call("POST", "/v1/connections", _auth(ADMIN_TOKEN, **headers), payload)
    scanner = json.loads(body)
    headers, payload = _json({"stream": "findings", "mode": "incremental"})
    status, _, body = call(
        "POST", f"/v1/connections/{scanner['id']}/sync", _auth(ADMIN_TOKEN, **headers), payload
    )
    assert status == 202, body
    assert asyncio.run(run_once(queues=("sync",), max_jobs=5)) == 1
    status, _, body = call("GET", "/v1/findings", _auth(ADMIN_TOKEN))
    assert status == 200 and len(json.loads(body)) == 1
    report = json.dumps({"items": [finding("api-imp")]}).encode()
    path = f"/v1/connections/{scanner['id']}/reports?importer=sample_report&filename=r.json"
    status, _, body = call("POST", path, _auth(ADMIN_TOKEN), report)
    assert status == 202, body
    first = json.loads(body)
    status, _, body = call("POST", path, _auth(ADMIN_TOKEN), report)
    assert json.loads(body)["import_id"] == first["import_id"]
    parsed = asyncio.run(run_import_job({"file_import_id": first["import_id"], "tenant_id": str(api_env["tenant_id"])}))
    assert parsed["state"] == "done"
    headers, payload = _json(_connection_body("sample_tracker_core", "tracker-two"))
    status, _, body = call("POST", "/v1/connections", _auth(ADMIN_TOKEN, **headers), payload)
    tracker = json.loads(body)
    headers, payload = _json(
        {"name": "route-api", "connection_id": tracker["id"], "action": "create_issue", "match": {"min_severity_id": 3}}
    )
    status, _, body = call("POST", "/v1/routes", _auth(ADMIN_TOKEN, **headers), payload)
    assert status == 201, body
    route = json.loads(body)
    headers, payload = _json({"enabled": False})
    status, _, body = call("PATCH", f"/v1/routes/{route['id']}", _auth(ADMIN_TOKEN, **headers), payload)
    assert status == 200 and json.loads(body)["enabled"] is False
    status, _, body = call("GET", "/v1/routes", _auth(ADMIN_TOKEN))
    assert len(json.loads(body)) == 1
    status, _, body = call("POST", f"/v1/connections/{tracker['id']}/webhooks", _auth(ADMIN_TOKEN))
    assert status == 201, body
    endpoint = json.loads(body)
    assert endpoint["secret"]
    status, _, body = call("POST", f"/v1/webhooks/{endpoint['endpoint_id']}/rotate", _auth(ADMIN_TOKEN))
    assert status == 200 and json.loads(body)["secret"] != endpoint["secret"]
    headers, payload = _json(
        {"priority": 5, "name": "deny-pings", "match_json": {"operations": ["ping"]}, "decision": "deny"}
    )
    status, _, body = call("POST", "/v1/policy/rules", _auth(ADMIN_TOKEN, **headers), payload)
    assert status == 201, body
    rule = json.loads(body)
    headers, payload = _json({"priority": 7})
    status, _, body = call("PATCH", f"/v1/policy/rules/{rule['id']}", _auth(ADMIN_TOKEN, **headers), payload)
    assert status == 200 and json.loads(body)["updated"] == ["priority"]
    status, _, body = call("GET", f"/v1/connections/{scanner['id']}/operations", _auth(ADMIN_TOKEN))
    assert all(row["name"] != "ping" for row in json.loads(body)), "denied operations are not offered"
    headers, payload = _json({"field": "api_token", "value": "rotated"})
    status, _, body = call(
        "PUT", f"/v1/connections/{scanner['id']}/credential", _auth(ADMIN_TOKEN, **headers), payload
    )
    assert status == 204, body


def test_mcp_lists_real_connector_tools_with_input_schemas(asgi: Any, api_env: Any) -> None:
    call = asgi(api_env["app"])
    headers, payload = _json(_connection_body("sample_tracker_core", "tracker-mcp"))
    status, _, body = call("POST", "/v1/connections", _auth(ADMIN_TOKEN, **headers), payload)
    assert status == 201, body

    ctx = SimpleNamespace(request=SimpleNamespace(headers=_auth(ADMIN_TOKEN)))
    result = asyncio.run(_list_tools(ctx, None))  # type: ignore[arg-type]

    tools = {tool.name: tool for tool in result.tools}
    assert "tracker-mcp.ping" in tools
    ping = tools["tracker-mcp.ping"]
    assert ping.annotations is not None and ping.annotations.read_only_hint is True
    assert ping.input_schema["type"] == "object"
    assert "summary" in ping.input_schema["properties"]
    assert ping.description
