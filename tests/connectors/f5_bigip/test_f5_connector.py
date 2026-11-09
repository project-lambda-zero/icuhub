"""Offline F5 iControl tests: token login, inventory, block/unblock lifecycle."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from icuhub.connectors.f5_bigip import F5BigIp
from icuhub.connectors.f5_bigip.models import BlockArgs, InventoryQuery, UnblockArgs
from icuhub.kit.testing import RouteTransport, make_connector

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "f5_bigip"
DG_PATH = "/mgmt/tm/ltm/data-group/internal/~Common~icuhub_blocked"


def _fixture(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text())


def _connector() -> tuple[F5BigIp, dict[str, Any], list[Any]]:
    state: dict[str, Any] = {"group": _fixture("data_group.json"), "requests": []}

    def login(request: Any) -> dict[str, Any]:
        return {"status": 200, "json": {"token": {"token": "f5-token", "timeout": 1200}}}

    def group_get(request: Any) -> dict[str, Any]:
        return {"status": 200, "json": state["group"]}

    def group_patch(request: Any) -> dict[str, Any]:
        body = json.loads(request.content)
        state["group"] = {
            **state["group"],
            "generation": state["group"]["generation"] + 1,
            "records": body["records"],
        }
        return {"status": 200, "json": state["group"]}

    routes = {
        ("POST", "/mgmt/shared/authn/login"): login,
        ("GET", DG_PATH): group_get,
        ("PATCH", DG_PATH): group_patch,
        ("GET", "/mgmt/tm/ltm/virtual"): {"status": 200, "json": _fixture("virtual_servers.json")},
        ("GET", "/mgmt/tm/sys/version"): {"status": 200, "json": _fixture("sys_version.json")},
    }
    connector = make_connector(
        F5BigIp,
        {"base_url": "https://f5.example.test", "username": {"ref": "u"}, "password": {"ref": "p"}},
        RouteTransport(routes),
        {"u": b"admin", "p": b"secret"},
    )
    return connector, state, state["requests"]  # type: ignore[return-value]


def test_inventory_and_health() -> None:
    connector, _, _ = _connector()
    result = asyncio.run(connector.list_virtual_servers(InventoryQuery()))
    assert result.total == 2
    assert result.items[0]["name"] == "vs_web"
    report = asyncio.run(connector.check())
    assert report.status == "healthy"
    assert report.vendor_version == "17.1.1"


def test_block_apply_and_duplicate_plan() -> None:
    connector, state, _ = _connector()
    plan = asyncio.run(connector.plan_block(BlockArgs(indicator="192.0.2.99", ttl_s=3600, reason="c2")))
    assert plan.changed is True
    assert plan.preconditions["generation"] == 12
    outcome = asyncio.run(connector.apply_block(plan))
    assert outcome.status == "succeeded"
    assert outcome.result["generation"] == 13
    assert state["group"]["records"][0]["name"] == "192.0.2.99"
    duplicate = asyncio.run(connector.plan_block(BlockArgs(indicator="192.0.2.99", ttl_s=3600, reason="c2")))
    assert duplicate.changed is False
    read = asyncio.run(connector.get_block(UnblockArgs(block_id="192.0.2.99")))
    assert read.present is True
    reconciled = asyncio.run(connector.reconcile_block(plan))
    assert reconciled.status == "succeeded"


def test_unblock_lifecycle() -> None:
    connector, state, _ = _connector()
    plan = asyncio.run(connector.plan_block(BlockArgs(indicator="192.0.2.99", ttl_s=60, reason="x")))
    asyncio.run(connector.apply_block(plan))
    unblock = asyncio.run(connector.plan_unblock(UnblockArgs(block_id="192.0.2.99")))
    assert unblock.changed is True
    outcome = asyncio.run(connector.apply_unblock(unblock))
    assert outcome.status == "succeeded"
    assert state["group"]["records"] == []
    missing = asyncio.run(connector.plan_unblock(UnblockArgs(block_id="192.0.2.99")))
    assert missing.changed is False
    reconciled = asyncio.run(connector.reconcile_unblock(unblock))
    assert reconciled.status == "succeeded"


def test_denied_data_group_scope_is_not_evaluated() -> None:
    _connector()
    routes = {
        ("POST", "/mgmt/shared/authn/login"): {"status": 200, "json": {"token": {"token": "t", "timeout": 10}}},
        ("GET", DG_PATH): {"status": 403, "json": {"code": 403, "message": "denied"}},
        ("GET", "/mgmt/tm/sys/version"): {"status": 200, "json": _fixture("sys_version.json")},
    }
    denied = make_connector(
        F5BigIp,
        {"base_url": "https://f5.example.test", "username": {"ref": "u"}, "password": {"ref": "p"}},
        RouteTransport(routes),
        {"u": b"a", "p": b"b"},
    )
    report = asyncio.run(denied.check())
    assert report.capabilities["Enforcer"].status == "not_evaluated"
    assert report.capabilities["TelemetrySource"].status == "healthy"
