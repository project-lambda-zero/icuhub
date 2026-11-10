"""Offline F5 iControl tests: token login, inventory, block/unblock lifecycle."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from icuhub.connectors.f5_bigip import F5BigIp
from icuhub.connectors.f5_bigip.models import BlockArgs, CreateIruleArgs, InventoryQuery, UnblockArgs
from icuhub.kit.errors import Conflict, PermissionDenied
from icuhub.kit.testing import RouteTransport, make_connector

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "f5_bigip"
DG_PATH = "/mgmt/tm/ltm/data-group/internal/~Common~icuhub_blocked"
IRULE_COLLECTION = "/mgmt/tm/ltm/rule"
IRULE_PATH = "/mgmt/tm/ltm/rule/~Common~icuhub_probe"
IRULE_DEFINITION = "when HTTP_REQUEST { HTTP::respond 200 }"


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
    reconciled = asyncio.run(connector.reconcile_block(plan, outcome))
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
    reconciled = asyncio.run(connector.reconcile_unblock(unblock, outcome))
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


def _irule_connector(
    *,
    write_enabled: bool = True,
    rule: dict[str, Any] | None = None,
    post_status: int = 200,
    store_on_post: bool = True,
) -> tuple[F5BigIp, dict[str, Any]]:
    state: dict[str, Any] = {"rule": rule, "posts": []}

    def login(request: Any) -> dict[str, Any]:
        return {"status": 200, "json": {"token": {"token": "f5-token", "timeout": 1200}}}

    def rule_get(request: Any) -> dict[str, Any]:
        if state["rule"] is None:
            return {"status": 404, "json": {"code": 404, "message": "not found"}}
        return {"status": 200, "json": state["rule"]}

    def rule_post(request: Any) -> dict[str, Any]:
        body = json.loads(request.content)
        state["posts"].append(body)
        if store_on_post and 200 <= post_status < 300:
            state["rule"] = {**body, "generation": 1}
        return {"status": post_status, "json": body}

    routes = {
        ("POST", "/mgmt/shared/authn/login"): login,
        ("GET", IRULE_PATH): rule_get,
        ("POST", IRULE_COLLECTION): rule_post,
    }
    connector = make_connector(
        F5BigIp,
        {
            "base_url": "https://f5.example.test",
            "username": {"ref": "u"},
            "password": {"ref": "p"},
            "write_enabled": write_enabled,
        },
        RouteTransport(routes),
        {"u": b"admin", "p": b"secret"},
    )
    return connector, state  # type: ignore[return-value]


def _create_args() -> CreateIruleArgs:
    return CreateIruleArgs(name="icuhub_probe", definition=IRULE_DEFINITION)


def test_create_irule_plan_apply_reconcile() -> None:
    connector, state = _irule_connector()
    plan = asyncio.run(connector.plan_create_irule(_create_args()))
    assert plan.changed is True
    assert plan.preconditions == {"exists": False}
    assert plan.request == {
        "kind": "tm:ltm:rule:rulestate",
        "name": "icuhub_probe",
        "fullPath": "/Common/icuhub_probe",
        "apiAnonymous": IRULE_DEFINITION,
    }
    outcome = asyncio.run(connector.apply_create_irule(plan))
    assert outcome.status == "succeeded"
    assert outcome.vendor_ref == "/Common/icuhub_probe"
    assert len(state["posts"]) == 1
    reconciled = asyncio.run(connector.reconcile_create_irule(plan, outcome))
    assert reconciled.status == "succeeded"
    assert len(state["posts"]) == 1


def test_create_irule_identical_existing_is_noop() -> None:
    existing = {
        "name": "icuhub_probe",
        "partition": "Common",
        "fullPath": "/Common/icuhub_probe",
        "apiAnonymous": IRULE_DEFINITION,
    }
    connector, state = _irule_connector(rule=existing)
    plan = asyncio.run(connector.plan_create_irule(_create_args()))
    assert plan.changed is False
    assert plan.preconditions == {"exists": True}
    assert state["posts"] == []


def test_create_irule_conflicting_existing_is_rejected() -> None:
    existing = {
        "name": "icuhub_probe",
        "partition": "Common",
        "fullPath": "/Common/icuhub_probe",
        "apiAnonymous": "when HTTP_REQUEST { HTTP::respond 403 }",
    }
    connector, state = _irule_connector(rule=existing)
    try:
        asyncio.run(connector.plan_create_irule(_create_args()))
    except Conflict:
        pass
    else:
        raise AssertionError("expected Conflict for a different existing definition")
    assert state["posts"] == []


def test_create_irule_write_disabled_is_refused_before_post() -> None:
    connector, state = _irule_connector(write_enabled=False)
    plan = asyncio.run(connector.plan_create_irule(_create_args()))
    try:
        asyncio.run(connector.apply_create_irule(plan))
    except PermissionDenied:
        pass
    else:
        raise AssertionError("expected PermissionDenied while write_enabled is false")
    assert state["posts"] == []


def test_create_irule_vendor_rejection_is_failed() -> None:
    connector, state = _irule_connector(post_status=409)
    plan = asyncio.run(connector.plan_create_irule(_create_args()))
    outcome = asyncio.run(connector.apply_create_irule(plan))
    assert outcome.status == "failed"
    assert state["rule"] is None


def test_create_irule_unreadable_after_post_is_ambiguous() -> None:
    connector, state = _irule_connector(store_on_post=False)
    plan = asyncio.run(connector.plan_create_irule(_create_args()))
    outcome = asyncio.run(connector.apply_create_irule(plan))
    assert outcome.status == "outcome_unknown"
    assert len(state["posts"]) == 1
    reconciled = asyncio.run(connector.reconcile_create_irule(plan, outcome))
    assert reconciled.status == "failed"
    assert len(state["posts"]) == 1
