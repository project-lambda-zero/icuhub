"""Live F5 acceptance: inventory, scopes, and opt-in block/unblock on a sandbox data-group."""

from __future__ import annotations

import asyncio

import httpx2

from icuhub.connectors.f5_bigip import F5BigIp
from icuhub.connectors.f5_bigip.models import BlockArgs, CreateIruleArgs, InventoryQuery, UnblockArgs
from icuhub.kit.testing import make_connector

ACCEPTANCE_KIND = "f5_bigip"


def _connector(acceptance) -> F5BigIp:
    return make_connector(F5BigIp, acceptance.config, httpx2.AsyncHTTPTransport(), acceptance.secrets)  # type: ignore[return-value]


def test_health_and_inventory(acceptance) -> None:
    connector = _connector(acceptance)
    report = asyncio.run(connector.check())
    acceptance.record("health", report.status == "healthy", report.status, version=report.vendor_version)
    assert report.status == "healthy"
    result = asyncio.run(connector.list_virtual_servers(InventoryQuery()))
    acceptance.record("list_virtual_servers", result.total >= 0, f"{result.total} virtual servers")


def test_get_block(acceptance) -> None:
    block_id = acceptance.params.get("block_id")
    if not block_id:
        acceptance.record("get_block", True, "no block_id parameter; skipped")
        return
    result = asyncio.run(_connector(acceptance).get_block(UnblockArgs(block_id=block_id)))
    acceptance.record("get_block", result.present, result.block_id)
    assert result.present


def test_block_unblock(acceptance) -> None:
    acceptance.require_writes()
    connector = _connector(acceptance)
    indicator = acceptance.params["indicator"]
    reason = acceptance.params.get("reason", "icuhub acceptance")
    plan = asyncio.run(connector.plan_block(BlockArgs(indicator=indicator, ttl_s=900, reason=reason)))
    outcome = asyncio.run(connector.apply_block(plan))
    acceptance.record("block", outcome.status == "succeeded", outcome.status)
    assert outcome.status == "succeeded"
    duplicate = asyncio.run(connector.plan_block(BlockArgs(indicator=indicator, ttl_s=900, reason=reason)))
    acceptance.record("block_idempotent", duplicate.changed is False, "repeat plan is a no-op")
    assert duplicate.changed is False
    unblock = asyncio.run(connector.plan_unblock(UnblockArgs(block_id=indicator)))
    removed = asyncio.run(connector.apply_unblock(unblock))
    acceptance.record("unblock", removed.status == "succeeded", removed.status)
    assert removed.status == "succeeded"
    read_back = asyncio.run(connector.get_block(UnblockArgs(block_id=indicator)))
    assert not read_back.present


def test_create_irule(acceptance) -> None:
    name = acceptance.params.get("irule_name")
    definition = acceptance.params.get("irule_definition")
    if not name or not definition:
        acceptance.record("create_irule", True, "no irule_name/irule_definition parameters; skipped")
        return
    acceptance.require_writes()
    connector = _connector(acceptance)
    args = CreateIruleArgs(name=name, definition=definition)
    plan = asyncio.run(connector.plan_create_irule(args))
    outcome = asyncio.run(connector.apply_create_irule(plan))
    acceptance.record(
        "create_irule", outcome.status == "succeeded", outcome.status, full_path=plan.request.get("fullPath")
    )
    assert outcome.status == "succeeded"
    repeat = asyncio.run(connector.plan_create_irule(args))
    acceptance.record("create_irule_idempotent", repeat.changed is False, "repeat plan is a no-op")
    assert repeat.changed is False
    reconciled = asyncio.run(connector.reconcile_create_irule(plan, outcome))
    assert reconciled.status == "succeeded"
