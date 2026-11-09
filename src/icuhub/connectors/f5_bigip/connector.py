"""F5 BIG-IP iControl REST connector: inventory reads and Enforcer block/unblock (MVP 4.18)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any, ClassVar

from icuhub.connectors.f5_bigip.models import (
    BlockArgs,
    BlockRecordResult,
    F5Config,
    InventoryQuery,
    UnblockArgs,
    VirtualServersResult,
)
from icuhub.kit.auth import SessionLogin
from icuhub.kit.connector import Connector, action, operation
from icuhub.kit.errors import PermissionDenied
from icuhub.kit.types import ActionOutcome, ActionPlan, CapabilityHealth, HealthReport, Scope

__all__ = ["F5BigIp"]


class F5BigIp(Connector):
    kind: ClassVar[str] = "f5_bigip"
    version: ClassVar[str] = "0.1.0"
    display_name: ClassVar[str] = "F5 BIG-IP"
    config_model: ClassVar[type[F5Config]] = F5Config
    auth_modes: ClassVar[tuple[str, ...]] = ("icontrol_token",)
    capabilities: ClassVar[tuple[str, ...]] = ("Enforcer", "TelemetrySource")
    scopes: ClassVar[tuple[Scope, ...]] = (
        Scope(name="inventory", probe="GET /mgmt/tm/sys/version", required_by=("TelemetrySource",)),
        Scope(name="data_group", probe="GET /mgmt/tm/ltm/data-group/internal", required_by=("Enforcer",)),
    )
    flows: ClassVar[tuple[str, ...]] = ("F-035",)

    async def build_auth(self) -> SessionLogin:
        config = self.config
        assert isinstance(config, F5Config)
        username = (await self.ctx.secrets.resolve(config.username)).decode()
        password = (await self.ctx.secrets.resolve(config.password)).decode()

        async def login() -> tuple[str, str, datetime | None]:
            result = await self.http.request(
                "POST",
                "/mgmt/shared/authn/login",
                json={"username": username, "password": password, "loginProviderName": "tmos"},
                authenticate=False,
            )
            body = result.json()
            token = body.get("token") or {}
            timeout = int(token.get("timeout") or 1200)
            return "X-F5-Auth-Token", str(token["token"]), datetime.now(UTC) + timedelta(seconds=timeout - 30)

        return SessionLogin(login=login)

    def _config(self) -> F5Config:
        config = self.config
        assert isinstance(config, F5Config)
        return config

    def _dg_path(self) -> str:
        config = self._config()
        return f"/mgmt/tm/ltm/data-group/internal/~{config.partition}~{config.data_group}"

    async def _data_group(self) -> dict[str, Any]:
        result = await self.http.request("GET", self._dg_path())
        return result.json()

    async def check(self) -> HealthReport:
        capabilities: dict[str, CapabilityHealth] = {}
        status = "healthy"
        try:
            result = await self.http.request("GET", "/mgmt/tm/sys/version")
            entries = (result.json().get("entries") or {})
            version = next(iter(entries.values()), {}).get("nestedStats", {}).get("entries", {}).get("Version")
            capabilities["TelemetrySource"] = CapabilityHealth(status="healthy")
        except (OSError, TimeoutError, RuntimeError) as exc:
            capabilities["TelemetrySource"] = CapabilityHealth(status="degraded", reason=type(exc).__name__)
            status = "degraded"
            version = None
        try:
            await self._data_group()
            capabilities["Enforcer"] = CapabilityHealth(status="healthy")
        except PermissionDenied as exc:
            capabilities["Enforcer"] = CapabilityHealth(status="not_evaluated", reason=type(exc).__name__)
        except (OSError, TimeoutError, RuntimeError) as exc:
            capabilities["Enforcer"] = CapabilityHealth(status="degraded", reason=type(exc).__name__)
            status = "degraded"
        return HealthReport(status=status, capabilities=capabilities, vendor_version=str(version) if version else None)

    @operation(
        "list_virtual_servers",
        classification="read",
        capability="TelemetrySource",
        input_model=InventoryQuery,
        output_model=VirtualServersResult,
    )
    async def list_virtual_servers(self, args: InventoryQuery) -> VirtualServersResult:
        del args  # the virtual-server collection has no filter input
        result = await self.http.request("GET", "/mgmt/tm/ltm/virtual")
        items = [
            {
                "name": item.get("name"),
                "partition": item.get("partition"),
                "destination": item.get("destination"),
                "enabled": item.get("enabled", True),
                "ip_protocol": item.get("ipProtocol"),
                "pool": item.get("pool"),
            }
            for item in result.json().get("items", [])
        ]
        return VirtualServersResult(items=items, total=len(items))

    @operation(
        "get_block",
        classification="read",
        capability="Enforcer",
        input_model=UnblockArgs,
        output_model=BlockRecordResult,
    )
    async def get_block(self, args: UnblockArgs) -> BlockRecordResult:
        group = await self._data_group()
        record = next((r for r in group.get("records", []) if r.get("name") == args.block_id), None)
        return BlockRecordResult(
            block_id=args.block_id,
            data_group=self._config().data_group,
            generation=group.get("generation"),
            record=record,
            present=record is not None,
        )

    @action("block", classification="destructive", capability="Enforcer", input_model=BlockArgs, idempotency="natural_key")
    async def plan_block(self, args: BlockArgs) -> ActionPlan:
        group = await self._data_group()
        records = list(group.get("records", []))
        existing = next((r for r in records if r.get("name") == args.indicator), None)
        generation = int(group.get("generation") or 0)
        if existing is not None:
            return ActionPlan(
                action="block",
                target_ref=f"f5:{self._config().data_group}:{args.indicator}",
                diff={},
                preconditions={"generation": generation},
                idempotency_key=f"block:{args.indicator}",
                changed=False,
                request={},
            )
        expires = datetime.now(UTC) + timedelta(seconds=args.ttl_s)
        record = {
            "name": args.indicator,
            "value": json.dumps({"reason": args.reason, "expires_at": expires.isoformat(), "by": "icuhub"}),
        }
        return ActionPlan(
            action="block",
            target_ref=f"f5:{self._config().data_group}:{args.indicator}",
            diff={"add": record},
            preconditions={"generation": generation},
            idempotency_key=f"block:{args.indicator}",
            changed=True,
            request={"records": [*records, record]},
        )

    @plan_block.apply
    async def apply_block(self, plan: ActionPlan) -> ActionOutcome:
        result = await self.http.request(
            "PATCH",
            self._dg_path(),
            json={"generation": plan.preconditions["generation"], "records": plan.request["records"]},
        )
        body = result.json()
        indicator = plan.target_ref.rsplit(":", 1)[-1]
        record = next((r for r in body.get("records", []) if r.get("name") == indicator), None)
        if record is None:
            return ActionOutcome(status="outcome_unknown", result={"generation": body.get("generation")})
        return ActionOutcome(
            status="succeeded", vendor_ref=indicator, result={"generation": body.get("generation"), "record": record}
        )

    @plan_block.reconcile
    async def reconcile_block(self, plan: ActionPlan) -> ActionOutcome:
        group = await self._data_group()
        indicator = plan.target_ref.rsplit(":", 1)[-1]
        record = next((r for r in group.get("records", []) if r.get("name") == indicator), None)
        if record is not None:
            return ActionOutcome(
                status="succeeded", vendor_ref=indicator, result={"generation": group.get("generation"), "record": record}
            )
        return ActionOutcome(status="outcome_unknown")

    @action(
        "unblock", classification="destructive", capability="Enforcer", input_model=UnblockArgs, idempotency="natural_key"
    )
    async def plan_unblock(self, args: UnblockArgs) -> ActionPlan:
        group = await self._data_group()
        records = list(group.get("records", []))
        remaining = [r for r in records if r.get("name") != args.block_id]
        generation = int(group.get("generation") or 0)
        if len(remaining) == len(records):
            return ActionPlan(
                action="unblock",
                target_ref=f"f5:{self._config().data_group}:{args.block_id}",
                diff={},
                preconditions={"generation": generation},
                idempotency_key=f"unblock:{args.block_id}",
                changed=False,
                request={},
            )
        return ActionPlan(
            action="unblock",
            target_ref=f"f5:{self._config().data_group}:{args.block_id}",
            diff={"remove": args.block_id},
            preconditions={"generation": generation},
            idempotency_key=f"unblock:{args.block_id}",
            changed=True,
            request={"records": remaining},
        )

    @plan_unblock.apply
    async def apply_unblock(self, plan: ActionPlan) -> ActionOutcome:
        result = await self.http.request(
            "PATCH",
            self._dg_path(),
            json={"generation": plan.preconditions["generation"], "records": plan.request["records"]},
        )
        body = result.json()
        block_id = plan.target_ref.rsplit(":", 1)[-1]
        if any(r.get("name") == block_id for r in body.get("records", [])):
            return ActionOutcome(status="outcome_unknown", result={"generation": body.get("generation")})
        return ActionOutcome(status="succeeded", vendor_ref=block_id, result={"generation": body.get("generation")})

    @plan_unblock.reconcile
    async def reconcile_unblock(self, plan: ActionPlan) -> ActionOutcome:
        group = await self._data_group()
        block_id = plan.target_ref.rsplit(":", 1)[-1]
        if not any(r.get("name") == block_id for r in group.get("records", [])):
            return ActionOutcome(status="succeeded", vendor_ref=block_id, result={"generation": group.get("generation")})
        return ActionOutcome(status="outcome_unknown")
