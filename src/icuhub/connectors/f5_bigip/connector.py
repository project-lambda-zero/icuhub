"""F5 BIG-IP iControl REST connector: inventory reads, Enforcer block/unblock, and create_irule (MVP 4.18)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any, ClassVar

from pydantic import ValidationError

from icuhub.connectors.f5_bigip.models import (
    BlockArgs,
    BlockRecordResult,
    CreateIruleArgs,
    F5Config,
    InventoryQuery,
    Irule,
    IruleListResult,
    IruleQuery,
    IruleResult,
    UnblockArgs,
    VirtualServersResult,
)
from icuhub.kit.auth import SessionLogin
from icuhub.kit.connector import Connector, action, operation
from icuhub.kit.errors import (
    Conflict,
    ConnectorError,
    NotFound,
    OutcomeUnknown,
    PermissionDenied,
    TransientVendorError,
    VendorContractError,
)
from icuhub.kit.http import HttpResult
from icuhub.kit.types import ActionOutcome, ActionPlan, CapabilityHealth, HealthReport, Scope

__all__ = ["F5BigIp"]

_IRULE_COLLECTION = "/mgmt/tm/ltm/rule"
_IRULE_KIND = "tm:ltm:rule:rulestate"


def _json_object(result: HttpResult) -> dict[str, Any]:
    try:
        body = result.json()
    except ValueError as exc:
        raise VendorContractError("F5 response is not JSON") from exc
    if not isinstance(body, dict):
        raise VendorContractError("F5 response is not a JSON object")
    return body


def _parse_irule(raw: Any) -> Irule:
    try:
        return Irule.model_validate(raw)
    except ValidationError as exc:
        raise VendorContractError(f"F5 iRule does not match the expected shape ({len(exc.errors())} errors)") from exc


def _natural_key_path(full_path: str) -> str:
    """Map ``/partition/[sub/]name`` to the iControl natural-key path ``/mgmt/tm/ltm/rule/~partition~[sub~]name``."""
    return f"{_IRULE_COLLECTION}/~" + "~".join(full_path.lstrip("/").split("/"))


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
    async def reconcile_block(self, plan: ActionPlan, outcome: ActionOutcome) -> ActionOutcome:
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
    async def reconcile_unblock(self, plan: ActionPlan, outcome: ActionOutcome) -> ActionOutcome:
        group = await self._data_group()
        block_id = plan.target_ref.rsplit(":", 1)[-1]
        if not any(r.get("name") == block_id for r in group.get("records", [])):
            return ActionOutcome(status="succeeded", vendor_ref=block_id, result={"generation": group.get("generation")})
        return ActionOutcome(status="outcome_unknown")

    async def _read_irule(self, full_path: str) -> Irule | None:
        try:
            result = await self.http.request("GET", _natural_key_path(full_path))
        except NotFound:
            return None
        return _parse_irule(_json_object(result))

    @operation(
        "list_irules",
        classification="read",
        capability="Enforcer",
        input_model=InventoryQuery,
        output_model=IruleListResult,
    )
    async def list_irules(self, args: InventoryQuery) -> IruleListResult:
        del args  # the iRule collection has no filter input
        body = _json_object(await self.http.request("GET", _IRULE_COLLECTION))
        raw_items = body.get("items", [])
        if not isinstance(raw_items, list):
            raise VendorContractError("F5 iRule collection items are not a list")
        items = [_parse_irule(item) for item in raw_items]
        return IruleListResult(items=items, total=len(items))

    @operation(
        "get_irule",
        classification="read",
        capability="Enforcer",
        input_model=IruleQuery,
        output_model=IruleResult,
    )
    async def get_irule(self, args: IruleQuery) -> IruleResult:
        rule = await self._read_irule(args.expected_full_path)
        return IruleResult(present=rule is not None, rule=rule)

    @action(
        "create_irule",
        classification="write",
        capability="Enforcer",
        input_model=CreateIruleArgs,
        idempotency="natural_key",
    )
    async def plan_create_irule(self, args: CreateIruleArgs) -> ActionPlan:
        full_path = args.expected_full_path
        existing = await self._read_irule(full_path)
        if existing is not None and existing.definition != args.definition:
            raise Conflict(f"iRule {full_path} already exists with a different definition; create_irule never updates")
        if existing is not None:
            return ActionPlan(
                action="create_irule",
                target_ref=f"f5:irule:{full_path}",
                diff={},
                preconditions={"exists": True},
                idempotency_key=f"create_irule:{full_path}",
                changed=False,
                request={},
            )
        return ActionPlan(
            action="create_irule",
            target_ref=f"f5:irule:{full_path}",
            diff={"add": {"fullPath": full_path}},
            preconditions={"exists": False},
            idempotency_key=f"create_irule:{full_path}",
            changed=True,
            request={"kind": _IRULE_KIND, "name": args.name, "fullPath": full_path, "apiAnonymous": args.definition},
        )

    @plan_create_irule.apply
    async def apply_create_irule(self, plan: ActionPlan) -> ActionOutcome:
        if not self._config().write_enabled:
            raise PermissionDenied(
                scope="write", message="create_irule is disabled: set write_enabled in the F5 connector config"
            )
        full_path = plan.request["fullPath"]
        try:
            await self.http.request("POST", _IRULE_COLLECTION, json=plan.request, idempotency="non_idempotent")
        except (OutcomeUnknown, TransientVendorError, VendorContractError):
            return ActionOutcome(
                status="outcome_unknown", vendor_ref=full_path, error="create response was not a clean success"
            )
        except ConnectorError as exc:
            return ActionOutcome(status="failed", vendor_ref=full_path, error=str(exc))
        try:
            rule = await self._read_irule(full_path)
        except ConnectorError as exc:
            return ActionOutcome(
                status="outcome_unknown", vendor_ref=full_path, error=f"read-back failed: {type(exc).__name__}"
            )
        return _create_verdict(plan, rule, absent_status="outcome_unknown")

    @plan_create_irule.reconcile
    async def reconcile_create_irule(self, plan: ActionPlan, outcome: ActionOutcome) -> ActionOutcome:
        rule = await self._read_irule(plan.request["fullPath"])
        return _create_verdict(plan, rule, absent_status="failed")


def _create_verdict(plan: ActionPlan, rule: Irule | None, *, absent_status: str) -> ActionOutcome:
    """Decide the create outcome from an exact read-back; the definition must match byte-for-byte."""
    full_path = plan.request["fullPath"]
    if rule is None:
        return ActionOutcome(status=absent_status, vendor_ref=full_path, error="iRule is not present on read-back")
    if rule.full_path != full_path or rule.definition != plan.request["apiAnonymous"]:
        return ActionOutcome(
            status="outcome_unknown", vendor_ref=full_path, error="iRule on read-back differs from the requested one"
        )
    return ActionOutcome(status="succeeded", vendor_ref=full_path, result={"full_path": full_path})
