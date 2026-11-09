"""MCP surface at ``/mcp``: tools are connection operations and actions.

Tool names are ``<connection.slug>.<operation>``. Reads map to ``run_operation``; writes map
to ``submit_action`` and return ``pending_approval`` as a normal result, not an error.
Authentication runs at the HTTP layer before the session manager sees a request, and again
for every message from the request headers the transport attaches to the handler context.
"""

from __future__ import annotations

import inspect
import json
import uuid
from typing import Any

from mcp import types
from mcp.server.context import ServerRequestContext  # type: ignore[attr-defined]
from mcp.server.lowlevel.server import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from icuhub.api.auth import authenticate
from icuhub.api.problems import AuthenticationError
from icuhub.connectors import CONNECTORS
from icuhub.core.actions import submit_action
from icuhub.core.auth_types import Caller
from icuhub.core.policy import PolicyInput, effective_outcome, evaluate
from icuhub.core.services import get_services
from icuhub.kit.connector import Connector
from icuhub.storage.db import session_scope
from icuhub.storage.models import Connection, PolicyRule, Tenant

__all__ = ["build_session_manager"]

SERVER_NAME = "icuhub"
SERVER_VERSION = "0.1.0"


def build_session_manager() -> StreamableHTTPSessionManager:
    """A fresh session manager per app; ``run()`` may only be entered once per instance."""
    server: Server[Any] = Server(
        SERVER_NAME,
        version=SERVER_VERSION,
        on_list_tools=_list_tools,
        on_call_tool=_call_tool,
    )
    return StreamableHTTPSessionManager(app=server)


def _split_tool(name: str) -> tuple[str, str] | None:
    slug, sep, operation = name.partition(".")
    if not sep or not slug or not operation:
        return None
    return slug, operation


async def _caller(ctx: ServerRequestContext[Any]) -> Caller:
    """Reauthenticate from the HTTP headers attached to this message."""
    request = ctx.request
    if request is None:
        raise AuthenticationError()
    return await authenticate(dict(request.headers))


async def _rules_and_switches(session: AsyncSession, caller: Caller) -> tuple[list[PolicyRule], bool, bool]:
    rules = list(
        (await session.execute(select(PolicyRule).where(PolicyRule.tenant_id == caller.tenant_id))).scalars().all()
    )
    tenant = await session.get(Tenant, caller.tenant_id)
    deployment = get_services().settings.automation_enabled
    tenant_on = bool(tenant and tenant.automation_enabled)
    return rules, deployment, tenant_on


def _tool_for(slug: str, name: str, spec: Any, read: bool) -> types.Tool:
    destructive = not read and spec.classification == "destructive"
    function = spec.fn if read else spec.plan
    annotations = types.ToolAnnotations(
        title=f"{slug}.{name}",
        read_only_hint=read,
        destructive_hint=destructive,
        idempotent_hint=read or spec.idempotency != "none",
        open_world_hint=True,
    )
    return types.Tool(
        name=f"{slug}.{name}",
        description=inspect.getdoc(function) or f"{name} on {slug}",
        input_schema=spec.input_model.model_json_schema(),
        annotations=annotations,
    )


async def _list_tools(
    ctx: ServerRequestContext[Any], params: types.PaginatedRequestParams | None
) -> types.ListToolsResult:
    caller = await _caller(ctx)
    tools: list[types.Tool] = []
    async with session_scope(caller.tenant_id) as session:
        rules, deployment, tenant_on = await _rules_and_switches(session, caller)
        connections = (
            await session.execute(select(Connection).where(Connection.tenant_id == caller.tenant_id))
        ).scalars().all()
        for connection in connections:
            if connection.status != "active":
                continue
            cls: type[Connector] | None = CONNECTORS.get(connection.kind)
            if cls is None:
                continue
            specs = [(n, s, True) for n, s in cls.operations().items()]
            specs += [(n, s, False) for n, s in cls.actions().items()]
            for name, spec, read in specs:
                if connection.allowed_operations is not None and name not in connection.allowed_operations:
                    continue
                req = PolicyInput(
                    caller=caller,
                    connection_id=connection.id,
                    connection_kind=connection.kind,
                    operation=name,
                    classification="read" if read else spec.classification,  # type: ignore[arg-type]
                    egress_class=connection.egress_class,
                    args={},
                )
                decision = evaluate(rules, req)
                outcome = effective_outcome(decision, req, deployment_switch=deployment, tenant_switch=tenant_on)
                if outcome != "denied":
                    tools.append(_tool_for(connection.slug, name, spec, read))
    return types.ListToolsResult(tools=tools)


def _error(message: str) -> types.CallToolResult:
    return types.CallToolResult(content=[types.TextContent(type="text", text=message)], is_error=True)


def _ok(payload: dict[str, Any]) -> types.CallToolResult:
    text = json.dumps(payload, default=str, sort_keys=True)
    return types.CallToolResult(content=[types.TextContent(type="text", text=text)], structured_content=payload)


async def _call_tool(ctx: ServerRequestContext[Any], params: types.CallToolRequestParams) -> types.CallToolResult:
    caller = await _caller(ctx)
    split = _split_tool(params.name)
    if split is None:
        return _error("tool name must be <connection.slug>.<operation>")
    slug, name = split
    args = dict(params.arguments or {})
    request = ctx.request
    header_cid = request.headers.get("x-correlation-id") if request is not None else None
    meta = params.meta or {}
    idempotency_key = meta.get("idempotency_key") if isinstance(meta, dict) else None

    async with session_scope(caller.tenant_id) as session:
        row = (
            await session.execute(
                select(Connection).where(Connection.tenant_id == caller.tenant_id, Connection.slug == slug)
            )
        ).scalar_one_or_none()
        if row is None or row.status != "active":
            return _error("unknown or inactive connection")
        cls: type[Connector] | None = CONNECTORS.get(row.kind)
        if cls is None:
            return _error("connector kind not registered")
        services = get_services()
        if name in cls.operations():
            result = await services.runtime.run_operation(session, caller, row.id, name, args)
            return _ok({"result": result})
        if name in cls.actions():
            if not idempotency_key:
                return _error("actions require meta.idempotency_key")
            cid = header_cid or str(uuid.uuid4())
            action = await submit_action(
                session,
                caller,
                row.id,
                name,
                args,
                idempotency_key=str(idempotency_key),
                correlation_id=cid,
            )
            return _ok({"action_id": str(action.id), "state": action.state, "correlation_id": cid})
    return _error("connection has no such operation or action")
