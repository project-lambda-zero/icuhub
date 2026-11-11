"""Shared FastAPI dependencies for REST routes: tenant-scoped session, services, headers."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator

from fastapi import Depends, Header
from sqlalchemy.ext.asyncio import AsyncSession

from icuhub.api.auth import current_caller
from icuhub.api.problems import ProblemError
from icuhub.connectors import CONNECTORS
from icuhub.core.auth_types import Caller
from icuhub.core.services import Services, get_services
from icuhub.kit.connector import Connector
from icuhub.storage.db import session_scope

__all__ = [
    "CallerDep",
    "ConnectorRegistry",
    "CorrelationHeader",
    "IdempotencyHeader",
    "ServicesDep",
    "TenantSession",
    "connector_registry",
    "parse_uuid",
    "require_correlation",
    "require_idempotency",
]

ConnectorRegistry = dict[str, type[Connector]]


def connector_registry() -> ConnectorRegistry:
    return CONNECTORS


async def tenant_session(caller: Caller = Depends(current_caller)) -> AsyncIterator[AsyncSession]:
    """One transaction bound to the caller's tenant; commits when the route returns."""
    async with session_scope(caller.tenant_id) as session:
        yield session


def _services() -> Services:
    return get_services()


CallerDep = Depends(current_caller)
TenantSession = Depends(tenant_session)
ServicesDep = Depends(_services)
CorrelationHeader = Header(default=None, alias="X-Correlation-Id")
IdempotencyHeader = Header(default=None, alias="Idempotency-Key")


def require_correlation(value: str | None) -> str:
    if not value:
        raise ProblemError(400, "missing-header", "Missing header", "X-Correlation-Id is required")
    return value


def require_idempotency(value: str | None) -> str:
    if not value:
        raise ProblemError(400, "missing-header", "Missing header", "Idempotency-Key is required")
    return value


def parse_uuid(raw: str) -> uuid.UUID:
    try:
        return uuid.UUID(raw)
    except ValueError as exc:
        raise ProblemError(404, "not-found", "Not found", "resource not found") from exc
