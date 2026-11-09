"""Caller identity shared by the REST API, MCP endpoint, and core services."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Literal

__all__ = ["Caller"]


@dataclass(frozen=True)
class Caller:
    """An authenticated caller. Tenant and roles come only from the credential, never from input."""

    id: str
    tenant_id: uuid.UUID
    roles: frozenset[str] = frozenset()
    groups: frozenset[str] = frozenset()
    kind: Literal["service_account", "oidc"] = "service_account"

    def has_role(self, role: str) -> bool:
        return role in self.roles or "admin" in self.roles
