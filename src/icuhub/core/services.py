"""Process-wide service wiring for API and worker entry points.

Entry points build one :class:`Services` at startup and call :func:`configure`. Job
handlers resolve it lazily so tests can substitute their own registry, transport, and
broker without touching global settings.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from icuhub.core.credentials import CredentialBroker, broker_from_settings
from icuhub.core.runtime import ConnectorRuntime
from icuhub.kit.connector import Connector
from icuhub.settings import Settings, get_settings

__all__ = ["Services", "configure", "get_services"]


@dataclass
class Services:
    settings: Settings
    broker: CredentialBroker
    runtime: ConnectorRuntime


_SERVICES: Services | None = None


def configure(
    settings: Settings | None = None,
    *,
    registry: dict[str, type[Connector]] | None = None,
    transport: Any = None,
    broker: CredentialBroker | None = None,
) -> Services:
    """Build (or replace) the process services. Called once by entry points and tests."""
    global _SERVICES
    resolved = settings or get_settings()
    resolved_broker = broker or broker_from_settings(resolved)
    _SERVICES = Services(
        settings=resolved,
        broker=resolved_broker,
        runtime=ConnectorRuntime(resolved_broker, resolved, registry, transport=transport),
    )
    return _SERVICES


def get_services() -> Services:
    if _SERVICES is None:
        return configure()
    return _SERVICES
