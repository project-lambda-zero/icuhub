"""Async PostgreSQL engine and transaction-scoped sessions.

Tenant isolation is enforced by row-level security. :func:`session_scope` sets
``app.tenant_id`` with ``set_config(..., true)`` so the value is local to the
transaction and cannot leak to the next borrower of a pooled connection.
:func:`admin_session` sets no tenant and is reserved for migrations, the queue
claimer, and the outbox relay, which are cross-tenant by design.
"""

from __future__ import annotations

import asyncio
import uuid
import weakref
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from icuhub.settings import get_settings

__all__ = ["admin_session", "create_engine", "get_engine", "session_scope"]

_POSTGRES_SCHEME = "postgresql://"
_ASYNCPG_SCHEME = "postgresql+asyncpg://"

# asyncpg connections are bound to the event loop that opened them, so the default engine is cached
# per loop rather than once per process. A worker runs one loop and gets one engine; code that runs
# several loops in sequence (for example one ``asyncio.run`` per call) gets a pool for each.
_default_engines: weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, AsyncEngine] = weakref.WeakKeyDictionary()


def create_engine(database_url: str) -> AsyncEngine:
    """Build an asyncpg engine; a plain ``postgresql://`` URL is upgraded to the asyncpg driver."""
    if database_url.startswith(_POSTGRES_SCHEME):
        database_url = _ASYNCPG_SCHEME + database_url[len(_POSTGRES_SCHEME) :]
    return create_async_engine(database_url, pool_pre_ping=True)


def get_engine() -> AsyncEngine:
    """Return the engine for the running event loop, built from ``ICUHUB_DATABASE_URL``.

    Must be called from a coroutine, since the engine is keyed by the running loop.
    """
    loop = asyncio.get_running_loop()
    engine = _default_engines.get(loop)
    if engine is None:
        database_url = get_settings().database_url
        if database_url is None:
            raise RuntimeError("ICUHUB_DATABASE_URL is not set")
        engine = create_engine(database_url)
        _default_engines[loop] = engine
    return engine


def _factory(engine: AsyncEngine | None) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine if engine is not None else get_engine(), expire_on_commit=False)


@asynccontextmanager
async def session_scope(tenant_id: uuid.UUID, *, engine: AsyncEngine | None = None) -> AsyncGenerator[AsyncSession]:
    """Yield a session in one transaction bound to ``tenant_id`` for row-level security."""
    async with _factory(engine)() as session, session.begin():
        await session.execute(
            text("SELECT set_config('app.tenant_id', :tenant_id, true)"),
            {"tenant_id": str(tenant_id)},
        )
        yield session


@asynccontextmanager
async def admin_session(*, engine: AsyncEngine | None = None) -> AsyncGenerator[AsyncSession]:
    """Yield a session in one transaction with no tenant bound; tenant-scoped tables return no rows."""
    async with _factory(engine)() as session, session.begin():
        yield session
