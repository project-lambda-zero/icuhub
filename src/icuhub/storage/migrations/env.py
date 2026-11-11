"""Alembic environment for the async PostgreSQL engine.

The URL comes from ``config.attributes["url"]`` when a caller sets it, so tests
never pass URLs through ConfigParser interpolation. Otherwise it is read from
``ICUHUB_DATABASE_URL`` through :func:`icuhub.settings.get_settings`.
Migrations are written as explicit DDL, so ``target_metadata`` is ``None``.
"""

from __future__ import annotations

import asyncio

from alembic import context
from sqlalchemy import Connection

from icuhub.settings import get_settings
from icuhub.storage.db import create_engine

__all__: list[str] = []

config = context.config
target_metadata = None


def _database_url() -> str:
    url = config.attributes.get("url") or get_settings().database_url
    if not url:
        raise RuntimeError("no database URL: set ICUHUB_DATABASE_URL or config.attributes['url']")
    return str(url)


def run_migrations_offline() -> None:
    """Emit migration SQL without a live connection."""
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def _run_migrations(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


async def _run_async_migrations() -> None:
    engine = create_engine(_database_url())
    try:
        async with engine.connect() as connection:
            await connection.run_sync(_run_migrations)
    finally:
        await engine.dispose()


def run_migrations_online() -> None:
    """Apply migrations through the async engine."""
    asyncio.run(_run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
