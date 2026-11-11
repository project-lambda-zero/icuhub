"""Migration 0001 upgrade, downgrade, and re-upgrade on a freshly reset database."""

from __future__ import annotations

import asyncio
from collections.abc import Callable

from alembic import command
from alembic.config import Config
from sqlalchemy import text

from icuhub.storage.db import create_engine

_APPLICATION_TABLE_COUNT = 27


async def _public_tables(url: str) -> list[str]:
    engine = create_engine(url)
    try:
        async with engine.connect() as connection:
            result = await connection.execute(
                text("SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename")
            )
            return list(result.scalars())
    finally:
        await engine.dispose()


def test_upgrade_downgrade_upgrade_round_trip(
    owner_database_url: str,
    alembic_config: Config,
    reset_schema: Callable[[str], None],
) -> None:
    reset_schema(owner_database_url)

    command.upgrade(alembic_config, "head")
    upgraded = asyncio.run(_public_tables(owner_database_url))
    assert len(upgraded) == _APPLICATION_TABLE_COUNT + 1  # application tables plus alembic_version

    command.downgrade(alembic_config, "base")
    assert asyncio.run(_public_tables(owner_database_url)) == ["alembic_version"]

    command.upgrade(alembic_config, "head")
    assert asyncio.run(_public_tables(owner_database_url)) == upgraded
