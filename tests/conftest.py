"""Shared fixtures for database-backed tests.

Connection URLs come from the process environment, falling back to the repo-root
``.env.local``. That file is parsed here only; its values are never printed or logged.
Tests that need a database skip with a reason when the relevant URL is unset.

Each event loop gets its own engine: tests build engines explicitly and call
``asyncio.run`` per scenario, so no engine is shared across loops.

Helpers that take no engine (``admin_session()``, the queue, the credential broker)
resolve ``ICUHUB_DATABASE_URL``. That is set to the owner test database here, so the
test process never touches the database named by the runtime configuration.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Callable, Coroutine, Iterator
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text

import icuhub.storage.migrations as migrations_package
from icuhub.settings import get_settings
from icuhub.storage.db import create_engine, dispose_engine

_REPO_ROOT = Path(__file__).resolve().parents[1]
_ENV_LOCAL = _REPO_ROOT / ".env.local"
_MIGRATIONS_DIR = Path(migrations_package.__file__).resolve().parent
_OWNER_VAR = "ICUHUB_TEST_DATABASE_URL"
_APP_VAR = "ICUHUB_TEST_APP_DATABASE_URL"
_DATABASE_VAR = "ICUHUB_DATABASE_URL"


def _read_env_local() -> dict[str, str]:
    if not _ENV_LOCAL.is_file():
        return {}
    values: dict[str, str] = {}
    for raw in _ENV_LOCAL.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


_LOCAL_ENV = _read_env_local()


def _url_from_env(name: str) -> str | None:
    return os.environ.get(name) or _LOCAL_ENV.get(name) or None


@pytest.fixture(scope="session", autouse=True)
def _default_database_url() -> Iterator[None]:
    """Point ``ICUHUB_DATABASE_URL`` at the owner test database for the whole session."""
    owner_url = _url_from_env(_OWNER_VAR)
    if owner_url is None:
        yield
        return
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv(_DATABASE_VAR, owner_url)
        get_settings.cache_clear()
        yield
    get_settings.cache_clear()


@pytest.fixture(autouse=True)
def _dispose_engines_after_asyncio_run(monkeypatch: pytest.MonkeyPatch) -> None:
    """Run every one-shot coroutine with same-loop pool cleanup before asyncio closes the loop."""
    original_run = asyncio.run

    def run(coro: Coroutine[Any, Any, Any]) -> Any:
        async def managed() -> Any:
            try:
                return await coro
            finally:
                await dispose_engine()

        return original_run(managed())

    monkeypatch.setattr(asyncio, "run", run)


def _alembic_config(url: str) -> Config:
    config = Config()
    config.set_main_option("script_location", str(_MIGRATIONS_DIR))
    config.attributes["url"] = url
    return config


async def _reset_public_schema(url: str) -> None:
    engine = create_engine(url)
    try:
        async with engine.begin() as connection:
            await connection.execute(text("DROP SCHEMA public CASCADE"))
            await connection.execute(text("CREATE SCHEMA public"))
    finally:
        await engine.dispose()


async def _truncate_application_tables(url: str) -> None:
    engine = create_engine(url)
    try:
        async with engine.begin() as connection:
            result = await connection.execute(
                text("SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename <> 'alembic_version'")
            )
            names = list(result.scalars())
            if names:
                quoted = ", ".join(f'"{name}"' for name in names)
                await connection.execute(text(f"TRUNCATE {quoted} RESTART IDENTITY CASCADE"))
    finally:
        await engine.dispose()


@pytest.fixture(scope="session")
def owner_database_url() -> str:
    """Superuser-equivalent owner URL for schema management and fixtures."""
    url = _url_from_env(_OWNER_VAR)
    if url is None:
        pytest.skip(f"{_OWNER_VAR} is not set")
    return url


@pytest.fixture(scope="session")
def app_database_url() -> str:
    """Non-superuser, non-BYPASSRLS application role URL; subject to row-level security."""
    url = _url_from_env(_APP_VAR)
    if url is None:
        pytest.skip(f"{_APP_VAR} is not set")
    return url


@pytest.fixture
def alembic_config(owner_database_url: str) -> Config:
    """Alembic config bound to the owner database through ``config.attributes``."""
    return _alembic_config(owner_database_url)


@pytest.fixture
def reset_schema() -> Callable[[str], None]:
    """Drop and recreate the ``public`` schema of the database at the given URL."""

    def reset(url: str) -> None:
        asyncio.run(_reset_public_schema(url))

    return reset


@pytest.fixture(scope="session")
def migrated_database(owner_database_url: str) -> str:
    """Reset ``public`` and migrate to head once per session."""
    asyncio.run(_reset_public_schema(owner_database_url))
    command.upgrade(_alembic_config(owner_database_url), "head")
    return owner_database_url


@pytest.fixture
def clean_database(migrated_database: str) -> None:
    """Empty every application table before a test; schema stays at head."""
    asyncio.run(_truncate_application_tables(migrated_database))
