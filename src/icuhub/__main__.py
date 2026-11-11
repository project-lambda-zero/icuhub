"""``python -m icuhub`` command dispatcher.

``migrate`` applies the Alembic history to the database named by
``ICUHUB_DATABASE_URL``. ``api``, ``worker``, and ``manifest`` hand the
remaining arguments to their owning entry point; those modules are imported
only when the command is selected.
"""

from __future__ import annotations

import importlib
import sys
from collections.abc import Callable
from pathlib import Path

from alembic import command
from alembic.config import Config

__all__ = ["main"]

_MIGRATIONS_DIR = Path(__file__).resolve().parent / "storage" / "migrations"

_SERVICES: dict[str, str] = {
    "api": "icuhub.api.app:main",
    "worker": "icuhub.workers.main:main",
    "manifest": "icuhub.kit.manifest:main",
}

_USAGE = (
    "usage: python -m icuhub {migrate | api | worker | manifest} [args...]\n"
    "  migrate   apply Alembic migrations to ICUHUB_DATABASE_URL\n"
    "  api       run the HTTP API (arguments are passed through)\n"
    "  worker    run the background worker (arguments are passed through)\n"
    "  manifest  generate or check the connector manifest (arguments are passed through)\n"
)


def _load_entry_point(target: str) -> Callable[[list[str] | None], int | None]:
    module_name, _, attribute = target.partition(":")
    entry: Callable[[list[str] | None], int | None] = getattr(importlib.import_module(module_name), attribute)
    return entry


def _migrate() -> int:
    config = Config()
    config.set_main_option("script_location", str(_MIGRATIONS_DIR))
    command.upgrade(config, "head")
    return 0


def main(argv: list[str] | None = None) -> int | None:
    """Dispatch one ``python -m icuhub`` command and return its exit status."""
    args = list(sys.argv[1:] if argv is None else argv)
    if args == ["migrate"]:
        return _migrate()
    if args and args[0] in _SERVICES:
        return _load_entry_point(_SERVICES[args[0]])(args[1:])
    print(_USAGE, file=sys.stderr, end="")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
