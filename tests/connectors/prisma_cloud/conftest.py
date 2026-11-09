"""Shared fixtures for offline Prisma Cloud connector tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

prisma_module = pytest.importorskip(
    "icuhub.connectors.prisma_cloud", reason="prisma connector implementation is still in progress"
)
PrismaCloud = prisma_module.PrismaCloud

from icuhub.kit.testing import RouteTransport, make_connector  # noqa: E402

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "prisma_cloud"
CSPM_BASE = "https://api.prismacloud.io"
COMPUTE_BASE = "https://console.example.invalid"
CSPM_CONFIG = {
    "base_url": CSPM_BASE,
    "editions": ["cspm"],
    "cspm_access_key_id": "access-key",
    "cspm_access_key_secret": {"ref": "cspm_secret"},
}
COMPUTE_CONFIG = {
    "base_url": COMPUTE_BASE,
    "editions": ["compute"],
    "compute_auth_mode": "session",
    "compute_username": "scanner",
    "compute_password": {"ref": "compute_password"},
}
SECRETS = {"cspm_secret": b"not-a-real-secret", "compute_password": b"not-a-real-password"}
CSPM_LOGIN = {"status": 200, "json": {"token": "cspm-jwt", "expires_in": 600}}
COMPUTE_LOGIN = {"status": 200, "json": {"token": "compute-jwt", "expires_in": 1800}}


def load_fixture(name: str) -> dict[str, Any]:
    value = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def cspm_connector(routes: dict[tuple[str, str], Any]) -> PrismaCloud:
    routes.setdefault(("POST", "/login"), CSPM_LOGIN)
    return make_connector(PrismaCloud, CSPM_CONFIG, RouteTransport(routes), SECRETS)


def compute_connector(routes: dict[tuple[str, str], Any]) -> PrismaCloud:
    routes.setdefault(("POST", "/api/v1/authenticate"), COMPUTE_LOGIN)
    return make_connector(PrismaCloud, COMPUTE_CONFIG, RouteTransport(routes), SECRETS)
