"""Fixture loading for the shared Invicti helpers."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from icuhub.kit.types import MapContext

_FIXTURES = Path(__file__).parents[2] / "fixtures"


def load_fixture(kind: str, name: str) -> Any:
    return json.loads((_FIXTURES / kind / name).read_text(encoding="utf-8"))


@pytest.fixture
def enterprise_issue_raw() -> dict[str, Any]:
    return load_fixture("invicti_enterprise", "issues.json")["List"][0]


@pytest.fixture
def standard_issue_raw() -> dict[str, Any]:
    return load_fixture("invicti_standard", "report.json")["Vulnerabilities"][0]


@pytest.fixture
def map_context() -> MapContext:
    return MapContext(
        connection_id="connection-1",
        tenant_id="tenant-1",
        connector_kind="invicti_enterprise",
        received_at=datetime(2026, 11, 10, tzinfo=UTC),
    )
