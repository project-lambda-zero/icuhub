"""Shared Invicti Enterprise fixtures."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from icuhub.connectors.invicti_enterprise import InvictiEnterprise
from icuhub.kit.testing import RouteTransport, make_connector
from icuhub.kit.types import Target

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "invicti_enterprise"
BASE = "https://invicti.example.test/api/1.0"


def load_fixture(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def enterprise_connector(routes: dict[tuple[str, str], Any], **config: Any) -> InvictiEnterprise:
    return make_connector(
        InvictiEnterprise,
        {
            "base_url": BASE,
            "user_id": "api-user",
            "api_token": {"ref": "api_token"},
            **config,
        },
        RouteTransport(routes),
        {"api_token": b"not-a-real-token"},
    )


def target_for_scan() -> Target:
    scan = load_fixture("scans.json")["List"][0]
    return Target(
        id=scan["Id"],
        source_uid=scan["Id"],
        kind="invicti_scan",
        display_name=scan["Id"],
        attributes={"website_id": scan["WebsiteId"], "website_root_url": scan["TargetUrl"]},
    )
