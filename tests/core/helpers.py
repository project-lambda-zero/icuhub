"""Shared helpers for core integration tests (DB + recorded vendor transport)."""

from __future__ import annotations

import os
import uuid
from typing import Any

from icuhub.core.auth_types import Caller
from icuhub.core.connections import create_connection
from icuhub.core.services import configure
from icuhub.kit.testing import RouteTransport
from icuhub.settings import Settings
from tests.core.sample.connector import SampleScanner, SampleScannerB, SampleTracker

REGISTRY = {
    "sample_scanner": SampleScanner,
    "sample_scanner_b": SampleScannerB,
    "sample_tracker_core": SampleTracker,
}


def make_services(transport: Any, kek_path: Any) -> Any:
    import os as _os  # noqa: PLC0415

    if not _os.path.exists(kek_path):
        with open(kek_path, "wb") as handle:
            handle.write(_os.urandom(32))
    settings = Settings(
        database_url=os.environ["ICUHUB_DATABASE_URL"],
        kek_provider="file",
        kek_file_path=kek_path,
        automation_enabled=False,
    )
    return configure(settings, registry=REGISTRY, transport=transport)


def caller_for(tenant_id: uuid.UUID, name: str = "admin", roles: set[str] | None = None,
               groups: set[str] | None = None) -> Caller:
    return Caller(
        id=name,
        tenant_id=tenant_id,
        roles=frozenset(roles or {"admin"}),
        groups=frozenset(groups or {"secops"}),
    )


async def new_connection(
    session: Any, services: Any, tenant_id: uuid.UUID, kind: str = "sample_scanner", slug: str | None = None
) -> Any:
    return await create_connection(
        session,
        tenant_id,
        kind=kind,
        slug=slug or f"{kind}-{uuid.uuid4().hex[:6]}",
        display_name="Sample",
        config={"base_url": "http://127.0.0.1:9", "allow_plain_http_loopback": True},
        secrets={"api_token": "test-token"},
        caller=caller_for(tenant_id),
        registry=REGISTRY,
        broker=services.broker,
    )


def finding(uid: str, *, cve: str = "CVE-2026-0001", purl: str = "pkg:pypi/requests@2.31.0",
            updated: int = 1_700_000_000_000, **extra: Any) -> dict[str, Any]:
    return {"uid": uid, "cve": cve, "purl": purl, "updated": updated, "title": f"finding {uid}", **extra}


def vendor_transport(state: dict[str, Any]) -> RouteTransport:
    """RouteTransport implementing the sample vendor with mutable state for assertions."""

    def findings(request: Any) -> dict[str, Any]:
        return {"status": 200, "json": {"items": state.get("findings", [])}}

    def list_issues(request: Any) -> dict[str, Any]:
        route_key = request.url.params.get("route_key")
        items = [i for i in state["issues"] if not route_key or i.get("route_key") == route_key]
        return {"status": 200, "json": {"items": items}}

    def create_issue(request: Any) -> dict[str, Any]:
        if state.get("create_fails"):
            return {"status": 500, "json": {"error": "boom"}}
        key = f"ISSUE-{len(state['issues']) + 1}"
        import json  # noqa: PLC0415

        body = json.loads(request.content)
        issue = {"key": key, "id": key, "url": f"http://vendor/{key}", **body}
        state["issues"].append(issue)
        return {"status": 200, "json": issue}

    routes: dict[tuple[str, str], Any] = {
        ("GET", "/api/ping"): {"status": 200, "json": {"ok": True}},
        ("GET", "/api/findings"): findings,
        ("GET", "/api/issues"): list_issues,
        ("POST", "/api/issues"): create_issue,
        ("GET", "/api/tickets"): lambda request: {"status": 200, "json": {"items": state.get("tickets", [])}},
        ("DELETE", "/api/issues/ISSUE-1"): {"status": 200, "json": {"deleted": True}},
    }
    return RouteTransport(routes)
