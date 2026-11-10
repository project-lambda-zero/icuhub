"""Jira OAuth refresh-token rotation through the real credential broker."""

from __future__ import annotations

import asyncio
import json
import uuid
from typing import Any

from icuhub.kit.testing import RouteTransport
from icuhub.kit.types import SecretRef
from icuhub.storage.db import session_scope
from icuhub.storage.models import Tenant
from tests.core.helpers import make_services, new_connection


def test_jira_rotated_refresh_token_is_durable_for_a_fresh_connector(
    tmp_path: Any,
    clean_database: None,
) -> None:
    grants: list[dict[str, Any]] = []
    api_auth: list[str | None] = []
    responses = iter(
        (
            {"access_token": "at-1", "refresh_token": "rt-2", "expires_in": 3600},
            {"access_token": "at-2", "expires_in": 3600},
        )
    )

    def token(request: Any) -> dict[str, Any]:
        grants.append(json.loads(request.content))
        return {"status": 200, "json": next(responses)}

    def myself(request: Any) -> dict[str, Any]:
        api_auth.append(request.headers.get("authorization"))
        return {"status": 200, "json": {"accountId": "service-account"}}

    transport = RouteTransport(
        {
            ("POST", "/oauth/token"): token,
            ("GET", "/ex/jira/cloud-1/rest/api/3/myself"): myself,
        }
    )

    async def scenario() -> None:
        services = make_services(transport, tmp_path / "kek")
        tenant_id = uuid.uuid4()
        config = {
            "base_url": "https://api.atlassian.com/ex/jira/cloud-1",
            "auth_method": "oauth2_3lo",
            "cloud_id": "cloud-1",
            "client_id": "synthetic-client",
        }
        async with session_scope(tenant_id) as session:
            session.add(Tenant(id=tenant_id, slug=f"t-{tenant_id.hex[:8]}", display_name="T"))
            await session.flush()
            connection = await new_connection(
                session,
                services,
                tenant_id,
                kind="jira_cloud",
                config=config,
                secrets={"client_secret": "client-secret", "refresh_token": "rt-1"},
            )
            refresh_ref = SecretRef(ref=connection.config_json["refresh_token"]["ref"])

        async with session_scope(tenant_id) as session:
            connector = await services.runtime.open(session, tenant_id, connection.id)
            report = await connector.check()
            assert report.status == "healthy"

        async with session_scope(tenant_id) as session:
            persisted = await services.broker.resolve(tenant_id, refresh_ref, session=session)
            assert persisted == b"rt-2"
            fresh = await services.runtime.open(session, tenant_id, connection.id)
            report = await fresh.check()
            assert report.status == "healthy"

        assert [grant["refresh_token"] for grant in grants] == ["rt-1", "rt-2"]
        assert api_auth == ["Bearer at-1", "Bearer at-2"]

    asyncio.run(scenario())
