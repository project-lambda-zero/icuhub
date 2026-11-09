"""CSPM authentication, pagination, and mapping tests."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest
from conftest import cspm_connector, load_fixture
from pydantic import ValidationError

from icuhub.connectors.prisma_cloud import PrismaCloud
from icuhub.connectors.prisma_cloud.models import EmptyInput, RqlInput
from icuhub.kit.errors import VendorContractError
from icuhub.kit.testing import collect_stream, map_all
from icuhub_schemas.ocsf import ApiActivity, ComplianceFinding


def test_config_requires_cspm_credentials() -> None:
    with pytest.raises(ValidationError):
        PrismaCloud.config_model.model_validate({"base_url": "https://api.prismacloud.io", "editions": ["cspm"]})


def test_cspm_session_is_cached_and_refreshed() -> None:
    tokens = iter(("jwt-1", "jwt-2"))
    seen: list[str | None] = []

    def login(_request: Any) -> dict[str, Any]:
        return {"status": 200, "json": {"token": next(tokens), "expires_in": 600}}

    def alerts(request: Any) -> dict[str, Any]:
        seen.append(request.headers.get("x-redlock-auth"))
        return {"status": 200, "json": {"items": [], "nextPageToken": None}}

    connector = cspm_connector({("POST", "/login"): login, ("POST", "/v2/alert"): alerts})
    asyncio.run(connector.list_alerts_v2(EmptyInput()))
    asyncio.run(connector.list_alerts_v2(EmptyInput()))
    assert seen == ["jwt-1", "jwt-1"]
    assert asyncio.run(connector.ctx.http._auth.refresh()) is True
    asyncio.run(connector.list_alerts_v2(EmptyInput()))
    assert seen == ["jwt-1", "jwt-1", "jwt-2"]


def test_alert_stream_requests_details_and_dedupes_overlap() -> None:
    alert = load_fixture("cspm_alert.json")
    bodies: list[dict[str, Any]] = []

    def alerts(request: Any) -> dict[str, Any]:
        bodies.append(json.loads(request.content))
        return {"status": 200, "json": {"items": [alert, alert], "nextPageToken": None}}

    connector = cspm_connector({("POST", "/v2/alert"): alerts})
    batches = collect_stream(connector, "cspm_config_alerts")
    assert bodies[0]["detailed"] is True
    assert [len(batch.records) for batch in batches] == [1]
    assert batches[-1].complete is True
    checkpoint = batches[-1].checkpoint
    assert checkpoint.ts is not None
    assert checkpoint.last_ids_at_ts == ["alert-100"]


def test_alert_stream_rejects_repeated_final_token() -> None:
    alert = load_fixture("cspm_alert.json")

    def alerts(_request: Any) -> dict[str, Any]:
        return {"status": 200, "json": {"items": [alert], "nextPageToken": "same-token"}}

    connector = cspm_connector({("POST", "/v2/alert"): alerts})
    with pytest.raises(VendorContractError, match="page token"):
        collect_stream(connector, "cspm_config_alerts")


def test_rql_continuation_preserves_schema_and_fails_on_downgrade() -> None:
    calls = 0

    def search(_request: Any) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        if calls == 1:
            return {"status": 200, "json": {"data": {"items": [{"id": "r1"}], "nextPageToken": "next", "metadata": {"schema": "v2"}}}}
        return {"status": 200, "json": {"data": {"items": []}}}

    connector = cspm_connector({("POST", "/v2/config"): search})
    with pytest.raises(VendorContractError, match="metadata|schema"):
        asyncio.run(connector.search_config_v2(RqlInput(query="config from cloud.resource")))


def test_config_alert_maps_to_valid_compliance_finding() -> None:
    connector = cspm_connector({})
    mapped = map_all(connector, "cspm_config_alerts", [load_fixture("cspm_alert.json")])
    assert len(mapped) == 1
    finding = mapped[0]
    assert isinstance(finding, ComplianceFinding)
    assert finding.class_uid == 2003
    assert finding.finding_info.uid == "alert-100"
    assert finding.severity_id == 4
    assert finding.status_id == 1
    assert finding.compliance.control == "policy-1"
    assert finding.resources is not None and finding.resources[0].uid.startswith("rrn::")
    finding.to_ocsf()


def test_detection_mapper_rejects_unclassified_policy_type() -> None:
    connector = cspm_connector({})
    assert map_all(connector, "cspm_detection_alerts", [load_fixture("cspm_alert.json")]) == []


def test_cloud_account_maps_to_ocsf_shaped_source_record() -> None:
    connector = cspm_connector({})
    mapped = map_all(connector, "cspm_cloud_accounts", [load_fixture("cspm_account.json")])
    assert len(mapped) == 1
    record = mapped[0]
    assert record.record_type == "cloud_account"
    assert record.data["class_uid"] == 3004
    assert record.data["account"]["uid"] == "123456789012"


def test_audit_event_maps_to_api_activity() -> None:
    connector = cspm_connector({})
    raw = {"id": "event-1", "timestamp": 1794150000000, "account": "123456789012", "user": "auditor", "resourceType": "alert", "resourceId": "alert-100", "action": "UPDATE", "status": "success"}
    mapped = map_all(connector, "cspm_audit_events", [raw])
    assert len(mapped) == 1
    assert isinstance(mapped[0], ApiActivity)
    mapped[0].to_ocsf()
