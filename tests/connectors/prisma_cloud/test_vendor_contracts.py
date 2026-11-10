"""Behavioral regression tests for validated Prisma Cloud vendor contracts."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from typing import Any, cast

import pytest

from icuhub.connectors.prisma_cloud import PrismaCloud
from icuhub.connectors.prisma_cloud.models import (
    AlertListInput,
    CollectionInput,
    ComputeQueryInput,
    IncidentInput,
    RemediateAlertInput,
    ReopenAlertInput,
    ResourceInput,
    RqlInput,
    RuntimeTimesliceInput,
    SnoozeAlertInput,
    StartRegistryScanInput,
    VulnerabilitySearchInput,
)
from icuhub.kit.cursors import TimeIdCursor, TimeIdSnapshotCursor
from icuhub.kit.errors import ConfigError, VendorContractError
from icuhub.kit.testing import RouteTransport, collect_stream, make_connector, map_all

from .conftest import (
    COMPUTE_CONFIG,
    COMPUTE_LOGIN,
    CSPM_CONFIG,
    CSPM_LOGIN,
    SECRETS,
    compute_connector,
    cspm_connector,
    load_fixture,
)


def cspm_with(routes: dict[tuple[str, str], Any], **overrides: Any) -> PrismaCloud:
    routes.setdefault(("POST", "/login"), CSPM_LOGIN)
    return cast(
        PrismaCloud,
        make_connector(
            PrismaCloud,
            {**CSPM_CONFIG, **overrides},
            RouteTransport(routes),
            SECRETS,
        ),
    )


def compute_with(routes: dict[tuple[str, str], Any], **overrides: Any) -> PrismaCloud:
    routes.setdefault(("POST", "/api/v1/authenticate"), COMPUTE_LOGIN)
    return cast(
        PrismaCloud,
        make_connector(
            PrismaCloud,
            {**COMPUTE_CONFIG, **overrides},
            RouteTransport(routes),
            SECRETS,
        ),
    )


def test_alert_total_rows_anomaly_does_not_advance_full_snapshot() -> None:
    alert = load_fixture("cspm_alert.json")
    committed = TimeIdSnapshotCursor(
        ts=None,
        overlap_s=0,
        snapshot_id="committed-snapshot",
        snapshot_started_at=datetime(2026, 11, 8, tzinfo=UTC),
    )
    connector = cspm_connector(
        {
            ("POST", "/v2/alert"): {
                "status": 200,
                "json": {"items": [alert], "nextPageToken": None, "totalRows": 2},
            }
        }
    )
    batches = collect_stream(
        connector,
        "cspm_config_alerts",
        checkpoint=committed,
        mode="full",
    )
    assert len(batches) == 1
    assert batches[0].records == [alert]
    assert batches[0].complete is False
    checkpoint = batches[0].checkpoint
    assert isinstance(checkpoint, TimeIdSnapshotCursor)
    assert checkpoint.snapshot_id == "committed-snapshot"


def test_complete_alert_full_snapshot_has_run_identity() -> None:
    alert = load_fixture("cspm_alert.json")
    connector = cspm_connector(
        {
            ("POST", "/v2/alert"): {
                "status": 200,
                "json": {"items": [alert], "nextPageToken": None, "totalRows": 1},
            }
        }
    )
    batches = collect_stream(connector, "cspm_config_alerts", mode="full")
    assert batches[-1].complete is True
    checkpoint = batches[-1].checkpoint
    assert isinstance(checkpoint, TimeIdSnapshotCursor)
    assert checkpoint.snapshot_id
    assert checkpoint.snapshot_started_at == datetime(2026, 11, 9, tzinfo=UTC)


def test_alert_list_uses_absolute_time_range_object() -> None:
    bodies: list[dict[str, Any]] = []

    def alerts(request: Any) -> dict[str, Any]:
        bodies.append(json.loads(request.content))
        return {"status": 200, "json": {"items": [], "nextPageToken": None, "totalRows": 0}}

    connector = cspm_connector({("POST", "/v2/alert"): alerts})
    result = asyncio.run(
        connector.list_alerts_v2(AlertListInput(start_time_ms=1000, end_time_ms=2000))
    )
    assert result.complete is True
    assert bodies[0]["timeRange"] == {
        "type": "absolute",
        "value": {"startTime": 1000, "endTime": 2000},
    }


def test_audit_completeness_uses_raw_page_length_before_dedupe() -> None:
    first = {"id": "event-1", "timestamp": 1794150000000}
    second = {"id": "event-2", "timestamp": 1794150001000}
    offsets: list[int] = []

    def audit(request: Any) -> dict[str, Any]:
        offset = int(request.url.params["offset"])
        offsets.append(offset)
        items = [first, dict(first)] if offset == 0 else [second]
        return {"status": 200, "json": items}

    connector = cspm_with({("GET", "/audit/redlock"): audit}, page_size=2)
    batches = collect_stream(connector, "cspm_audit_events")
    assert offsets == [0, 2]
    assert [batch.complete for batch in batches] == [False, True]
    assert [record["id"] for batch in batches for record in batch.records] == [
        "event-1",
        "event-2",
    ]
    first_checkpoint = batches[0].checkpoint
    second_checkpoint = batches[1].checkpoint
    assert isinstance(first_checkpoint, TimeIdCursor)
    assert isinstance(second_checkpoint, TimeIdCursor)
    assert first_checkpoint.ts is None
    assert second_checkpoint.ts == datetime.fromtimestamp(1794150001, tz=UTC)


def test_rql_continuation_uses_page_token_only_and_preserves_metadata() -> None:
    bodies: list[tuple[str, dict[str, Any]]] = []

    def first(request: Any) -> dict[str, Any]:
        bodies.append((request.url.path, json.loads(request.content)))
        return {
            "status": 200,
            "json": {
                "data": {
                    "items": [{"id": "r1"}],
                    "nextPageToken": "next",
                    "metadata": {"schema": "v2"},
                }
            },
        }

    def continuation(request: Any) -> dict[str, Any]:
        bodies.append((request.url.path, json.loads(request.content)))
        return {
            "status": 200,
            "json": {
                "data": {
                    "items": [],
                    "nextPageToken": None,
                    "metadata": {"schema": "v2"},
                }
            },
        }

    connector = cspm_connector(
        {
            ("POST", "/search/api/v2/config"): first,
            ("POST", "/search/config/page"): continuation,
        }
    )
    result = asyncio.run(
        connector.search_config_v2(
            RqlInput(
                query="config from cloud.resource",
                limit=1,
                time_range={"type": "to_now", "value": "epoch"},
            )
        )
    )
    assert result.items == [{"id": "r1"}]
    assert result.complete is True
    assert bodies == [
        (
            "/search/api/v2/config",
            {
                "query": "config from cloud.resource",
                "limit": 1,
                "timeRange": {"type": "to_now", "value": "epoch"},
            },
        ),
        ("/search/config/page", {"pageToken": "next"}),
    ]


def test_unfiltered_get_resource_is_rejected_before_vendor_query() -> None:
    connector = cspm_connector({})
    with pytest.raises(ConfigError, match="resource_id, rrn, or query"):
        asyncio.run(connector.get_resource(ResourceInput()))


def test_snooze_uses_dismissal_end_time_and_reads_back_expiry() -> None:
    alert = load_fixture("cspm_alert.json")
    expiry = datetime(2026, 12, 1, tzinfo=UTC)
    expiry_ms = int(expiry.timestamp() * 1000)
    snoozed = {**alert, "status": "snoozed", "dismissalUntilTs": expiry_ms}
    states = iter((alert, alert, snoozed))
    bodies: list[dict[str, Any]] = []

    def dismiss(request: Any) -> dict[str, Any]:
        bodies.append(json.loads(request.content))
        return {"status": 200, "json": {}}

    connector = cspm_connector(
        {
            ("GET", "/alert/alert-100"): lambda _request: {
                "status": 200,
                "json": next(states),
            },
            ("POST", "/alert/dismiss"): dismiss,
        }
    )
    plan = asyncio.run(
        connector.plan_snooze_alert(
            SnoozeAlertInput(
                alert_id="alert-100",
                dismiss_until=expiry,
                note="approved maintenance",
            )
        )
    )
    outcome = asyncio.run(connector.apply_snooze_alert(plan))
    assert outcome.status == "succeeded"
    assert bodies == [
        {
            "alerts": ["alert-100"],
            "dismissalNote": "approved maintenance",
            "dismissalTimeRange": {
                "type": "absolute",
                "value": {"endTime": expiry_ms},
            },
        }
    ]


def test_snooze_beyond_configured_window_is_rejected() -> None:
    connector = cspm_connector({})
    with pytest.raises(ConfigError, match="30-day window"):
        asyncio.run(
            connector.plan_snooze_alert(
                SnoozeAlertInput(
                    alert_id="alert-100",
                    dismiss_until=datetime(2027, 2, 1, tzinfo=UTC),
                    note="too long",
                )
            )
        )


def test_reopen_refuses_resolved_alert() -> None:
    alert = {**load_fixture("cspm_alert.json"), "status": "resolved"}
    connector = cspm_connector(
        {("GET", "/alert/alert-100"): {"status": 200, "json": alert}}
    )
    with pytest.raises(ConfigError, match="cannot be reopened"):
        asyncio.run(connector.plan_reopen_alert(ReopenAlertInput(alert_id="alert-100")))


def test_remediation_requires_preview_and_applies_empty_patch() -> None:
    alert = load_fixture("cspm_alert.json")
    resolved = {**alert, "status": "resolved"}
    states = iter((alert, alert, resolved))
    patch_bodies: list[bytes] = []

    def remediate(request: Any) -> dict[str, Any]:
        patch_bodies.append(bytes(request.content))
        return {"status": 200, "json": {}}

    connector = cspm_with(
        {
            ("GET", "/alert/alert-100"): lambda _request: {
                "status": 200,
                "json": next(states),
            },
            ("POST", "/alert/remediation"): {
                "status": 200,
                "json": {"items": [{"command": "storage remediation command"}]},
            },
            ("PATCH", "/alert/remediation/alert-100"): remediate,
        },
        destructive_enabled=True,
    )
    plan = asyncio.run(
        connector.plan_remediate_alert(
            RemediateAlertInput(alert_id="alert-100", approved=True)
        )
    )
    assert plan.diff["payload"]["remediation"]["command"] == "storage remediation command"
    assert plan.request["payload"] is None
    outcome = asyncio.run(connector.apply_remediate_alert(plan))
    assert outcome.status == "succeeded"
    assert patch_bodies == [b""]


def test_uve_search_uses_query_token_and_reports_incomplete_page() -> None:
    requests: list[tuple[str | None, dict[str, Any]]] = []

    def search(request: Any) -> dict[str, Any]:
        requests.append((request.url.params.get("page_token"), json.loads(request.content)))
        return {
            "status": 200,
            "json": {
                "data": {
                    "totalRows": 2,
                    "items": [{"cveId": "CVE-2026-0001"}],
                    "nextPageToken": "next-cve",
                }
            },
        }

    connector = cspm_connector(
        {("POST", "/uve/api/v1/vulnerabilities/search"): search}
    )
    result = asyncio.run(
        connector.search_vulnerabilities(
            VulnerabilitySearchInput(
                query="vulnerability where age > 30 days",
                page_token="current",
            )
        )
    )
    assert result.complete is False
    assert result.next_page_token == "next-cve"
    assert result.total == 2
    assert requests == [("current", {"query": "vulnerability where age > 30 days"})]


def test_uve_search_rejects_truncation_without_token() -> None:
    connector = cspm_connector(
        {
            ("POST", "/uve/api/v1/vulnerabilities/search"): {
                "status": 200,
                "json": {
                    "data": {
                        "totalRows": 2,
                        "items": [{"cveId": "CVE-2026-0001"}],
                        "nextPageToken": None,
                    }
                },
            }
        }
    )
    with pytest.raises(VendorContractError, match="truncated without nextPageToken"):
        asyncio.run(
            connector.search_vulnerabilities(
                VulnerabilitySearchInput(query="vulnerability where age > 30 days")
            )
        )


def test_compute_assets_dedupe_identical_acknowledgment_partitions() -> None:
    image = load_fixture("compute_image.json")
    requests: list[Any] = []

    def images(request: Any) -> dict[str, Any]:
        requests.append(request)
        return {"status": 200, "json": [image]}

    connector = compute_connector({("GET", "/api/v1/images"): images})
    batches = collect_stream(connector, "compute_image_vulnerabilities", mode="full")
    records = [record for batch in batches for record in batch.records]
    assert len(records) == 1
    assert [request.url.params["acknowledged"] for request in requests] == ["false", "true"]
    assert all(request.url.params["compact"] == "false" for request in requests)
    assert batches[-1].complete is True


def test_compute_partition_mutation_fails_snapshot() -> None:
    image = load_fixture("compute_image.json")

    def images(request: Any) -> dict[str, Any]:
        changed = {
            **image,
            "scanTime": request.url.params["acknowledged"],
        }
        return {"status": 200, "json": [changed]}

    connector = compute_connector({("GET", "/api/v1/images"): images})
    with pytest.raises(VendorContractError, match="changed while reading"):
        collect_stream(connector, "compute_image_vulnerabilities", mode="full")


def test_compute_full_duplicate_page_fails_forward_progress() -> None:
    image = load_fixture("compute_image.json")
    other = {**image, "_id": "sha256:bbbb"}
    calls = 0

    def images(_request: Any) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        return {"status": 200, "json": [image, other]}

    connector = compute_with({("GET", "/api/v1/images"): images}, page_size=2)
    with pytest.raises(VendorContractError, match="repeated known records"):
        collect_stream(connector, "compute_image_vulnerabilities", mode="full")
    assert calls == 2


def test_compute_runtime_full_snapshot_has_identity_and_stable_audit_id() -> None:
    audit = load_fixture("compute_audit.json")
    connector = compute_connector(
        {("GET", "/api/v1/audits/runtime/container"): {"status": 200, "json": [audit]}}
    )
    batches = collect_stream(connector, "compute_runtime_container_audits", mode="full")
    assert len(batches) == 1
    assert batches[0].complete is True
    assert batches[0].records[0]["_audit_uid"] == "audit-1"
    checkpoint = batches[0].checkpoint
    assert isinstance(checkpoint, TimeIdSnapshotCursor)
    assert checkpoint.snapshot_id
    assert checkpoint.snapshot_started_at == datetime(2026, 11, 9, tzinfo=UTC)


def test_compute_runtime_rejects_missing_source_time() -> None:
    audit = load_fixture("compute_audit.json")
    del audit["time"]
    connector = compute_connector(
        {("GET", "/api/v1/audits/runtime/container"): {"status": 200, "json": [audit]}}
    )
    with pytest.raises(VendorContractError, match="no valid time or timestamp"):
        collect_stream(connector, "compute_runtime_container_audits")


def test_waas_and_timeslice_use_documented_per_family_paths() -> None:
    waas_paths = [
        "/audits/firewall/app/host",
        "/audits/firewall/app/agentless",
        "/audits/firewall/app/app-embedded",
        "/audits/firewall/app/serverless",
        "/audits/firewall/app/container",
    ]
    seen: list[str] = []

    def waas(request: Any) -> dict[str, Any]:
        seen.append(request.url.path)
        assert "acknowledged" not in request.url.params
        return {"status": 200, "json": []}

    routes: dict[tuple[str, str], Any] = {
        ("GET", f"/api/v1{path}"): waas for path in waas_paths
    }
    routes[("GET", "/api/v1/audits/runtime/host/timeslice")] = {
        "status": 200,
        "json": {"buckets": []},
    }
    connector = compute_connector(routes)
    result = asyncio.run(connector.get_waas_alerts(ComputeQueryInput()))
    assert result.complete is True
    assert result.pages == 5
    assert seen == [f"/api/v1{path}" for path in waas_paths]
    timeslice = asyncio.run(
        connector.get_runtime_timeslice(
            RuntimeTimesliceInput(audit_type="host", start_time_ms=1, end_time_ms=2)
        )
    )
    assert timeslice.data == {"buckets": []}


def registry_image(scan_time: str) -> dict[str, Any]:
    return {
        "_id": "sha256:aaaaaaaa",
        "cloudType": "aws",
        "repoTag": {"registry": "registry.example", "repo": "team/service", "tag": "1.2.3"},
        "scanTime": scan_time,
    }


def registry_args(on_demand: bool = True) -> StartRegistryScanInput:
    return StartRegistryScanInput(
        registry="registry.example",
        repository="team/service",
        digest="sha256:aaaaaaaa",
        tag="1.2.3",
        on_demand=on_demand,
    )


def test_on_demand_registry_scan_requires_new_result_evidence() -> None:
    old = registry_image("2026-11-08T23:00:00Z")
    new = registry_image("2026-11-09T00:01:00Z")
    results = iter(([old], [new]))
    writes: list[Any] = []

    def registry(_request: Any) -> dict[str, Any]:
        return {"status": 200, "json": next(results)}

    def scan(request: Any) -> dict[str, Any]:
        writes.append(request)
        return {"status": 202, "json": {}}

    connector = compute_connector(
        {
            ("GET", "/api/v1/registry"): registry,
            ("POST", "/api/v1/registry/scan"): scan,
        }
    )
    plan = asyncio.run(connector.plan_start_registry_scan(registry_args()))
    accepted = asyncio.run(connector.apply_start_registry_scan(plan))
    assert accepted.status == "accepted_async"
    final = asyncio.run(connector.reconcile_start_registry_scan(plan, accepted))
    assert final.status == "succeeded"
    assert json.loads(writes[0].content) == {
        "tag": {
            "registry": "registry.example",
            "repo": "team/service",
            "digest": "sha256:aaaaaaaa",
            "tag": "1.2.3",
        },
        "onDemandScan": True,
    }
    assert json.loads(writes[0].headers["x-prisma-cloud-target-env"]) == {
        "permission": "monitorImages"
    }


def test_preexisting_registry_result_does_not_prove_new_scan() -> None:
    old = registry_image("2026-11-08T23:00:00Z")
    connector = compute_connector(
        {
            ("GET", "/api/v1/registry"): {"status": 200, "json": [old]},
            ("POST", "/api/v1/registry/scan"): {"status": 202, "json": {}},
        }
    )
    plan = asyncio.run(connector.plan_start_registry_scan(registry_args()))
    accepted = asyncio.run(connector.apply_start_registry_scan(plan))
    final = asyncio.run(connector.reconcile_start_registry_scan(plan, accepted))
    assert final.status == "unverified"


def test_regular_registry_scan_requires_new_completed_status() -> None:
    old = registry_image("2026-11-08T23:00:00Z")
    new = registry_image("2026-11-09T00:01:00Z")
    statuses = iter(
        (
            {"completed": True, "scanTime": old["scanTime"]},
            {"completed": True, "scanTime": old["scanTime"]},
            {"completed": True, "scanTime": new["scanTime"]},
        )
    )
    scans: list[Any] = []

    def scan(request: Any) -> dict[str, Any]:
        scans.append(request)
        return {"status": 202, "json": {}}

    connector = compute_connector(
        {
            ("GET", "/api/v1/statuses/registry"): lambda _request: {
                "status": 200,
                "json": next(statuses),
            },
            ("GET", "/api/v1/registry"): {"status": 200, "json": [new]},
            ("POST", "/api/v1/registry/scan"): scan,
        }
    )
    plan = asyncio.run(connector.plan_start_registry_scan(registry_args(on_demand=False)))
    assert scans == []
    accepted = asyncio.run(connector.apply_start_registry_scan(plan))
    final = asyncio.run(connector.reconcile_start_registry_scan(plan, accepted))
    assert final.status == "succeeded"
    assert json.loads(scans[0].content) == {
        "tag": {
            "registry": "registry.example",
            "repo": "team/service",
            "digest": "sha256:aaaaaaaa",
            "tag": "1.2.3",
        }
    }


@pytest.mark.parametrize(
    ("after_write", "expected"),
    [(True, "succeeded"), (False, "failed"), (None, "unverified")],
)
def test_incident_acknowledgment_read_back_taxonomy(
    after_write: bool | None,
    expected: str,
) -> None:
    state: dict[str, Any] = {"acknowledged": False}
    writes: list[Any] = []

    def incidents(request: Any) -> dict[str, Any]:
        acknowledged = request.url.params["acknowledged"] == "true"
        if state["acknowledged"] is acknowledged:
            return {
                "status": 200,
                "json": [{"_id": "incident-1", "acknowledged": acknowledged}],
            }
        return {"status": 200, "json": []}

    def acknowledge(request: Any) -> dict[str, Any]:
        writes.append(request)
        state["acknowledged"] = after_write
        return {"status": 200, "json": {}}

    connector = compute_connector(
        {
            ("GET", "/api/v1/audits/incidents"): incidents,
            ("PATCH", "/api/v1/audits/incidents/acknowledge/incident-1"): acknowledge,
        }
    )
    plan = asyncio.run(
        connector.plan_acknowledge_incident(IncidentInput(incident_id="incident-1"))
    )
    outcome = asyncio.run(connector.apply_acknowledge_incident(plan))
    assert outcome.status == expected
    assert json.loads(writes[0].content) == {"acknowledged": True}
    assert json.loads(writes[0].headers["x-prisma-cloud-target-env"]) == {
        "permission": "monitorRuntimeIncidents"
    }


def test_collection_create_reads_list_and_reads_back_exact_name() -> None:
    current: list[dict[str, Any]] = []

    def collections(_request: Any) -> dict[str, Any]:
        return {"status": 200, "json": current}

    def create(request: Any) -> dict[str, Any]:
        current.append(json.loads(request.content))
        return {"status": 201, "json": {}}

    connector = compute_connector(
        {
            ("GET", "/api/v1/collections"): collections,
            ("POST", "/api/v1/collections"): create,
        }
    )
    args = CollectionInput(
        name="Team scope",
        description="Approved scope",
        color="#112233",
        resources={"hosts": ["host.example"]},
    )
    plan = asyncio.run(connector.plan_create_or_update_collection(args))
    outcome = asyncio.run(connector.apply_create_or_update_collection(plan))
    assert outcome.status == "succeeded"
    assert outcome.result["collection"]["name"] == "Team scope"


def test_mapper_requires_cloud_provider_evidence() -> None:
    audit = load_fixture("compute_audit.json")
    del audit["cloudType"]
    connector = compute_connector({})
    with pytest.raises(VendorContractError, match="no cloud provider evidence"):
        map_all(connector, "compute_runtime_container_audits", [audit])
