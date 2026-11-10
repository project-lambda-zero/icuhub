"""Live Prisma Cloud acceptance for independent CSPM and Compute profiles."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import httpx2

from icuhub.connectors.prisma_cloud import PrismaCloud
from icuhub.connectors.prisma_cloud.models import (
    AlertIdInput,
    AlertListInput,
    ComputeQueryInput,
    DismissAlertInput,
    EmptyInput,
    IncidentInput,
    ReopenAlertInput,
    SnoozeAlertInput,
    VulnerabilityExportInput,
)
from icuhub.kit.testing import make_connector, map_all

ACCEPTANCE_KIND = "prisma_cloud"


def _connector(acceptance) -> PrismaCloud:
    return make_connector(PrismaCloud, acceptance.config, httpx2.AsyncHTTPTransport(), acceptance.secrets)  # type: ignore[return-value]


def test_health_and_discovery(acceptance) -> None:
    connector = _connector(acceptance)
    report = asyncio.run(connector.check())
    acceptance.record("health", report.status == "healthy", report.status, editions=report.detail.get("editions"))
    assert report.status == "healthy"
    if "cspm" in acceptance.config.get("editions", []):
        targets = []

        async def collect() -> None:
            async for target in connector.discover():
                targets.append(target)

        asyncio.run(collect())
        acceptance.record("cspm_account_discovery", True, f"{len(targets)} accounts")


def test_cspm_reads(acceptance) -> None:
    if "cspm" not in acceptance.config.get("editions", []):
        acceptance.record("cspm_reads", True, "not_evaluated: CSPM edition disabled")
        return
    connector = _connector(acceptance)
    alerts = asyncio.run(connector.list_alerts_v2(AlertListInput(limit=1, detailed=True)))
    acceptance.record("list_alerts_v2", True, f"{len(alerts.items)} alert on first page")
    alert_id = acceptance.params.get("alert_id") or (alerts.items[0].get("id") if alerts.items else None)
    if alert_id:
        detail = asyncio.run(connector.get_alert(AlertIdInput(alert_id=str(alert_id))))
        acceptance.record("get_alert", isinstance(detail.data, dict), str(alert_id))


def test_cspm_vulnerability_export(acceptance) -> None:
    if "cspm" not in acceptance.config.get("editions", []):
        acceptance.record("cspm_vulnerability_export", True, "not_evaluated: CSPM edition disabled")
        return
    query = acceptance.params.get("vulnerability_query")
    if not query:
        acceptance.record(
            "cspm_vulnerability_export",
            True,
            "not_evaluated: set vulnerability_query to an authorized full-export RQL query",
        )
        return
    connector = _connector(acceptance)
    exported = asyncio.run(connector.download_vulnerability_export(VulnerabilityExportInput(query=query)))
    mapped = map_all(connector, "cspm_vulnerability_export", exported.items)
    passed = exported.complete and len(mapped) == len(exported.items)
    acceptance.record(
        "cspm_vulnerability_export",
        passed,
        f"{len(exported.items)} impacted-asset rows across {len(exported.data['downloads'])} CVE downloads",
    )
    assert passed


def test_compute_reads(acceptance) -> None:
    if "compute" not in acceptance.config.get("editions", []):
        acceptance.record("compute_reads", True, "not_evaluated: Compute edition disabled")
        return
    connector = _connector(acceptance)
    version = asyncio.run(connector.get_compute_version(EmptyInput()))
    acceptance.record("compute_version", isinstance(version.data, dict), str(version.data.get("version")))
    collections = asyncio.run(connector.list_collections(ComputeQueryInput(limit=1)))
    acceptance.record("list_collections", True, f"{len(collections.items)} collection on first page")


def test_cspm_suppression_read_back(acceptance) -> None:
    if "cspm" not in acceptance.config.get("editions", []):
        acceptance.record("cspm_suppression", True, "not_evaluated: CSPM edition disabled")
        return
    acceptance.require_writes()
    alert_id = str(acceptance.params["alert_id"])
    connector = _connector(acceptance)
    note = "ICUHUB live acceptance suppression"
    dismiss_plan = asyncio.run(connector.plan_dismiss_alert(DismissAlertInput(alert_id=alert_id, note=note)))
    dismissed = asyncio.run(connector.apply_dismiss_alert(dismiss_plan))
    acceptance.record("dismiss_alert", dismissed.status in {"succeeded", "no_op"}, dismissed.status)
    assert dismissed.status in {"succeeded", "no_op"}
    snooze_until = datetime.now(UTC) + timedelta(minutes=10)
    snooze_plan = asyncio.run(connector.plan_snooze_alert(SnoozeAlertInput(alert_id=alert_id, dismiss_until=snooze_until, note=note)))
    snoozed = asyncio.run(connector.apply_snooze_alert(snooze_plan))
    acceptance.record("snooze_alert", snoozed.status in {"succeeded", "no_op"}, snoozed.status)
    assert snoozed.status in {"succeeded", "no_op"}
    reopen_plan = asyncio.run(connector.plan_reopen_alert(ReopenAlertInput(alert_id=alert_id, note="ICUHUB acceptance cleanup")))
    reopened = asyncio.run(connector.apply_reopen_alert(reopen_plan))
    acceptance.record("reopen_alert", reopened.status in {"succeeded", "no_op"}, reopened.status)
    assert reopened.status in {"succeeded", "no_op"}


def test_compute_incident_read_back(acceptance) -> None:
    if "compute" not in acceptance.config.get("editions", []):
        acceptance.record("compute_incident", True, "not_evaluated: Compute edition disabled")
        return
    acceptance.require_writes()
    incident_id = str(acceptance.params["incident_id"])
    connector = _connector(acceptance)
    ack_plan = asyncio.run(connector.plan_acknowledge_incident(IncidentInput(incident_id=incident_id)))
    acknowledged = asyncio.run(connector.apply_acknowledge_incident(ack_plan))
    acceptance.record("acknowledge_incident", acknowledged.status in {"succeeded", "no_op"}, acknowledged.status)
    assert acknowledged.status in {"succeeded", "no_op"}
    unack_plan = asyncio.run(connector.plan_unacknowledge_incident(IncidentInput(incident_id=incident_id)))
    unacknowledged = asyncio.run(connector.apply_unacknowledge_incident(unack_plan))
    acceptance.record("unacknowledge_incident", unacknowledged.status in {"succeeded", "no_op"}, unacknowledged.status)
    assert unacknowledged.status in {"succeeded", "no_op"}
