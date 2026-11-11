"""Ordered replay tests for documented Prisma Cloud HTTP contracts."""

from __future__ import annotations

import asyncio
import hashlib
from typing import cast

from icuhub.connectors.prisma_cloud import PrismaCloud
from icuhub.connectors.prisma_cloud.models import (
    AlertExportInput,
    DismissAlertInput,
    DownloadExportInput,
    StartRegistryScanInput,
)
from icuhub.kit.testing import RecordedTransport, make_connector

from .conftest import COMPUTE_CONFIG, CSPM_CONFIG, FIXTURES, SECRETS


def test_registry_scan_recorded_contract() -> None:
    transport = RecordedTransport(
        cassette_path=FIXTURES / "cassettes" / "compute_registry_scan.json"
    )
    connector = cast(
        PrismaCloud,
        make_connector(PrismaCloud, COMPUTE_CONFIG, transport, SECRETS),
    )
    plan = asyncio.run(
        connector.plan_start_registry_scan(
            StartRegistryScanInput(
                registry="registry.example",
                repository="team/service",
                digest="sha256:aaaaaaaa",
                tag="1.2.3",
                on_demand=True,
            )
        )
    )
    accepted = asyncio.run(connector.apply_start_registry_scan(plan))
    assert accepted.status == "accepted_async"
    final = asyncio.run(connector.reconcile_start_registry_scan(plan, accepted))
    assert final.status == "succeeded"
    transport.assert_all_used()


def test_dismiss_recorded_contract() -> None:
    transport = RecordedTransport(cassette_path=FIXTURES / "cassettes" / "cspm_dismiss.json")
    connector = cast(
        PrismaCloud,
        make_connector(PrismaCloud, CSPM_CONFIG, transport, SECRETS),
    )
    plan = asyncio.run(
        connector.plan_dismiss_alert(
            DismissAlertInput(alert_id="alert-100", note="approved")
        )
    )
    outcome = asyncio.run(connector.apply_dismiss_alert(plan))
    assert outcome.status == "succeeded"
    transport.assert_all_used()


def test_alert_export_recorded_contract() -> None:
    transport = RecordedTransport(
        cassette_path=FIXTURES / "cassettes" / "cspm_alert_export.json"
    )
    connector = cast(
        PrismaCloud,
        make_connector(PrismaCloud, CSPM_CONFIG, transport, SECRETS),
    )
    submitted = asyncio.run(connector.submit_alert_export(AlertExportInput(format="json")))
    assert submitted.data == {"jobId": "job-1"}
    download = asyncio.run(
        connector.download_alert_export(DownloadExportInput(job_id="job-1", format="json"))
    )
    assert download.records == [{"id": "alert-100"}]
    assert download.sha256 == hashlib.sha256(b'[{"id":"alert-100"}]').hexdigest()
    assert download.media_type == "application/json"
    assert download.complete is True
    transport.assert_all_used()
