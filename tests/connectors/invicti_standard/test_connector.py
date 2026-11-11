"""Offline Invicti Standard behavior tests."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from icuhub.connectors.invicti_standard import InvictiStandard, ParseReportArgs
from icuhub.kit.errors import ConfigError, WebhookRejected
from icuhub.kit.testing import RouteTransport, collect_stream, make_connector, map_all
from icuhub.kit.types import ImportedFile, WebhookDelivery

_FIXTURES = Path(__file__).parents[2] / "fixtures" / "invicti_standard"


def _connector(tmp_path: Path | None = None, *, webhook_mode: str = "static_header") -> InvictiStandard:
    files = (str(tmp_path / "report.json"),) if tmp_path is not None else ()
    return make_connector(
        InvictiStandard,
        {
            "base_url": "",
            "report_files": files,
            "website_id": "website-configured-1",
            "website_name": "Blog",
            "webhook_mode": webhook_mode,
        },
        RouteTransport({}),
        {},
    )


def test_json_operation_returns_exact_snapshot_identity() -> None:
    connector = _connector()
    data = (_FIXTURES / "report.json").read_bytes()
    output = asyncio.run(
        connector.parse_report_operation(ParseReportArgs(content_base64=base64.b64encode(data).decode()))
    )
    assert output.report.file_sha256 == hashlib.sha256(data).hexdigest()
    assert output.report.snapshot.snapshot_id == f"{output.report.report_id}:{output.report.file_sha256}"
    assert output.report.vulnerabilities[0].classification.cwe == "79"


def test_unverified_xml_profile_is_not_advertised() -> None:
    connector = _connector()
    with pytest.raises(ConfigError, match="unsupported"):
        connector._parse(b"<InvictiReport />", "invicti_standard_xml")
    assert set(connector.importers()) == {"invicti_json"}


def test_full_report_stream_and_replay_have_stable_complete_snapshot(tmp_path: Path) -> None:
    data = (_FIXTURES / "report.json").read_bytes()
    (tmp_path / "report.json").write_bytes(data)
    connector = _connector(tmp_path)

    first = collect_stream(connector, "report_issues", mode="full")
    replay = collect_stream(connector, "report_issues", mode="replay")

    assert len(first) == 2
    assert first[0].complete is False
    assert first[-1].complete is True
    assert first[0].checkpoint == first[-1].checkpoint
    assert [batch.checkpoint for batch in first] == [batch.checkpoint for batch in replay]
    findings = map_all(connector, "report_issues", first[0].records)
    assert len(findings) == 1
    assert findings[0].class_uid == 2002
    assert findings[0].unmapped["invicti"]["website"]["id"] == "website-configured-1"
    findings[0].to_ocsf()


def test_empty_full_report_configuration_cannot_close_absence() -> None:
    with pytest.raises(ConfigError, match="at least one"):
        collect_stream(_connector(), "report_issues", mode="full")


def test_all_importers_use_the_same_versioned_mapping() -> None:
    connector = _connector()
    for importer, filename in [("invicti_json", "report.json")]:
        imported = ImportedFile(filename=filename, media_type=None, data=(_FIXTURES / filename).read_bytes())

        async def collect() -> list[dict]:
            return [record async for record in connector.importers()[importer].fn(connector, imported)]

        records = asyncio.run(collect())
        assert len(records) == 1
        findings = map_all(connector, "report_issues", records)
        assert len(findings) == 1
        findings[0].to_ocsf()


def test_static_webhook_verifier_and_body_digest_mapping() -> None:
    connector = _connector()
    verifier = connector.webhook_verifier(b"high-entropy-token")
    body = (_FIXTURES / "report.json").read_bytes()
    delivery = WebhookDelivery(
        headers={"x-icuhub-token": "high-entropy-token"},
        body=body,
        received_at=datetime(2026, 11, 10, tzinfo=UTC),
    )
    verifier.verify(delivery, now=delivery.received_at)
    with pytest.raises(WebhookRejected):
        verifier.verify(
            WebhookDelivery(headers={"x-icuhub-token": "wrong"}, body=body, received_at=delivery.received_at),
            now=delivery.received_at,
        )

    records = connector.receive_event(delivery)
    assert records[0].stream == "webhook_issues"
    digest = hashlib.sha256(body).hexdigest()
    assert records[0].raw["delivery"]["delivery_id"] == digest
    assert base64.b64decode(records[0].raw["delivery"]["raw_body_base64"]) == body
    finding = map_all(connector, "webhook_issues", [records[0].raw])[0]
    assert finding.metadata.uid == digest
    assert finding.unmapped["invicti"]["webhook"]["configuration_revision"] == 1
    assert "raw_body_base64" not in finding.unmapped["invicti"]["webhook"]
    finding.to_ocsf()


def test_basic_webhook_verifier_and_single_issue_template() -> None:
    connector = _connector(webhook_mode="basic_auth")
    verifier = connector.webhook_verifier(b"operator:password")
    issue = json.loads((_FIXTURES / "report.json").read_text())["Vulnerabilities"][0]
    body = json.dumps(issue).encode()
    credentials = base64.b64encode(b"operator:password").decode()
    delivery = WebhookDelivery(
        headers={"authorization": f"Basic {credentials}"}, body=body, received_at=datetime(2026, 11, 10, tzinfo=UTC)
    )
    verifier.verify(delivery, now=delivery.received_at)
    record = connector.receive_event(delivery)[0]
    finding = map_all(connector, "webhook_issues", [record.raw])[0]
    assert finding.finding_info.uid == "standard-issue-001"
    assert finding.metadata.uid == hashlib.sha256(body).hexdigest()
    finding.to_ocsf()


def test_standard_has_no_enterprise_surface_or_remote_action() -> None:
    connector = _connector()
    assert connector.uses_http is False
    assert set(connector.operations()) == {"parse_report"}
    assert connector.actions() == {}
    assert connector.check
    report = asyncio.run(connector.check())
    assert report.status == "healthy"
    assert report.detail["remote_api"] is False
