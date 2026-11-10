"""Opt-in Invicti Standard local-export acceptance."""

from __future__ import annotations

import asyncio
import base64
from pathlib import Path

import httpx2

from icuhub.connectors.invicti_standard import InvictiStandard, ParseReportArgs
from icuhub.kit.testing import collect_stream, make_connector

ACCEPTANCE_KIND = "invicti_standard"


def _connector(acceptance) -> InvictiStandard:
    return make_connector(InvictiStandard, acceptance.config, httpx2.AsyncHTTPTransport(), acceptance.secrets)


def test_local_reports_and_replay(acceptance) -> None:
    connector = _connector(acceptance)
    health = asyncio.run(connector.check())
    acceptance.record("health", health.status == "healthy", health.status)
    files = acceptance.config.get("report_files", [])
    if not files:
        acceptance.record("parse_report", True, "not_evaluated: no local exports configured")
        return
    unsupported_xml = False
    for filename in files:
        path = Path(filename)
        data = path.read_bytes()
        if path.suffix.lower() != ".json":
            acceptance.record(f"parse_report:{path.name}", False, "GAP-INVICTI-001: current native XML parser is not enabled")
            unsupported_xml = True
            continue
        output = asyncio.run(
            connector.parse_report_operation(ParseReportArgs(content_base64=base64.b64encode(data).decode("ascii")))
        )
        acceptance.record(f"parse_report:{path.name}", bool(output.report.vulnerabilities), output.report.report_id)
    if unsupported_xml:
        return
    full = collect_stream(connector, "report_issues", mode="full")
    replay = collect_stream(connector, "report_issues", mode="replay")
    identical = [batch.checkpoint for batch in full] == [batch.checkpoint for batch in replay]
    acceptance.record("report_replay", identical, f"{len(full)} batches")
    assert identical
    assert full[-1].complete is True


def test_no_enterprise_remote_surface(acceptance) -> None:
    connector = _connector(acceptance)
    no_remote = not connector.uses_http and not connector.actions() and set(connector.operations()) == {"parse_report"}
    acceptance.record("no_enterprise_remote_surface", no_remote, "local report and webhook only")
    assert no_remote
