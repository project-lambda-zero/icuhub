"""Connector-level tests for the Fortify SSC connector.

Covers auth wiring, health checks, the ``issues``, ``artifacts``, and ``activity``
streams, the mappers, and the ``get_issue`` operation. Requests are answered by
``RouteTransport`` from the synthetic fixtures in ``tests/fixtures/fortify_ssc/``.

Pagination note: the real fixture pages are short (2 and 1 items), so a single
page ends the offset loop. The continuation test builds 200 synthetic issues
in-test to force a second page request.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest

from icuhub.connectors.fortify_ssc import FortifySsc
from icuhub.connectors.fortify_ssc.connector import ActivityRecord, ArtifactRecord
from icuhub.connectors.fortify_ssc.models import GetIssueArgs
from icuhub.kit.cursors import SequenceCursor, TimeIdCursor
from icuhub.kit.errors import ConfigError, RateLimited, TransientVendorError, VendorContractError
from icuhub.kit.testing import RouteTransport, collect_stream, make_connector, map_all
from icuhub.kit.types import Target
from icuhub_schemas.ocsf import VulnerabilityFinding, validate_ocsf

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "fortify_ssc"
BASE = "https://ssc.example.test/ssc"
API = "/ssc/api/v1"
TOKEN_REF = "fortify-token"
SECRETS = {TOKEN_REF: b"fixture-token"}
PV = Target(
    id="pv-42",
    source_uid="42",
    kind="project_version",
    display_name="synthetic-app",
    attributes={},
)


def _load(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _config(**extra: Any) -> dict[str, Any]:
    return {"base_url": BASE, "api_token": {"ref": TOKEN_REF}, **extra}


def _connector(routes: dict[tuple[str, str], Any], **config_extra: Any) -> FortifySsc:
    return cast(
        FortifySsc,
        make_connector(FortifySsc, _config(**config_extra), RouteTransport(routes), SECRETS),
    )


def _paged(pages_by_start: dict[str, Any], seen: list[Any]) -> Any:
    """Serve one page per ``start`` offset and record every request."""

    def handler(request: Any) -> dict[str, Any]:
        seen.append(request)
        return {"status": 200, "json": pages_by_start[request.url.params["start"]]}

    return handler


def _findings(connector: FortifySsc, records: list[dict[str, Any]]) -> list[VulnerabilityFinding]:
    return [cast(VulnerabilityFinding, r) for r in map_all(connector, "issues", records, target=PV)]


def _source(finding: VulnerabilityFinding) -> dict[str, Any]:
    assert finding.unmapped is not None
    return cast(dict[str, Any], finding.unmapped["fortify_ssc"])


def _issue_item(n: int) -> dict[str, Any]:
    return {
        "id": n,
        "issueInstanceId": f"synthetic-instance-{n}",
        "projectVersionId": 42,
        "revision": 1,
        "primaryRuleGuid": f"synthetic-rule-{n}",
        "issueName": "Synthetic",
        "fullFileName": "src/synthetic/Synthetic.java",
        "lineNumber": n,
        "issueStatus": "Unaudited",
        "suppressed": False,
        "removed": False,
        "foundDate": "2026-03-01T10:00:00.000+0000",
    }


# --- auth and health -------------------------------------------------------


def _probe_body(**overrides: Any) -> dict[str, Any]:
    """A healthy ``POST /userSession/info`` response; ``overrides`` replace individual data fields."""
    data = {
        "webappVersion": "25.4.0.0137",
        "applicationContextPath": "/ssc",
        "licenseCapabilities": [],
        "permissions": [],
    } | overrides
    return {"data": data}


def test_build_auth_sends_fortify_token_header() -> None:
    seen: list[tuple[str, str]] = []

    def probe(request: Any) -> dict[str, Any]:
        seen.append((request.method, request.headers["authorization"]))
        return {"status": 200, "json": _probe_body()}

    connector = _connector({("POST", f"{API}/userSession/info"): probe})
    asyncio.run(connector.check())

    assert seen == [("POST", "FortifyToken fixture-token")]


def test_non_ascii_token_is_rejected_at_build() -> None:
    with pytest.raises(ConfigError, match="ASCII"):
        make_connector(
            FortifySsc,
            _config(),
            RouteTransport({}),
            {TOKEN_REF: "tokén".encode()},
        )


def _probe_route(body: dict[str, Any] | None = None, status: int = 200) -> dict[tuple[str, str], Any]:
    return {("POST", f"{API}/userSession/info"): {"status": status, "json": body if body is not None else {}}}


def test_check_is_healthy_on_supported_version_and_matching_context_root() -> None:
    report = asyncio.run(_connector(_probe_route(_probe_body())).check())

    assert report.status == "healthy"
    assert report.vendor_version == "25.4.0.0137"
    assert report.capabilities["FindingSource"].status == "healthy"


def test_check_is_failing_on_unauthorized() -> None:
    report = asyncio.run(_connector(_probe_route(status=401)).check())

    assert report.status == "failing"
    assert report.capabilities["FindingSource"].reason == "vendor rejected credentials"


def test_check_is_degraded_on_forbidden() -> None:
    report = asyncio.run(_connector(_probe_route(status=403)).check())

    assert report.status == "degraded"


def test_check_is_degraded_when_rate_limited(monkeypatch: pytest.MonkeyPatch) -> None:
    connector = _connector(_probe_route(_probe_body()))

    async def rate_limited() -> None:
        raise RateLimited(retry_after_s=0, message="probe remained rate limited")

    monkeypatch.setattr(connector, "_probe_session", rate_limited)
    report = asyncio.run(connector.check())

    assert report.status == "degraded"
    assert report.capabilities["FindingSource"].reason == "vendor unavailable"


def test_check_is_degraded_when_transient_vendor_error(monkeypatch: pytest.MonkeyPatch) -> None:
    connector = _connector(_probe_route(_probe_body()))

    async def transient() -> None:
        raise TransientVendorError("probe exhausted its retry budget")

    monkeypatch.setattr(connector, "_probe_session", transient)
    report = asyncio.run(connector.check())

    assert report.status == "degraded"
    assert report.capabilities["FindingSource"].reason == "vendor unavailable"


@pytest.mark.parametrize("version", ["24.1.0.0001", "not-a-version"])
def test_check_is_failing_below_minimum_or_non_numeric_version(version: str) -> None:
    report = asyncio.run(_connector(_probe_route(_probe_body(webappVersion=version))).check())

    assert report.status == "failing"
    assert report.vendor_version == version
    assert "24.2 or later is required" in report.capabilities["FindingSource"].reason


def test_check_is_failing_when_effective_context_root_differs_from_base_url() -> None:
    report = asyncio.run(_connector(_probe_route(_probe_body(applicationContextPath="/other"))).check())

    assert report.status == "failing"
    assert report.vendor_version == "25.4.0.0137"
    assert "context root" in report.capabilities["FindingSource"].reason


# --- issues stream ---------------------------------------------------------


def test_issues_incremental_performs_complete_reconciliation() -> None:
    seen: list[Any] = []
    connector = _connector(
        {
            ("GET", f"{API}/projectVersions/42/issues"): _paged(
                {"0": _load("issues_page1.json")}, seen
            )
        }
    )
    batches = collect_stream(connector, "issues", target=PV)

    assert [b.complete for b in batches] == [False, True]
    assert [r["id"] for r in batches[0].records] == [1001, 1002]

    params = seen[0].url.params
    assert params["fields"] == "all"
    assert params["orderby"] == "foundDate"
    assert params["withoutCount"] == "true"
    assert params["showhidden"] == "true"
    assert params["showremoved"] == "true"
    assert params["showsuppressed"] == "true"
    assert params["start"] == "0"
    assert params["limit"] == "200"
    assert "filter" not in params


def test_issues_incremental_checkpoint_advances_to_latest_updated() -> None:
    connector = _connector(
        {
            ("GET", f"{API}/projectVersions/42/issues"): _paged(
                {"0": _load("issues_page1.json")}, []
            )
        }
    )
    batches = collect_stream(connector, "issues", target=PV)

    checkpoint = batches[0].checkpoint
    assert isinstance(checkpoint, TimeIdCursor)
    assert checkpoint.ts == datetime(2026, 3, 1, 11, 30, tzinfo=UTC)


def test_issues_incremental_with_checkpoint_still_reconciles_all_visibility() -> None:
    seen: list[Any] = []
    connector = _connector(
        {
            ("GET", f"{API}/projectVersions/42/issues"): _paged(
                {"0": _load("issues_page1.json")}, seen
            )
        }
    )
    batches = collect_stream(
        connector,
        "issues",
        target=PV,
        checkpoint=TimeIdCursor(ts=datetime(2026, 3, 1, 10, 0, tzinfo=UTC)),
    )

    assert "filter" not in seen[0].url.params
    assert seen[0].url.params["showhidden"] == "true"
    assert seen[0].url.params["showremoved"] == "true"
    assert seen[0].url.params["showsuppressed"] == "true"
    assert batches[-1].complete is True


def test_issues_full_mode_ends_with_complete_batch() -> None:
    connector = _connector(
        {
            ("GET", f"{API}/projectVersions/42/issues"): _paged(
                {"0": _load("issues_page1.json")}, []
            )
        }
    )
    batches = collect_stream(connector, "issues", target=PV, mode="full")

    assert [b.complete for b in batches] == [False, True]
    assert len(batches[0].records) == 2
    assert batches[-1].records == []


def test_issues_paginates_until_a_short_page() -> None:
    """Synthetic continuation: 200 items fill page one, so a second page is requested."""
    full_page = {"data": [_issue_item(n) for n in range(1, 201)], "count": 201}
    tail_page = {"data": [_issue_item(201)], "count": 201}
    seen: list[Any] = []
    connector = _connector(
        {
            ("GET", f"{API}/projectVersions/42/issues"): _paged(
                {"0": full_page, "200": tail_page}, seen
            )
        }
    )
    batches = collect_stream(connector, "issues", target=PV)

    assert [len(b.records) for b in batches] == [200, 1, 0]
    assert [r.url.params["start"] for r in seen] == ["0", "200"]


def test_issues_requires_target() -> None:
    connector = _connector({})
    with pytest.raises(ValueError):
        collect_stream(connector, "issues")


# --- issue mapper ----------------------------------------------------------


def test_issue_mapper_emits_ocsf_vulnerability_finding() -> None:
    connector = _connector({})
    items = _load("issues_page1.json")["data"]
    first, second = _findings(connector, items)

    document = first.model_dump(mode="json", exclude_none=True)
    assert document["class_uid"] == 2002
    validate_ocsf(document)
    assert first.finding_info.uid == "fortify_ssc:pv:42:instance:a1b2c3d4-0001-4000-8000-000000000001"
    assert first.finding_info.uid_alt == "1001"
    assert first.finding_info.title == "SQL Injection"
    assert first.metadata.uid == "42:a1b2c3d4-0001-4000-8000-000000000001"
    assert first.cloud.provider == "fortify_ssc"
    assert first.time == int(datetime(2026, 3, 1, 10, 0, tzinfo=UTC).timestamp() * 1000)
    assert first.vulnerabilities == []
    assert first.status_id == 1
    assert first.status == "New"

    source = _source(first)
    assert source["issue_id"] == 1001
    assert source["issue_instance_id"] == "a1b2c3d4-0001-4000-8000-000000000001"
    assert source["project_version_id"] == 42
    assert source["revision"] == 3
    assert source["rule_guid"] == "11111111-aaaa-4bbb-8ccc-000000000001"
    assert source["category"] == "SQL Injection"
    assert source["file_path"] == "src/app/Db.java"
    assert source["line"] == 88
    assert source["suppressed"] is False
    assert source["removed"] is False
    assert set(source["fingerprint_inputs"]) == {
        "algorithmVersion",
        "primaryRuleGuid",
        "issueName",
        "kingdom",
        "fullFileName",
        "lineNumber",
    }

    assert second.finding_info.uid == f"fortify_ssc:pv:42:instance:{items[1]['issueInstanceId']}"
    assert second.status_id == 3
    assert second.status == "Suppressed"
    assert _source(second)["issue_id"] == 1002
    assert _source(second)["revision"] == 1
    assert _source(second)["line"] == 17
    assert _source(second)["suppressed"] is True


def test_audit_state_reads_official_fixture_field() -> None:
    connector = _connector({})
    first, _ = _findings(connector, _load("issues_page1.json")["data"])

    assert _source(first)["audit_state"] == "Unaudited"


def test_removed_issue_maps_to_resolved_even_when_suppressed() -> None:
    connector = _connector({})
    (finding,) = _findings(
        connector, [_issue_item(8) | {"removed": True, "suppressed": True, "issueStatus": "Suppressed"}]
    )

    assert finding.status_id == 4
    assert finding.status == "Resolved"
    assert _source(finding)["removed"] is True
    assert finding.status_detail == "Suppressed"


def test_audit_state_reads_top_level_field() -> None:
    connector = _connector({})
    (finding,) = _findings(connector, [_issue_item(7) | {"issueStatus": "Audited"}])

    assert _source(finding)["audit_state"] == "Audited"


def test_issue_mapper_rejects_boolean_project_version() -> None:
    connector = _connector({})
    with pytest.raises(VendorContractError, match="projectVersionId must be an integer"):
        _findings(connector, [_issue_item(7) | {"projectVersionId": True}])


# --- artifacts stream ------------------------------------------------------


def test_artifacts_full_stream_uses_project_version_collection() -> None:
    seen: list[Any] = []
    connector = _connector(
        {("GET", f"{API}/projectVersions/42/artifacts"): _paged({"0": _load("artifacts.json")}, seen)}
    )
    batches = collect_stream(connector, "artifacts", target=PV, mode="full")

    assert "q" not in seen[0].url.params
    assert seen[0].url.params["fields"] == "all"
    assert [b.complete for b in batches] == [False, True]
    assert len(batches[0].records) == 1


def test_artifact_mapper_on_fixture() -> None:
    connector = _connector({})
    (artifact,) = map_all(connector, "artifacts", _load("artifacts.json")["data"], target=PV)

    assert isinstance(artifact, ArtifactRecord)
    assert artifact.artifact_id == 501
    assert artifact.project_version_id == 42
    assert artifact.status == "PROCESSING_COMPLETE"
    assert artifact.sha256 is None
    assert artifact.indexed is False


def test_artifacts_rejects_incremental_mode() -> None:
    connector = _connector({})
    with pytest.raises(ValueError):
        collect_stream(connector, "artifacts", target=PV, mode="incremental")


# --- activity stream -------------------------------------------------------


def test_activity_stream_uses_official_collection_and_ends_complete() -> None:
    seen: list[Any] = []
    connector = _connector(
        {("GET", f"{API}/activityFeedEvents"): _paged({"0": _load("activities.json")}, seen)}
    )
    batches = collect_stream(connector, "activity")

    params = seen[0].url.params
    assert "orderby" not in params
    assert "q" not in params
    assert [b.complete for b in batches] == [False, True]
    assert [r["id"] for r in batches[0].records] == [9001, 9002]


def test_activity_incremental_defers_checkpoint_and_filters_replayed_ids() -> None:
    connector = _connector(
        {("GET", f"{API}/activityFeedEvents"): _paged({"0": _load("activities.json")}, [])}
    )
    batches = collect_stream(connector, "activity", checkpoint=SequenceCursor(seq=9001))

    assert [r["id"] for r in batches[0].records] == [9002]
    assert batches[0].checkpoint == SequenceCursor(seq=9001)
    assert batches[-1].checkpoint == SequenceCursor(seq=9002)
    assert batches[-1].complete is True


def test_activity_mapper_maps_official_fixture() -> None:
    connector = _connector({})
    first, second = map_all(connector, "activity", _load("activities.json")["data"])
    activity = cast(ActivityRecord, first)

    assert activity.event_id == 9001
    assert activity.project_version_id == 42
    assert activity.event_type == "AUDIT"
    assert activity.occurred_at == datetime(2026, 3, 1, 10, 5, tzinfo=UTC)
    assert cast(ActivityRecord, second).event_type == "UPLOAD"


# --- get_issue operation ---------------------------------------------------


def test_get_issue_returns_finding_for_issue_id() -> None:
    seen: list[Any] = []
    issue = _load("issues_page1.json")["data"][0]

    def issue_route(request: Any) -> dict[str, Any]:
        seen.append(request)
        return {"status": 200, "json": {"data": issue}}

    connector = _connector({("GET", f"{API}/projectVersions/42/issues/1001"): issue_route})
    output = asyncio.run(connector.get_issue(GetIssueArgs(project_version_id=42, issue_id=1001)))

    assert output.finding.issue_id == 1001
    assert output.finding.revision == 3
    assert seen[0].url.params["fields"] == "all"
    assert seen[0].url.params["withoutCount"] == "true"
