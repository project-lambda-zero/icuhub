"""Mend SCA stream tests: cursor and page sequencing, record counts, mapper output, version gating."""

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from icuhub.connectors.mend_sca.connector import _alert_uuid
from icuhub.connectors.mend_sca.models import MendTimeCursor
from icuhub.kit.errors import ConfigError, PermissionDenied, VendorContractError
from icuhub.kit.testing import collect_stream, map_all

from .conftest import ORG_UUID, SECRETS, make_mend, project_target

FIXTURES = Path(__file__).parents[2] / "fixtures" / "mend_sca"
SOURCE = "00000000-0000-4000-8000-000000000101"
V2_LOGIN = ("POST", "/api/v2.0/login")
V2_CONFIG: dict[str, Any] = {
    "api_version": "2.0",
    "org_uuid": None,
    "org_token": {"ref": "vault:mend-org-token"},
}
V2_SECRETS = {**SECRETS, "vault:mend-org-token": b"test-org-token"}
V3_CURSOR_PAGE_2 = "example-cursor-page-2"


def fixture(rel: str) -> Any:
    return json.loads((FIXTURES / rel).read_text(encoding="utf-8"))


def records_of(batches: list[Any]) -> list[Any]:
    return [record for batch in batches for record in batch.records]


# Snapshot streams whose body is a single fixture page: (stream, path, fixture, expected count, needs target).
V3_SNAPSHOT_STREAMS = [
    ("legal_violations", f"/api/v3.0/projects/{SOURCE}/licenses/violations", "v3/legal_violations_page1.json", 2, True),
    ("libraries", f"/api/v3.0/projects/{SOURCE}/libraries", "v3/libraries_page1.json", 3, True),
    ("projects", f"/api/v3.0/orgs/{ORG_UUID}/projects", "v3/projects_page1.json", 3, False),
]
V2_SNAPSHOT_STREAMS = [
    ("legal_alerts", f"/api/v2.0/projects/{SOURCE}/alerts/legal", "v2/legal_alerts_page1.json", 1, True),
]


@pytest.mark.parametrize(("stream", "path", "fixture_rel", "expected", "needs_target"), V3_SNAPSHOT_STREAMS)
def test_v3_snapshot_stream_emits_and_maps_every_fixture_record(
    stream: str, path: str, fixture_rel: str, expected: int, needs_target: bool
) -> None:
    connector = make_mend({("GET", path): {"json": fixture(fixture_rel)}})
    target = project_target() if needs_target else None
    records = records_of(collect_stream(connector, stream, target=target, mode="full"))
    assert len(records) == expected
    assert map_all(connector, stream, records, target=target)


@pytest.mark.parametrize(("stream", "path", "fixture_rel", "expected", "needs_target"), V2_SNAPSHOT_STREAMS)
def test_v2_snapshot_stream_emits_and_maps_every_fixture_record(
    stream: str, path: str, fixture_rel: str, expected: int, needs_target: bool
) -> None:
    connector = make_mend(
        {V2_LOGIN: {"json": fixture("v2/login.json")}, ("GET", path): {"json": fixture(fixture_rel)}},
        config_overrides=V2_CONFIG,
        secrets=V2_SECRETS,
    )
    target = project_target() if needs_target else None
    records = records_of(collect_stream(connector, stream, target=target, mode="full"))
    assert len(records) == expected
    assert map_all(connector, stream, records, target=target)


def test_security_findings_follows_v3_cursor_until_next_is_null() -> None:
    seen: list[Any] = []
    pages = {None: "v3/security_findings_page1.json", V3_CURSOR_PAGE_2: "v3/security_findings_page2.json"}

    def respond(request: Any) -> dict[str, Any]:
        seen.append(request)
        return {"json": fixture(pages[request.url.params.get("cursor")])}

    connector = make_mend({("GET", f"/api/v3.0/projects/{SOURCE}/dependencies/findings/security"): respond})
    batches = collect_stream(connector, "security_findings", target=project_target(), mode="full")
    records = records_of(batches)

    assert [request.url.params.get("cursor") for request in seen] == [None, V3_CURSOR_PAGE_2]
    assert len(records) == 3
    assert batches[-1].complete is True
    assert map_all(connector, "security_findings", records, target=project_target())


def test_security_alerts_pages_v2_zero_based_until_is_last_page() -> None:
    seen: list[Any] = []
    pages = {"0": "v2/security_alerts_page1.json", "1": "v2/security_alerts_page2.json"}

    def respond(request: Any) -> dict[str, Any]:
        seen.append(request)
        return {"json": fixture(pages[request.url.params["page"]])}

    connector = make_mend(
        {
            V2_LOGIN: {"json": fixture("v2/login.json")},
            ("GET", f"/api/v2.0/projects/{SOURCE}/alerts/security"): respond,
        },
        config_overrides=V2_CONFIG,
        secrets=V2_SECRETS,
    )
    target = project_target()
    records = records_of(collect_stream(connector, "security_alerts", target=target))

    assert [(request.url.params["page"], request.url.params["pageSize"]) for request in seen] == [
        ("0", "50"),
        ("1", "50"),
    ]
    assert len(records) == 3
    assert map_all(connector, "security_alerts", records, target=target)


def test_legal_alerts_stamps_the_organization_key_not_a_version_or_none() -> None:
    connector = make_mend(
        {
            V2_LOGIN: {"json": fixture("v2/login.json")},
            ("GET", f"/api/v2.0/projects/{SOURCE}/alerts/legal"): {"json": fixture("v2/legal_alerts_page1.json")},
        },
        config_overrides=V2_CONFIG,
        secrets=V2_SECRETS,
    )
    records = records_of(collect_stream(connector, "legal_alerts", target=project_target(), mode="full"))

    assert records
    for record in records:
        assert record["_organization"] == connector._organization_key()
        assert record["_organization"] not in (None, "", "v2")


def test_projects_listing_forbidden_raises_permission_denied() -> None:
    connector = make_mend(
        {
            ("GET", f"/api/v3.0/orgs/{ORG_UUID}/projects"): {
                "status": 403,
                "json": fixture("denied/projects_access_denied.json"),
            }
        }
    )
    with pytest.raises(PermissionDenied):
        collect_stream(connector, "projects", mode="full")


def test_v3_only_stream_is_rejected_on_v2_connection() -> None:
    connector = make_mend(
        {V2_LOGIN: {"json": fixture("v2/login.json")}},
        config_overrides=V2_CONFIG,
        secrets=V2_SECRETS,
    )
    with pytest.raises(ConfigError):
        collect_stream(connector, "legal_violations", target=project_target(), mode="full")


def test_v2_only_stream_is_rejected_on_v3_connection() -> None:
    connector = make_mend({})
    with pytest.raises(ConfigError):
        collect_stream(connector, "security_alerts", target=project_target())


def test_snapshot_stream_rejects_incremental_mode() -> None:
    connector = make_mend({})
    with pytest.raises(ValueError):
        collect_stream(connector, "libraries", target=project_target(), mode="incremental")


ACTIVITY_PATH = f"/api/v3.0/orgs/{ORG_UUID}/activity"
ACTIVITY_TIE_FIRST = "00000000-0000-4000-8000-000000000801"
ACTIVITY_TIE_SECOND = "00000000-0000-4000-8000-000000000802"
ACTIVITY_NEWEST = "00000000-0000-4000-8000-000000000803"
UNTIMED_ACTIVITY = "00000000-0000-4000-8000-000000000804"
TIE_TS = datetime(2026, 1, 16, 9, 30, tzinfo=UTC)
NEWEST_TS = datetime(2026, 1, 17, 12, 0, tzinfo=UTC)


def activity_connector(payload: dict[str, Any] | None = None) -> Any:
    body = payload if payload is not None else fixture("v3/activity_page1.json")
    return make_mend({("GET", ACTIVITY_PATH): {"json": body}})


@pytest.mark.parametrize("mode", ["full", "incremental"])
def test_cold_activity_run_emits_every_record_and_checkpoints_newest(mode: str) -> None:
    batches = collect_stream(activity_connector(), "activity", mode=mode)
    assert len(records_of(batches)) == 3
    final = batches[-1].checkpoint
    assert final.ts == NEWEST_TS
    assert final.last_ids_at_ts == [ACTIVITY_NEWEST]


def test_incremental_activity_drops_committed_tie_and_keeps_unseen_tie() -> None:
    checkpoint = MendTimeCursor(ts=TIE_TS, last_ids_at_ts=[ACTIVITY_TIE_FIRST])
    batches = collect_stream(activity_connector(), "activity", checkpoint=checkpoint, mode="incremental")
    assert [raw["uuid"] for raw in records_of(batches)] == [ACTIVITY_TIE_SECOND, ACTIVITY_NEWEST]
    assert batches[-1].checkpoint.ts == NEWEST_TS
    assert batches[-1].checkpoint.last_ids_at_ts == [ACTIVITY_NEWEST]


def test_incremental_activity_skips_records_older_than_replay_window() -> None:
    later = datetime(2026, 1, 18, tzinfo=UTC)
    checkpoint = MendTimeCursor(ts=later, last_ids_at_ts=[])
    batches = collect_stream(activity_connector(), "activity", checkpoint=checkpoint, mode="incremental")
    assert records_of(batches) == []
    assert batches[-1].checkpoint.ts == later


def test_untimed_activity_record_is_kept_and_does_not_move_cursor() -> None:
    payload = fixture("v3/activity_page1.json")
    payload["response"].insert(0, {"uuid": UNTIMED_ACTIVITY, "type": "ORGANIZATION_UPDATED"})
    checkpoint = MendTimeCursor(ts=TIE_TS, last_ids_at_ts=[ACTIVITY_TIE_FIRST])
    batches = collect_stream(activity_connector(payload), "activity", checkpoint=checkpoint, mode="incremental")
    assert [raw["uuid"] for raw in records_of(batches)] == [UNTIMED_ACTIVITY, ACTIVITY_TIE_SECOND, ACTIVITY_NEWEST]
    assert batches[-1].checkpoint.ts == NEWEST_TS


def test_alert_identity_prefers_top_level_uuid_and_rejects_conflicts() -> None:
    assert _alert_uuid({"uuid": "A", "alertInfo": {"uuid": "A"}}) == "A"
    assert _alert_uuid({"alertInfo": {"uuid": "B"}}) == "B"
    with pytest.raises(VendorContractError):
        _alert_uuid({"uuid": "A", "alertInfo": {"uuid": "B"}})
    with pytest.raises(VendorContractError):
        _alert_uuid({"alertInfo": {}})
