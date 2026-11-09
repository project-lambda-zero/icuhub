"""Offline tests for the Fortify on Demand connector: snapshot stream, paging guards, bulk audit action."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError

from icuhub.connectors.fortify_fod import FortifyFod
from icuhub.connectors.fortify_fod.models import BulkAuditInput
from icuhub.kit.cursors import SnapshotCursor
from icuhub.kit.errors import StalePlan, VendorContractError
from icuhub.kit.testing import RouteTransport, collect_stream, conformance_problems, make_connector
from icuhub.kit.types import Target

BASE = "https://api.ams.fortify.com"
VULNS = "/api/v3/releases/42/vulnerabilities"
BULK = "/api/v3/releases/42/vulnerabilities/bulk-edit"
CONFIG = {"base_url": BASE, "client_id": "client-1", "client_secret": {"ref": "fod_secret"}}
SECRETS = {"fod_secret": b"not-a-real-secret"}
TOKEN = {"status": 200, "json": {"access_token": "token-1", "expires_in": 3600}}
TARGET = Target(id="release-42", source_uid="42", kind="release", display_name="Release 42", attributes={})


def _vuln(vuln_id: str, *, developer: str = "New", severity: str = "High") -> dict[str, Any]:
    return {
        "id": int(vuln_id),
        "vulnId": f"vuln-{vuln_id}",
        "instanceId": f"instance-{vuln_id}",
        "severity": severity,
        "developerStatus": developer,
        "auditorStatus": "Unreviewed",
    }


def _page(items: list[dict[str, Any]], *, offset: int, total: int) -> dict[str, Any]:
    return {"status": 200, "json": {"items": items, "offset": offset, "limit": 50, "totalCount": total}}


def _queue(responses: list[dict[str, Any]]) -> Callable[[Any], dict[str, Any]]:
    pending = list(responses)

    def handler(_request: Any) -> dict[str, Any]:
        assert pending, "unexpected extra request"
        return pending.pop(0)

    return handler


def _resolve(developer_status: str = "Resolved") -> BulkAuditInput:
    return BulkAuditInput(release_id="42", vulnerability_ids=["10001"], developer_status=developer_status)


def _connector(routes: dict[tuple[str, str], Any]) -> FortifyFod:
    transport = RouteTransport({("POST", "/oauth/token"): TOKEN, **routes})
    connector = make_connector(FortifyFod, CONFIG, transport, SECRETS)
    assert isinstance(connector, FortifyFod)
    return connector


def test_conformance_is_clean() -> None:
    assert conformance_problems(FortifyFod) == []


def test_issues_snapshot_injects_release_scope() -> None:
    items = [_vuln("1"), _vuln("2")]
    connector = _connector({("GET", VULNS): _queue([_page(items, offset=0, total=2)])})

    batches = collect_stream(connector, "issues", target=TARGET, mode="full")

    assert [batch.complete for batch in batches] == [False, True]
    records = [raw for batch in batches for raw in batch.records]
    assert [raw["id"] for raw in records] == [1, 2]
    assert all(raw["_release_id"] == "42" for raw in records)
    assert items[0].get("_release_id") is None
    final = batches[-1].checkpoint
    assert isinstance(final, SnapshotCursor)
    assert final.targets_done == ["42"]


def test_issues_pages_advance_by_returned_items() -> None:
    first = [_vuln(str(n)) for n in range(1, 51)]
    second = [_vuln("51")]
    connector = _connector(
        {("GET", VULNS): _queue([_page(first, offset=0, total=51), _page(second, offset=50, total=51)])}
    )

    batches = collect_stream(connector, "issues", target=TARGET, mode="full")

    records = [raw for batch in batches for raw in batch.records]
    assert [raw["id"] for raw in records] == list(range(1, 52))
    assert [batch.complete for batch in batches] == [False, False, True]


def test_issues_totalcount_drift_raises() -> None:
    connector = _connector(
        {("GET", VULNS): _queue([_page([_vuln("1")], offset=0, total=3), _page([_vuln("2")], offset=1, total=4)])}
    )

    with pytest.raises(VendorContractError, match="totalCount changed"):
        collect_stream(connector, "issues", target=TARGET, mode="full")


def test_issues_empty_page_before_total_raises() -> None:
    connector = _connector({("GET", VULNS): _queue([_page([], offset=0, total=2)])})

    with pytest.raises(VendorContractError, match="empty page"):
        collect_stream(connector, "issues", target=TARGET, mode="full")


def test_issues_page_overrunning_total_raises() -> None:
    connector = _connector({("GET", VULNS): _queue([_page([_vuln("1"), _vuln("2")], offset=0, total=1)])})

    with pytest.raises(VendorContractError, match="overruns"):
        collect_stream(connector, "issues", target=TARGET, mode="full")


def test_issues_duplicate_native_id_raises() -> None:
    connector = _connector({("GET", VULNS): _queue([_page([_vuln("1"), _vuln("1")], offset=0, total=2)])})

    with pytest.raises(VendorContractError, match="repeated issue id"):
        collect_stream(connector, "issues", target=TARGET, mode="full")


def test_issues_offset_echo_mismatch_raises() -> None:
    connector = _connector({("GET", VULNS): _queue([_page([_vuln("1")], offset=5, total=1)])})

    with pytest.raises(VendorContractError, match="echoed offset"):
        collect_stream(connector, "issues", target=TARGET, mode="full")


def test_issues_accepted_202_fails_closed() -> None:
    connector = _connector({("GET", VULNS): {"status": 202, "json": {"state": "updating"}}})

    with pytest.raises(VendorContractError):
        collect_stream(connector, "issues", target=TARGET, mode="full")


def test_issues_completed_release_is_skipped_on_resume() -> None:
    connector = _connector({})
    started_at = datetime(2026, 11, 10, tzinfo=UTC)
    checkpoint = SnapshotCursor(
        snapshot_id=f"fortify_fod:issues:{started_at.isoformat()}",
        started_at=started_at,
        targets_done=["42"],
    )

    batches = collect_stream(connector, "issues", target=TARGET, checkpoint=checkpoint, mode="full")

    assert [batch.records for batch in batches] == [[]]
    assert batches[0].complete is True


def test_identity_lookup_multiple_records_raises() -> None:
    connector = _connector({("GET", VULNS): _queue([_page([_vuln("10001"), _vuln("10001")], offset=0, total=2)])})

    with pytest.raises(VendorContractError, match="exactly one record"):
        asyncio.run(connector.plan_bulk_audit(_resolve()))


def test_bulk_audit_success_applies_and_reads_back() -> None:
    connector = _connector(
        {
            ("GET", VULNS): _queue(
                [
                    _page([_vuln("10001")], offset=0, total=1),  # plan
                    _page([_vuln("10001")], offset=0, total=1),  # apply pre-read
                    _page([_vuln("10001", developer="Resolved")], offset=0, total=1),  # read-back
                ]
            ),
            ("POST", BULK): {"status": 200, "json": [{"errorCode": 0}]},
        }
    )
    args = BulkAuditInput(release_id="42", vulnerability_ids=["10001"], developer_status="Resolved")

    plan = asyncio.run(connector.plan_bulk_audit(args))
    assert plan.changed is True
    assert plan.diff["status"] == {"10001": {"developerStatus": {"from": "New", "to": "Resolved"}}}
    outcome = asyncio.run(connector.apply_bulk_audit(plan))

    assert outcome.status == "succeeded"
    assert outcome.result == {"entries": 1, "unverified_fields": []}


def test_bulk_audit_nonzero_error_code_fails() -> None:
    connector = _connector(
        {
            ("GET", VULNS): _queue(
                [_page([_vuln("10001")], offset=0, total=1), _page([_vuln("10001")], offset=0, total=1)]
            ),
            ("POST", BULK): {"status": 200, "json": [{"errorCode": 4}]},
        }
    )
    plan = asyncio.run(
        connector.plan_bulk_audit(_resolve())
    )

    outcome = asyncio.run(connector.apply_bulk_audit(plan))

    assert outcome.status == "failed"
    assert "errorCode" in (outcome.error or "")


def test_bulk_audit_malformed_response_is_outcome_unknown() -> None:
    connector = _connector(
        {
            ("GET", VULNS): _queue(
                [_page([_vuln("10001")], offset=0, total=1), _page([_vuln("10001")], offset=0, total=1)]
            ),
            ("POST", BULK): {"status": 200, "json": {"ok": True}},
        }
    )
    plan = asyncio.run(
        connector.plan_bulk_audit(_resolve())
    )

    outcome = asyncio.run(connector.apply_bulk_audit(plan))

    assert outcome.status == "outcome_unknown"


def test_bulk_audit_stale_plan_raises() -> None:
    connector = _connector(
        {
            ("GET", VULNS): _queue(
                [
                    _page([_vuln("10001")], offset=0, total=1),
                    _page([_vuln("10001", developer="Assigned")], offset=0, total=1),
                ]
            ),
        }
    )
    plan = asyncio.run(
        connector.plan_bulk_audit(_resolve())
    )

    with pytest.raises(StalePlan):
        asyncio.run(connector.apply_bulk_audit(plan))


def test_bulk_audit_no_change_is_no_op() -> None:
    connector = _connector({("GET", VULNS): _queue([_page([_vuln("10001")], offset=0, total=1)])})
    plan = asyncio.run(
        connector.plan_bulk_audit(BulkAuditInput(release_id="42", vulnerability_ids=["10001"], developer_status="New"))
    )

    assert plan.changed is False
    outcome = asyncio.run(connector.apply_bulk_audit(plan))
    assert outcome.status == "no_op"


def test_bulk_audit_reconcile_mismatch_fails() -> None:
    connector = _connector(
        {
            ("GET", VULNS): _queue(
                [_page([_vuln("10001")], offset=0, total=1), _page([_vuln("10001")], offset=0, total=1)]
            ),
        }
    )
    plan = asyncio.run(
        connector.plan_bulk_audit(_resolve())
    )

    outcome = asyncio.run(connector.reconcile_bulk_audit(plan))

    assert outcome.status == "failed"
    assert "10001.developerStatus" in (outcome.error or "")


def test_bulk_audit_input_rejects_empty_update() -> None:
    with pytest.raises(ValidationError, match="at least one field"):
        BulkAuditInput(release_id="42", vulnerability_ids=["10001"])


def test_bulk_audit_input_rejects_non_numeric_ids() -> None:
    with pytest.raises(ValidationError):
        BulkAuditInput(release_id="42", vulnerability_ids=["abc"], developer_status="Resolved")


def test_bulk_audit_input_rejects_non_numeric_release() -> None:
    with pytest.raises(ValidationError):
        BulkAuditInput(release_id="release-42", vulnerability_ids=["10001"], developer_status="Resolved")
