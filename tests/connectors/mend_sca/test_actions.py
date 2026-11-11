"""Offline behavior tests for Mend SCA triage and SBOM import actions."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from typing import Any

import pytest

from icuhub.kit.errors import ConfigError, PermissionDenied, StalePlan
from icuhub.kit.testing import ReadOnlyGuard
from icuhub.kit.types import ActionOutcome, ActionPlan

from .conftest import LOGIN, ORG_UUID, REFRESH, RouteTransport, make_mend

PROJECT_TOKEN = "project-token"
ALERT_UUID = "alert-uuid"
PROJECT_UUID = "00000000-0000-4000-8000-000000000101"
ROOT_LIBRARY_UUID = "root-library-uuid"
SCAN_UUID = "scan-uuid"
COMMENT = "Reviewed and approved by the security team"
APPROVED_PLAN_HASH = "0" * 64
MIN_MAX_SBOM_BYTES = 1024  # the smallest value MendSCAConfig accepts
ALERT_LIST_PATH = f"/api/v2.0/projects/{PROJECT_TOKEN}/alerts/security"
ALERT_WRITE_PATH = f"{ALERT_LIST_PATH}/{ALERT_UUID}"
ROOT_LIST_PATH = f"/api/v3.0/projects/{PROJECT_UUID}/dependencies/findings/security/groupBy/rootLibrary"
ROOT_WRITE_PATH = f"/api/v3.0/projects/{PROJECT_UUID}/dependencies/findings/security/rootLibrary/{ROOT_LIBRARY_UUID}"
SBOM_PATH = f"/api/v3.0/projects/{PROJECT_UUID}/dependencies/importSbom"
SCAN_PATH = f"/api/v3.0/orgs/{ORG_UUID}/projects/{PROJECT_UUID}/scans/{SCAN_UUID}"
VENDOR_FINDING_STATUS = {"SUPPRESS": "SUPPRESSED"}


def _spec(connector: Any, name: str) -> Any:
    return connector.actions()[name]


def _args(connector: Any, name: str, **fields: Any) -> Any:
    return _spec(connector, name).input_model(approved_plan_hash=APPROVED_PLAN_HASH, **fields)


def _plan(connector: Any, name: str, **fields: Any) -> ActionPlan:
    return asyncio.run(_spec(connector, name).plan(connector, _args(connector, name, **fields)))


def _apply(connector: Any, name: str, plan: ActionPlan) -> ActionOutcome:
    return asyncio.run(_spec(connector, name).apply(connector, plan))


def _reconcile(connector: Any, name: str, plan: ActionPlan, outcome: ActionOutcome) -> ActionOutcome:
    spec = _spec(connector, name)
    assert spec.reconcile is not None
    return asyncio.run(spec.reconcile(connector, plan, outcome))


def _read_only_mend(routes: dict[tuple[str, str], Any]) -> tuple[Any, Any]:
    """Build a connector whose transport permits no write except the login POST."""
    transport = RouteTransport(routes)
    return make_mend(ReadOnlyGuard(transport, allowed_post_paths=(LOGIN[1], REFRESH[1]))), transport


def _writes(transport: Any) -> list[Any]:
    return [
        request
        for request in transport.requests
        if request.method in {"POST", "PUT", "PATCH", "DELETE"} and request.url.path not in {LOGIN[1], REFRESH[1]}
    ]


def _identity(kind: str) -> dict[str, str]:
    if kind == "alert":
        return {"project_token": PROJECT_TOKEN, "alert_uuid": ALERT_UUID}
    return {"project_uuid": PROJECT_UUID, "root_library_uuid": ROOT_LIBRARY_UUID}


def _alert_routes(state: dict[str, str], write_status: int = 200) -> dict[tuple[str, str], Any]:
    def listing(_request: Any) -> dict[str, Any]:
        return {
            "json": {
                "retVal": [{"alertInfo": {"uuid": ALERT_UUID, "findingStatus": state["status"]}}],
                "additionalData": {"isLastPage": True},
            }
        }

    def write(request: Any) -> dict[str, Any]:
        if write_status == 200:
            state["status"] = json.loads(request.content)["status"]
        return {"status": write_status, "json": {}}

    return {("GET", ALERT_LIST_PATH): listing, ("PUT", ALERT_WRITE_PATH): write}


def _root_routes(state: dict[str, str], write_status: int = 200) -> dict[tuple[str, str], Any]:
    def listing(_request: Any) -> dict[str, Any]:
        return {
            "json": {
                "response": [{"rootLibraryUuid": ROOT_LIBRARY_UUID, "rootStatus": state["status"]}],
                "additionalData": {},
            }
        }

    def write(request: Any) -> dict[str, Any]:
        if write_status == 200:
            state["status"] = VENDOR_FINDING_STATUS[json.loads(request.content)["status"]]
        return {"status": write_status, "json": {}}

    return {("GET", ROOT_LIST_PATH): listing, ("PUT", ROOT_WRITE_PATH): write}


def _triage_fields(kind: str) -> dict[str, Any]:
    desired, is_violating = ("IGNORED", False) if kind == "alert" else ("SUPPRESSED", True)
    return {**_identity(kind), "desired_status": desired, "comment": COMMENT, "is_violating": is_violating}


def _triage_case(
    kind: str, write_status: int = 200
) -> tuple[str, dict[str, Any], dict[tuple[str, str], Any], dict[str, str]]:
    state = {"status": "ACTIVE" if kind == "alert" else "UNREVIEWED"}
    routes = _alert_routes(state, write_status) if kind == "alert" else _root_routes(state, write_status)
    return f"set_{kind}_status", _triage_fields(kind), routes, state


def _sbom_fields(raw: bytes = b'{"bomFormat":"CycloneDX"}') -> dict[str, Any]:
    return {
        "project_uuid": PROJECT_UUID,
        "filename": "bom.json",
        "media_type": "application/json",
        "sbom_base64": base64.b64encode(raw).decode("ascii"),
        "sbom_sha256": hashlib.sha256(raw).hexdigest(),
    }


@pytest.mark.parametrize("kind", ["alert", "finding"])
def test_triage_plan_is_read_only_and_carries_write_intent(kind: str) -> None:
    name, fields, routes, state = _triage_case(kind)
    connector, transport = _read_only_mend(routes)

    plan = _plan(connector, name, **fields)

    assert plan.changed is True
    assert plan.target_ref == (ALERT_UUID if kind == "alert" else ROOT_LIBRARY_UUID)
    assert plan.preconditions == {"expected_status": state["status"]}
    assert plan.request == {
        **_identity(kind),
        "desired_status": fields["desired_status"],
        "comment": COMMENT,
        "is_violating": fields["is_violating"],
    }
    assert _writes(transport) == []


@pytest.mark.parametrize("kind", ["alert", "finding"])
def test_triage_plan_is_stale_when_target_is_absent(kind: str) -> None:
    name, fields, _, _ = _triage_case(kind)
    path, key = (ALERT_LIST_PATH, "retVal") if kind == "alert" else (ROOT_LIST_PATH, "response")
    connector, transport = _read_only_mend({("GET", path): {"json": {key: [], "additionalData": {"isLastPage": True}}}})

    with pytest.raises(StalePlan, match="not present in the project"):
        _plan(connector, name, **fields)
    assert _writes(transport) == []


@pytest.mark.parametrize("kind", ["alert", "finding"])
def test_triage_apply_requires_write_enabled_without_sending_write(kind: str) -> None:
    name, fields, routes, _ = _triage_case(kind)
    transport = RouteTransport(routes)
    connector = make_mend(transport)
    plan = _plan(connector, name, **fields)

    with pytest.raises(PermissionDenied, match="write_enabled"):
        _apply(connector, name, plan)
    assert _writes(transport) == []


@pytest.mark.parametrize("kind", ["alert", "finding"])
def test_triage_apply_writes_once_and_reconcile_only_reads(kind: str) -> None:
    name, fields, routes, _ = _triage_case(kind)
    transport = RouteTransport(routes)
    connector = make_mend(transport, config_overrides={"write_enabled": True})
    plan = _plan(connector, name, **fields)

    outcome = _apply(connector, name, plan)
    reconciled = _reconcile(connector, name, plan, outcome)

    writes = _writes(transport)
    assert outcome.status == "succeeded"
    assert outcome.result == {"status": fields["desired_status"]}
    assert reconciled.status == "succeeded"
    assert reconciled.result == outcome.result
    assert len(writes) == 1
    assert writes[0].method == "PUT"
    assert writes[0].url.path == (ALERT_WRITE_PATH if kind == "alert" else ROOT_WRITE_PATH)
    assert json.loads(writes[0].content) == {
        "status": "IGNORED" if kind == "alert" else "SUPPRESS",
        "comment": COMMENT,
        "isViolating": fields["is_violating"],
    }


@pytest.mark.parametrize("kind", ["alert", "finding"])
def test_triage_unchanged_plan_is_no_op_without_write(kind: str) -> None:
    name, fields, routes, state = _triage_case(kind)
    fields["desired_status"] = state["status"]
    transport = RouteTransport(routes)
    connector = make_mend(transport, config_overrides={"write_enabled": True})
    plan = _plan(connector, name, **fields)

    outcome = _apply(connector, name, plan)

    assert plan.changed is False
    assert outcome.status == "no_op"
    assert _writes(transport) == []


@pytest.mark.parametrize("kind", ["alert", "finding"])
def test_triage_write_5xx_is_attempted_once_and_reported_unknown(kind: str) -> None:
    name, fields, routes, state = _triage_case(kind, write_status=500)
    transport = RouteTransport(routes)
    connector = make_mend(transport, config_overrides={"write_enabled": True})
    plan = _plan(connector, name, **fields)

    outcome = _apply(connector, name, plan)

    assert outcome.status == "outcome_unknown"
    assert state["status"] == ("ACTIVE" if kind == "alert" else "UNREVIEWED")
    assert len(_writes(transport)) == 1


@pytest.mark.parametrize("kind", ["alert", "finding"])
def test_triage_readback_showing_unapproved_status_is_failed(kind: str) -> None:
    name, fields, routes, state = _triage_case(kind)
    transport = RouteTransport(routes)
    connector = make_mend(transport, config_overrides={"write_enabled": True})
    plan = _plan(connector, name, **fields)
    outcome = _apply(connector, name, plan)
    assert outcome.status == "succeeded"

    # Vendor reverted to a known wrong state before the readback: the readback definitively disproves the write.
    state["status"] = "ACTIVE" if kind == "alert" else "UNREVIEWED"
    reconciled = _reconcile(connector, name, plan, outcome)

    assert reconciled.status == "failed"
    assert reconciled.error is not None
    assert len(_writes(transport)) == 1


@pytest.mark.parametrize("kind", ["alert", "finding"])
def test_triage_readback_missing_item_is_unverified(kind: str) -> None:
    name, fields, routes, _ = _triage_case(kind)
    path, key = (ALERT_LIST_PATH, "retVal") if kind == "alert" else (ROOT_LIST_PATH, "response")
    present = {"value": True}
    listing = routes[("GET", path)]

    def readback(request: Any) -> dict[str, Any]:
        if present["value"]:
            return listing(request)
        return {"json": {key: [], "additionalData": {"isLastPage": True}}}

    routes[("GET", path)] = readback
    transport = RouteTransport(routes)
    connector = make_mend(transport, config_overrides={"write_enabled": True})
    plan = _plan(connector, name, **fields)
    outcome = _apply(connector, name, plan)
    assert outcome.status == "succeeded"

    present["value"] = False
    reconciled = _reconcile(connector, name, plan, outcome)

    assert reconciled.status == "unverified"
    assert len(_writes(transport)) == 1


def test_import_sbom_plan_is_read_only_and_carries_import_intent() -> None:
    connector, transport = _read_only_mend({})
    fields = _sbom_fields()

    plan = _plan(connector, "import_sbom", **fields)

    assert plan.changed is True
    assert plan.target_ref == PROJECT_UUID
    assert plan.request == fields
    assert plan.diff == {
        "filename": fields["filename"],
        "media_type": fields["media_type"],
        "sbom_sha256": fields["sbom_sha256"],
    }
    assert _writes(transport) == []


def test_import_sbom_plan_requires_org_uuid() -> None:
    transport = RouteTransport({})
    connector = make_mend(
        transport,
        config_overrides={
            "api_version": "2.0",
            "org_uuid": None,
            "org_token": {"ref": "vault:mend-org-token"},
        },
        secrets={"vault:mend-user-key": b"test-user-key", "vault:mend-org-token": b"test-org-token"},
    )

    with pytest.raises(ConfigError, match="org_uuid"):
        _plan(connector, "import_sbom", **_sbom_fields())
    assert _writes(transport) == []


@pytest.mark.parametrize(
    ("fields", "error"),
    [
        ({**_sbom_fields(), "sbom_base64": "not base64!"}, "sbom_base64 is not valid base64"),
        (_sbom_fields(b"x" * (MIN_MAX_SBOM_BYTES + 1)), "SBOM exceeds max_sbom_bytes"),
    ],
)
def test_import_sbom_apply_rejects_invalid_payload_without_write(fields: dict[str, Any], error: str) -> None:
    transport = RouteTransport({})
    connector = make_mend(
        transport,
        config_overrides={"write_enabled": True, "max_sbom_bytes": MIN_MAX_SBOM_BYTES},
    )
    plan = _plan(connector, "import_sbom", **fields)

    outcome = _apply(connector, "import_sbom", plan)

    assert outcome.status == "failed"
    assert outcome.error == error
    assert _writes(transport) == []


def test_import_sbom_apply_requires_write_enabled_without_sending_write() -> None:
    transport = RouteTransport({})
    connector = make_mend(transport)
    plan = _plan(connector, "import_sbom", **_sbom_fields())

    with pytest.raises(PermissionDenied, match="write_enabled"):
        _apply(connector, "import_sbom", plan)
    assert _writes(transport) == []


def test_import_sbom_apply_sends_one_import_request() -> None:
    transport = RouteTransport({("POST", SBOM_PATH): {"json": {"scan": {"scanUuid": SCAN_UUID}}}})
    connector = make_mend(transport, config_overrides={"write_enabled": True})
    plan = _plan(connector, "import_sbom", **_sbom_fields())

    outcome = _apply(connector, "import_sbom", plan)

    writes = _writes(transport)
    assert outcome.status == "accepted_async"
    assert outcome.vendor_ref == SCAN_UUID
    assert outcome.result == {"scan_uuid": SCAN_UUID}
    assert len(writes) == 1
    assert writes[0].method == "POST"
    assert writes[0].url.path == SBOM_PATH


@pytest.mark.parametrize(
    ("scan_status", "expected"),
    [("FINISHED", "succeeded"), ("FAILED", "failed"), ("RUNNING", "accepted_async"), ("UNKNOWN", "outcome_unknown")],
)
def test_import_sbom_reconcile_maps_scan_state_without_resending(scan_status: str, expected: str) -> None:
    scan: dict[str, Any] = {"status": scan_status}
    if scan_status == "FAILED":
        scan["agentInfo"] = {"errorMessage": "vendor rejected the SBOM"}
    transport = RouteTransport({("GET", SCAN_PATH): {"json": {"response": scan}}})
    connector = make_mend(transport, config_overrides={"write_enabled": True})
    plan = _plan(connector, "import_sbom", **_sbom_fields())
    accepted = ActionOutcome(status="accepted_async", vendor_ref=SCAN_UUID, result={"scan_uuid": SCAN_UUID})

    outcome = _reconcile(connector, "import_sbom", plan, accepted)

    assert outcome.status == expected
    assert outcome.vendor_ref == SCAN_UUID
    assert outcome.result == {"scan_uuid": SCAN_UUID, "status": scan_status}
    if scan_status == "FAILED":
        assert outcome.error == "vendor rejected the SBOM"
    assert _writes(transport) == []


def test_import_sbom_write_5xx_is_attempted_once_and_reported_unknown() -> None:
    transport = RouteTransport({("POST", SBOM_PATH): {"status": 500, "json": {}}})
    connector = make_mend(transport, config_overrides={"write_enabled": True})
    plan = _plan(connector, "import_sbom", **_sbom_fields())

    outcome = _apply(connector, "import_sbom", plan)

    assert outcome.status == "outcome_unknown"
    assert len(_writes(transport)) == 1
