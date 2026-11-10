"""Mend SCA write actions.

Each apply reads vendor state first, raises StalePlan when the plan preconditions no longer hold, performs at most
one vendor write through ``conn.call``, and returns an ActionOutcome. Each reconcile reads vendor state back and never
resends a write. connector.py binds these functions with ``@action(...)``; this module declares no decorators.

Plan contract (flat dicts, serialized by the planner):
- set_alert_status: request {project_token, alert_uuid, desired_status, comment, is_violating};
  preconditions {expected_status}.
- set_finding_status: request {project_uuid, root_library_uuid, desired_status, comment, is_violating};
  preconditions {expected_status}.
- import_sbom: request {project_uuid, filename, media_type, sbom_base64, sbom_sha256}.
Scan readback uses conn.config.org_uuid.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from typing import TYPE_CHECKING, Any

from icuhub.connectors.mend_sca.models import ImportSbomArgs, SetAlertStatusArgs, SetFindingStatusArgs
from icuhub.kit import (
    ActionOutcome,
    ActionPlan,
    AuthFailed,
    ConfigError,
    Conflict,
    NotFound,
    OutcomeUnknown,
    PermissionDenied,
    RateLimited,
    StalePlan,
    TransientVendorError,
    VendorContractError,
)

if TYPE_CHECKING:
    from icuhub.connectors.mend_sca.connector import MendSca

__all__ = [
    "import_sbom_apply",
    "import_sbom_reconcile",
    "plan_import_sbom",
    "plan_set_alert_status",
    "plan_set_finding_status",
    "set_alert_status_apply",
    "set_alert_status_reconcile",
    "set_finding_status_apply",
    "set_finding_status_reconcile",
]

# A write that may have reached the vendor. The outcome is unknown; never resend.
_AMBIGUOUS = (OutcomeUnknown, TransientVendorError, RateLimited)
# A write the vendor definitively refused or that never left this process.
_REJECTED = (AuthFailed, Conflict, NotFound, PermissionDenied, VendorContractError)
# Any readback failure after a write attempt cannot prove the vendor state, so it is outcome_unknown.
_READ_FAILED = (*_AMBIGUOUS, *_REJECTED)

_FINDING_STATUS_TO_VENDOR = {
    "UNREVIEWED": "MARK_AS_UNREVIEWED",
    "IN_REVIEW": "MARK_AS_IN_REVIEW",
    "SUPPRESSED": "SUPPRESS",
}
_IN_FLIGHT_SCAN_STATUSES = frozenset({"RUNNING", "PARTIAL", "PROCESSING"})


def _require_write(conn: MendSca) -> None:
    if not conn.config.write_enabled:
        raise PermissionDenied("write", "write actions require write_enabled on this connection")


def _drop_none(fields: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in fields.items() if value is not None}


def _page(body: Any, key: str) -> tuple[list[Any], dict[str, Any]]:
    if not isinstance(body, dict) or not isinstance(body.get(key), list):
        raise VendorContractError(f"Mend list response has no {key} array")
    meta = body.get("additionalData")
    if meta is None:
        meta = {}
    if not isinstance(meta, dict):
        raise VendorContractError("Mend list response additionalData is not an object")
    return body[key], meta


# Planners: read vendor state and describe the write. They never write. connector.py exposes them to the planner.


async def plan_set_alert_status(conn: MendSca, args: SetAlertStatusArgs) -> ActionPlan:
    current = await _find_alert(conn, args.project_token, args.alert_uuid)
    if current is None:
        raise StalePlan(f"alert {args.alert_uuid} is not present in the project")
    status = _alert_status(current)
    if status is None:
        raise VendorContractError(f"alert {args.alert_uuid} record carries no status")
    if args.expected_status is not None and status != args.expected_status:
        raise StalePlan(f"alert {args.alert_uuid} status is {status!r}; plan expected {args.expected_status!r}")
    return ActionPlan(
        action="set_alert_status",
        target_ref=args.alert_uuid,
        diff={"status": {"from": status, "to": args.desired_status}},
        preconditions={"expected_status": status},
        idempotency_key=f"set_alert_status:{args.project_token}:{args.alert_uuid}:{args.desired_status}",
        changed=status != args.desired_status,
        request={
            "project_token": args.project_token,
            "alert_uuid": args.alert_uuid,
            "desired_status": args.desired_status,
            "comment": args.comment,
            "is_violating": args.is_violating,
        },
    )


async def plan_set_finding_status(conn: MendSca, args: SetFindingStatusArgs) -> ActionPlan:
    current = await _find_root_library(conn, args.project_uuid, args.root_library_uuid)
    if current is None:
        raise StalePlan(f"root library {args.root_library_uuid} is not present in the project")
    status = _root_status(current)
    if status is None:
        raise VendorContractError(f"root library {args.root_library_uuid} record carries no rootStatus")
    if args.expected_status is not None and status != args.expected_status:
        raise StalePlan(
            f"root library {args.root_library_uuid} status is {status!r}; plan expected {args.expected_status!r}"
        )
    return ActionPlan(
        action="set_finding_status",
        target_ref=args.root_library_uuid,
        diff={"status": {"from": status, "to": args.desired_status}},
        preconditions={"expected_status": status},
        idempotency_key=f"set_finding_status:{args.project_uuid}:{args.root_library_uuid}:{args.desired_status}",
        changed=status != args.desired_status,
        request={
            "project_uuid": args.project_uuid,
            "root_library_uuid": args.root_library_uuid,
            "desired_status": args.desired_status,
            "comment": args.comment,
            "is_violating": args.is_violating,
        },
    )


async def plan_import_sbom(conn: MendSca, args: ImportSbomArgs) -> ActionPlan:
    if conn.config.org_uuid is None:
        raise ConfigError("org_uuid must be configured before an SBOM import can be reconciled")
    return ActionPlan(
        action="import_sbom",
        target_ref=args.project_uuid,
        diff={"filename": args.filename, "media_type": args.media_type, "sbom_sha256": args.sbom_sha256},
        preconditions={},
        idempotency_key=f"import_sbom:{args.project_uuid}:{args.sbom_sha256}",
        changed=True,
        request={
            "project_uuid": args.project_uuid,
            "filename": args.filename,
            "media_type": args.media_type,
            "sbom_base64": args.sbom_base64,
            "sbom_sha256": args.sbom_sha256,
        },
    )


# Alerts (API 2.0, project-token scoped)


def _alert_info(item: dict[str, Any]) -> dict[str, Any]:
    info = item.get("alertInfo")
    if not isinstance(info, dict):
        raise VendorContractError("alert record has no alertInfo object")
    return info


def _alert_status(item: dict[str, Any]) -> str | None:
    info = _alert_info(item)
    status = info.get("findingStatus") or info.get("status")
    return status if isinstance(status, str) else None


async def _find_alert(conn: MendSca, project_token: str, alert_uuid: str) -> dict[str, Any] | None:
    for page in range(conn.config.max_pages):
        body = await conn.call(
            "GET",
            f"/api/v2.0/projects/{project_token}/alerts/security",
            params={"page": page, "pageSize": conn.config.page_size},
        )
        items, meta = _page(body, "retVal")
        for item in items:
            if isinstance(item, dict) and _alert_info(item).get("uuid") == alert_uuid:
                return item
        if meta.get("isLastPage") is True or not items:
            return None
    raise VendorContractError("alert listing exceeded max_pages before the last page")


async def _alert_state_outcome(conn: MendSca, plan: ActionPlan) -> ActionOutcome:
    request = plan.request
    desired = request["desired_status"]
    try:
        current = await _find_alert(conn, request["project_token"], request["alert_uuid"])
        status = None if current is None else _alert_status(current)
    except _READ_FAILED as exc:
        return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))
    if current is None:
        return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error="alert not found on readback")
    if status == desired:
        return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref, result={"status": status})
    return ActionOutcome(
        status="outcome_unknown",
        vendor_ref=plan.target_ref,
        error=f"readback status {status!r} does not match desired {desired!r}",
    )


async def set_alert_status_apply(conn: MendSca, plan: ActionPlan) -> ActionOutcome:
    _require_write(conn)
    if not plan.changed:
        return ActionOutcome(status="no_op", vendor_ref=plan.target_ref)
    request = plan.request
    project_token = request["project_token"]
    alert_uuid = request["alert_uuid"]
    desired = request["desired_status"]
    current = await _find_alert(conn, project_token, alert_uuid)
    if current is None:
        raise StalePlan(f"alert {alert_uuid} is no longer present in the project")
    status = _alert_status(current)
    expected = plan.preconditions.get("expected_status")
    if expected is not None and status != expected:
        raise StalePlan(f"alert {alert_uuid} status is {status!r}; plan expected {expected!r}")
    if status == desired:
        return ActionOutcome(status="no_op", vendor_ref=plan.target_ref, result={"status": status})
    body = _drop_none(
        {
            "status": desired,
            "comment": request.get("comment"),
            "isViolating": request.get("is_violating"),
        }
    )
    try:
        await conn.call(
            "PUT",
            f"/api/v2.0/projects/{project_token}/alerts/security/{alert_uuid}",
            body=body,
        )
    except _AMBIGUOUS as exc:
        return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))
    except _REJECTED as exc:
        return ActionOutcome(status="failed", vendor_ref=plan.target_ref, error=str(exc))
    return await _alert_state_outcome(conn, plan)


async def set_alert_status_reconcile(conn: MendSca, plan: ActionPlan, outcome: ActionOutcome) -> ActionOutcome:
    return await _alert_state_outcome(conn, plan)


# Root-library findings (API 3.0, SCA project scope)


def _root_status(item: dict[str, Any]) -> str | None:
    status = item.get("rootStatus")
    return status if isinstance(status, str) else None


async def _find_root_library(conn: MendSca, project_uuid: str, root_library_uuid: str) -> dict[str, Any] | None:
    cursor: Any = None
    for _ in range(conn.config.max_pages):
        params: dict[str, Any] = {"limit": conn.config.page_size}
        if cursor is not None:
            params["cursor"] = cursor
        body = await conn.call(
            "GET",
            f"/api/v3.0/projects/{project_uuid}/dependencies/findings/security/groupBy/rootLibrary",
            params=params,
        )
        items, meta = _page(body, "response")
        for item in items:
            if isinstance(item, dict) and item.get("rootLibraryUuid") == root_library_uuid:
                return item
        if not items or not meta.get("next"):
            return None
        cursor = meta.get("cursor")
        if cursor is None:
            raise VendorContractError("root library listing has a next page but no cursor")
    raise VendorContractError("root library listing exceeded max_pages before the last page")


async def _root_state_outcome(conn: MendSca, plan: ActionPlan) -> ActionOutcome:
    request = plan.request
    desired = request["desired_status"]
    try:
        current = await _find_root_library(conn, request["project_uuid"], request["root_library_uuid"])
        status = None if current is None else _root_status(current)
    except _READ_FAILED as exc:
        return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))
    if current is None:
        return ActionOutcome(
            status="outcome_unknown", vendor_ref=plan.target_ref, error="root library not found on readback"
        )
    if status == desired:
        return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref, result={"status": status})
    return ActionOutcome(
        status="outcome_unknown",
        vendor_ref=plan.target_ref,
        error=f"readback status {status!r} does not match desired {desired!r}",
    )


async def set_finding_status_apply(conn: MendSca, plan: ActionPlan) -> ActionOutcome:
    _require_write(conn)
    if not plan.changed:
        return ActionOutcome(status="no_op", vendor_ref=plan.target_ref)
    request = plan.request
    project_uuid = request["project_uuid"]
    root_library_uuid = request["root_library_uuid"]
    desired = request["desired_status"]
    vendor_status = _FINDING_STATUS_TO_VENDOR[desired]
    current = await _find_root_library(conn, project_uuid, root_library_uuid)
    if current is None:
        raise StalePlan(f"root library {root_library_uuid} is no longer present in the project")
    status = _root_status(current)
    expected = plan.preconditions.get("expected_status")
    if expected is not None and status != expected:
        raise StalePlan(f"root library {root_library_uuid} status is {status!r}; plan expected {expected!r}")
    if status == desired:
        return ActionOutcome(status="no_op", vendor_ref=plan.target_ref, result={"status": status})
    body = _drop_none(
        {
            "status": vendor_status,
            "comment": request.get("comment"),
            "isViolating": request.get("is_violating"),
        }
    )
    try:
        await conn.call(
            "PUT",
            f"/api/v3.0/projects/{project_uuid}/dependencies/findings/security/rootLibrary/{root_library_uuid}",
            body=body,
        )
    except _AMBIGUOUS as exc:
        return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))
    except _REJECTED as exc:
        return ActionOutcome(status="failed", vendor_ref=plan.target_ref, error=str(exc))
    return await _root_state_outcome(conn, plan)


async def set_finding_status_reconcile(conn: MendSca, plan: ActionPlan, outcome: ActionOutcome) -> ActionOutcome:
    return await _root_state_outcome(conn, plan)


# SBOM import (API 3.0, asynchronous scan)


def _decode_sbom(conn: MendSca, request: dict[str, Any]) -> tuple[bytes | None, str | None]:
    """Return (sbom bytes, None) when valid, else (None, reason)."""
    encoded = request["sbom_base64"]
    max_bytes = conn.config.max_sbom_bytes
    # Base64 of N bytes is at most 4 * ceil(N / 3) characters; reject oversized input before decoding it.
    if len(encoded) > max_bytes * 4 // 3 + 4:
        return None, "SBOM exceeds max_sbom_bytes"
    try:
        raw = base64.b64decode(encoded, validate=True)
    except binascii.Error:
        return None, "sbom_base64 is not valid base64"
    if len(raw) > max_bytes:
        return None, "SBOM exceeds max_sbom_bytes"
    if hashlib.sha256(raw).hexdigest() != request["sbom_sha256"]:
        return None, "SBOM bytes do not match sbom_sha256"
    return raw, None


def _scan_uuid(body: Any) -> str | None:
    scan = body.get("scan") if isinstance(body, dict) else None
    uuid = scan.get("scanUuid") if isinstance(scan, dict) else None
    return uuid if isinstance(uuid, str) and uuid else None


async def _read_scan(conn: MendSca, org_uuid: str, project_uuid: str, scan_uuid: str) -> dict[str, Any]:
    body = await conn.call("GET", f"/api/v3.0/orgs/{org_uuid}/projects/{project_uuid}/scans/{scan_uuid}")
    response = body.get("response") if isinstance(body, dict) else None
    if not isinstance(response, dict):
        raise VendorContractError("scan response has no response object")
    return response


def _scan_error(scan: dict[str, Any]) -> str | None:
    info = scan.get("agentInfo")
    message = info.get("errorMessage") if isinstance(info, dict) else None
    return message if isinstance(message, str) and message else None


async def import_sbom_apply(conn: MendSca, plan: ActionPlan) -> ActionOutcome:
    _require_write(conn)
    if not plan.changed:
        return ActionOutcome(status="no_op", vendor_ref=plan.target_ref)
    request = plan.request
    project_uuid = request["project_uuid"]
    if conn.config.org_uuid is None:
        return ActionOutcome(
            status="failed",
            vendor_ref=plan.target_ref,
            error="org_uuid must be configured before an SBOM import can be reconciled",
        )
    raw, problem = _decode_sbom(conn, request)
    if raw is None:
        return ActionOutcome(status="failed", vendor_ref=plan.target_ref, error=problem)
    try:
        body = await conn.call(
            "POST",
            f"/api/v3.0/projects/{project_uuid}/dependencies/importSbom",
            files={"sbomFile": (request["filename"], raw, request["media_type"])},
        )
    except _AMBIGUOUS as exc:
        return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))
    except _REJECTED as exc:
        return ActionOutcome(status="failed", vendor_ref=plan.target_ref, error=str(exc))
    scan_uuid = _scan_uuid(body)
    if scan_uuid is None:
        return ActionOutcome(
            status="outcome_unknown",
            vendor_ref=plan.target_ref,
            error="importSbom response carried no scan.scanUuid",
        )
    return ActionOutcome(status="accepted_async", vendor_ref=scan_uuid, result={"scan_uuid": scan_uuid})


async def import_sbom_reconcile(conn: MendSca, plan: ActionPlan, outcome: ActionOutcome) -> ActionOutcome:
    org_uuid = conn.config.org_uuid
    scan_uuid = outcome.result.get("scan_uuid") or outcome.vendor_ref
    if org_uuid is None or not scan_uuid:
        return ActionOutcome(
            status="outcome_unknown",
            vendor_ref=outcome.vendor_ref,
            error="scan identity or org_uuid unavailable for readback",
        )
    try:
        scan = await _read_scan(conn, org_uuid, plan.request["project_uuid"], scan_uuid)
    except _READ_FAILED as exc:
        return ActionOutcome(status="outcome_unknown", vendor_ref=scan_uuid, error=str(exc))
    status = scan.get("status")
    result = {"scan_uuid": scan_uuid, "status": status}
    if status == "FINISHED":
        return ActionOutcome(status="succeeded", vendor_ref=scan_uuid, result=result)
    if status == "FAILED":
        return ActionOutcome(status="failed", vendor_ref=scan_uuid, result=result, error=_scan_error(scan) or "scan failed")
    if status in _IN_FLIGHT_SCAN_STATUSES:
        return ActionOutcome(status="accepted_async", vendor_ref=scan_uuid, result=result)
    return ActionOutcome(
        status="outcome_unknown",
        vendor_ref=scan_uuid,
        result=result,
        error=f"unrecognized scan status {status!r}",
    )
