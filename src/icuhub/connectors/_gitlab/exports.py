"""Vulnerability export create action, status read, and bounded download.

Create is one non-idempotent POST. ``apply`` never retries it: a rate limit or transient failure
returns ``outcome_unknown`` with no export id. ``reconcile`` never re-POSTs: it reads the status of
an export whose id was returned, and otherwise returns ``outcome_unknown``. No list call is made,
so an export whose id was lost is not recovered.
"""

from __future__ import annotations

import csv
import hashlib
import io
from typing import Any

from icuhub.kit import (
    ActionOutcome,
    ActionPlan,
    Conflict,
    NotFound,
    OutcomeUnknown,
    PermissionDenied,
    RateLimited,
    TransientVendorError,
    VendorContractError,
)

from .actions import _request, _require_write, action_identity
from .models import (
    CreateVulnerabilityExportInput,
    DownloadVulnerabilityExportInput,
    ExportRef,
    VendorResult,
)

__all__ = [
    "apply_create_vulnerability_export",
    "download_vulnerability_export",
    "get_vulnerability_export",
    "plan_create_vulnerability_export",
    "reconcile_create_vulnerability_export",
]

_CREATE_AMBIGUOUS = (OutcomeUnknown, TransientVendorError, RateLimited)
_CREATE_REJECTED = (Conflict, NotFound, PermissionDenied, VendorContractError)
_STATUS_AMBIGUOUS = (OutcomeUnknown, TransientVendorError, RateLimited, NotFound, VendorContractError)
_TERMINAL_EXPORT_STATUSES = ("finished", "failed", "expired")


def _scope(request: dict[str, Any]) -> tuple[str, int | None]:
    if request["project_id"] is not None:
        return "project", request["project_id"]
    if request["group_id"] is not None:
        return "group", request["group_id"]
    return "instance", None


def _create_path(scope: str, scope_id: int | None) -> str:
    if scope == "project":
        return f"/security/projects/{scope_id}/vulnerability_exports"
    if scope == "group":
        return f"/security/groups/{scope_id}/vulnerability_exports"
    return "/security/vulnerability_exports"


def _status_path(export_id: int) -> str:
    return f"/security/vulnerability_exports/{export_id}"


async def plan_create_vulnerability_export(connector: Any, args: CreateVulnerabilityExportInput) -> ActionPlan:
    request = _request(args)
    scope, scope_id = _scope(request)
    return ActionPlan(
        action="create_vulnerability_export",
        target_ref=f"gitlab:{scope}" if scope_id is None else f"gitlab:{scope}:{scope_id}",
        diff={"scope": scope, "scope_id": scope_id},
        preconditions={},
        idempotency_key=action_identity(connector, "create_vulnerability_export", f"{scope}:{scope_id}"),
        changed=True,
        request=request,
    )


async def apply_create_vulnerability_export(connector: Any, plan: ActionPlan) -> ActionOutcome:
    _require_write(connector)
    scope = plan.diff["scope"]
    scope_id = plan.diff["scope_id"]
    try:
        response = await connector.http.request(
            "POST",
            _create_path(scope, scope_id),
            json={},
            idempotency="non_idempotent",
            expected=(200, 201, 202),
        )
    except _CREATE_AMBIGUOUS as exc:
        return ActionOutcome(
            status="outcome_unknown",
            error=(
                f"export request not confirmed ({exc}); not retried. GitLab may have rejected the request because "
                "an export for this user and scope is already in progress. Check the GitLab UI for an active export "
                "and supply its export id, or retry after that export finishes."
            ),
        )
    except _CREATE_REJECTED as exc:
        return ActionOutcome(status="failed", error=str(exc))
    body = response.json()
    export_id = body.get("id") if isinstance(body, dict) else None
    if not isinstance(export_id, int) or isinstance(export_id, bool) or export_id < 1:
        return ActionOutcome(status="outcome_unknown", error="GitLab accepted the export request but returned no export id")
    return ActionOutcome(
        status="accepted_async",
        vendor_ref=str(export_id),
        result={"export_id": export_id, "scope": scope, "scope_id": scope_id, "status": body.get("status")},
    )


async def reconcile_create_vulnerability_export(connector: Any, plan: ActionPlan, outcome: ActionOutcome) -> ActionOutcome:
    if outcome.vendor_ref is None:
        return ActionOutcome(status="outcome_unknown", error=outcome.error)
    export_id = int(outcome.vendor_ref)
    scope_result = {"export_id": export_id, "scope": plan.diff["scope"], "scope_id": plan.diff["scope_id"]}
    try:
        response = await connector.http.request("GET", _status_path(export_id), expected=(200, 202))
    except _STATUS_AMBIGUOUS as exc:
        return ActionOutcome(status="outcome_unknown", vendor_ref=str(export_id), result=scope_result, error=str(exc))
    body = response.json()
    if not isinstance(body, dict) or not isinstance(body.get("status"), str):
        return ActionOutcome(
            status="outcome_unknown",
            vendor_ref=str(export_id),
            result=scope_result,
            error="GitLab export response has no status",
        )
    status = body["status"]
    result = {**scope_result, "status": status}
    if status == "finished":
        return ActionOutcome(status="succeeded", vendor_ref=str(export_id), result=result)
    if status in ("failed", "expired"):
        return ActionOutcome(status="failed", vendor_ref=str(export_id), result=result, error=f"export ended with status {status}")
    return ActionOutcome(status="accepted_async", vendor_ref=str(export_id), result=result)


async def get_vulnerability_export(connector: Any, args: ExportRef) -> VendorResult:
    response = await connector.http.request("GET", _status_path(args.export_id), expected=(200, 202))
    body = response.json()
    if not isinstance(body, dict) or not isinstance(body.get("status"), str):
        raise VendorContractError("GitLab export response has no status")
    return VendorResult(data={"export_id": args.export_id, **body}, status_code=response.status)


async def download_vulnerability_export(connector: Any, args: DownloadVulnerabilityExportInput) -> VendorResult:
    max_bytes = connector._config().max_export_bytes  # noqa: SLF001 -- connector owns its typed config
    try:
        response = await connector.http.stream_download_result(
            "GET",
            f"{_status_path(args.export_id)}/download",
            max_bytes=max_bytes,
            expected=(200,),
        )
    except NotFound as exc:
        # The status read raises NotFound itself when the export id does not exist; that propagates unchanged.
        status = (await get_vulnerability_export(connector, args)).data["status"]
        if status in _TERMINAL_EXPORT_STATUSES:
            raise NotFound(
                f"vulnerability export {args.export_id} ended with status {status} and has no download"
            ) from exc
        raise TransientVendorError(f"vulnerability export {args.export_id} is {status}; download is not ready") from exc
    return VendorResult(
        data={
            "export_id": args.export_id,
            "sha256": hashlib.sha256(response.content).hexdigest(),
            "bytes": len(response.content),
            "rows": _csv_data_rows(args.export_id, response.content),
        },
        status_code=response.status,
    )


def _csv_data_rows(export_id: int, content: bytes) -> int:
    """Count CSV data records (header excluded). The body is never echoed into an error."""
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise VendorContractError(f"vulnerability export {export_id} is not UTF-8 CSV") from exc
    records = sum(1 for _ in csv.reader(io.StringIO(text, newline="")))
    return max(records - 1, 0)
