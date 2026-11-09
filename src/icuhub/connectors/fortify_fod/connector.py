"""Fortify on Demand connector: complete release issue snapshots and bulk audit edits.

Wire contract sources: ``docs/VENDOR_CONNECTORS.md`` (Fortify on Demand) and
``local://sota_fortify_research.md`` (fcli-derived request shapes). Only
operations with a sourced wire path are implemented. Incremental sync is not
declared: the changed-since filter is unverified per tenant, so every release
is read as a complete snapshot with fixed and suppressed records included.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import AsyncIterator
from typing import Any, ClassVar

from icuhub.connectors._fortify.mappers import map_fod_issue
from icuhub.connectors.fortify_fod.models import BulkAuditInput, FortifyFodConfig
from icuhub.kit.auth import AuthStrategy, OAuth2ClientCredentials
from icuhub.kit.connector import Connector, action, mapper, stream
from icuhub.kit.cursors import SnapshotCursor
from icuhub.kit.errors import ConfigError, OutcomeUnknown, StalePlan, TransientVendorError, VendorContractError
from icuhub.kit.http import HttpResult
from icuhub.kit.types import (
    ActionOutcome,
    ActionPlan,
    CapabilityHealth,
    ConnectorConfig,
    HealthReport,
    MapContext,
    RawBatch,
    Scope,
    Target,
)
from icuhub_schemas.ocsf import VulnerabilityFinding

__all__ = ["FortifyFod"]

_VULNERABILITIES_PATH = "/api/v3/releases/{release_id}/vulnerabilities"
_BULK_EDIT_PATH = "/api/v3/releases/{release_id}/vulnerabilities/bulk-edit"
# [INFERENCE] 50 is the sourced maximum for applications, releases, scans and reports. The
# vulnerability page cap is tenant-configured, so the server may return fewer items; paging
# advances by the number of items actually returned.
_PAGE_LIMIT = 50
_STATUS_FIELDS = ("developerStatus", "auditorStatus", "severity")
# Bulk-edit body fields that cannot be read back from the vulnerability list.
_UNVERIFIED_BODY_FIELDS = ("userId", "comment", "attributes")


def _json_object(result: HttpResult) -> dict[str, Any]:
    body = result.json()
    if not isinstance(body, dict):
        raise VendorContractError("FoD response must be a JSON object")
    return body


def _release_id(target: Target) -> str:
    release_id = target.source_uid
    if not (release_id.isascii() and release_id.isdigit()):
        raise ConfigError(f"fortify_fod release id must be decimal digits, got {release_id!r}")
    return release_id


def _sha256_json(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _desired_status(body: dict[str, Any]) -> dict[str, Any]:
    return {name: body[name] for name in _STATUS_FIELDS if name in body}


def _status_mismatches(states: dict[str, dict[str, Any]], desired: dict[str, Any]) -> list[str]:
    return [
        f"{vuln_id}.{field}"
        for vuln_id, record in states.items()
        for field, wanted in desired.items()
        if record.get(field) != wanted
    ]


def _bulk_edit_error_codes(body: Any) -> list[int] | None:
    if not isinstance(body, list) or not body:
        return None
    codes: list[int] = []
    for entry in body:
        code = entry.get("errorCode") if isinstance(entry, dict) else None
        if isinstance(code, bool) or not isinstance(code, int):
            return None
        codes.append(code)
    return codes


class FortifyFod(Connector):
    """Fortify on Demand: release vulnerability snapshots and bulk audit edits."""

    kind: ClassVar[str] = "fortify_fod"
    version: ClassVar[str] = "0.1.0"
    display_name: ClassVar[str] = "Fortify on Demand"
    config_model: ClassVar[type[ConnectorConfig]] = FortifyFodConfig
    auth_modes: ClassVar[tuple[str, ...]] = ("OAuth2ClientCredentials",)
    capabilities: ClassVar[tuple[str, ...]] = ("FindingSource",)
    flows: ClassVar[tuple[str, ...]] = ("F-228",)
    scopes: ClassVar[tuple[Scope, ...]] = (
        Scope(
            name="view-issues",
            probe="GET /api/v3/releases/{releaseId}/vulnerabilities",
            required_by=("FindingSource",),
        ),
        Scope(
            name="manage-issues",
            probe="POST /api/v3/releases/{releaseId}/vulnerabilities/bulk-edit",
            required_by=("FindingSource",),
        ),
    )

    async def build_auth(self) -> AuthStrategy:
        if not isinstance(self.config, FortifyFodConfig):
            raise ConfigError("fortify_fod requires a FortifyFodConfig")
        raw_secret = await self.ctx.secrets.resolve(self.config.client_secret)
        try:
            client_secret = raw_secret.decode("utf-8")
        except UnicodeDecodeError:
            raise ConfigError("fortify_fod client_secret must be UTF-8") from None
        return OAuth2ClientCredentials(
            token_url=f"{self.config.base_url.rstrip('/')}/oauth/token",
            client_id=self.config.client_id,
            client_secret=client_secret,
            scope="api-tenant",
        )

    async def check(self) -> HealthReport:
        # No target-free read endpoint is sourced, and a release-scoped probe needs a target.
        return HealthReport(
            status="not_evaluated",
            capabilities={
                "FindingSource": CapabilityHealth(
                    status="not_evaluated",
                    reason="no sourced target-free endpoint; a release-scoped probe needs a target",
                ),
            },
        )

    async def _issue_page(self, release_id: str, offset: int) -> tuple[list[dict[str, Any]], int]:
        result = await self.http.request(
            "GET",
            _VULNERABILITIES_PATH.format(release_id=release_id),
            params={
                "excludeFilters": "true",
                "orderBy": "severity",
                "orderDirection": "ASC",
                "includeFixed": "true",
                "includeSuppressed": "true",
                "offset": str(offset),
                "limit": str(_PAGE_LIMIT),
            },
        )
        body = _json_object(result)
        if body.get("offset") != offset:
            raise VendorContractError(f"FoD echoed offset {body.get('offset')!r} for requested offset {offset}")
        items = body.get("items")
        total = body.get("totalCount")
        if not isinstance(items, list):
            raise VendorContractError("FoD vulnerability page items must be a list")
        records = [item for item in items if isinstance(item, dict)]
        if len(records) != len(items):
            raise VendorContractError("FoD vulnerability page items must be objects")
        if isinstance(total, bool) or not isinstance(total, int) or total < 0:
            raise VendorContractError("FoD vulnerability page totalCount must be a non-negative integer")
        return records, total

    async def _issue_pages(self, release_id: str) -> AsyncIterator[list[dict[str, Any]]]:
        """Yield the pages of one release snapshot. Any inconsistency raises before the next yield.

        Ordering by severity is not a unique key, so duplicate native ids are rejected and the
        number of distinct ids must equal ``totalCount`` when the snapshot ends.
        """
        seen: set[str] = set()
        offset = 0
        total: int | None = None
        # The first page establishes totalCount; no request is issued once offset reaches it.
        while total is None or offset < total:
            items, page_total = await self._issue_page(release_id, offset)
            if total is None:
                total = page_total
            elif page_total != total:
                raise VendorContractError(
                    f"release {release_id} totalCount changed from {total} to {page_total} during the snapshot"
                )
            if not items:
                raise VendorContractError(
                    f"release {release_id} returned an empty page at offset {offset} before totalCount {total}"
                )
            if offset + len(items) > total:
                raise VendorContractError(f"release {release_id} page at offset {offset} overruns totalCount {total}")
            for item in items:
                identity = item.get("id")
                if identity is None or isinstance(identity, bool):
                    raise VendorContractError(f"release {release_id} issue record has no numeric id")
                key = str(identity)
                if key in seen:
                    raise VendorContractError(f"release {release_id} snapshot repeated issue id {key}")
                seen.add(key)
            yield items
            offset += len(items)
        if len(seen) != total:
            raise VendorContractError(
                f"release {release_id} snapshot yielded {len(seen)} distinct issues, expected {total}"
            )

    async def _lookup_vulnerability(self, release_id: str, vuln_id: str) -> dict[str, Any]:
        result = await self.http.request(
            "GET",
            _VULNERABILITIES_PATH.format(release_id=release_id),
            params={
                "excludeFilters": "true",
                "filters": f"id:{vuln_id}",
                "includeFixed": "true",
                "includeSuppressed": "true",
                "limit": "2",
            },
        )
        items = _json_object(result).get("items")
        if not isinstance(items, list) or len(items) != 1 or not isinstance(items[0], dict):
            raise VendorContractError(f"vulnerability {vuln_id} lookup must return exactly one record")
        record = items[0]
        if str(record.get("id")) != vuln_id:
            raise VendorContractError(f"vulnerability lookup for {vuln_id} returned id {record.get('id')!r}")
        return record

    async def _read_states(self, release_id: str, vuln_ids: list[str]) -> dict[str, dict[str, Any]]:
        states: dict[str, dict[str, Any]] = {}
        for vuln_id in vuln_ids:
            record = await self._lookup_vulnerability(release_id, vuln_id)
            states[vuln_id] = {field: record.get(field) for field in _STATUS_FIELDS}
        return states

    @stream(
        "issues",
        cursor=SnapshotCursor,
        capability="FindingSource",
        ocsf_class=2002,
        record_type="vulnerability_finding",
        modes=("full",),
        requires_target=True,
    )
    async def issues(self, target: Target | None, checkpoint: Any, mode: str) -> AsyncIterator[RawBatch]:
        if target is None:
            raise ConfigError("fortify_fod issues stream requires a release target")
        release_id = _release_id(target)
        if isinstance(checkpoint, SnapshotCursor):
            started_at = checkpoint.started_at
            snapshot_id = checkpoint.snapshot_id
            done = list(checkpoint.targets_done)
        else:
            started_at = self.ctx.clock()
            snapshot_id = f"fortify_fod:issues:{started_at.isoformat()}"
            done = []
        cursor = SnapshotCursor(snapshot_id=snapshot_id, started_at=started_at, targets_done=done)
        if release_id in done:
            yield RawBatch(records=[], checkpoint=cursor, complete=True)
            return
        async for page in self._issue_pages(release_id):
            yield RawBatch(
                records=[{**item, "_release_id": release_id} for item in page],
                checkpoint=cursor,
                complete=False,
            )
        yield RawBatch(
            records=[],
            checkpoint=cursor.model_copy(update={"targets_done": [*done, release_id]}),
            complete=True,
        )

    @mapper("issues", version=1)
    def map_issue(self, raw: dict[str, Any], ctx: MapContext) -> list[VulnerabilityFinding]:
        return map_fod_issue(raw, ctx)

    @action(
        "bulk_audit_issues",
        classification="write",
        capability="FindingSource",
        input_model=BulkAuditInput,
        idempotency="natural_key",
        stability="beta",
    )
    async def plan_bulk_audit(self, args: BulkAuditInput) -> ActionPlan:
        ids = sorted(set(args.vulnerability_ids), key=int)
        states = await self._read_states(args.release_id, ids)
        body: dict[str, Any] = {"vulnerabilityIds": ids}
        optional: dict[str, Any] = {
            "userId": args.user_id,
            "developerStatus": args.developer_status,
            "auditorStatus": args.auditor_status,
            "severity": args.severity,
            "comment": args.comment,
            "attributes": args.attributes,
        }
        body.update({name: value for name, value in optional.items() if value is not None})
        desired = _desired_status(body)
        status_diff: dict[str, dict[str, dict[str, Any]]] = {}
        for vuln_id, record in states.items():
            changes = {
                field: {"from": record[field], "to": wanted}
                for field, wanted in desired.items()
                if record[field] != wanted
            }
            if changes:
                status_diff[vuln_id] = changes
        unverified = [name for name in _UNVERIFIED_BODY_FIELDS if name in body]
        return ActionPlan(
            action="bulk_audit_issues",
            target_ref=f"fortify_fod:release:{args.release_id}",
            diff={"status": status_diff, "unverified_fields": unverified},
            preconditions={
                "release_id": args.release_id,
                "vulnerability_ids": ids,
                "state_sha256": _sha256_json(states),
            },
            idempotency_key="bulk_audit:" + _sha256_json({"release_id": args.release_id, "body": body}),
            changed=bool(status_diff) or bool(unverified),
            request={
                "method": "POST",
                "path": _BULK_EDIT_PATH.format(release_id=args.release_id),
                "params": {"excludeFilters": "true"},
                "json": body,
            },
        )

    @plan_bulk_audit.apply
    async def apply_bulk_audit(self, plan: ActionPlan) -> ActionOutcome:
        if not plan.changed:
            return ActionOutcome(status="no_op", vendor_ref=plan.target_ref)
        release_id: str = plan.preconditions["release_id"]
        ids: list[str] = plan.preconditions["vulnerability_ids"]
        current = await self._read_states(release_id, ids)
        if _sha256_json(current) != plan.preconditions["state_sha256"]:
            raise StalePlan(f"release {release_id} vulnerability state changed after planning")
        try:
            result = await self.http.request(
                "POST",
                plan.request["path"],
                params=plan.request["params"],
                json=plan.request["json"],
                idempotency="non_idempotent",
                expected=(200,),
            )
        except (OutcomeUnknown, TransientVendorError) as exc:
            return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(exc))
        codes = _bulk_edit_error_codes(result.json())
        if codes is None:
            return ActionOutcome(
                status="outcome_unknown",
                vendor_ref=plan.target_ref,
                error="bulk-edit response was not a list of objects with integer errorCode",
            )
        failed = [code for code in codes if code != 0]
        if failed:
            return ActionOutcome(
                status="failed",
                vendor_ref=plan.target_ref,
                error=f"{len(failed)} of {len(codes)} bulk-edit entries returned errorCode {sorted(set(failed))}",
            )
        readback = await self._read_states(release_id, ids)
        mismatches = _status_mismatches(readback, _desired_status(plan.request["json"]))
        if mismatches:
            return ActionOutcome(
                status="outcome_unknown",
                vendor_ref=plan.target_ref,
                error=f"bulk-edit reported success but state differs: {', '.join(mismatches)}",
            )
        return ActionOutcome(
            status="succeeded",
            vendor_ref=plan.target_ref,
            result={"entries": len(codes), "unverified_fields": plan.diff["unverified_fields"]},
        )

    @plan_bulk_audit.reconcile
    async def reconcile_bulk_audit(self, plan: ActionPlan) -> ActionOutcome:
        release_id: str = plan.preconditions["release_id"]
        ids: list[str] = plan.preconditions["vulnerability_ids"]
        states = await self._read_states(release_id, ids)
        mismatches = _status_mismatches(states, _desired_status(plan.request["json"]))
        if mismatches:
            return ActionOutcome(
                status="failed",
                vendor_ref=plan.target_ref,
                error=f"status not applied: {', '.join(mismatches)}",
            )
        return ActionOutcome(
            status="succeeded",
            vendor_ref=plan.target_ref,
            result={"reconciled": True, "unverified_fields": plan.diff["unverified_fields"]},
        )
