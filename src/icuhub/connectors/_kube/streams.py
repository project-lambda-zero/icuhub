"""Kubernetes streams: policy reports, Gatekeeper constraints, OpenShift Route and SCC assessments,
and resource inventory, as snapshot and change feeds.

Snapshot streams list every selected partition in one run and close absence only when the run
emitted no coverage marker. A forbidden partition, an unreadable discovery step, a truncated
Gatekeeper status, or an unconfirmed Gatekeeper audit run emits a coverage marker, so a degraded
run never reads as an empty complete result.

Change streams keep one opaque resourceVersion per partition. A watch window that returns 410
drops only that partition's version and relists it in the same run. A relist cannot recover
deletions that happened inside the compaction gap; those are reconciled only by the snapshot stream.

Audit events are delivered by audit ingress, not polled. RECORD_STREAMS names them so the mapper
validates their record kind like every other kind.
"""

from __future__ import annotations

import hashlib
from collections.abc import AsyncIterator, Mapping
from typing import Any

from icuhub.connectors._kube.client import ResourceSpec
from icuhub.connectors._kube.models import (
    KubePartitionCursor,
    KubeSnapshotCursor,
    ResourceSelection,
)
from icuhub.kit import RawBatch
from icuhub.kit.errors import PermissionDenied, VendorContractError

__all__ = ["RECORD_STREAMS", "STREAM_SPECS", "run_stream"]

_POLICY_REPORTS = (
    ResourceSelection(group="wgpolicyk8s.io", version="v1alpha2", resource="policyreports", kind="PolicyReport"),
    ResourceSelection(
        group="wgpolicyk8s.io", version="v1alpha2", resource="clusterpolicyreports", kind="ClusterPolicyReport"
    ),
)
_GATEKEEPER_TEMPLATES = ResourceSelection(
    group="templates.gatekeeper.sh", version="v1", resource="constrainttemplates", kind="ConstraintTemplate"
)
_CONSTRAINT_GROUP = "constraints.gatekeeper.sh"
_CONSTRAINT_VERSION = "v1beta1"
_AUDIT_PARTITION = f"{_CONSTRAINT_GROUP}/audit@*"
_PROJECTS = ResourceSelection(group="project.openshift.io", version="v1", resource="projects", kind="Project")
_ROUTES = ResourceSelection(group="route.openshift.io", version="v1", resource="routes", kind="Route")
_SCCS = ResourceSelection(
    group="security.openshift.io",
    version="v1",
    resource="securitycontextconstraints",
    kind="SecurityContextConstraints",
)
_COMPLIANCE_RESULTS = ResourceSelection(
    group="compliance.openshift.io",
    version="v1alpha1",
    resource="compliancecheckresults",
    kind="ComplianceCheckResult",
)
_COMPLIANCE_SCANS = ResourceSelection(
    group="compliance.openshift.io", version="v1alpha1", resource="compliancescans", kind="ComplianceScan"
)
_COMPLIANCE_SUITES = ResourceSelection(
    group="compliance.openshift.io", version="v1alpha1", resource="compliancesuites", kind="ComplianceSuite"
)
_OPENSHIFT_INVENTORY = (
    ResourceSelection(group="config.openshift.io", version="v1", resource="clusterversions", kind="ClusterVersion"),
    ResourceSelection(group="build.openshift.io", version="v1", resource="buildconfigs", kind="BuildConfig"),
    ResourceSelection(group="build.openshift.io", version="v1", resource="builds", kind="Build"),
    ResourceSelection(group="image.openshift.io", version="v1", resource="imagestreams", kind="ImageStream"),
    ResourceSelection(group="image.openshift.io", version="v1", resource="images", kind="Image"),
    ResourceSelection(group="user.openshift.io", version="v1", resource="users", kind="User"),
    ResourceSelection(group="user.openshift.io", version="v1", resource="groups", kind="Group"),
)
# Fixed OpenShift-only discovery per record kind. Configured kinds (policy, Gatekeeper, workload,
# RBAC, resource inventory) are resolved in _discover from connector config.
_OPENSHIFT_SELECTIONS: dict[str, tuple[ResourceSelection, ...]] = {
    "openshift_inventory": _OPENSHIFT_INVENTORY,
    "project": (_PROJECTS,),
    "route_assessment": (_ROUTES,),
    "scc_assessment": (_SCCS,),
    "compliance_result": (_COMPLIANCE_RESULTS,),
    "compliance_scan_status": (_COMPLIANCE_SCANS, _COMPLIANCE_SUITES),
}

# The single source of truth for which stream emits which record kind. Names match the stream
# specs declared on the connector classes. The mapper validates every record against this table.
RECORD_STREAMS: dict[str, tuple[str, ...]] = {
    "policy_report": ("policy_report_changes", "policy_report_snapshot"),
    "gatekeeper_constraint": ("gatekeeper_constraint_changes", "gatekeeper_audit_snapshot"),
    "workload_assessment": ("workload_assessment_changes", "workload_assessment_snapshot"),
    "rbac_assessment": ("rbac_assessment_changes", "rbac_assessment_snapshot"),
    "resource_inventory": ("resource_inventory_changes", "resource_inventory_snapshot"),
    "openshift_inventory": ("openshift_inventory_changes", "openshift_inventory_snapshot"),
    "project": ("projects_changes", "projects_snapshot"),
    "route_assessment": ("route_assessment_changes", "route_assessment_snapshot"),
    "scc_assessment": ("scc_assessment_changes", "scc_assessment_snapshot"),
    "compliance_result": ("compliance_result_changes", "compliance_result_snapshot"),
    "compliance_scan_status": ("compliance_scan_status",),
    "audit_event": ("audit_events",),
}

# Polled stream specs. "partition" streams keep one resourceVersion per partition; "snapshot"
# streams list every partition in one run. Partition streams that declare "full" relist from
# scratch in full mode; they never resume from a checkpoint.
STREAM_SPECS: dict[str, dict[str, Any]] = {
    "policy_report_changes": {"cursor": "partition", "modes": ("incremental",)},
    "policy_report_snapshot": {"cursor": "snapshot", "modes": ("full",)},
    "gatekeeper_constraint_changes": {"cursor": "partition", "modes": ("incremental",)},
    "gatekeeper_audit_snapshot": {"cursor": "snapshot", "modes": ("full",), "requires_audit_id": True},
    "workload_assessment_changes": {"cursor": "partition", "modes": ("incremental",)},
    "workload_assessment_snapshot": {"cursor": "snapshot", "modes": ("full",)},
    "rbac_assessment_changes": {"cursor": "partition", "modes": ("incremental",)},
    "rbac_assessment_snapshot": {"cursor": "snapshot", "modes": ("full",)},
    "resource_inventory_changes": {"cursor": "partition", "modes": ("incremental",)},
    "resource_inventory_snapshot": {"cursor": "snapshot", "modes": ("full",)},
    "openshift_inventory_changes": {"cursor": "partition", "modes": ("incremental",)},
    "openshift_inventory_snapshot": {"cursor": "snapshot", "modes": ("full",)},
    "projects_changes": {"cursor": "partition", "modes": ("incremental",)},
    "projects_snapshot": {"cursor": "snapshot", "modes": ("full",)},
    "route_assessment_changes": {"cursor": "partition", "modes": ("incremental",)},
    "route_assessment_snapshot": {"cursor": "snapshot", "modes": ("full",)},
    "scc_assessment_changes": {"cursor": "partition", "modes": ("incremental",)},
    "scc_assessment_snapshot": {"cursor": "snapshot", "modes": ("full",)},
    "compliance_result_changes": {"cursor": "partition", "modes": ("incremental",)},
    "compliance_result_snapshot": {"cursor": "snapshot", "modes": ("full",)},
    "compliance_scan_status": {"cursor": "partition", "modes": ("incremental", "full")},
}


def _record_kind(name: str) -> str:
    for record_kind, streams in RECORD_STREAMS.items():
        if name in streams:
            return record_kind
    raise VendorContractError(f"unknown Kubernetes stream {name!r}")


async def _discover(connector, record_kind: str) -> tuple[tuple[ResourceSelection, ...], list[dict[str, Any]]]:
    """Selections for a record kind, plus coverage markers for any discovery step that was not readable."""
    cfg = connector.config
    if record_kind == "policy_report":
        return (_POLICY_REPORTS if cfg.policy_reports_enabled else ()), []
    if record_kind == "gatekeeper_constraint":
        return await _gatekeeper_constraints(connector)
    if record_kind == "workload_assessment":
        return cfg.workload_resources, []
    if record_kind == "rbac_assessment":
        return cfg.rbac_resources, []
    if record_kind == "resource_inventory":
        return cfg.inventory_resources, []
    if connector.kind != "openshift":
        raise VendorContractError(f"{record_kind} streams are OpenShift-only")
    return _OPENSHIFT_SELECTIONS[record_kind], []


async def _gatekeeper_constraints(connector) -> tuple[tuple[ResourceSelection, ...], list[dict[str, Any]]]:
    """Constraint kinds come from the ConstraintTemplates the cluster serves, one partition per kind."""
    if connector.kind != "kubernetes":
        raise VendorContractError("gatekeeper_constraint streams are Kubernetes-only")
    if not connector.config.gatekeeper_enabled:
        return (), []
    try:
        listed = await connector.api.list_all(_spec(_GATEKEEPER_TEMPLATES))
    except PermissionDenied:
        marker = _coverage(connector, "gatekeeper_constraint", _partition(_GATEKEEPER_TEMPLATES), "forbidden")
        return (), [marker]
    kinds = sorted({_constraint_kind(template) for template in listed.items})
    selections = tuple(
        ResourceSelection(group=_CONSTRAINT_GROUP, version=_CONSTRAINT_VERSION, resource=kind.lower(), kind=kind)
        for kind in kinds
    )
    return selections, []


def _constraint_kind(template: Mapping[str, Any]) -> str:
    spec = template.get("spec") or {}
    names = ((spec.get("crd") or {}).get("spec") or {}).get("names") or {}
    kind = names.get("kind")
    if not isinstance(kind, str) or not kind:
        raise VendorContractError("Gatekeeper ConstraintTemplate has no constraint kind")
    return kind


def _spec(selection: ResourceSelection) -> ResourceSpec:
    group = selection.group or "core"
    return ResourceSpec(
        key=f"{group}/{selection.version}/{selection.resource}",
        group=selection.group,
        version=selection.version,
        resource=selection.resource,
        kind=selection.kind,
    )


def _partition(selection: ResourceSelection) -> str:
    scope = selection.namespace or "*"
    return f"{selection.group or 'core'}/{selection.version}/{selection.resource}@{scope}"


def _redact_route_key(obj: dict[str, Any]) -> dict[str, Any]:
    """Copy a Route without its private key; all other assessment evidence remains intact."""
    if obj.get("kind") != "Route" or not str(obj.get("apiVersion", "")).startswith("route.openshift.io/"):
        return obj
    spec = obj.get("spec")
    tls = spec.get("tls") if isinstance(spec, dict) else None
    if not isinstance(tls, dict) or "key" not in tls:
        return obj
    redacted = dict(obj)
    redacted["spec"] = dict(spec)
    redacted["spec"]["tls"] = {key: value for key, value in tls.items() if key != "key"}
    return redacted


def _record(connector, record_kind: str, partition: str, event: str, obj: dict[str, Any]) -> dict[str, Any]:
    return {
        "_record_kind": record_kind,
        "_event": event,
        "_partition": partition,
        "_cluster": connector.config.cluster_name,
        "object": _redact_route_key(obj),
    }


def _coverage(
    connector, record_kind: str, partition: str, reason: str, subject: str | None = None
) -> dict[str, Any]:
    """A marker for a read that was not allowed or not complete; never a successful empty read."""
    return {
        "_record_kind": record_kind,
        "_event": "COVERAGE",
        "_partition": partition,
        "_cluster": connector.config.cluster_name,
        "_partial_coverage": True,
        "_coverage": {"partition": partition, "reason": reason, "subject": subject},
        "object": None,
    }


def _object_records(
    connector,
    record_kind: str,
    partition: str,
    event: str,
    obj: dict[str, Any],
) -> list[dict[str, Any]]:
    """The record for one object, plus a truncation marker when a Gatekeeper status is partial."""
    records = [_record(connector, record_kind, partition, event, obj)]
    if record_kind == "gatekeeper_constraint" and _truncated(obj):
        subject = (obj.get("metadata") or {}).get("uid")
        records.append(_coverage(connector, record_kind, partition, "status_truncated", subject))
    return records


def _status(constraint: Mapping[str, Any]) -> Mapping[str, Any]:
    status = constraint.get("status")
    return status if isinstance(status, Mapping) else {}


def _truncated(constraint: Mapping[str, Any]) -> bool:
    """Gatekeeper caps status.violations; a total above the listed count means the listing is partial."""
    status = _status(constraint)
    total = status.get("totalViolations")
    return isinstance(total, int) and total > len(status.get("violations") or [])


def _audit_run(constraints: list[dict[str, Any]]) -> str | None:
    """The one Gatekeeper audit run every listed constraint reports; None when any lacks one or they disagree."""
    stamps = {_status(constraint).get("auditTimestamp") or None for constraint in constraints}
    if not constraints or len(stamps) != 1 or None in stamps:
        return None
    return next(iter(stamps))


def _snapshot_cursor(connector, name: str) -> KubeSnapshotCursor:
    started_at = connector.ctx.clock()
    digest = hashlib.sha256(f"{connector.ctx.connection_id}:{name}:{started_at.isoformat()}".encode()).hexdigest()
    return KubeSnapshotCursor(snapshot_id=digest[:32], started_at=started_at)


async def run_stream(connector, name: str, target, checkpoint, mode) -> AsyncIterator[RawBatch]:
    """Yield one batch for a polled Kubernetes stream.

    Snapshot streams list every partition. Partition streams resume from the checkpoint in
    incremental mode and relist every partition from scratch in full mode.
    """
    spec = STREAM_SPECS.get(name)
    if spec is None:
        raise VendorContractError(f"Kubernetes stream {name!r} is not polled")
    record_kind = _record_kind(name)
    if spec["cursor"] == "snapshot":
        yield await _snapshot(connector, name, spec, record_kind)
        return
    start = checkpoint if isinstance(checkpoint, KubePartitionCursor) and mode == "incremental" else None
    yield await _changes(connector, record_kind, start)


async def _snapshot(connector, name: str, spec: Mapping[str, Any], record_kind: str) -> RawBatch:
    cursor = _snapshot_cursor(connector, name)
    selections, records = await _discover(connector, record_kind)
    observed: list[dict[str, Any]] = []
    for selection in selections:
        partition = _partition(selection)
        try:
            listed = await connector.api.list_all(_spec(selection), namespace=selection.namespace)
        except PermissionDenied:
            records.append(_coverage(connector, record_kind, partition, "forbidden"))
            continue
        observed.extend(listed.items)
        for obj in listed.items:
            records.extend(_object_records(connector, record_kind, partition, "ADDED", obj))
        cursor = cursor.complete_partition(partition)
    if spec.get("requires_audit_id") and _audit_run(observed) is None:
        records.append(_coverage(connector, record_kind, _AUDIT_PARTITION, "audit_id_unconfirmed"))
    complete = not any(record.get("_partial_coverage") for record in records)
    return RawBatch(records=records, checkpoint=cursor, complete=complete)


async def _changes(connector, record_kind: str, checkpoint: KubePartitionCursor | None) -> RawBatch:
    cursor = checkpoint if checkpoint is not None else KubePartitionCursor()
    selections, records = await _discover(connector, record_kind)
    for selection in selections:
        partition = _partition(selection)
        try:
            cursor, batch = await _partition_changes(connector, selection, record_kind, partition, cursor)
        except PermissionDenied:
            records.append(_coverage(connector, record_kind, partition, "forbidden"))
            continue
        records.extend(batch)
    return RawBatch(records=records, checkpoint=cursor, complete=True)


async def _partition_changes(
    connector,
    selection: ResourceSelection,
    record_kind: str,
    partition: str,
    cursor: KubePartitionCursor,
) -> tuple[KubePartitionCursor, list[dict[str, Any]]]:
    version = cursor.resource_version(partition)
    if version is None:
        return await _relist(connector, selection, record_kind, partition, cursor)
    window = await connector.api.watch(
        _spec(selection),
        resource_version=version,
        timeout_s=connector.config.watch_timeout_s,
        namespace=selection.namespace,
    )
    if window.relisted:
        return await _relist(connector, selection, record_kind, partition, cursor.relist(partition))
    records: list[dict[str, Any]] = []
    for event in window.events:
        if event.get("type") != "BOOKMARK":
            records.extend(_object_records(connector, record_kind, partition, event["type"], event["object"]))
    if window.resource_version is not None:
        cursor = cursor.advance(partition, window.resource_version)
    return cursor, records


async def _relist(
    connector,
    selection: ResourceSelection,
    record_kind: str,
    partition: str,
    cursor: KubePartitionCursor,
) -> tuple[KubePartitionCursor, list[dict[str, Any]]]:
    listed = await connector.api.list_all(_spec(selection), namespace=selection.namespace)
    if not listed.resource_version:
        raise VendorContractError(f"list for {partition} returned no resourceVersion")
    records: list[dict[str, Any]] = []
    for obj in listed.items:
        records.extend(_object_records(connector, record_kind, partition, "ADDED", obj))
    return cursor.advance(partition, listed.resource_version), records
