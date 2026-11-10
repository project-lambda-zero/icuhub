"""Shared Kubernetes and OpenShift stream, mapper, action, and audit-webhook bindings.

Concrete editions (``kubernetes`` and ``openshift``) bind their own edition-only streams and
actions in their class bodies with :func:`declare_stream`, :func:`declare_mapper`, and the
edition tables below. The kit collects specs from each class's own dict, so edition-owned
bindings stay out of the shared base.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any, ClassVar, Literal

from pydantic import BaseModel

from icuhub.connectors._kube import actions, mappers, streams
from icuhub.connectors._kube.base import KubeBase
from icuhub.connectors._kube.models import AuditCursor, KubePartitionCursor, KubeSnapshotCursor
from icuhub.connectors._kube.webhooks import KUBE_WEBHOOK_EVENTS, audit_hints_for_delivery
from icuhub.kit.connector import mapper, stream, webhook
from icuhub.kit.errors import ConnectorError
from icuhub.kit.types import MapContext, RawBatch, StreamRecord, Target, WebhookDelivery

__all__ = [
    "KUBERNETES_STREAM_SPECS",
    "OPENSHIFT_STREAM_SPECS",
    "KubeConnectorBase",
    "declare_mapper",
    "declare_stream",
]

_StreamOptions = dict[str, Any]

# Shared streams are polled through streams.run_stream. Their metadata lives here so the kit can
# validate capabilities and modes at class definition time.
_SHARED_STREAM_SPECS: dict[str, _StreamOptions] = {
    "policy_report_changes": {
        "cursor": KubePartitionCursor,
        "capability": "FindingSource",
        "ocsf_class": 2003,
        "modes": ("incremental",),
    },
    "policy_report_snapshot": {
        "cursor": KubeSnapshotCursor,
        "capability": "FindingSource",
        "ocsf_class": 2003,
        "modes": ("full",),
    },
    "resource_inventory_changes": {
        "cursor": KubePartitionCursor,
        "capability": "ClusterOps",
        "record_type": "resource_inventory",
        "modes": ("incremental",),
    },
    "resource_inventory_snapshot": {
        "cursor": KubeSnapshotCursor,
        "capability": "ClusterOps",
        "record_type": "resource_inventory",
        "modes": ("full",),
    },
}

# Kubernetes edition: Gatekeeper constraint findings.
KUBERNETES_STREAM_SPECS: dict[str, _StreamOptions] = {
    "gatekeeper_constraint_changes": {
        "cursor": KubePartitionCursor,
        "capability": "FindingSource",
        "ocsf_class": 2003,
        "modes": ("incremental",),
    },
    "gatekeeper_audit_snapshot": {
        "cursor": KubeSnapshotCursor,
        "capability": "FindingSource",
        "ocsf_class": 2003,
        "modes": ("full",),
    },
    "workload_assessment_changes": {
        "cursor": KubePartitionCursor,
        "capability": "FindingSource",
        "ocsf_class": 2003,
        "modes": ("incremental",),
    },
    "workload_assessment_snapshot": {
        "cursor": KubeSnapshotCursor,
        "capability": "FindingSource",
        "ocsf_class": 2003,
        "modes": ("full",),
    },
    "rbac_assessment_changes": {
        "cursor": KubePartitionCursor,
        "capability": "FindingSource",
        "ocsf_class": 2003,
        "modes": ("incremental",),
    },
    "rbac_assessment_snapshot": {
        "cursor": KubeSnapshotCursor,
        "capability": "FindingSource",
        "ocsf_class": 2003,
        "modes": ("full",),
    },
}

# OpenShift edition: cluster inventory, projects, route and SCC assessments, and compliance evidence.
OPENSHIFT_STREAM_SPECS: dict[str, _StreamOptions] = {
    "openshift_inventory_changes": {
        "cursor": KubePartitionCursor,
        "capability": "ClusterOps",
        "record_type": "openshift_inventory",
        "modes": ("incremental",),
    },
    "openshift_inventory_snapshot": {
        "cursor": KubeSnapshotCursor,
        "capability": "ClusterOps",
        "record_type": "openshift_inventory",
        "modes": ("full",),
    },
    "projects_changes": {
        "cursor": KubePartitionCursor,
        "capability": "ClusterOps",
        "record_type": "project",
        "modes": ("incremental",),
    },
    "projects_snapshot": {
        "cursor": KubeSnapshotCursor,
        "capability": "ClusterOps",
        "record_type": "project",
        "modes": ("full",),
    },
    "route_assessment_changes": {
        "cursor": KubePartitionCursor,
        "capability": "FindingSource",
        "ocsf_class": 2003,
        "modes": ("incremental",),
    },
    "route_assessment_snapshot": {
        "cursor": KubeSnapshotCursor,
        "capability": "FindingSource",
        "ocsf_class": 2003,
        "modes": ("full",),
    },
    "scc_assessment_changes": {
        "cursor": KubePartitionCursor,
        "capability": "FindingSource",
        "ocsf_class": 2003,
        "modes": ("incremental",),
    },
    "scc_assessment_snapshot": {
        "cursor": KubeSnapshotCursor,
        "capability": "FindingSource",
        "ocsf_class": 2003,
        "modes": ("full",),
    },
    "compliance_result_changes": {
        "cursor": KubePartitionCursor,
        "capability": "FindingSource",
        "ocsf_class": 2003,
        "modes": ("incremental",),
    },
    "compliance_result_snapshot": {
        "cursor": KubeSnapshotCursor,
        "capability": "FindingSource",
        "ocsf_class": 2003,
        "modes": ("full",),
    },
    # One stream carries both modes: page_token incremental and snapshot full. The kit binds one
    # cursor class per stream, so the shared runner dispatches the full mode on mode, not on cursor.
    "compliance_scan_status": {
        "cursor": KubePartitionCursor,
        "capability": "ClusterOps",
        "record_type": "compliance_scan",
        "modes": ("incremental", "full"),
    },
}

# Audit events arrive through the webhook; there is no poll path for this stream.
_AUDIT_STREAM = "audit_events"

# Every polled stream name must have a streams.run_stream implementation, and nothing else may.
_POLLED_STREAMS = frozenset(_SHARED_STREAM_SPECS) | frozenset(KUBERNETES_STREAM_SPECS) | frozenset(
    OPENSHIFT_STREAM_SPECS
)
if _POLLED_STREAMS != set(streams.STREAM_SPECS):  # noqa: SLF001 - same-family binding contract
    raise TypeError("Kubernetes stream bindings do not match the shared stream implementation")


def declare_stream(name: str, options: _StreamOptions):
    """Build a kit stream that delegates to the shared polled implementation for ``name``."""

    @stream(
        name,
        cursor=options["cursor"],
        capability=options["capability"],
        ocsf_class=options.get("ocsf_class"),
        record_type=options.get("record_type"),
        modes=options.get("modes", ("full",)),
        requires_target=options.get("requires_target", True),
    )
    async def read(
        connector: KubeConnectorBase,
        target: Target | None,
        checkpoint: BaseModel | None,
        mode: str,
    ) -> AsyncIterator[RawBatch]:
        async for batch in streams.run_stream(connector, name, target, checkpoint, mode):
            yield batch

    return read


def declare_mapper(name: str):
    """Build a kit mapper for stream ``name`` that delegates to the shared dispatcher."""

    @mapper(name, 1)
    def map_record(connector: KubeConnectorBase, raw: dict[str, Any], ctx: MapContext) -> list[BaseModel]:
        return mappers.map_record(connector, name, raw, ctx)

    return map_record


class KubeConnectorBase(KubeBase):
    """Kubernetes and OpenShift behavior shared by both editions.

    Subclasses set ``edition`` and bind their edition-only streams and actions in the class body.
    """

    edition: ClassVar[Literal["kubernetes", "openshift"]]
    capabilities: ClassVar[tuple[str, ...]] = ("ClusterOps", "FindingSource", "TelemetrySource")

    # Bind the shared polled implementations into the kit's per-class registry.
    for _name, _options in _SHARED_STREAM_SPECS.items():
        locals()[f"stream_{_name}"] = declare_stream(_name, _options)
        locals()[f"map_{_name}"] = declare_mapper(_name)
    del _name, _options

    @stream(
        _AUDIT_STREAM,
        cursor=AuditCursor,
        capability="TelemetrySource",
        ocsf_class=6003,
        modes=("event",),
        requires_target=False,
    )
    async def stream_audit_events(
        self: KubeConnectorBase,
        target: Target | None,
        checkpoint: BaseModel | None,
        mode: str,
    ) -> AsyncIterator[RawBatch]:
        # The kit requires an async generator; this path is unreachable because the only mode is
        # "event", and event records are produced by receive_audit rather than polled.
        raise ConnectorError("audit_events are delivered by the audit webhook and cannot be polled")
        yield RawBatch(records=[], checkpoint=None, complete=False)  # pragma: no cover

    map_audit_events = declare_mapper(_AUDIT_STREAM)

    # Both editions expose these actions. Core resolves apply and reconcile by function name.
    annotate_or_label_resource = actions.annotate_or_label_resource
    apply_annotate_or_label_resource = actions.apply_annotate_or_label_resource
    reconcile_annotate_or_label_resource = actions.reconcile_annotate_or_label_resource
    scale_workload = actions.scale_workload
    apply_scale_workload = actions.apply_scale_workload
    reconcile_scale_workload = actions.reconcile_scale_workload
    delete_pod = actions.delete_pod
    apply_delete_pod = actions.apply_delete_pod
    reconcile_delete_pod = actions.reconcile_delete_pod

    # OpenShift-only action triplets are bound in the OpenShift subclass body.

    @webhook(event_types=KUBE_WEBHOOK_EVENTS)
    def receive_audit(self, delivery: WebhookDelivery) -> list[StreamRecord]:
        return audit_hints_for_delivery(delivery, self.config.audit_api_source)
