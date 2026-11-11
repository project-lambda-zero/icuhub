"""Kubernetes and OpenShift edition surfaces: conformance plus the edition-specific stream and action sets."""

from __future__ import annotations

from icuhub.connectors._kube.operations import KUBERNETES_OPERATIONS, OPENSHIFT_OPERATIONS
from icuhub.connectors.kubernetes import Kubernetes
from icuhub.connectors.openshift import OpenShift
from icuhub.kit.connector import Connector
from icuhub.kit.testing import conformance_problems

SHARED_STREAMS = {
    "policy_report_changes",
    "policy_report_snapshot",
    "resource_inventory_changes",
    "resource_inventory_snapshot",
    "audit_events",
}
KUBERNETES_ONLY_STREAMS = {
    "gatekeeper_constraint_changes",
    "gatekeeper_audit_snapshot",
    "workload_assessment_changes",
    "workload_assessment_snapshot",
    "rbac_assessment_changes",
    "rbac_assessment_snapshot",
}
OPENSHIFT_ONLY_STREAMS = {
    "openshift_inventory_changes",
    "openshift_inventory_snapshot",
    "projects_changes",
    "projects_snapshot",
    "route_assessment_changes",
    "route_assessment_snapshot",
    "scc_assessment_changes",
    "scc_assessment_snapshot",
    "compliance_result_changes",
    "compliance_result_snapshot",
    "compliance_scan_status",
}
SHARED_ACTIONS = {"annotate_or_label_resource", "scale_workload", "delete_pod"}
OPENSHIFT_ONLY_ACTIONS = {"update_route_tls", "instantiate_buildconfig", "update_scc"}
REMOVED_ROUTE_ACTION_ATTRIBUTES = {"annotate_route", "apply_annotate_route", "reconcile_annotate_route"}
KUBERNETES_OPERATION_NAMES = {operation.__name__ for operation in KUBERNETES_OPERATIONS}
OPENSHIFT_OPERATION_NAMES = {operation.__name__ for operation in OPENSHIFT_OPERATIONS}


def _assert_action_triples(edition: type[Connector], names: set[str]) -> None:
    actions = edition.actions()
    for name in names:
        spec = actions[name]
        assert callable(spec.plan)
        assert callable(spec.apply)
        assert callable(spec.reconcile)
        assert spec.apply.__name__ == f"apply_{name}"
        assert spec.reconcile is not None
        assert spec.reconcile.__name__ == f"reconcile_{name}"


def test_kubernetes_conforms() -> None:
    assert conformance_problems(Kubernetes) == []


def test_openshift_conforms() -> None:
    assert conformance_problems(OpenShift) == []


def test_kubernetes_surface_has_mvp_streams_and_no_openshift_streams() -> None:
    assert set(Kubernetes.streams()) == SHARED_STREAMS | KUBERNETES_ONLY_STREAMS
    assert set(Kubernetes.streams()).isdisjoint(OPENSHIFT_ONLY_STREAMS)


def test_kubernetes_exposes_only_kubernetes_operations_and_shared_actions() -> None:
    assert set(Kubernetes.operations()) == KUBERNETES_OPERATION_NAMES
    assert set(Kubernetes.actions()) == SHARED_ACTIONS
    assert set(Kubernetes.actions()).isdisjoint(OPENSHIFT_ONLY_ACTIONS)
    _assert_action_triples(Kubernetes, SHARED_ACTIONS)
    for attribute in REMOVED_ROUTE_ACTION_ATTRIBUTES:
        assert not hasattr(Kubernetes, attribute)


def test_openshift_surface_has_mvp_streams_and_no_kubernetes_streams() -> None:
    assert set(OpenShift.streams()) == SHARED_STREAMS | OPENSHIFT_ONLY_STREAMS
    assert set(OpenShift.streams()).isdisjoint(KUBERNETES_ONLY_STREAMS)


def test_openshift_exposes_openshift_operations_and_all_action_triples() -> None:
    assert set(OpenShift.operations()) == OPENSHIFT_OPERATION_NAMES
    assert set(OpenShift.actions()) == SHARED_ACTIONS | OPENSHIFT_ONLY_ACTIONS
    _assert_action_triples(OpenShift, SHARED_ACTIONS | OPENSHIFT_ONLY_ACTIONS)
    for attribute in REMOVED_ROUTE_ACTION_ATTRIBUTES:
        assert not hasattr(OpenShift, attribute)


def test_editions_declare_their_flow_and_kind() -> None:
    assert (Kubernetes.kind, Kubernetes.flows) == ("kubernetes", ("F-112",))
    assert (OpenShift.kind, OpenShift.flows) == ("openshift", ("F-113",))
