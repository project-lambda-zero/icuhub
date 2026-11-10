"""Plan, apply, gate, and reconcile tests for Kubernetes and OpenShift actions."""

from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import datetime
from typing import Any, cast

import pytest
from pydantic import ValidationError

from icuhub.connectors._kube.connector import KubeConnectorBase
from icuhub.connectors._kube.models import (
    AnnotateResourceArgs,
    DeletePodArgs,
    InstantiateBuildConfigArgs,
    ScaleWorkloadArgs,
    UpdateRouteTlsArgs,
    UpdateSccArgs,
)
from icuhub.connectors.kubernetes import Kubernetes
from icuhub.connectors.openshift import OpenShift
from icuhub.kit.connector import ActionSpec
from icuhub.kit.errors import (
    ConfigError,
    PermissionDenied,
    StalePlan,
    TransientVendorError,
    VendorContractError,
)
from icuhub.kit.testing import RouteTransport, make_connector
from icuhub.kit.types import ActionOutcome, ActionPlan, SecretRef

TOKEN_REF = "cluster-token"
APPROVED = "0" * 64
BASE = {
    "base_url": "https://api.example.test",
    "cluster_name": "prod",
    "bearer_token": {"ref": TOKEN_REF},
    "write_enabled": True,
    "destructive_enabled": True,
}


def _connector(
    cls: type[KubeConnectorBase],
    routes: dict[tuple[str, str], Any],
    *,
    secrets: dict[str, bytes] | None = None,
    **config: Any,
) -> tuple[KubeConnectorBase, RouteTransport]:
    transport = RouteTransport(routes)
    connector = make_connector(cls, {**BASE, **config}, transport, {TOKEN_REF: b"token", **(secrets or {})})
    return cast(KubeConnectorBase, connector), transport


def _spec(connector: KubeConnectorBase, name: str) -> ActionSpec:
    return type(connector).actions()[name]


def _plan(connector: KubeConnectorBase, name: str, args: Any) -> ActionPlan:
    return asyncio.run(_spec(connector, name).plan(connector, args))


def _apply(connector: KubeConnectorBase, name: str, plan: ActionPlan) -> ActionOutcome:
    return asyncio.run(_spec(connector, name).apply(connector, plan))


def _reconcile(
    connector: KubeConnectorBase, name: str, plan: ActionPlan, prior: ActionOutcome
) -> ActionOutcome:
    spec = _spec(connector, name)
    assert spec.reconcile is not None
    return asyncio.run(spec.reconcile(connector, plan, prior))


def _unknown(plan: ActionPlan) -> ActionOutcome:
    return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref)


def _object(uid: str, resource_version: str, **fields: Any) -> dict[str, Any]:
    return {"metadata": {"uid": uid, "resourceVersion": resource_version, **fields}}


def _sha256(material: bytes) -> str:
    return hashlib.sha256(material).hexdigest()


def _assert_write_gate(
    cls: type[KubeConnectorBase], name: str, args: Any, plan: ActionPlan
) -> None:
    connector, transport = _connector(cls, {}, write_enabled=False)
    with pytest.raises(ConfigError, match="writes are disabled"):
        _plan(connector, name, args)
    with pytest.raises(ConfigError, match="writes are disabled"):
        _apply(connector, name, plan)
    assert transport.requests == []


def _assert_destructive_gate(
    cls: type[KubeConnectorBase], name: str, args: Any, plan: ActionPlan
) -> None:
    connector, transport = _connector(cls, {}, destructive_enabled=False)
    with pytest.raises(ConfigError, match="destructive actions are disabled"):
        _plan(connector, name, args)
    with pytest.raises(ConfigError, match="destructive actions are disabled"):
        _apply(connector, name, plan)
    assert transport.requests == []


NS = "apps-prod"
POD = f"/api/v1/namespaces/{NS}/pods/web-0"
DEPLOYMENT = f"/apis/apps/v1/namespaces/{NS}/deployments/web"
DEPLOYMENT_SCALE = f"{DEPLOYMENT}/scale"
ROUTE = f"/apis/route.openshift.io/v1/namespaces/{NS}/routes/web"
BUILD_CONFIG = f"/apis/build.openshift.io/v1/namespaces/{NS}/buildconfigs/web"
BUILDS = f"/apis/build.openshift.io/v1/namespaces/{NS}/builds"
BUILD = f"{BUILDS}/web-5"
SCC = "/apis/security.openshift.io/v1/securitycontextconstraints/restricted"
MERGE_PATCH = "application/merge-patch+json"
TLS_SECRETS = {"route-cert": b"CERT-PEM", "route-key": b"KEY-PEM"}
FUTURE = "2099-01-01T00:00:00Z"
TLS_CONVERGED = {
    "termination": "edge",
    "insecureEdgeTerminationPolicy": "Redirect",
    "certificate": "CERT-PEM",
    "key": "KEY-PEM",
}


def _ok(body: Any, status: int = 200) -> dict[str, Any]:
    return {"status": status, "json": body}


def _queue(*responses: dict[str, Any]) -> Any:
    """Serve responses in order; the last one repeats once the queue is exhausted."""
    pending = list(responses)

    def handler(_request: Any) -> dict[str, Any]:
        return pending.pop(0) if len(pending) > 1 else pending[0]

    return handler


def _body(request: Any) -> Any:
    return json.loads(request.read())


def _writes(transport: RouteTransport) -> list[Any]:
    return [request for request in transport.requests if request.method != "GET"]


def _dummy_plan(action: str) -> ActionPlan:
    """Plan used only where the gate fires before the plan is read."""
    return ActionPlan(
        action=action,
        target_ref="/unused",
        diff={},
        preconditions={},
        idempotency_key="unused",
        changed=True,
        request={"method": "PATCH", "path": "/unused", "json": None, "content_type": None},
    )


def _expected_identity(
    connector: KubeConnectorBase,
    action: str,
    plan: ActionPlan,
    *,
    gvr: str,
    namespace: str | None,
    name: str,
    uid: str,
    resource_version: str,
) -> str:
    """Recompute the natural-key identity the planner is expected to derive."""
    natural_key = {
        "cluster": "prod",
        "gvr": gvr,
        "namespace": namespace,
        "name": name,
        "uid": uid,
        "resource_version": resource_version,
        "diff_hash": _sha256(json.dumps(plan.diff, sort_keys=True, separators=(",", ":")).encode("utf-8")),
    }
    return connector.action_identity(action, natural_key)


def _annotate_args(**overrides: Any) -> AnnotateResourceArgs:
    fields: dict[str, Any] = {
        "group": "",
        "version": "v1",
        "resource": "pods",
        "name": "web-0",
        "namespace": NS,
        "expected_uid": "u1",
        "expected_resource_version": "7",
        "annotations": {"owner": "platform"},
    }
    return AnnotateResourceArgs(**{**fields, **overrides})


def _scale_args(**overrides: Any) -> ScaleWorkloadArgs:
    fields: dict[str, Any] = {
        "group": "apps",
        "version": "v1",
        "resource": "deployments",
        "name": "web",
        "namespace": NS,
        "expected_uid": "u1",
        "expected_resource_version": "9",
        "replicas": 5,
        "current_replicas": 3,
        "approved_plan_hash": APPROVED,
    }
    return ScaleWorkloadArgs(**{**fields, **overrides})


def _delete_args(**overrides: Any) -> DeletePodArgs:
    fields: dict[str, Any] = {
        "namespace": NS,
        "name": "web-0",
        "expected_uid": "u1",
        "expected_resource_version": "7",
        "grace_period_seconds": 30,
        "approved_plan_hash": APPROVED,
    }
    return DeletePodArgs(**{**fields, **overrides})


def _tls_args(**overrides: Any) -> UpdateRouteTlsArgs:
    fields: dict[str, Any] = {
        "namespace": NS,
        "name": "web",
        "expected_uid": "u1",
        "expected_resource_version": "7",
        "termination": "edge",
        "insecure_edge_termination_policy": "Redirect",
        "certificate_ref": SecretRef(ref="route-cert"),
        "private_key_ref": SecretRef(ref="route-key"),
        "ca_certificate_ref": None,
        "destination_ca_certificate_ref": None,
        "approved_plan_hash": APPROVED,
    }
    return UpdateRouteTlsArgs(**{**fields, **overrides})


def _build_args(**overrides: Any) -> InstantiateBuildConfigArgs:
    fields: dict[str, Any] = {
        "namespace": NS,
        "name": "web",
        "expected_uid": "u1",
        "expected_resource_version": "7",
        "approved_plan_hash": APPROVED,
    }
    return InstantiateBuildConfigArgs(**{**fields, **overrides})


def _scc_args(**overrides: Any) -> UpdateSccArgs:
    fields: dict[str, Any] = {
        "name": "restricted",
        "expected_uid": "u-scc",
        "expected_resource_version": "3",
        "changes": {"allowPrivilegeEscalation": False},
        "approved_plan_hash": APPROVED,
    }
    return UpdateSccArgs(**{**fields, **overrides})


def _deployment(replicas: int, rv: str = "9") -> dict[str, Any]:
    return {"metadata": {"uid": "u1", "resourceVersion": rv}, "spec": {"replicas": replicas}}


def _route(tls: dict[str, Any], rv: str = "7") -> dict[str, Any]:
    return {"metadata": {"uid": "u1", "resourceVersion": rv}, "spec": {"tls": tls}}


def _admitted_route(tls: dict[str, Any], rv: str = "8") -> dict[str, Any]:
    route = _route(tls, rv=rv)
    route["status"] = {"ingress": [{"conditions": [{"type": "Admitted", "status": "True"}]}]}
    return route


def _build_config(last_version: int, rv: str = "7") -> dict[str, Any]:
    return {
        "metadata": {"name": "web", "uid": "u1", "resourceVersion": rv},
        "status": {"lastVersion": last_version},
    }


def _build_obj(phase: str | None) -> dict[str, Any]:
    status: dict[str, Any] = {} if phase is None else {"phase": phase}
    return {"metadata": {"name": "web-5"}, "status": status}


def _build_item(name: str, created: str = FUTURE) -> dict[str, Any]:
    return {"metadata": {"name": name, "creationTimestamp": created}}


def _scc(allow: bool, rv: str = "3") -> dict[str, Any]:
    return {"metadata": {"uid": "u-scc", "resourceVersion": rv}, "allowPrivilegeEscalation": allow}


# -- annotate_or_label_resource -----------------------------------------------------------------


def test_annotate_plan_diffs_and_builds_conditional_merge_patch() -> None:
    connector, _ = _connector(Kubernetes, {("GET", POD): _ok(_object("u1", "7", annotations={"owner": "old"}))})
    plan = _plan(connector, "annotate_or_label_resource", _annotate_args())
    assert plan.changed is True
    assert plan.diff["annotations"] == {"owner": {"from": "old", "to": "platform"}}
    assert plan.diff.get("labels", {}) == {}
    assert plan.request["method"] == "PATCH"
    assert plan.request["path"] == POD
    assert plan.request["content_type"] == MERGE_PATCH
    assert plan.request["json"]["metadata"]["resourceVersion"] == "7"
    assert plan.request["json"]["metadata"]["annotations"] == {"owner": "platform"}
    assert plan.preconditions["object_path"] == POD
    assert plan.preconditions["resource_version"] == "7"


def test_annotate_plan_rejects_changed_uid() -> None:
    connector, _ = _connector(Kubernetes, {("GET", POD): _ok(_object("u2", "7"))})
    with pytest.raises(StalePlan, match="uid changed"):
        _plan(connector, "annotate_or_label_resource", _annotate_args())


def test_annotate_plan_rejects_changed_resource_version() -> None:
    connector, _ = _connector(Kubernetes, {("GET", POD): _ok(_object("u1", "8"))})
    with pytest.raises(StalePlan, match="resourceVersion changed"):
        _plan(connector, "annotate_or_label_resource", _annotate_args())


def test_annotate_apply_sends_exactly_one_conditional_patch() -> None:
    routes = {
        ("GET", POD): _ok(_object("u1", "7", annotations={"owner": "old"})),
        ("PATCH", POD): _ok(_object("u1", "8")),
    }
    connector, transport = _connector(Kubernetes, routes)
    plan = _plan(connector, "annotate_or_label_resource", _annotate_args())
    outcome = _apply(connector, "annotate_or_label_resource", plan)
    assert outcome == ActionOutcome(status="succeeded", vendor_ref=POD)
    writes = _writes(transport)
    assert len(writes) == 1
    assert writes[0].headers["Idempotency-Key"] == plan.idempotency_key
    assert writes[0].headers["Content-Type"] == MERGE_PATCH
    assert _body(writes[0]) == plan.request["json"]


def test_annotate_apply_is_noop_when_already_applied() -> None:
    connector, transport = _connector(
        Kubernetes, {("GET", POD): _ok(_object("u1", "7", annotations={"owner": "platform"}))}
    )
    plan = _plan(connector, "annotate_or_label_resource", _annotate_args())
    assert plan.changed is False
    transport.requests.clear()
    assert _apply(connector, "annotate_or_label_resource", plan) == ActionOutcome(status="no_op", vendor_ref=POD)
    assert transport.requests == []


def test_annotate_apply_conflict_raises_stale_plan() -> None:
    routes = {
        ("GET", POD): _ok(_object("u1", "7")),
        ("PATCH", POD): {"status": 409, "json": {"kind": "Status"}},
    }
    connector, _ = _connector(Kubernetes, routes)
    plan = _plan(connector, "annotate_or_label_resource", _annotate_args())
    with pytest.raises(StalePlan, match="precondition failed"):
        _apply(connector, "annotate_or_label_resource", plan)


def test_annotate_apply_server_error_is_transient_for_idempotent_write() -> None:
    routes = {
        ("GET", POD): _ok(_object("u1", "7")),
        ("PATCH", POD): {"status": 500, "json": {"kind": "Status"}},
    }
    connector, _ = _connector(Kubernetes, routes)
    plan = _plan(connector, "annotate_or_label_resource", _annotate_args())
    with pytest.raises(TransientVendorError):
        _apply(connector, "annotate_or_label_resource", plan)


def test_annotate_reconcile_after_unknown_succeeds_when_converged() -> None:
    connector, transport = _connector(
        Kubernetes,
        {
            ("GET", POD): _queue(
                _ok(_object("u1", "7", annotations={"owner": "old"})),
                _ok(_object("u1", "8", annotations={"owner": "platform"})),
            )
        },
    )
    plan = _plan(connector, "annotate_or_label_resource", _annotate_args())
    outcome = _reconcile(connector, "annotate_or_label_resource", plan, _unknown(plan))
    assert outcome == ActionOutcome(status="succeeded", vendor_ref=POD)
    assert _writes(transport) == []


def test_annotate_reconcile_fails_when_write_not_applied() -> None:
    connector, _ = _connector(Kubernetes, {("GET", POD): _ok(_object("u1", "7"))})
    plan = _plan(connector, "annotate_or_label_resource", _annotate_args())
    outcome = _reconcile(connector, "annotate_or_label_resource", plan, _unknown(plan))
    assert outcome.status == "failed"
    assert "write not applied" in str(outcome.error)


def test_annotate_reconcile_fails_when_changed_but_not_converged() -> None:
    connector, _ = _connector(
        Kubernetes,
        {
            ("GET", POD): _queue(
                _ok(_object("u1", "7", annotations={"owner": "old"})),
                _ok(_object("u1", "8", annotations={"owner": "someone-else"})),
            )
        },
    )
    plan = _plan(connector, "annotate_or_label_resource", _annotate_args())
    outcome = _reconcile(connector, "annotate_or_label_resource", plan, _unknown(plan))
    assert outcome.status == "failed"
    assert "not observed" in str(outcome.error)


def test_annotate_reconcile_rejects_prior_succeeded_outcome() -> None:
    connector, _ = _connector(Kubernetes, {("GET", POD): _ok(_object("u1", "7"))})
    plan = _plan(connector, "annotate_or_label_resource", _annotate_args())
    prior = ActionOutcome(status="succeeded", vendor_ref=POD)
    outcome = _reconcile(connector, "annotate_or_label_resource", plan, prior)
    assert outcome.status == "failed"
    assert "unexpected prior outcome" in str(outcome.error)


def test_annotate_write_gate() -> None:
    _assert_write_gate(
        Kubernetes, "annotate_or_label_resource", _annotate_args(), _dummy_plan("annotate_or_label_resource")
    )


# -- scale_workload ------------------------------------------------------------------------------


def test_scale_plan_targets_scale_subresource_with_planned_replicas() -> None:
    connector, _ = _connector(Kubernetes, {("GET", DEPLOYMENT_SCALE): _ok(_deployment(3))})
    plan = _plan(connector, "scale_workload", _scale_args())
    assert plan.changed is True
    assert plan.target_ref == DEPLOYMENT
    assert plan.diff == {"replicas": {"from": 3, "to": 5}}
    assert plan.request["method"] == "PATCH"
    assert plan.request["path"] == DEPLOYMENT_SCALE
    assert plan.request["json"] == {"metadata": {"resourceVersion": "9"}, "spec": {"replicas": 5}}
    assert plan.preconditions["object_path"] == DEPLOYMENT_SCALE


def test_scale_plan_rejects_live_replicas_that_drifted() -> None:
    connector, _ = _connector(Kubernetes, {("GET", DEPLOYMENT_SCALE): _ok(_deployment(4))})
    with pytest.raises(StalePlan, match="workload has 4 replicas"):
        _plan(connector, "scale_workload", _scale_args())


def test_scale_apply_sends_one_patch_and_verifies_replicas_by_rereading_scale() -> None:
    routes = {
        ("GET", DEPLOYMENT_SCALE): _queue(
            _ok(_deployment(3)),
            _ok(_deployment(3)),
            _ok(_deployment(5, rv="10")),
        ),
        ("PATCH", DEPLOYMENT_SCALE): _ok({"spec": {"replicas": 5}}),
    }
    connector, transport = _connector(Kubernetes, routes)
    plan = _plan(connector, "scale_workload", _scale_args())
    assert _apply(connector, "scale_workload", plan) == ActionOutcome(status="succeeded", vendor_ref=DEPLOYMENT)
    writes = _writes(transport)
    assert [request.url.path for request in writes] == [DEPLOYMENT_SCALE]
    assert _body(writes[0]) == {"metadata": {"resourceVersion": "9"}, "spec": {"replicas": 5}}


def test_scale_apply_readback_mismatch_is_outcome_unknown() -> None:
    routes = {
        ("GET", DEPLOYMENT_SCALE): _queue(_ok(_deployment(3)), _ok(_deployment(3)), _ok(_deployment(3, rv="10"))),
        ("PATCH", DEPLOYMENT_SCALE): _ok({"spec": {"replicas": 5}}),
    }
    connector, transport = _connector(Kubernetes, routes)
    plan = _plan(connector, "scale_workload", _scale_args())
    outcome = _apply(connector, "scale_workload", plan)
    assert outcome.status == "outcome_unknown"
    assert "does not show the planned state" in str(outcome.error)
    assert len(_writes(transport)) == 1


def test_scale_reconcile_succeeds_when_planned_replicas_observed() -> None:
    connector, _ = _connector(
        Kubernetes, {("GET", DEPLOYMENT_SCALE): _queue(_ok(_deployment(3)), _ok(_deployment(5, rv="10")))}
    )
    plan = _plan(connector, "scale_workload", _scale_args())
    assert _reconcile(connector, "scale_workload", plan, _unknown(plan)) == ActionOutcome(
        status="succeeded", vendor_ref=DEPLOYMENT
    )


def test_scale_reconcile_fails_when_write_not_applied() -> None:
    connector, _ = _connector(Kubernetes, {("GET", DEPLOYMENT_SCALE): _ok(_deployment(3))})
    plan = _plan(connector, "scale_workload", _scale_args())
    outcome = _reconcile(connector, "scale_workload", plan, _unknown(plan))
    assert outcome.status == "failed"
    assert "write not applied" in str(outcome.error)


def test_scale_reconcile_rejects_prior_succeeded_outcome() -> None:
    connector, _ = _connector(Kubernetes, {("GET", DEPLOYMENT_SCALE): _ok(_deployment(3))})
    plan = _plan(connector, "scale_workload", _scale_args())
    outcome = _reconcile(
        connector, "scale_workload", plan, ActionOutcome(status="succeeded", vendor_ref=DEPLOYMENT)
    )
    assert outcome.status == "failed"
    assert "unexpected prior outcome" in str(outcome.error)


def test_scale_rejects_unchanged_replicas_at_model_level() -> None:
    with pytest.raises(ValidationError, match="desired replicas must differ"):
        _scale_args(replicas=3, current_replicas=3)


def test_scale_write_gate() -> None:
    _assert_write_gate(Kubernetes, "scale_workload", _scale_args(), _dummy_plan("scale_workload"))


# -- delete_pod (destructive) --------------------------------------------------------------------


def test_delete_plan_builds_conditional_delete_options() -> None:
    connector, _ = _connector(Kubernetes, {("GET", POD): _ok(_object("u1", "7"))})
    plan = _plan(connector, "delete_pod", _delete_args())
    assert plan.changed is True
    assert plan.diff == {"deletion_in_progress": False, "grace_period_seconds": 30}
    assert plan.request["method"] == "DELETE"
    assert plan.request["path"] == POD
    assert plan.request["content_type"] is None
    assert plan.request["json"] == {
        "apiVersion": "v1",
        "kind": "DeleteOptions",
        "preconditions": {"uid": "u1", "resourceVersion": "7"},
        "gracePeriodSeconds": 30,
    }


def test_delete_plan_on_terminating_pod_is_unchanged() -> None:
    connector, transport = _connector(
        Kubernetes, {("GET", POD): _ok(_object("u1", "7", deletionTimestamp="2026-11-10T00:00:00Z"))}
    )
    plan = _plan(connector, "delete_pod", _delete_args())
    assert plan.changed is False
    transport.requests.clear()
    assert _apply(connector, "delete_pod", plan) == ActionOutcome(status="no_op", vendor_ref=POD)
    assert transport.requests == []


def test_delete_apply_sends_one_delete_and_returns_accepted_async() -> None:
    routes = {
        ("GET", POD): _ok(_object("u1", "7")),
        ("DELETE", POD): _ok({"kind": "Status"}, status=202),
    }
    connector, transport = _connector(Kubernetes, routes)
    plan = _plan(connector, "delete_pod", _delete_args())
    outcome = _apply(connector, "delete_pod", plan)
    assert outcome == ActionOutcome(status="accepted_async", vendor_ref=POD)
    writes = _writes(transport)
    assert len(writes) == 1
    assert writes[0].headers["Idempotency-Key"] == plan.idempotency_key
    assert _body(writes[0]) == plan.request["json"]


def test_delete_apply_ambiguous_send_returns_outcome_unknown_without_resend() -> None:
    routes = {
        ("GET", POD): _ok(_object("u1", "7")),
        ("DELETE", POD): {"status": 500, "json": {"kind": "Status"}},
    }
    connector, transport = _connector(Kubernetes, routes)
    plan = _plan(connector, "delete_pod", _delete_args())
    outcome = _apply(connector, "delete_pod", plan)
    assert outcome.status == "outcome_unknown"
    assert outcome.vendor_ref == POD
    assert len(_writes(transport)) == 1


def test_delete_apply_conflict_raises_stale_plan() -> None:
    routes = {
        ("GET", POD): _ok(_object("u1", "7")),
        ("DELETE", POD): {"status": 409, "json": {"kind": "Status"}},
    }
    connector, _ = _connector(Kubernetes, routes)
    plan = _plan(connector, "delete_pod", _delete_args())
    with pytest.raises(StalePlan, match="precondition failed"):
        _apply(connector, "delete_pod", plan)


def test_delete_reconcile_after_unknown_observes_not_found_without_repeating_delete() -> None:
    routes = {
        ("GET", POD): _queue(
            _ok(_object("u1", "7")),
            _ok(_object("u1", "7")),
            {"status": 404, "json": {"kind": "Status"}},
        ),
        ("DELETE", POD): {"status": 500, "json": {"kind": "Status"}},
    }
    connector, transport = _connector(Kubernetes, routes)
    plan = _plan(connector, "delete_pod", _delete_args())
    assert _apply(connector, "delete_pod", plan).status == "outcome_unknown"
    outcome = _reconcile(connector, "delete_pod", plan, _unknown(plan))
    assert outcome == ActionOutcome(status="succeeded", vendor_ref=POD, result={"deleted": True})
    assert len(_writes(transport)) == 1


def test_delete_reconcile_reports_replaced_when_uid_differs() -> None:
    connector, _ = _connector(
        Kubernetes, {("GET", POD): _queue(_ok(_object("u1", "7")), _ok(_object("u2", "1")))}
    )
    plan = _plan(connector, "delete_pod", _delete_args())
    outcome = _reconcile(connector, "delete_pod", plan, _unknown(plan))
    assert outcome == ActionOutcome(status="succeeded", vendor_ref=POD, result={"replaced": True})


def test_delete_reconcile_polls_accepted_async_without_repeating_delete() -> None:
    connector, transport = _connector(
        Kubernetes,
        {
            ("GET", POD): _queue(
                _ok(_object("u1", "7")),
                _ok(_object("u1", "7", deletionTimestamp="2026-11-10T00:00:00Z")),
            )
        },
    )
    plan = _plan(connector, "delete_pod", _delete_args())
    prior = ActionOutcome(status="accepted_async", vendor_ref=POD)
    assert _reconcile(connector, "delete_pod", plan, prior).status == "accepted_async"
    assert _writes(transport) == []


def test_delete_reconcile_unknown_with_deletion_timestamp_is_accepted_async() -> None:
    connector, transport = _connector(
        Kubernetes,
        {
            ("GET", POD): _queue(
                _ok(_object("u1", "7")),
                _ok(_object("u1", "7", deletionTimestamp="2026-11-10T00:00:00Z")),
            )
        },
    )
    plan = _plan(connector, "delete_pod", _delete_args())
    outcome = _reconcile(connector, "delete_pod", plan, _unknown(plan))
    assert outcome == ActionOutcome(status="accepted_async", vendor_ref=POD)
    assert _writes(transport) == []


def test_delete_reconcile_unknown_without_deletion_timestamp_fails() -> None:
    connector, _ = _connector(Kubernetes, {("GET", POD): _ok(_object("u1", "7"))})
    plan = _plan(connector, "delete_pod", _delete_args())
    outcome = _reconcile(connector, "delete_pod", plan, _unknown(plan))
    assert outcome.status == "failed"
    assert "delete not applied" in str(outcome.error)


def test_delete_write_gate() -> None:
    _assert_write_gate(Kubernetes, "delete_pod", _delete_args(), _dummy_plan("delete_pod"))


def test_delete_destructive_gate() -> None:
    _assert_destructive_gate(Kubernetes, "delete_pod", _delete_args(), _dummy_plan("delete_pod"))


# -- update_route_tls ----------------------------------------------------------------------------


def test_tls_plan_records_redacted_secret_changes_without_pem_material() -> None:
    connector, _ = _connector(
        OpenShift, {("GET", ROUTE): _ok(_route({"termination": "passthrough"}))}, secrets=TLS_SECRETS
    )
    plan = _plan(connector, "update_route_tls", _tls_args())
    dumped = json.dumps(plan.model_dump(mode="json"))
    assert "CERT-PEM" not in dumped
    assert "KEY-PEM" not in dumped
    assert plan.changed is True
    assert plan.diff["termination"] == {"from": "passthrough", "to": "edge"}
    assert plan.diff["insecureEdgeTerminationPolicy"] == {"from": None, "to": "Redirect"}
    assert plan.diff["certificate"] == {"secret_ref": "redacted", "changed": True}
    assert plan.diff["key"] == {"secret_ref": "redacted", "changed": True}
    assert plan.request["method"] == "PATCH"
    assert plan.request["path"] == ROUTE
    assert plan.request["content_type"] == MERGE_PATCH
    assert plan.request["tls"] == {
        "wanted": {"termination": "edge", "insecureEdgeTerminationPolicy": "Redirect"},
        "secret_refs": {
            "certificate": SecretRef(ref="route-cert").model_dump(mode="json"),
            "key": SecretRef(ref="route-key").model_dump(mode="json"),
        },
    }


def test_tls_plan_is_never_noop_because_pem_is_compared_only_at_apply() -> None:
    live = {"termination": "edge", "insecureEdgeTerminationPolicy": "Redirect"}
    connector, _ = _connector(OpenShift, {("GET", ROUTE): _ok(_route(live))}, secrets=TLS_SECRETS)
    plan = _plan(connector, "update_route_tls", _tls_args())
    assert plan.changed is True
    assert "termination" not in plan.diff
    assert "insecureEdgeTerminationPolicy" not in plan.diff
    assert plan.diff["certificate"] == {"secret_ref": "redacted", "changed": True}


def test_tls_apply_sends_decoded_pem_and_verifies_spec_and_router_admission() -> None:
    passthrough = _route({"termination": "passthrough"})
    routes = {
        ("GET", ROUTE): _queue(
            _ok(passthrough),
            _ok(passthrough),
            _ok(_admitted_route(TLS_CONVERGED)),
            _ok(_admitted_route(TLS_CONVERGED)),
        ),
        ("PATCH", ROUTE): _ok(_admitted_route(TLS_CONVERGED)),
    }
    connector, transport = _connector(OpenShift, routes, secrets=TLS_SECRETS)
    plan = _plan(connector, "update_route_tls", _tls_args())
    outcome = _apply(connector, "update_route_tls", plan)
    assert outcome == ActionOutcome(
        status="succeeded",
        vendor_ref=ROUTE,
        result={
            "fingerprints": {
                "certificate": _sha256(b"CERT-PEM"),
                "key": _sha256(b"KEY-PEM"),
            }
        },
    )
    writes = _writes(transport)
    assert len(writes) == 1
    assert _body(writes[0]) == {
        "metadata": {"resourceVersion": "7"},
        "spec": {"tls": TLS_CONVERGED},
    }
    assert "CERT-PEM" not in json.dumps(outcome.model_dump(mode="json"))
    assert "KEY-PEM" not in json.dumps(outcome.model_dump(mode="json"))


def test_tls_apply_fingerprints_are_sha256_hex_digests() -> None:
    passthrough = _route({"termination": "passthrough"})
    routes = {
        ("GET", ROUTE): _queue(
            _ok(passthrough),
            _ok(passthrough),
            _ok(_admitted_route(TLS_CONVERGED)),
            _ok(_admitted_route(TLS_CONVERGED)),
        ),
        ("PATCH", ROUTE): _ok(_admitted_route(TLS_CONVERGED)),
    }
    connector, _ = _connector(OpenShift, routes, secrets=TLS_SECRETS)
    plan = _plan(connector, "update_route_tls", _tls_args())
    outcome = _apply(connector, "update_route_tls", plan)
    assert outcome.result is not None
    fingerprints = outcome.result["fingerprints"]
    assert set(fingerprints) == {"certificate", "key"}
    for digest in fingerprints.values():
        assert len(digest) == 64
        assert all(char in "0123456789abcdef" for char in digest)


def test_tls_apply_resolves_secret_material_at_apply_time_not_plan_time() -> None:
    rotated = {**TLS_CONVERGED, "certificate": "CERT-PEM-ROTATED"}
    passthrough = _route({"termination": "passthrough"})
    routes = {
        ("GET", ROUTE): _queue(
            _ok(passthrough),
            _ok(passthrough),
            _ok(_admitted_route(rotated)),
            _ok(_admitted_route(rotated)),
        ),
        ("PATCH", ROUTE): _ok(_admitted_route(rotated)),
    }
    planner, _ = _connector(OpenShift, routes, secrets=TLS_SECRETS)
    plan = _plan(planner, "update_route_tls", _tls_args())
    applier, transport = _connector(
        OpenShift, routes, secrets={"route-cert": b"CERT-PEM-ROTATED", "route-key": b"KEY-PEM"}
    )
    assert _apply(applier, "update_route_tls", plan).status == "succeeded"
    writes = _writes(transport)
    assert _body(writes[0])["spec"]["tls"]["certificate"] == "CERT-PEM-ROTATED"


def test_tls_apply_rejects_non_utf8_secret_before_any_write() -> None:
    routes = {("GET", ROUTE): _ok(_route({"termination": "passthrough"}))}
    connector, transport = _connector(
        OpenShift, routes, secrets={"route-cert": b"\xff\xfe", "route-key": b"KEY-PEM"}
    )
    plan = _plan(connector, "update_route_tls", _tls_args())
    with pytest.raises(ConfigError, match="not UTF-8 PEM"):
        _apply(connector, "update_route_tls", plan)
    assert _writes(transport) == []


def test_tls_apply_readback_mismatch_is_outcome_unknown() -> None:
    passthrough = _route({"termination": "passthrough"})
    routes = {
        ("GET", ROUTE): _queue(_ok(passthrough), _ok(passthrough), _ok(passthrough, status=200)),
        ("PATCH", ROUTE): _ok(_route(TLS_CONVERGED, rv="8")),
    }
    connector, transport = _connector(OpenShift, routes, secrets=TLS_SECRETS)
    plan = _plan(connector, "update_route_tls", _tls_args())
    outcome = _apply(connector, "update_route_tls", plan)
    assert outcome.status == "outcome_unknown"
    assert "does not show the planned state" in str(outcome.error)
    assert len(_writes(transport)) == 1


def test_tls_apply_unadmitted_route_is_outcome_unknown() -> None:
    passthrough = _route({"termination": "passthrough"})
    routes = {
        ("GET", ROUTE): _queue(
            _ok(passthrough),
            _ok(passthrough),
            _ok(_route(TLS_CONVERGED, rv="8")),
            _ok(_route(TLS_CONVERGED, rv="8")),
        ),
        ("PATCH", ROUTE): _ok(_route(TLS_CONVERGED, rv="8")),
    }
    connector, transport = _connector(OpenShift, routes, secrets=TLS_SECRETS)
    plan = _plan(connector, "update_route_tls", _tls_args())
    outcome = _apply(connector, "update_route_tls", plan)
    assert outcome.status == "outcome_unknown"
    assert "has not admitted the Route" in str(outcome.error)
    assert outcome.result == {
        "fingerprints": {"certificate": _sha256(b"CERT-PEM"), "key": _sha256(b"KEY-PEM")}
    }
    assert len(_writes(transport)) == 1


def test_tls_reconcile_succeeds_when_wanted_fields_pem_and_admission_converge() -> None:
    connector, _ = _connector(
        OpenShift,
        {
            ("GET", ROUTE): _queue(
                _ok(_route({"termination": "passthrough"})),
                _ok(_admitted_route(TLS_CONVERGED, rv="8")),
            )
        },
        secrets=TLS_SECRETS,
    )
    plan = _plan(connector, "update_route_tls", _tls_args())
    assert _reconcile(connector, "update_route_tls", plan, _unknown(plan)) == ActionOutcome(
        status="succeeded", vendor_ref=ROUTE
    )


def test_tls_reconcile_fails_when_spec_converged_but_route_not_admitted() -> None:
    connector, _ = _connector(
        OpenShift,
        {
            ("GET", ROUTE): _queue(
                _ok(_route({"termination": "passthrough"})),
                _ok(_route(TLS_CONVERGED, rv="8")),
            )
        },
        secrets=TLS_SECRETS,
    )
    plan = _plan(connector, "update_route_tls", _tls_args())
    outcome = _reconcile(connector, "update_route_tls", plan, _unknown(plan))
    assert outcome.status == "failed"
    assert "not observed" in str(outcome.error)


def test_tls_write_gate() -> None:
    _assert_write_gate(OpenShift, "update_route_tls", _tls_args(), _dummy_plan("update_route_tls"))


# -- instantiate_buildconfig ---------------------------------------------------------------------


def test_build_plan_records_planned_last_version_and_window_without_build_name() -> None:
    connector, _ = _connector(OpenShift, {("GET", BUILD_CONFIG): _ok(_build_config(4))})
    plan = _plan(connector, "instantiate_buildconfig", _build_args())
    assert plan.target_ref == BUILD_CONFIG
    assert plan.diff == {"last_version": {"from": 4, "to": 5}}
    assert plan.request["method"] == "POST"
    assert plan.request["path"] == f"{BUILD_CONFIG}/instantiate"
    assert plan.request["json"] == {
        "apiVersion": "build.openshift.io/v1",
        "kind": "BuildRequest",
        "metadata": {"name": "web"},
    }
    assert plan.preconditions["last_version"] == 4
    assert plan.preconditions["namespace"] == NS
    assert "build_name" not in plan.preconditions
    window_start = datetime.fromisoformat(plan.preconditions["window_start"])
    assert window_start.tzinfo is not None


def test_build_apply_returns_accepted_async_with_created_build_identity() -> None:
    routes = {
        ("GET", BUILD_CONFIG): _ok(_build_config(4)),
        ("POST", f"{BUILD_CONFIG}/instantiate"): _ok({"metadata": {"name": "web-5"}}, status=201),
    }
    connector, transport = _connector(OpenShift, routes)
    plan = _plan(connector, "instantiate_buildconfig", _build_args())
    outcome = _apply(connector, "instantiate_buildconfig", plan)
    assert outcome == ActionOutcome(status="accepted_async", vendor_ref="web-5", result={"build": "web-5"})
    assert len(_writes(transport)) == 1


def test_build_apply_rejects_changed_last_version() -> None:
    connector, transport = _connector(
        OpenShift, {("GET", BUILD_CONFIG): _queue(_ok(_build_config(4)), _ok(_build_config(5)))}
    )
    plan = _plan(connector, "instantiate_buildconfig", _build_args())
    with pytest.raises(StalePlan, match="lastVersion changed"):
        _apply(connector, "instantiate_buildconfig", plan)
    assert _writes(transport) == []


def test_build_apply_rejects_response_without_build_name() -> None:
    routes = {
        ("GET", BUILD_CONFIG): _ok(_build_config(4)),
        ("POST", f"{BUILD_CONFIG}/instantiate"): _ok({"kind": "Build"}, status=201),
    }
    connector, _ = _connector(OpenShift, routes)
    plan = _plan(connector, "instantiate_buildconfig", _build_args())
    with pytest.raises(VendorContractError):
        _apply(connector, "instantiate_buildconfig", plan)


def test_build_apply_ambiguous_send_returns_outcome_unknown() -> None:
    routes = {
        ("GET", BUILD_CONFIG): _ok(_build_config(4)),
        ("POST", f"{BUILD_CONFIG}/instantiate"): {"status": 500, "json": {"kind": "Status"}},
    }
    connector, transport = _connector(OpenShift, routes)
    plan = _plan(connector, "instantiate_buildconfig", _build_args())
    outcome = _apply(connector, "instantiate_buildconfig", plan)
    assert outcome.status == "outcome_unknown"
    assert len(_writes(transport)) == 1


def test_build_reconcile_polls_accepted_build_without_repeating_instantiate() -> None:
    routes = {
        ("GET", BUILD_CONFIG): _ok(_build_config(4)),
        ("GET", BUILD): _ok(_build_obj("Complete")),
    }
    connector, transport = _connector(OpenShift, routes)
    plan = _plan(connector, "instantiate_buildconfig", _build_args())
    prior = ActionOutcome(status="accepted_async", vendor_ref="web-5")
    outcome = _reconcile(connector, "instantiate_buildconfig", plan, prior)
    assert outcome.status == "succeeded"
    assert outcome.result["phase"] == "Complete"
    assert _writes(transport) == []


def test_build_reconcile_fails_when_build_failed() -> None:
    routes = {
        ("GET", BUILD_CONFIG): _ok(_build_config(4)),
        ("GET", BUILD): _ok(_build_obj("Failed")),
    }
    connector, _ = _connector(OpenShift, routes)
    plan = _plan(connector, "instantiate_buildconfig", _build_args())
    outcome = _reconcile(
        connector, "instantiate_buildconfig", plan, ActionOutcome(status="accepted_async", vendor_ref="web-5")
    )
    assert outcome.status == "failed"
    assert "ended in phase Failed" in str(outcome.error)


def test_build_reconcile_keeps_running_build_accepted() -> None:
    routes = {
        ("GET", BUILD_CONFIG): _ok(_build_config(4)),
        ("GET", BUILD): _ok(_build_obj("Running")),
    }
    connector, _ = _connector(OpenShift, routes)
    plan = _plan(connector, "instantiate_buildconfig", _build_args())
    outcome = _reconcile(
        connector, "instantiate_buildconfig", plan, ActionOutcome(status="accepted_async", vendor_ref="web-5")
    )
    assert outcome.status == "accepted_async"
    assert outcome.result["phase"] == "Running"


def test_build_reconcile_treats_missing_build_as_accepted_without_phase() -> None:
    routes = {
        ("GET", BUILD_CONFIG): _ok(_build_config(4)),
        ("GET", BUILD): {"status": 404, "json": {"kind": "Status"}},
    }
    connector, _ = _connector(OpenShift, routes)
    plan = _plan(connector, "instantiate_buildconfig", _build_args())
    outcome = _reconcile(
        connector, "instantiate_buildconfig", plan, ActionOutcome(status="accepted_async", vendor_ref="web-5")
    )
    assert outcome.status == "accepted_async"
    assert outcome.result == {"phase": None}


def test_build_reconcile_after_unknown_polls_build_created_in_planned_window() -> None:
    routes = {
        ("GET", BUILD_CONFIG): _queue(_ok(_build_config(4)), _ok(_build_config(5))),
        ("GET", BUILDS): _ok({"items": [_build_item("web-5")]}),
        ("GET", BUILD): _ok(_build_obj("Complete")),
    }
    connector, transport = _connector(OpenShift, routes)
    plan = _plan(connector, "instantiate_buildconfig", _build_args())
    outcome = _reconcile(connector, "instantiate_buildconfig", plan, _unknown(plan))
    assert outcome == ActionOutcome(
        status="succeeded", vendor_ref="web-5", result={"build": "web-5", "phase": "Complete"}
    )
    selectors = [
        request.url.params.get("labelSelector") for request in transport.requests if request.url.path == BUILDS
    ]
    assert selectors == ["openshift.io/build-config.name=web"]
    assert _writes(transport) == []


def test_build_reconcile_after_unknown_fails_when_no_build_in_window() -> None:
    routes = {
        ("GET", BUILD_CONFIG): _queue(_ok(_build_config(4)), _ok(_build_config(5))),
        ("GET", BUILDS): _ok({"items": [_build_item("web-5", created="2000-01-01T00:00:00Z")]}),
    }
    connector, _ = _connector(OpenShift, routes)
    plan = _plan(connector, "instantiate_buildconfig", _build_args())
    outcome = _reconcile(connector, "instantiate_buildconfig", plan, _unknown(plan))
    assert outcome.status == "failed"
    assert "no Build created in the planned window" in str(outcome.error)


def test_build_reconcile_after_unknown_fails_when_window_holds_two_builds() -> None:
    routes = {
        ("GET", BUILD_CONFIG): _queue(_ok(_build_config(4)), _ok(_build_config(6))),
        ("GET", BUILDS): _ok({"items": [_build_item("web-5"), _build_item("web-6")]}),
    }
    connector, _ = _connector(OpenShift, routes)
    plan = _plan(connector, "instantiate_buildconfig", _build_args())
    outcome = _reconcile(connector, "instantiate_buildconfig", plan, _unknown(plan))
    assert outcome.status == "failed"
    assert "ambiguous" in str(outcome.error)


def test_build_reconcile_after_unknown_fails_when_last_version_unchanged() -> None:
    connector, _ = _connector(OpenShift, {("GET", BUILD_CONFIG): _ok(_build_config(4))})
    plan = _plan(connector, "instantiate_buildconfig", _build_args())
    outcome = _reconcile(connector, "instantiate_buildconfig", plan, _unknown(plan))
    assert outcome.status == "failed"
    assert "instantiate not applied" in str(outcome.error)


def test_build_write_gate() -> None:
    _assert_write_gate(
        OpenShift, "instantiate_buildconfig", _build_args(), _dummy_plan("instantiate_buildconfig")
    )


# -- update_scc (destructive) --------------------------------------------------------------------


def test_scc_plan_diffs_changed_fields_and_records_full_security_evidence() -> None:
    live = {**_scc(True), "runAsUser": {"type": "RunAsAny"}}
    connector, _ = _connector(OpenShift, {("GET", SCC): _ok(live)})
    plan = _plan(connector, "update_scc", _scc_args())
    assert plan.changed is True
    assert plan.diff["changes"] == {"allowPrivilegeEscalation": {"from": True, "to": False}}
    assert plan.diff["security_evidence"] == {"allowPrivilegeEscalation": True, "runAsUser": {"type": "RunAsAny"}}
    assert plan.request["method"] == "PATCH"
    assert plan.request["path"] == SCC
    assert plan.request["content_type"] == MERGE_PATCH
    assert plan.request["json"] == {"metadata": {"resourceVersion": "3"}, "allowPrivilegeEscalation": False}
    assert plan.preconditions["object_path"] == SCC
    assert len(plan.preconditions["evidence_hash"]) == 64


def test_scc_plan_is_noop_when_fields_already_match() -> None:
    connector, transport = _connector(OpenShift, {("GET", SCC): _ok(_scc(False))})
    plan = _plan(connector, "update_scc", _scc_args())
    assert plan.changed is False
    assert plan.diff["changes"] == {}
    transport.requests.clear()
    assert _apply(connector, "update_scc", plan) == ActionOutcome(status="no_op", vendor_ref=SCC)
    assert transport.requests == []


def test_scc_apply_sends_one_merge_patch_after_fresh_evidence_check() -> None:
    routes = {
        ("GET", SCC): _queue(_ok(_scc(True, rv="3")), _ok(_scc(True, rv="3")), _ok(_scc(False, rv="4"))),
        ("PATCH", SCC): _ok(_scc(False, rv="4")),
    }
    connector, transport = _connector(OpenShift, routes)
    plan = _plan(connector, "update_scc", _scc_args())
    assert _apply(connector, "update_scc", plan) == ActionOutcome(status="succeeded", vendor_ref=SCC)
    writes = _writes(transport)
    assert len(writes) == 1
    assert _body(writes[0]) == {"metadata": {"resourceVersion": "3"}, "allowPrivilegeEscalation": False}


def test_scc_apply_rejects_resource_version_drift() -> None:
    connector, transport = _connector(
        OpenShift, {("GET", SCC): _queue(_ok(_scc(True, rv="3")), _ok(_scc(True, rv="4")))}
    )
    plan = _plan(connector, "update_scc", _scc_args())
    with pytest.raises(StalePlan, match="resourceVersion changed"):
        _apply(connector, "update_scc", plan)
    assert _writes(transport) == []


def test_scc_apply_rejects_policy_drift_outside_changed_fields() -> None:
    drifted = {**_scc(True), "priority": 5}
    connector, transport = _connector(
        OpenShift, {("GET", SCC): _queue(_ok(_scc(True)), _ok(drifted))}
    )
    plan = _plan(connector, "update_scc", _scc_args())
    with pytest.raises(StalePlan, match="policy changed since planning"):
        _apply(connector, "update_scc", plan)
    assert _writes(transport) == []


def test_scc_reconcile_succeeds_when_desired_fields_observed() -> None:
    connector, _ = _connector(
        OpenShift, {("GET", SCC): _queue(_ok(_scc(True, rv="3")), _ok(_scc(False, rv="4")))}
    )
    plan = _plan(connector, "update_scc", _scc_args())
    assert _reconcile(connector, "update_scc", plan, _unknown(plan)) == ActionOutcome(
        status="succeeded", vendor_ref=SCC
    )


def test_scc_reconcile_fails_when_changed_but_desired_not_observed() -> None:
    connector, _ = _connector(
        OpenShift, {("GET", SCC): _queue(_ok(_scc(True, rv="3")), _ok(_scc(True, rv="4")))}
    )
    plan = _plan(connector, "update_scc", _scc_args())
    outcome = _reconcile(connector, "update_scc", plan, _unknown(plan))
    assert outcome.status == "failed"
    assert "not observed" in str(outcome.error)


def test_scc_rejects_undeclared_fields_at_model_level() -> None:
    with pytest.raises(ValidationError, match="undeclared SCC fields: fooBar"):
        _scc_args(changes={"fooBar": True})


def test_scc_rejects_metadata_changes_in_plan() -> None:
    # The model allowlist already excludes metadata, so this guards a model built without validation.
    args = UpdateSccArgs.model_construct(
        name="restricted",
        expected_uid="u-scc",
        expected_resource_version="3",
        changes={"metadata": {"labels": {}}},
        approved_plan_hash=APPROVED,
    )
    connector, _ = _connector(OpenShift, {("GET", SCC): _ok(_scc(True))})
    with pytest.raises(ConfigError, match="must not set metadata"):
        _plan(connector, "update_scc", args)


def test_scc_destructive_gate() -> None:
    _assert_destructive_gate(OpenShift, "update_scc", _scc_args(), _dummy_plan("update_scc"))


def test_scc_write_gate() -> None:
    _assert_write_gate(OpenShift, "update_scc", _scc_args(), _dummy_plan("update_scc"))


# -- idempotency keys ----------------------------------------------------------------------------


def test_annotate_idempotency_key_matches_natural_key_identity() -> None:
    connector, _ = _connector(Kubernetes, {("GET", POD): _ok(_object("u1", "7"))})
    plan = _plan(connector, "annotate_or_label_resource", _annotate_args())
    assert plan.idempotency_key == _expected_identity(
        connector,
        "annotate_or_label_resource",
        plan,
        gvr="core/v1/pods",
        namespace=NS,
        name="web-0",
        uid="u1",
        resource_version="7",
    )


def test_annotate_idempotency_key_is_stable_for_same_args_and_changes_with_desired_value() -> None:
    connector, _ = _connector(Kubernetes, {("GET", POD): _ok(_object("u1", "7"))})
    first = _plan(connector, "annotate_or_label_resource", _annotate_args())
    again = _plan(connector, "annotate_or_label_resource", _annotate_args())
    changed = _plan(connector, "annotate_or_label_resource", _annotate_args(annotations={"owner": "other"}))
    assert first.idempotency_key == again.idempotency_key
    assert first.idempotency_key != changed.idempotency_key


def test_scale_idempotency_key_matches_natural_key_identity() -> None:
    connector, _ = _connector(Kubernetes, {("GET", DEPLOYMENT_SCALE): _ok(_deployment(3))})
    plan = _plan(connector, "scale_workload", _scale_args())
    assert plan.idempotency_key == _expected_identity(
        connector,
        "scale_workload",
        plan,
        gvr="apps/v1/deployments",
        namespace=NS,
        name="web",
        uid="u1",
        resource_version="9",
    )


def test_delete_idempotency_key_matches_natural_key_identity() -> None:
    connector, _ = _connector(Kubernetes, {("GET", POD): _ok(_object("u1", "7"))})
    plan = _plan(connector, "delete_pod", _delete_args())
    assert plan.idempotency_key == _expected_identity(
        connector,
        "delete_pod",
        plan,
        gvr="core/v1/pods",
        namespace=NS,
        name="web-0",
        uid="u1",
        resource_version="7",
    )


def test_tls_idempotency_key_matches_natural_key_identity() -> None:
    connector, _ = _connector(
        OpenShift, {("GET", ROUTE): _ok(_route({"termination": "passthrough"}))}, secrets=TLS_SECRETS
    )
    plan = _plan(connector, "update_route_tls", _tls_args())
    assert plan.idempotency_key == _expected_identity(
        connector,
        "update_route_tls",
        plan,
        gvr="route.openshift.io/v1/routes",
        namespace=NS,
        name="web",
        uid="u1",
        resource_version="7",
    )


def test_build_idempotency_key_matches_natural_key_identity() -> None:
    connector, _ = _connector(OpenShift, {("GET", BUILD_CONFIG): _ok(_build_config(4))})
    plan = _plan(connector, "instantiate_buildconfig", _build_args())
    assert plan.idempotency_key == _expected_identity(
        connector,
        "instantiate_buildconfig",
        plan,
        gvr="build.openshift.io/v1/buildconfigs",
        namespace=NS,
        name="web",
        uid="u1",
        resource_version="7",
    )


def test_scc_idempotency_key_matches_natural_key_identity() -> None:
    connector, _ = _connector(OpenShift, {("GET", SCC): _ok(_scc(True))})
    plan = _plan(connector, "update_scc", _scc_args())
    assert plan.idempotency_key == _expected_identity(
        connector,
        "update_scc",
        plan,
        gvr="security.openshift.io/v1/securitycontextconstraints",
        namespace=None,
        name="restricted",
        uid="u-scc",
        resource_version="3",
    )


# -- authorization -------------------------------------------------------------------------------


def test_plan_denied_read_raises_permission_denied_without_writing() -> None:
    connector, transport = _connector(Kubernetes, {("GET", POD): {"status": 403, "json": {"kind": "Status"}}})
    with pytest.raises(PermissionDenied, match="forbidden"):
        _plan(connector, "delete_pod", _delete_args())
    assert _writes(transport) == []


# -- edition membership, classification, and model validation ------------------------------------


def test_kubernetes_binds_only_shared_cluster_actions() -> None:
    assert set(Kubernetes.actions()) == {"annotate_or_label_resource", "scale_workload", "delete_pod"}


def test_openshift_adds_route_build_and_scc_actions() -> None:
    assert set(OpenShift.actions()) == {
        "annotate_or_label_resource",
        "scale_workload",
        "delete_pod",
        "update_route_tls",
        "instantiate_buildconfig",
        "update_scc",
    }


def test_action_classification_and_capability() -> None:
    kube = Kubernetes.actions()
    openshift = OpenShift.actions()
    assert kube["annotate_or_label_resource"].classification == "write"
    assert kube["scale_workload"].classification == "write"
    assert kube["delete_pod"].classification == "destructive"
    assert openshift["update_route_tls"].classification == "write"
    assert openshift["instantiate_buildconfig"].classification == "write"
    assert openshift["update_scc"].classification == "destructive"
    for name in kube:
        assert kube[name].capability == "ClusterOps"
    for name in openshift:
        assert openshift[name].capability == "ClusterOps"


@pytest.mark.parametrize("bad_hash", ["", "abc", "G" * 64, "0" * 63])
def test_approved_plan_hash_must_be_64_lowercase_hex(bad_hash: str) -> None:
    # Approval itself is enforced by core; the connector validates only the hash format.
    with pytest.raises(ValidationError):
        _delete_args(approved_plan_hash=bad_hash)


def test_annotate_requires_at_least_one_change() -> None:
    with pytest.raises(ValidationError, match="at least one annotation or label change"):
        _annotate_args(annotations={}, labels={})
