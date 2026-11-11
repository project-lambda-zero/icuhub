"""Kubernetes and OpenShift write actions: plan, apply, and reconcile.

Plan reads live state with GET only (core swaps in a read-only HTTP facade while planning). Apply
re-checks the planned preconditions and sends at most one write. An ambiguous send returns
``outcome_unknown``; reconcile resolves it from vendor state and never resends. ``accepted_async``
outcomes keep the async identity in ``vendor_ref``; reconcile polls it and never repeats the write.

Core resolves apply and reconcile on the connector instance by function name, so each connector
edition binds every action it exposes as class attributes:

    annotate_or_label_resource = actions.annotate_or_label_resource
    apply_annotate_or_label_resource = actions.apply_annotate_or_label_resource
    reconcile_annotate_or_label_resource = actions.reconcile_annotate_or_label_resource

Route TLS secret material is never stored in a plan. The plan keeps only SecretRef dumps and a redacted
diff; apply and reconcile resolve the material in memory and record only SHA-256 fingerprints in outcomes.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

from icuhub.connectors._kube.base import CLUSTER_CAPABILITY, KubeBase
from icuhub.connectors._kube.models import (
    AnnotateResourceArgs,
    DeletePodArgs,
    InstantiateBuildConfigArgs,
    ScaleWorkloadArgs,
    UpdateRouteTlsArgs,
    UpdateSccArgs,
)
from icuhub.kit.connector import action
from icuhub.kit.errors import (
    ConfigError,
    Conflict,
    ConnectorError,
    NotFound,
    OutcomeUnknown,
    StalePlan,
    VendorContractError,
)
from icuhub.kit.http import IdempotencyMode
from icuhub.kit.types import ActionOutcome, ActionPlan, SecretRef

__all__ = [
    "annotate_or_label_resource",
    "delete_pod",
    "instantiate_buildconfig",
    "scale_workload",
    "update_route_tls",
    "update_scc",
    "apply_annotate_or_label_resource",
    "apply_delete_pod",
    "apply_instantiate_buildconfig",
    "apply_scale_workload",
    "apply_update_route_tls",
    "apply_update_scc",
    "reconcile_annotate_or_label_resource",
    "reconcile_delete_pod",
    "reconcile_instantiate_buildconfig",
    "reconcile_scale_workload",
    "reconcile_update_route_tls",
    "reconcile_update_scc",
]

_MERGE_PATCH = "application/merge-patch+json"
_ROUTE_GROUP = "route.openshift.io"
_BUILD_GROUP = "build.openshift.io"
_BUILD_CONFIG_LABEL = "openshift.io/build-config.name"
_SECURITY_GROUP = "security.openshift.io"
_POD_GROUP = ""
_BUILD_FAILED_PHASES = frozenset({"Failed", "Error", "Cancelled"})
_SCC_EVIDENCE_EXCLUDED = frozenset({"apiVersion", "kind", "metadata"})


# -- shared helpers ---------------------------------------------------------------------------------


def _require_write(connector: KubeBase) -> None:
    if not connector.config.write_enabled:
        raise ConfigError("Kubernetes writes are disabled by write_enabled=False")


def _require_destructive(connector: KubeBase) -> None:
    if not connector.config.destructive_enabled:
        raise ConfigError("Kubernetes destructive actions are disabled by destructive_enabled=False")


def _segment(value: str) -> str:
    return quote(value, safe="")


def _api_root(group: str, version: str) -> str:
    return f"/api/{_segment(version)}" if not group else f"/apis/{_segment(group)}/{_segment(version)}"


def _resource_path(
    group: str,
    version: str,
    resource: str,
    *,
    name: str,
    namespace: str | None = None,
    subresource: str | None = None,
) -> str:
    scope = f"/namespaces/{_segment(namespace)}" if namespace is not None else ""
    path = f"{_api_root(group, version)}{scope}/{_segment(resource)}/{_segment(name)}"
    return path if subresource is None else f"{path}/{_segment(subresource)}"


def _collection_path(group: str, version: str, resource: str, *, namespace: str) -> str:
    return f"{_api_root(group, version)}/namespaces/{_segment(namespace)}/{_segment(resource)}"


def _gvr(group: str, version: str, resource: str) -> str:
    return f"{group or 'core'}/{version}/{resource}"


def _object(body: Any) -> dict[str, Any]:
    if not isinstance(body, dict):
        raise VendorContractError("Kubernetes response must be a JSON object")
    return body


async def _get(connector: KubeBase, path: str) -> dict[str, Any]:
    return _object((await connector.http.request("GET", path)).json())


def _meta(obj: Mapping[str, Any]) -> Mapping[str, Any]:
    meta = obj.get("metadata")
    if not isinstance(meta, Mapping):
        raise VendorContractError("Kubernetes object requires metadata")
    return meta


def _mapping(obj: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    value = obj.get(key)
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise VendorContractError(f"Kubernetes field {key} must be an object")
    return value


def _string_map(obj: Mapping[str, Any], key: str) -> dict[str, str]:
    value = obj.get(key)
    if value is None:
        return {}
    if not isinstance(value, Mapping) or not all(isinstance(k, str) and isinstance(v, str) for k, v in value.items()):
        raise VendorContractError(f"Kubernetes metadata.{key} must map strings to strings")
    return dict(value)


def _integer(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise VendorContractError(f"Kubernetes field {field} must be a non-negative integer")
    return value


def _assert_precondition(current: Mapping[str, Any], *, uid: str | None, resource_version: str) -> None:
    meta = _meta(current)
    if uid is not None and meta.get("uid") != uid:
        raise StalePlan("Kubernetes object uid changed since planning")
    if meta.get("resourceVersion") != resource_version:
        raise StalePlan("Kubernetes object resourceVersion changed since planning")


def _canonical(document: Any) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256(material: bytes) -> str:
    return hashlib.sha256(material).hexdigest()


def _request(
    method: str,
    path: str,
    *,
    body: Mapping[str, Any] | None,
    content_type: str | None,
    extra: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    request: dict[str, Any] = {
        "method": method,
        "path": path,
        "json": None if body is None else dict(body),
        "content_type": content_type,
    }
    if extra:
        request.update(extra)
    return request


def _make_plan(
    connector: KubeBase,
    action_name: str,
    *,
    gvr: str,
    namespace: str | None,
    name: str,
    current: Mapping[str, Any],
    target_ref: str,
    diff: dict[str, Any],
    preconditions: dict[str, Any],
    request: dict[str, Any],
    changed: bool = True,
) -> ActionPlan:
    natural_key = {
        "cluster": connector.config.cluster_name,
        "gvr": gvr,
        "namespace": namespace,
        "name": name,
        "uid": _meta(current).get("uid"),
        "resource_version": _meta(current).get("resourceVersion"),
        "diff_hash": _sha256(_canonical(diff)),
    }
    return ActionPlan(
        action=action_name,
        target_ref=target_ref,
        diff=diff,
        preconditions=preconditions,
        idempotency_key=connector.action_identity(action_name, natural_key),
        changed=changed,
        request=request,
    )


def _no_op(plan: ActionPlan) -> ActionOutcome:
    return ActionOutcome(status="no_op", vendor_ref=plan.target_ref)


def _unknown(plan: ActionPlan, error: OutcomeUnknown) -> ActionOutcome:
    return ActionOutcome(status="outcome_unknown", vendor_ref=plan.target_ref, error=str(error))


def _failed(vendor_ref: str | None, error: str) -> ActionOutcome:
    return ActionOutcome(status="failed", vendor_ref=vendor_ref, error=error)


async def _send(
    connector: KubeBase,
    plan: ActionPlan,
    body: Mapping[str, Any] | None,
    *,
    idempotency: IdempotencyMode,
    expected: tuple[int, ...],
) -> Any:
    headers = {"Idempotency-Key": plan.idempotency_key}
    content_type = plan.request["content_type"]
    if content_type is not None:
        headers["Content-Type"] = str(content_type)
    try:
        return await connector.http.request(
            str(plan.request["method"]),
            str(plan.request["path"]),
            json=None if body is None else dict(body),
            headers=headers,
            idempotency=idempotency,
            expected=expected,
        )
    except Conflict as exc:
        raise StalePlan(f"Kubernetes rejected {plan.request['method']} {plan.request['path']}: precondition failed") from exc


async def _apply_patch(
    connector: KubeBase,
    plan: ActionPlan,
    body: Mapping[str, Any],
    *,
    check: Callable[[Mapping[str, Any]], None] | None = None,
    verify: Callable[[Mapping[str, Any]], bool] | None = None,
    result: Mapping[str, Any] | None = None,
) -> ActionOutcome:
    object_path = str(plan.preconditions["object_path"])
    current = await _get(connector, object_path)
    _assert_precondition(
        current,
        uid=plan.preconditions["uid"],
        resource_version=str(plan.preconditions["resource_version"]),
    )
    if check is not None:
        check(current)
    try:
        await _send(connector, plan, body, idempotency="idempotent_write", expected=(200,))
    except OutcomeUnknown as exc:
        return _unknown(plan, exc)
    if verify is not None:
        try:
            landed = await _get(connector, object_path)
        except ConnectorError as exc:
            return ActionOutcome(
                status="outcome_unknown",
                vendor_ref=plan.target_ref,
                error=f"readback after PATCH failed: {type(exc).__name__}",
            )
        if not verify(landed):
            return ActionOutcome(
                status="outcome_unknown",
                vendor_ref=plan.target_ref,
                error="readback after PATCH does not show the planned state",
            )
    return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref, result=dict(result or {}))


async def _reconcile_patch(
    connector: KubeBase,
    plan: ActionPlan,
    prior_outcome: ActionOutcome,
    converged: Callable[[Mapping[str, Any], ActionPlan], bool],
) -> ActionOutcome:
    if prior_outcome.status != "outcome_unknown":
        return _failed(plan.target_ref, f"unexpected prior outcome {prior_outcome.status!r} for a merge patch")
    current = await _get(connector, str(plan.preconditions["object_path"]))
    if _meta(current).get("resourceVersion") == plan.preconditions["resource_version"]:
        return _failed(plan.target_ref, "write not applied: resourceVersion unchanged")
    if converged(current, plan):
        return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref)
    return _failed(plan.target_ref, "object changed but the planned desired state is not observed")


def _patch_preconditions(current: Mapping[str, Any], *, object_path: str, resource_version: str) -> dict[str, Any]:
    return {
        "object_path": object_path,
        "uid": _meta(current).get("uid"),
        "resource_version": resource_version,
    }


# -- annotate_or_label_resource ---------------------------------------------------------------------


def _map_diff(current: Mapping[str, str], desired: Mapping[str, str | None]) -> dict[str, dict[str, str | None]]:
    return {key: {"from": current.get(key), "to": value} for key, value in desired.items() if current.get(key) != value}


def _map_matches(current: Mapping[str, str], desired: Mapping[str, Any]) -> bool:
    return all(current.get(key) == value for key, value in desired.items())


async def _plan_annotate(connector: KubeBase, args: AnnotateResourceArgs) -> ActionPlan:
    _require_write(connector)
    path = _resource_path(
        args.group, args.version, args.resource, name=args.name, namespace=args.namespace
    )
    current = await _get(connector, path)
    _assert_precondition(current, uid=args.expected_uid, resource_version=args.expected_resource_version)
    meta = _meta(current)
    diff = {
        "annotations": _map_diff(_string_map(meta, "annotations"), args.annotations),
        "labels": _map_diff(_string_map(meta, "labels"), args.labels),
    }
    metadata: dict[str, Any] = {"resourceVersion": args.expected_resource_version}
    if args.annotations:
        metadata["annotations"] = dict(args.annotations)
    if args.labels:
        metadata["labels"] = dict(args.labels)
    return _make_plan(
        connector,
        "annotate_or_label_resource",
        gvr=_gvr(args.group, args.version, args.resource),
        namespace=args.namespace,
        name=args.name,
        current=current,
        target_ref=path,
        diff=diff,
        preconditions=_patch_preconditions(
            current, object_path=path, resource_version=args.expected_resource_version
        ),
        request=_request("PATCH", path, body={"metadata": metadata}, content_type=_MERGE_PATCH),
        changed=any(diff.values()),
    )


def _annotate_converged(current: Mapping[str, Any], plan: ActionPlan) -> bool:
    desired = _object(plan.request["json"])["metadata"]
    meta = _meta(current)
    return _map_matches(_string_map(meta, "annotations"), desired.get("annotations", {})) and _map_matches(
        _string_map(meta, "labels"), desired.get("labels", {})
    )


@action(
    "annotate_or_label_resource",
    classification="write",
    capability=CLUSTER_CAPABILITY,
    input_model=AnnotateResourceArgs,
    idempotency="natural_key",
)
async def annotate_or_label_resource(connector: KubeBase, args: AnnotateResourceArgs) -> ActionPlan:
    return await _plan_annotate(connector, args)


@annotate_or_label_resource.apply
async def apply_annotate_or_label_resource(connector: KubeBase, plan: ActionPlan) -> ActionOutcome:
    _require_write(connector)
    if not plan.changed:
        return _no_op(plan)
    return await _apply_patch(connector, plan, _object(plan.request["json"]))


@annotate_or_label_resource.reconcile
async def reconcile_annotate_or_label_resource(
    connector: KubeBase, plan: ActionPlan, prior_outcome: ActionOutcome
) -> ActionOutcome:
    return await _reconcile_patch(connector, plan, prior_outcome, _annotate_converged)


# -- scale_workload ---------------------------------------------------------------------------------


def _replicas(current: Mapping[str, Any]) -> int:
    return _integer(_mapping(current, "spec").get("replicas"), "spec.replicas")


@action(
    "scale_workload",
    classification="write",
    capability=CLUSTER_CAPABILITY,
    input_model=ScaleWorkloadArgs,
    idempotency="none",
)
async def scale_workload(connector: KubeBase, args: ScaleWorkloadArgs) -> ActionPlan:
    _require_write(connector)
    object_path = _resource_path(
        args.group, args.version, args.resource, name=args.name, namespace=args.namespace
    )
    scale_path = f"{object_path}/scale"
    current = await _get(connector, scale_path)
    _assert_precondition(current, uid=args.expected_uid, resource_version=args.expected_resource_version)
    live = _replicas(current)
    if live != args.current_replicas:
        raise StalePlan(f"workload has {live} replicas, not the planned {args.current_replicas}")
    body = {"metadata": {"resourceVersion": args.expected_resource_version}, "spec": {"replicas": args.replicas}}
    return _make_plan(
        connector,
        "scale_workload",
        gvr=_gvr(args.group, args.version, args.resource),
        namespace=args.namespace,
        name=args.name,
        current=current,
        target_ref=object_path,
        diff={"replicas": {"from": live, "to": args.replicas}},
        preconditions=_patch_preconditions(
            current, object_path=scale_path, resource_version=args.expected_resource_version
        ),
        request=_request("PATCH", scale_path, body=body, content_type=_MERGE_PATCH),
        changed=live != args.replicas,
    )


@scale_workload.apply
async def apply_scale_workload(connector: KubeBase, plan: ActionPlan) -> ActionOutcome:
    _require_write(connector)
    if not plan.changed:
        return _no_op(plan)
    planned = _object(plan.request["json"])["spec"]["replicas"]
    return await _apply_patch(
        connector,
        plan,
        _object(plan.request["json"]),
        verify=lambda landed: _replicas(landed) == planned,
    )


@scale_workload.reconcile
async def reconcile_scale_workload(connector: KubeBase, plan: ActionPlan, prior_outcome: ActionOutcome) -> ActionOutcome:
    def converged(current: Mapping[str, Any], planned: ActionPlan) -> bool:
        return _replicas(current) == _object(planned.request["json"])["spec"]["replicas"]

    return await _reconcile_patch(connector, plan, prior_outcome, converged)


# -- delete_pod (destructive, asynchronous) ---------------------------------------------------------


@action(
    "delete_pod",
    classification="destructive",
    capability=CLUSTER_CAPABILITY,
    input_model=DeletePodArgs,
    idempotency="none",
)
async def delete_pod(connector: KubeBase, args: DeletePodArgs) -> ActionPlan:
    _require_destructive(connector)
    _require_write(connector)
    path = _resource_path(_POD_GROUP, "v1", "pods", name=args.name, namespace=args.namespace)
    current = await _get(connector, path)
    _assert_precondition(current, uid=args.expected_uid, resource_version=args.expected_resource_version)
    terminating = _meta(current).get("deletionTimestamp") is not None
    options: dict[str, Any] = {
        "apiVersion": "v1",
        "kind": "DeleteOptions",
        "preconditions": {"uid": args.expected_uid, "resourceVersion": args.expected_resource_version},
    }
    if args.grace_period_seconds is not None:
        options["gracePeriodSeconds"] = args.grace_period_seconds
    return _make_plan(
        connector,
        "delete_pod",
        gvr=_gvr(_POD_GROUP, "v1", "pods"),
        namespace=args.namespace,
        name=args.name,
        current=current,
        target_ref=path,
        diff={"deletion_in_progress": terminating, "grace_period_seconds": args.grace_period_seconds},
        preconditions=_patch_preconditions(current, object_path=path, resource_version=args.expected_resource_version),
        request=_request("DELETE", path, body=options, content_type=None),
        changed=not terminating,
    )


@delete_pod.apply
async def apply_delete_pod(connector: KubeBase, plan: ActionPlan) -> ActionOutcome:
    _require_destructive(connector)
    _require_write(connector)
    if not plan.changed:
        return _no_op(plan)
    current = await _get(connector, str(plan.preconditions["object_path"]))
    _assert_precondition(
        current,
        uid=plan.preconditions["uid"],
        resource_version=str(plan.preconditions["resource_version"]),
    )
    try:
        await _send(connector, plan, plan.request["json"], idempotency="non_idempotent", expected=(200, 202))
    except OutcomeUnknown as exc:
        return _unknown(plan, exc)
    return ActionOutcome(status="accepted_async", vendor_ref=plan.target_ref)


@delete_pod.reconcile
async def reconcile_delete_pod(connector: KubeBase, plan: ActionPlan, prior_outcome: ActionOutcome) -> ActionOutcome:
    vendor_ref = plan.target_ref
    try:
        current = await _get(connector, str(plan.preconditions["object_path"]))
    except NotFound:
        return ActionOutcome(status="succeeded", vendor_ref=vendor_ref, result={"deleted": True})
    if _meta(current).get("uid") != plan.preconditions["uid"]:
        return ActionOutcome(status="succeeded", vendor_ref=vendor_ref, result={"replaced": True})
    if prior_outcome.status == "accepted_async":
        return ActionOutcome(status="accepted_async", vendor_ref=vendor_ref)
    if prior_outcome.status == "outcome_unknown" and _meta(current).get("deletionTimestamp") is not None:
        return ActionOutcome(status="accepted_async", vendor_ref=vendor_ref)
    return _failed(vendor_ref, "delete not applied: pod has no deletionTimestamp")


# -- update_route_tls -------------------------------------------------------------------------------


_TLS_SECRET_KEYS = ("certificate", "key", "caCertificate", "destinationCACertificate")


def _tls_request(plan: ActionPlan) -> Mapping[str, Any]:
    return _object(plan.request["tls"])


async def _resolve_tls(connector: KubeBase, secret_refs: Mapping[str, Any]) -> dict[str, str]:
    """Resolve each SecretRef dump in memory; the returned PEM text is never persisted."""
    material: dict[str, str] = {}
    for tls_key, ref_dump in secret_refs.items():
        raw = await connector.ctx.secrets.resolve(SecretRef.model_validate(ref_dump))
        try:
            material[tls_key] = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ConfigError(f"secret for route TLS field {tls_key} is not UTF-8 PEM") from exc
    return material


def _route_admitted(current: Mapping[str, Any]) -> bool:
    ingress = _mapping(current, "status").get("ingress")
    if not isinstance(ingress, list) or not ingress:
        return False
    for entry in ingress:
        conditions = entry.get("conditions") if isinstance(entry, Mapping) else None
        if not isinstance(conditions, list):
            return False
        if not any(
            isinstance(condition, Mapping) and condition.get("type") == "Admitted" and condition.get("status") == "True"
            for condition in conditions
        ):
            return False
    return True


def _tls_spec_matches(current: Mapping[str, Any], wanted: Mapping[str, Any], material: Mapping[str, str]) -> bool:
    live = _mapping(_mapping(current, "spec"), "tls")
    return all(live.get(key) == value for key, value in wanted.items()) and all(
        live.get(key) == value for key, value in material.items()
    )


def _tls_matches(current: Mapping[str, Any], wanted: Mapping[str, Any], material: Mapping[str, str]) -> bool:
    return _tls_spec_matches(current, wanted, material) and _route_admitted(current)


@action(
    "update_route_tls",
    classification="write",
    capability=CLUSTER_CAPABILITY,
    input_model=UpdateRouteTlsArgs,
    idempotency="natural_key",
)
async def update_route_tls(connector: KubeBase, args: UpdateRouteTlsArgs) -> ActionPlan:
    _require_write(connector)
    path = _resource_path(_ROUTE_GROUP, "v1", "routes", name=args.name, namespace=args.namespace)
    current = await _get(connector, path)
    _assert_precondition(current, uid=args.expected_uid, resource_version=args.expected_resource_version)
    live = _mapping(_mapping(current, "spec"), "tls")

    wanted: dict[str, str] = {"termination": args.termination}
    if args.insecure_edge_termination_policy is not None:
        wanted["insecureEdgeTerminationPolicy"] = args.insecure_edge_termination_policy

    secret_refs: dict[str, SecretRef | None] = {
        "certificate": args.certificate_ref,
        "key": args.private_key_ref,
        "caCertificate": args.ca_certificate_ref,
        "destinationCACertificate": args.destination_ca_certificate_ref,
    }
    ref_dumps = {key: ref.model_dump(mode="json") for key, ref in secret_refs.items() if ref is not None}

    # Plan never resolves PEM: secret material is compared only at apply time. Each supplied field is
    # recorded as a redacted change keyed by its SecretRef, so the diff hash reflects intent without
    # embedding or fingerprinting key material.
    diff: dict[str, Any] = {}
    for key, value in wanted.items():
        if live.get(key) != value:
            diff[key] = {"from": live.get(key), "to": value}
    for tls_key in ref_dumps:
        diff[tls_key] = {"secret_ref": "redacted", "changed": True}

    return _make_plan(
        connector,
        "update_route_tls",
        gvr=_gvr(_ROUTE_GROUP, "v1", "routes"),
        namespace=args.namespace,
        name=args.name,
        current=current,
        target_ref=path,
        diff=diff,
        preconditions=_patch_preconditions(current, object_path=path, resource_version=args.expected_resource_version),
        request=_request(
            "PATCH",
            path,
            body=None,
            content_type=_MERGE_PATCH,
            extra={"tls": {"wanted": wanted, "secret_refs": ref_dumps}},
        ),
        changed=bool(diff),
    )


@update_route_tls.apply
async def apply_update_route_tls(connector: KubeBase, plan: ActionPlan) -> ActionOutcome:
    _require_write(connector)
    if not plan.changed:
        return _no_op(plan)
    tls_request = _tls_request(plan)
    material = await _resolve_tls(connector, tls_request["secret_refs"])
    body = {
        "metadata": {"resourceVersion": plan.preconditions["resource_version"]},
        "spec": {"tls": {**tls_request["wanted"], **material}},
    }
    fingerprints = {tls_key: _sha256(pem.encode("utf-8")) for tls_key, pem in material.items()}
    outcome = await _apply_patch(
        connector,
        plan,
        body,
        verify=lambda landed: _tls_spec_matches(landed, tls_request["wanted"], material),
        result={"fingerprints": fingerprints},
    )
    if outcome.status != "succeeded":
        return outcome
    # Independent router verification: a fresh GET of the Route status after the patch, separate from the
    # spec read-back, so an admitted status from before the change cannot satisfy the check.
    try:
        admitted = _route_admitted(await _get(connector, str(plan.preconditions["object_path"])))
    except ConnectorError as exc:
        return ActionOutcome(
            status="outcome_unknown",
            vendor_ref=plan.target_ref,
            error=f"router status readback failed: {type(exc).__name__}",
            result=outcome.result,
        )
    if not admitted:
        return ActionOutcome(
            status="outcome_unknown",
            vendor_ref=plan.target_ref,
            error="router has not admitted the Route after the TLS change",
            result=outcome.result,
        )
    return outcome


@update_route_tls.reconcile
async def reconcile_update_route_tls(connector: KubeBase, plan: ActionPlan, prior_outcome: ActionOutcome) -> ActionOutcome:
    tls_request = _tls_request(plan)
    material = await _resolve_tls(connector, tls_request["secret_refs"])
    return await _reconcile_patch(
        connector,
        plan,
        prior_outcome,
        lambda current, _planned: _tls_matches(current, tls_request["wanted"], material),
    )


# -- instantiate_buildconfig (asynchronous) ---------------------------------------------------------


def _last_version(current: Mapping[str, Any]) -> int:
    return _integer(_mapping(current, "status").get("lastVersion", 0), "status.lastVersion")


def _timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise VendorContractError(f"Kubernetes field {field} must be an RFC 3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise VendorContractError(f"Kubernetes field {field} must be an RFC 3339 timestamp") from exc
    if parsed.tzinfo is None:
        raise VendorContractError(f"Kubernetes field {field} must include a timezone")
    return parsed


async def _list_builds(connector: KubeBase, *, namespace: str, build_config: str) -> list[Mapping[str, Any]]:
    path = _collection_path(_BUILD_GROUP, "v1", "builds", namespace=namespace)
    response = await connector.http.request(
        "GET", path, params={"labelSelector": f"{_BUILD_CONFIG_LABEL}={build_config}"}
    )
    items = _object(response.json()).get("items")
    if not isinstance(items, list) or not all(isinstance(item, Mapping) for item in items):
        raise VendorContractError("Kubernetes Build list requires an items array of objects")
    return items


def _builds_in_window(
    items: list[Mapping[str, Any]], *, build_config: str, last_version: int, window_start: datetime
) -> list[str]:
    """Builds numbered after the planned lastVersion and created at or after the planned window start."""
    prefix = f"{build_config}-"
    names: list[str] = []
    for item in items:
        meta = _meta(item)
        name = meta.get("name")
        if not isinstance(name, str) or not name.startswith(prefix):
            continue
        number = name[len(prefix):]
        if not number.isdigit() or int(number) <= last_version:
            continue
        if _timestamp(meta.get("creationTimestamp"), "Build metadata.creationTimestamp") >= window_start:
            names.append(name)
    return names


async def _poll_build(connector: KubeBase, plan: ActionPlan, build_name: str) -> ActionOutcome:
    path = _resource_path(
        _BUILD_GROUP, "v1", "builds", name=build_name, namespace=str(plan.preconditions["namespace"])
    )
    try:
        build = await _get(connector, path)
    except NotFound:
        return ActionOutcome(status="accepted_async", vendor_ref=build_name, result={"phase": None})
    phase = _mapping(build, "status").get("phase")
    result = {"build": build_name, "phase": phase}
    if phase == "Complete":
        return ActionOutcome(status="succeeded", vendor_ref=build_name, result=result)
    if phase in _BUILD_FAILED_PHASES:
        return ActionOutcome(
            status="failed", vendor_ref=build_name, result=result, error=f"build {build_name} ended in phase {phase}"
        )
    return ActionOutcome(status="accepted_async", vendor_ref=build_name, result=result)


@action(
    "instantiate_buildconfig",
    classification="write",
    capability=CLUSTER_CAPABILITY,
    input_model=InstantiateBuildConfigArgs,
    idempotency="none",
)
async def instantiate_buildconfig(connector: KubeBase, args: InstantiateBuildConfigArgs) -> ActionPlan:
    _require_write(connector)
    object_path = _resource_path(_BUILD_GROUP, "v1", "buildconfigs", name=args.name, namespace=args.namespace)
    current = await _get(connector, object_path)
    _assert_precondition(current, uid=args.expected_uid, resource_version=args.expected_resource_version)
    last = _last_version(current)
    instantiate_path = _resource_path(
        _BUILD_GROUP, "v1", "buildconfigs", name=args.name, namespace=args.namespace, subresource="instantiate"
    )
    body = {
        "apiVersion": "build.openshift.io/v1",
        "kind": "BuildRequest",
        "metadata": {"name": args.name},
    }
    preconditions = _patch_preconditions(current, object_path=object_path, resource_version=args.expected_resource_version)
    preconditions.update(
        {
            "last_version": last,
            "namespace": args.namespace,
            "window_start": datetime.now(UTC).replace(microsecond=0).isoformat(),
        }
    )
    return _make_plan(
        connector,
        "instantiate_buildconfig",
        gvr=_gvr(_BUILD_GROUP, "v1", "buildconfigs"),
        namespace=args.namespace,
        name=args.name,
        current=current,
        target_ref=object_path,
        diff={"last_version": {"from": last, "to": last + 1}},
        preconditions=preconditions,
        request=_request("POST", instantiate_path, body=body, content_type=None),
    )


@instantiate_buildconfig.apply
async def apply_instantiate_buildconfig(connector: KubeBase, plan: ActionPlan) -> ActionOutcome:
    _require_write(connector)
    if not plan.changed:
        return _no_op(plan)
    current = await _get(connector, str(plan.preconditions["object_path"]))
    _assert_precondition(
        current,
        uid=plan.preconditions["uid"],
        resource_version=str(plan.preconditions["resource_version"]),
    )
    if _last_version(current) != plan.preconditions["last_version"]:
        raise StalePlan("BuildConfig status.lastVersion changed since planning")
    try:
        response = await _send(
            connector, plan, plan.request["json"], idempotency="non_idempotent", expected=(200, 201)
        )
    except OutcomeUnknown as exc:
        return _unknown(plan, exc)
    created = _meta(_object(response.json())).get("name")
    if not isinstance(created, str) or not created:
        raise VendorContractError("instantiate response requires the created Build metadata.name")
    return ActionOutcome(status="accepted_async", vendor_ref=created, result={"build": created})


@instantiate_buildconfig.reconcile
async def reconcile_instantiate_buildconfig(
    connector: KubeBase, plan: ActionPlan, prior_outcome: ActionOutcome
) -> ActionOutcome:
    if prior_outcome.status == "accepted_async" and prior_outcome.vendor_ref:
        return await _poll_build(connector, plan, prior_outcome.vendor_ref)
    if prior_outcome.status != "outcome_unknown":
        return _failed(plan.target_ref, f"unexpected prior outcome {prior_outcome.status!r} for instantiate")
    current = await _get(connector, str(plan.preconditions["object_path"]))
    if _last_version(current) == plan.preconditions["last_version"]:
        return _failed(plan.target_ref, "instantiate not applied: BuildConfig status.lastVersion unchanged")
    namespace = str(plan.preconditions["namespace"])
    build_config = str(_meta(current).get("name"))
    items = await _list_builds(connector, namespace=namespace, build_config=build_config)
    window_start = _timestamp(plan.preconditions["window_start"], "plan window_start")
    names = _builds_in_window(
        items,
        build_config=build_config,
        last_version=int(plan.preconditions["last_version"]),
        window_start=window_start,
    )
    if not names:
        return _failed(plan.target_ref, "instantiate not applied: no Build created in the planned window")
    if len(names) > 1:
        return _failed(plan.target_ref, f"instantiate ambiguous: {len(names)} Builds created in the planned window")
    return await _poll_build(connector, plan, names[0])


# -- update_scc (destructive) -----------------------------------------------------------------------


def _scc_evidence_hash(current: Mapping[str, Any]) -> str:
    """Hash of every SCC policy field the plan read; apply refuses to write if any of them moved."""
    return _sha256(_canonical({key: value for key, value in current.items() if key not in _SCC_EVIDENCE_EXCLUDED}))


def _scc_converged(current: Mapping[str, Any], plan: ActionPlan) -> bool:
    desired = {key: value for key, value in _object(plan.request["json"]).items() if key != "metadata"}
    return all(current.get(key) == value for key, value in desired.items())


@action(
    "update_scc",
    classification="destructive",
    capability=CLUSTER_CAPABILITY,
    input_model=UpdateSccArgs,
    idempotency="natural_key",
)
async def update_scc(connector: KubeBase, args: UpdateSccArgs) -> ActionPlan:
    _require_destructive(connector)
    _require_write(connector)
    if "metadata" in args.changes:
        raise ConfigError("update_scc changes must not set metadata; resourceVersion is planned internally")
    path = _resource_path(_SECURITY_GROUP, "v1", "securitycontextconstraints", name=args.name)
    current = await _get(connector, path)
    _assert_precondition(current, uid=args.expected_uid, resource_version=args.expected_resource_version)
    diff = {key: {"from": current.get(key), "to": value} for key, value in args.changes.items() if current.get(key) != value}
    body: dict[str, Any] = {"metadata": {"resourceVersion": args.expected_resource_version}, **args.changes}
    preconditions = _patch_preconditions(current, object_path=path, resource_version=args.expected_resource_version)
    preconditions["evidence_hash"] = _scc_evidence_hash(current)
    # Full security-impact evidence: every policy field the plan read, not only the changed keys, so the
    # plan hash binds the exact pre-change policy that the destructive change is authorized against.
    security_evidence = {key: value for key, value in current.items() if key not in _SCC_EVIDENCE_EXCLUDED}
    return _make_plan(
        connector,
        "update_scc",
        gvr=_gvr(_SECURITY_GROUP, "v1", "securitycontextconstraints"),
        namespace=None,
        name=args.name,
        current=current,
        target_ref=path,
        diff={"changes": diff, "security_evidence": security_evidence},
        preconditions=preconditions,
        request=_request("PATCH", path, body=body, content_type=_MERGE_PATCH),
        changed=bool(diff),
    )


@update_scc.apply
async def apply_update_scc(connector: KubeBase, plan: ActionPlan) -> ActionOutcome:
    _require_destructive(connector)
    _require_write(connector)
    if not plan.changed:
        return _no_op(plan)
    planned_evidence = str(plan.preconditions["evidence_hash"])

    def fresh_evidence(current: Mapping[str, Any]) -> None:
        if _scc_evidence_hash(current) != planned_evidence:
            raise StalePlan("SecurityContextConstraints policy changed since planning")

    return await _apply_patch(
        connector,
        plan,
        _object(plan.request["json"]),
        check=fresh_evidence,
        verify=lambda landed: _scc_converged(landed, plan),
    )


@update_scc.reconcile
async def reconcile_update_scc(connector: KubeBase, plan: ActionPlan, prior_outcome: ActionOutcome) -> ActionOutcome:
    return await _reconcile_patch(connector, plan, prior_outcome, _scc_converged)
