"""Live Kubernetes acceptance for read modes, negative paths, and gated actions.

Required gates and configuration:
- ICUHUB_ACC=1 enables this module; ICUHUB_ACC_KUBERNETES points to the acceptance JSON.
- params.namespace selects the read sandbox. params.read_resources optionally replaces the
  default Pod, Service, and Deployment selections with ListResourcesArgs-compatible mappings.
- params.rbac_denied_resource is a selection mapping (group, version, resource, optional namespace)
  for a resource the acceptance identity cannot list.
- params.unreachable_base_url optionally overrides the default loopback connection-refused URL.
- params.watch_timeout_s optionally bounds the watch tests (default 5 seconds).
- ICUHUB_ACC_WRITE=1 and allow_writes=true enable annotate, scale, and delete_pod tests.
- ICUHUB_ACC_DESTRUCTIVE=1 is additionally required for delete_pod.
- params.annotate, params.scale, and params.delete_pod contain their respective action inputs.
  Models that bind a plan (scale_workload, delete_pod) require approved_plan_hash equal to the
  live plan hash; the harness fails on mismatch so a stale approval cannot authorize a change.
  Live write runs also require config.write_enabled=true. delete_pod requires
  config.destructive_enabled=true and a disposable pod with fresh UID and resourceVersion.

The acceptance file has config, secrets, params, and allow_writes fields. Secret references are
resolved by the existing harness. Tests record only counts, statuses, resource coordinates, and
coverage; bearer values and object bodies are never printed or written.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Mapping
from typing import Any

import httpx2
import pytest
from pydantic import BaseModel

from icuhub.connectors._kube.models import (
    AnnotateResourceArgs,
    DeletePodArgs,
    EmptyArgs,
    ListResourcesArgs,
    ScaleWorkloadArgs,
    WatchResourceArgs,
)
from icuhub.connectors.kubernetes import Kubernetes
from icuhub.kit.testing import collect_stream, make_connector
from icuhub.kit.types import Target

ACCEPTANCE_KIND = "kubernetes"
_BAD_TOKEN_REF = "icuhub-acceptance-invalid-bearer"
_DEFAULT_READ_RESOURCES = (
    {"group": "", "version": "v1", "resource": "pods", "kind": "Pod"},
    {"group": "", "version": "v1", "resource": "services", "kind": "Service"},
    {"group": "apps", "version": "v1", "resource": "deployments", "kind": "Deployment"},
)
_ACTION_SUCCESS = frozenset({"succeeded", "no_op", "accepted_async"})


def _connector(
    acceptance,
    *,
    config: dict[str, Any] | None = None,
    secrets: dict[str, bytes] | None = None,
) -> Kubernetes:
    return make_connector(  # type: ignore[return-value]
        Kubernetes,
        acceptance.config if config is None else config,
        httpx2.AsyncHTTPTransport(),
        acceptance.secrets if secrets is None else secrets,
    )


def _required_param(acceptance, name: str) -> str:
    if name not in acceptance.params:
        pytest.skip(f"kubernetes: params.{name} is required")
    return str(acceptance.params[name])


def _mapping_param(acceptance, name: str) -> dict[str, Any]:
    value = acceptance.params.get(name)
    if not isinstance(value, Mapping):
        pytest.skip(f"kubernetes: params.{name} must be a mapping")
    return dict(value)


def _read_selections(acceptance) -> list[dict[str, Any]]:
    configured = acceptance.params.get("read_resources", _DEFAULT_READ_RESOURCES)
    if not isinstance(configured, (list, tuple)) or not all(isinstance(item, Mapping) for item in configured):
        raise TypeError("kubernetes params.read_resources must be a list of resource mappings")
    return [dict(item) for item in configured]


def _resource_label(selection: Mapping[str, Any]) -> str:
    return f"{selection.get('group') or 'core'}/{selection['version']}/{selection['resource']}"


def _cluster_target(connector: Kubernetes) -> Target:
    async def first():
        async for record in connector.discover():
            return record
        return None

    record = asyncio.run(first())
    assert record is not None, "discover yielded no cluster target"
    return Target(
        id=record.source_uid,
        source_uid=record.source_uid,
        kind=record.kind,
        display_name=record.display_name,
        attributes=record.attributes,
    )


def _namespace_read(connector: Kubernetes, acceptance) -> list[dict[str, Any]]:
    namespace = _required_param(acceptance, "namespace")
    reports: list[dict[str, Any]] = []
    for selection in _read_selections(acceptance):
        continue_token: str | None = None
        count = 0
        resource_version: str | None = None
        complete = False
        coverage = "not_evaluated"
        for _page in range(1000):
            result = asyncio.run(
                connector.list_resources(
                    ListResourcesArgs(
                        **selection,
                        namespace=namespace,
                        limit=100,
                        continue_token=continue_token,
                    )
                )
            )
            count += len(result.items)
            resource_version = result.resource_version or resource_version
            coverage = result.coverage
            continue_token = result.continue_token
            if result.coverage == "not_evaluated" or continue_token is None:
                complete = result.complete
                break
        else:
            raise AssertionError("kubernetes namespace read exceeded 1000 pages")
        reports.append(
            {
                "resource": _resource_label(selection),
                "count": count,
                "complete": complete,
                "coverage": coverage,
                "resource_version": resource_version,
                "selection": selection,
            }
        )
    return reports


def _require_writes(acceptance, *, destructive: bool = False) -> None:
    if os.environ.get("ICUHUB_ACC_WRITE") != "1":
        pytest.skip("kubernetes: set ICUHUB_ACC_WRITE=1 to enable live write actions")
    acceptance.require_writes()
    if destructive and os.environ.get("ICUHUB_ACC_DESTRUCTIVE") != "1":
        pytest.skip("kubernetes: set ICUHUB_ACC_DESTRUCTIVE=1 to enable destructive actions")


def _run_action(
    acceptance,
    name: str,
    model: type[BaseModel],
    *,
    destructive: bool = False,
) -> None:
    _require_writes(acceptance, destructive=destructive)
    payload = _mapping_param(acceptance, name)
    bound = "approved_plan_hash" in model.model_fields
    if bound and not payload.get("approved_plan_hash"):
        pytest.skip(f"kubernetes: params.{name}.approved_plan_hash is required (operator-approved plan hash)")
    args = model.model_validate(payload)
    connector = _connector(acceptance)
    spec = connector.actions()[name]
    plan = asyncio.run(spec.plan(connector, args))
    if bound:
        approved = plan.plan_hash == payload["approved_plan_hash"]
        acceptance.record(
            f"{name}:plan_approval",
            approved,
            "live plan hash matches approved_plan_hash" if approved else "live plan hash differs; re-review plan",
            plan_hash=plan.plan_hash,
        )
        assert approved
    outcome = asyncio.run(spec.apply(connector, plan))
    reconciled = False
    if outcome.status in ("accepted_async", "outcome_unknown"):
        assert spec.reconcile is not None
        outcome = asyncio.run(spec.reconcile(connector, plan, outcome))
        reconciled = True
    passed = outcome.status in _ACTION_SUCCESS
    acceptance.record(name, passed, outcome.status, changed=plan.changed, reconciled=reconciled)
    assert passed


def test_health_and_cluster_discovery(acceptance) -> None:
    connector = _connector(acceptance)
    report = asyncio.run(connector.check())
    acceptance.record("health", report.status in ("healthy", "degraded"), report.status, version=report.vendor_version)
    target = _cluster_target(connector)
    acceptance.record("discover", True, target.display_name, source_uid=target.source_uid)


def test_policy_report_snapshot_is_complete(acceptance) -> None:
    connector = _connector(acceptance)
    target = _cluster_target(connector)
    batches = collect_stream(connector, "policy_report_snapshot", target, None, "full")
    complete = all(batch.complete for batch in batches)
    records = sum(len(batch.records) for batch in batches)
    acceptance.record(
        "policy_report_snapshot",
        complete,
        f"{records} raw records in {len(batches)} batches",
        complete=complete,
    )


def test_resource_inventory_snapshot_is_complete(acceptance) -> None:
    connector = _connector(acceptance)
    target = _cluster_target(connector)
    batches = collect_stream(connector, "resource_inventory_snapshot", target, None, "full")
    complete = all(batch.complete for batch in batches)
    records = sum(len(batch.records) for batch in batches)
    acceptance.record(
        "resource_inventory_snapshot",
        complete,
        f"{records} raw records in {len(batches)} batches",
        complete=complete,
    )


def test_gatekeeper_audit_snapshot_is_complete(acceptance) -> None:
    connector = _connector(acceptance)
    target = _cluster_target(connector)
    batches = collect_stream(connector, "gatekeeper_audit_snapshot", target, None, "full")
    complete = all(batch.complete for batch in batches)
    records = sum(len(batch.records) for batch in batches)
    acceptance.record(
        "gatekeeper_audit_snapshot",
        complete,
        f"{records} raw records in {len(batches)} batches",
        complete=complete,
    )


def test_namespace_read_is_complete(acceptance) -> None:
    connector = _connector(acceptance)
    reports = _namespace_read(connector, acceptance)
    complete = all(report["complete"] for report in reports)
    summary = [
        {"resource": report["resource"], "count": report["count"], "coverage": report["coverage"]}
        for report in reports
    ]
    acceptance.record("namespace_read", complete, f"{len(reports)} resource partitions", resources=summary)
    assert complete


def test_server_version_and_api_discovery(acceptance) -> None:
    connector = _connector(acceptance)
    version = asyncio.run(connector.get_server_version(EmptyArgs()))
    discovery = asyncio.run(connector.list_api_resources(EmptyArgs()))
    version_ok = version.coverage == "evaluated"
    discovery_ok = discovery.coverage == "evaluated"
    acceptance.record("server_version", version_ok, version.coverage, git_version=version.data.get("gitVersion"))
    acceptance.record(
        "api_resources",
        discovery_ok,
        discovery.coverage,
        groups=len(discovery.groups),
        resources=len(discovery.resources),
        refreshed=discovery.refreshed,
    )
    assert version_ok and discovery_ok


def test_watch_resource_is_bounded(acceptance) -> None:
    connector = _connector(acceptance)
    namespace = _required_param(acceptance, "namespace")
    selection = _read_selections(acceptance)[0]
    timeout_s = int(acceptance.params.get("watch_timeout_s", 5))
    result = asyncio.run(
        connector.watch_resource(WatchResourceArgs(**selection, namespace=namespace, timeout_s=timeout_s))
    )
    passed = result.coverage == "evaluated"
    acceptance.record(
        "watch_resource",
        passed,
        result.coverage,
        resource=_resource_label(selection),
        events=len(result.events),
        relisted=result.relisted,
    )
    assert passed


def test_rbac_denied_resource_is_not_evaluated(acceptance) -> None:
    selection = _mapping_param(acceptance, "rbac_denied_resource")
    connector = _connector(acceptance)
    result = asyncio.run(connector.list_resources(ListResourcesArgs(**selection)))
    passed = result.coverage == "not_evaluated" and not result.complete
    acceptance.record(
        "rbac_denied_not_evaluated",
        passed,
        result.coverage_reason or result.coverage,
        resource=_resource_label(selection),
        coverage=result.coverage,
    )
    assert passed


def test_invalid_bearer_token_reports_failing(acceptance) -> None:
    config = {
        **acceptance.config,
        "bearer_token": {"ref": _BAD_TOKEN_REF},
        "bearer_file": None,
        "kubeconfig": None,
        "in_cluster": False,
    }
    connector = _connector(acceptance, config=config, secrets={_BAD_TOKEN_REF: b"icuhub-invalid-token"})
    report = asyncio.run(connector.check())
    passed = report.status == "failing"
    acceptance.record("invalid_bearer_rejected", passed, report.status)
    assert passed


def test_unreachable_api_reports_failing(acceptance) -> None:
    base_url = str(acceptance.params.get("unreachable_base_url", "https://127.0.0.1:9"))
    connector = _connector(acceptance, config={**acceptance.config, "base_url": base_url})
    report = asyncio.run(connector.check())
    passed = report.status == "failing"
    acceptance.record("unreachable_api_failing", passed, report.status)
    assert passed


def test_annotate_or_label_resource_applies_and_reconciles(acceptance) -> None:
    _run_action(acceptance, "annotate_or_label_resource", AnnotateResourceArgs)


def test_scale_workload_requires_approved_plan(acceptance) -> None:
    _run_action(acceptance, "scale_workload", ScaleWorkloadArgs)


def test_delete_pod_requires_destructive_gate(acceptance) -> None:
    _run_action(acceptance, "delete_pod", DeletePodArgs, destructive=True)
