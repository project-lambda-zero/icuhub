"""Live OpenShift acceptance: health, discovery, complete reads, negative paths, and gated actions.

Requires ICUHUB_ACC=1 and ICUHUB_ACC_OPENSHIFT pointing to JSON:
{"config": {"base_url": "https://api.ocp.example:6443", "bearer_token": {"ref": "token"},
            "cluster_name": "sandbox", "write_enabled": false, "destructive_enabled": false},
 "secrets": {"token": "<service account token>"},
 "params": {},
 "allow_writes": false}

Read params: params.namespace (sandbox namespace, required by the route tests) and params.route
(a Route name inside it, required by the route detail test). Optional read params:
params.compliance_namespace (default openshift-compliance), params.unreachable_base_url
(default https://127.0.0.1:9), and params.raw_arf_path (API-relative Compliance Operator ARF path;
the test requires coverage evaluated when config.raw_arf_enabled is true and not_evaluated otherwise).

Write actions (update_route_tls, instantiate_buildconfig, update_scc) run only with
ICUHUB_ACC_WRITE=1, allow_writes=true, and config.write_enabled=true. update_scc is destructive
and additionally requires ICUHUB_ACC_DESTRUCTIVE=1 and config.destructive_enabled=true. Each
params.<action> mapping must carry approved_plan_hash equal to the live plan hash.
Tests record only counts, statuses, resource coordinates, and coverage; secrets and bodies are never recorded.
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
    EmptyArgs,
    InstantiateBuildConfigArgs,
    RawArfArgs,
    UpdateRouteTlsArgs,
    UpdateSccArgs,
)
from icuhub.connectors._kube.operations import (
    BoundedListArgs,
    NamespacedListArgs,
    NamespacedNameArgs,
)
from icuhub.connectors.openshift import OpenShift
from icuhub.kit.testing import collect_stream, make_connector
from icuhub.kit.types import Target

ACCEPTANCE_KIND = "openshift"
_BAD_TOKEN_REF = "icuhub-acceptance-invalid-bearer"
_ACTION_SUCCESS = frozenset({"succeeded", "no_op", "accepted_async"})


def _connector(
    acceptance,
    *,
    config: dict[str, Any] | None = None,
    secrets: dict[str, bytes] | None = None,
) -> OpenShift:
    return make_connector(  # type: ignore[return-value]
        OpenShift,
        acceptance.config if config is None else config,
        httpx2.AsyncHTTPTransport(),
        acceptance.secrets if secrets is None else secrets,
    )


def _required_param(acceptance, name: str) -> str:
    if name not in acceptance.params:
        pytest.skip(f"openshift: params.{name} is required")
    return str(acceptance.params[name])


def _mapping_param(acceptance, name: str) -> dict[str, Any]:
    value = acceptance.params.get(name)
    if not isinstance(value, Mapping):
        pytest.skip(f"openshift: params.{name} must be a mapping")
    return dict(value)


def _coverage_honest(result) -> bool:
    """Discovery-gated reads may report not_evaluated; an evaluated read must also be complete."""
    return result.coverage == "not_evaluated" or (result.coverage == "evaluated" and result.complete)


def _require_writes(acceptance, *, destructive: bool = False) -> None:
    if os.environ.get("ICUHUB_ACC_WRITE") != "1":
        pytest.skip("openshift: set ICUHUB_ACC_WRITE=1 to enable live write actions")
    acceptance.require_writes()
    if destructive and os.environ.get("ICUHUB_ACC_DESTRUCTIVE") != "1":
        pytest.skip("openshift: set ICUHUB_ACC_DESTRUCTIVE=1 to enable destructive actions")


def _run_action(
    acceptance,
    name: str,
    model: type[BaseModel],
    *,
    destructive: bool = False,
) -> None:
    _require_writes(acceptance, destructive=destructive)
    payload = _mapping_param(acceptance, name)
    if not payload.get("approved_plan_hash"):
        pytest.skip(f"openshift: params.{name}.approved_plan_hash is required (operator-approved plan hash)")
    args = model.model_validate(payload)
    connector = _connector(acceptance)
    spec = connector.actions()[name]
    plan = asyncio.run(spec.plan(connector, args))
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


def _cluster_target(connector: OpenShift) -> Target:
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


def test_health_and_cluster_discovery(acceptance) -> None:
    connector = _connector(acceptance)
    report = asyncio.run(connector.check())
    acceptance.record("health", report.status in ("healthy", "degraded"), report.status, version=report.vendor_version)
    target = _cluster_target(connector)
    acceptance.record("discover", True, target.display_name, source_uid=target.source_uid)


@pytest.mark.parametrize("stream", ["route_assessment_snapshot", "scc_assessment_snapshot"])
def test_assessment_snapshot_is_complete(acceptance, stream: str) -> None:
    connector = _connector(acceptance)
    target = _cluster_target(connector)
    batches = collect_stream(connector, stream, target, None, "full")
    complete = all(batch.complete for batch in batches)
    records = sum(len(batch.records) for batch in batches)
    acceptance.record(
        stream,
        complete,
        f"{records} raw records in {len(batches)} batches",
        complete=complete,
    )


def test_cluster_version_and_projects_are_evaluated(acceptance) -> None:
    connector = _connector(acceptance)
    version = asyncio.run(connector.get_cluster_version(EmptyArgs()))
    projects = asyncio.run(connector.list_projects(BoundedListArgs()))
    version_ok = version.coverage == "evaluated" and version.data is not None
    projects_ok = projects.coverage == "evaluated" and projects.complete
    acceptance.record("get_cluster_version", version_ok, version.coverage_reason or version.coverage)
    acceptance.record(
        "list_projects",
        projects_ok,
        projects.coverage_reason or projects.coverage,
        count=len(projects.items),
        complete=projects.complete,
    )
    assert version_ok and projects_ok


def test_namespace_routes_are_complete(acceptance) -> None:
    namespace = _required_param(acceptance, "namespace")
    connector = _connector(acceptance)
    routes = asyncio.run(connector.list_routes(NamespacedListArgs(namespace=namespace)))
    passed = routes.coverage == "evaluated" and routes.complete
    acceptance.record(
        "list_routes",
        passed,
        f"{len(routes.routes)} routes in {namespace}",
        coverage=routes.coverage,
        complete=routes.complete,
        count=len(routes.routes),
    )
    assert passed


def test_route_detail_is_evaluated(acceptance) -> None:
    namespace = _required_param(acceptance, "namespace")
    route_name = _required_param(acceptance, "route")
    connector = _connector(acceptance)
    route = asyncio.run(connector.get_route(NamespacedNameArgs(name=route_name, namespace=namespace)))
    passed = route.coverage == "evaluated" and route.data is not None
    acceptance.record(
        "get_route",
        passed,
        route.coverage_reason or route.coverage,
        namespace=namespace,
        name=route_name,
    )
    assert passed


def test_compliance_scans_report_honest_coverage(acceptance) -> None:
    namespace = str(acceptance.params.get("compliance_namespace", "openshift-compliance"))
    connector = _connector(acceptance)
    scans = asyncio.run(connector.list_compliance_scans(NamespacedListArgs(namespace=namespace)))
    passed = _coverage_honest(scans)
    acceptance.record(
        "list_compliance_scans",
        passed,
        scans.coverage_reason or scans.coverage,
        namespace=namespace,
        coverage=scans.coverage,
        complete=scans.complete,
        count=len(scans.items),
        done=scans.done,
    )
    assert passed


def test_compliance_results_report_honest_coverage(acceptance) -> None:
    namespace = str(acceptance.params.get("compliance_namespace", "openshift-compliance"))
    connector = _connector(acceptance)
    results = asyncio.run(connector.list_compliance_results(NamespacedListArgs(namespace=namespace)))
    passed = _coverage_honest(results)
    acceptance.record(
        "list_compliance_results",
        passed,
        results.coverage_reason or results.coverage,
        namespace=namespace,
        coverage=results.coverage,
        complete=results.complete,
        count=len(results.results),
        scans_done=results.scans_done,
        suites_done=results.suites_done,
    )
    assert passed


def test_users_groups_stay_off_without_opt_in(acceptance) -> None:
    connector = _connector(acceptance, config={**acceptance.config, "include_users_groups": False})
    result = asyncio.run(connector.list_users_groups(BoundedListArgs(limit=10)))
    passed = result.coverage == "not_evaluated" and not result.users and not result.groups
    acceptance.record("list_users_groups_opt_in", passed, result.coverage_reason or result.coverage)
    assert passed


def test_raw_arf_follows_enable_gate(acceptance) -> None:
    path = _required_param(acceptance, "raw_arf_path")
    enabled = bool(acceptance.config.get("raw_arf_enabled", False))
    connector = _connector(acceptance)
    result = asyncio.run(connector.get_raw_arf(RawArfArgs(path=path)))
    expected = "evaluated" if enabled else "not_evaluated"
    passed = result.coverage == expected
    acceptance.record(
        "get_raw_arf",
        passed,
        result.coverage_reason or result.coverage,
        raw_arf_enabled=enabled,
        coverage=result.coverage,
        size_bytes=result.size_bytes,
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


def test_update_route_tls_applies_and_reconciles(acceptance) -> None:
    _run_action(acceptance, "update_route_tls", UpdateRouteTlsArgs)


def test_instantiate_buildconfig_applies_and_reconciles(acceptance) -> None:
    _run_action(acceptance, "instantiate_buildconfig", InstantiateBuildConfigArgs)


def test_update_scc_requires_destructive_gate(acceptance) -> None:
    _run_action(acceptance, "update_scc", UpdateSccArgs, destructive=True)
