"""Kubernetes polled stream behavior: snapshot, incremental resume, relist, and coverage markers."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest

from icuhub.connectors._kube import streams
from icuhub.connectors._kube.client import ResourceSpec
from icuhub.connectors._kube.models import (
    KubeConfig,
    KubePartitionCursor,
    KubeSnapshotCursor,
    ResourceSelection,
)
from icuhub.kit.errors import PermissionDenied, VendorContractError
from icuhub.kit.types import RawBatch, SecretRef

POD = ResourceSelection(version="v1", resource="pods", kind="Pod")
POD_PARTITION = "core/v1/pods@*"
POLICY_PARTITION = "wgpolicyk8s.io/v1alpha2/policyreports@*"
CLUSTER_POLICY_PARTITION = "wgpolicyk8s.io/v1alpha2/clusterpolicyreports@*"
GATEKEEPER_PARTITION = "constraints.gatekeeper.sh/v1beta1/k8srequiredlabels@*"
ROUTE_PARTITION = "route.openshift.io/v1/routes@*"
SCC_PARTITION = "security.openshift.io/v1/securitycontextconstraints@*"


class _ListResult:
    def __init__(self, items: list[dict[str, Any]], resource_version: str) -> None:
        self.items = items
        self.resource_version = resource_version
        self.continue_token = None
        self.complete = True


class FakeApi:
    def __init__(
        self,
        *,
        lists: dict[str, _ListResult] | None = None,
        watch: Any = None,
        forbidden: frozenset[str] = frozenset(),
    ) -> None:
        self._lists = lists or {}
        self._watch = watch
        self._forbidden = forbidden
        self.list_calls: list[tuple[str, str | None]] = []
        self.watches: list[tuple[str, str]] = []

    async def list_all(self, spec: ResourceSpec, namespace: str | None = None) -> _ListResult:
        self.list_calls.append((spec.resource, namespace))
        if spec.resource in self._forbidden:
            raise PermissionDenied(scope=spec.resource, message="forbidden")
        return self._lists[spec.resource]

    async def watch(self, spec: ResourceSpec, *, resource_version: str, timeout_s: int, namespace: str | None = None):
        self.watches.append((spec.resource, resource_version))
        return self._watch


def obj(uid: str, rv: str = "1") -> dict[str, Any]:
    return {"metadata": {"uid": uid, "name": uid, "namespace": "default", "resourceVersion": rv}}


def connector(api: FakeApi, kind: str = "kubernetes", **config: Any) -> SimpleNamespace:
    cfg = KubeConfig(
        base_url="https://api.example.test",
        bearer_token=SecretRef(ref="cluster-token"),
        **config,
    )
    return SimpleNamespace(
        kind=kind,
        config=cfg,
        api=api,
        ctx=SimpleNamespace(connection_id="conn-1", clock=lambda: datetime(2026, 11, 10, tzinfo=UTC)),
    )


def run(conn: SimpleNamespace, name: str, *, checkpoint: Any = None, mode: str = "full") -> list[RawBatch]:
    async def drain() -> list[RawBatch]:
        return [batch async for batch in streams.run_stream(conn, name, None, checkpoint, mode)]

    return asyncio.run(drain())


def test_policy_snapshot_lists_both_report_kinds_and_marks_complete() -> None:
    api = FakeApi(lists={
        "policyreports": _ListResult([obj("r1")], "10"),
        "clusterpolicyreports": _ListResult([obj("r2")], "11"),
    })
    (batch,) = run(connector(api), "policy_report_snapshot")
    assert batch.complete is True
    assert isinstance(batch.checkpoint, KubeSnapshotCursor)
    assert {record["_record_kind"] for record in batch.records} == {"policy_report"}
    assert {record["_partition"] for record in batch.records} == {POLICY_PARTITION, CLUSTER_POLICY_PARTITION}
    assert all(record["_event"] == "ADDED" and record["_cluster"] == "cluster" for record in batch.records)


def test_forbidden_partition_yields_coverage_marker_and_incomplete_snapshot() -> None:
    api = FakeApi(
        lists={"policyreports": _ListResult([obj("r1")], "10")},
        forbidden=frozenset({"clusterpolicyreports"}),
    )
    (batch,) = run(connector(api), "policy_report_snapshot")
    assert batch.complete is False
    markers = [record for record in batch.records if record.get("_partial_coverage")]
    assert len(markers) == 1
    assert markers[0]["_partition"] == CLUSTER_POLICY_PARTITION
    assert markers[0]["_coverage"]["reason"] == "forbidden"
    assert markers[0]["object"] is None


def test_disabled_policy_reports_make_no_requests() -> None:
    api = FakeApi()
    (batch,) = run(connector(api, policy_reports_enabled=False), "policy_report_changes", mode="full")
    assert api.list_calls == []
    assert api.watches == []
    assert batch.records == []
    assert batch.complete is True


def test_incremental_without_checkpoint_relists_and_records_resource_version() -> None:
    api = FakeApi(lists={"pods": _ListResult([obj("p1", "7")], "7")})
    (batch,) = run(connector(api, inventory_resources=(POD,)), "resource_inventory_changes", mode="incremental")
    assert api.list_calls == [("pods", None)]
    assert [record["_event"] for record in batch.records] == ["ADDED"]
    cursor = batch.checkpoint
    assert isinstance(cursor, KubePartitionCursor)
    assert cursor.resource_version(POD_PARTITION) == "7"
    assert batch.complete is True


def test_incremental_resumes_from_watch_and_skips_bookmarks() -> None:
    checkpoint = KubePartitionCursor(partitions={POD_PARTITION: "5"})
    watch = SimpleNamespace(
        events=[
            {"type": "ADDED", "object": obj("p2", "6")},
            {"type": "BOOKMARK", "object": {"metadata": {"resourceVersion": "8"}}},
        ],
        resource_version="8",
        relisted=False,
    )
    api = FakeApi(watch=watch)
    (batch,) = run(
        connector(api, inventory_resources=(POD,)),
        "resource_inventory_changes",
        checkpoint=checkpoint,
        mode="incremental",
    )
    assert api.watches == [("pods", "5")]
    assert api.list_calls == []
    assert [record["_event"] for record in batch.records] == ["ADDED"]
    cursor = batch.checkpoint
    assert isinstance(cursor, KubePartitionCursor)
    assert cursor.resource_version(POD_PARTITION) == "8"


def test_watch_relist_falls_back_to_full_list() -> None:
    checkpoint = KubePartitionCursor(partitions={POD_PARTITION: "5"})
    watch = SimpleNamespace(events=[], resource_version=None, relisted=True)
    api = FakeApi(lists={"pods": _ListResult([obj("p1", "9")], "9")}, watch=watch)
    (batch,) = run(
        connector(api, inventory_resources=(POD,)),
        "resource_inventory_changes",
        checkpoint=checkpoint,
        mode="incremental",
    )
    assert api.watches == [("pods", "5")]
    assert api.list_calls == [("pods", None)]
    cursor = batch.checkpoint
    assert isinstance(cursor, KubePartitionCursor)
    assert cursor.resource_version(POD_PARTITION) == "9"


def test_gatekeeper_snapshot_is_kubernetes_only() -> None:
    api = FakeApi()
    with pytest.raises(VendorContractError):
        run(connector(api, kind="openshift"), "gatekeeper_audit_snapshot")
    assert api.list_calls == []


def test_route_assessment_snapshot_is_openshift_only() -> None:
    api = FakeApi()
    with pytest.raises(VendorContractError):
        run(connector(api, kind="kubernetes"), "route_assessment_snapshot")
    assert api.list_calls == []


def test_scc_assessment_snapshot_is_openshift_only() -> None:
    api = FakeApi()
    with pytest.raises(VendorContractError):
        run(connector(api, kind="kubernetes"), "scc_assessment_snapshot")
    assert api.list_calls == []


def test_gatekeeper_changes_are_kubernetes_only() -> None:
    api = FakeApi()
    with pytest.raises(VendorContractError):
        run(connector(api, kind="openshift"), "gatekeeper_constraint_changes")
    assert api.list_calls == []


def test_route_assessment_changes_is_openshift_only() -> None:
    api = FakeApi()
    with pytest.raises(VendorContractError):
        run(connector(api, kind="kubernetes"), "route_assessment_changes")
    assert api.list_calls == []


def test_scc_assessment_changes_is_openshift_only() -> None:
    api = FakeApi()
    with pytest.raises(VendorContractError):
        run(connector(api, kind="kubernetes"), "scc_assessment_changes")
    assert api.list_calls == []


def test_route_assessment_snapshot_lists_routes_on_openshift() -> None:
    api = FakeApi(lists={"routes": _ListResult([obj("rt1")], "20")})
    (batch,) = run(connector(api, kind="openshift"), "route_assessment_snapshot")
    assert api.list_calls == [("routes", None)]
    assert batch.complete is True
    assert isinstance(batch.checkpoint, KubeSnapshotCursor)
    assert {record["_record_kind"] for record in batch.records} == {"route_assessment"}
    assert {record["_partition"] for record in batch.records} == {ROUTE_PARTITION}


def test_route_assessment_changes_relists_without_checkpoint_on_openshift() -> None:
    api = FakeApi(lists={"routes": _ListResult([obj("rt1", "21")], "21")})
    (batch,) = run(connector(api, kind="openshift"), "route_assessment_changes", mode="incremental")
    assert api.list_calls == [("routes", None)]
    assert api.watches == []
    assert [record["_event"] for record in batch.records] == ["ADDED"]
    cursor = batch.checkpoint
    assert isinstance(cursor, KubePartitionCursor)
    assert cursor.resource_version(ROUTE_PARTITION) == "21"
    assert batch.complete is True


def test_route_assessment_full_mode_relists_even_with_checkpoint() -> None:
    checkpoint = KubePartitionCursor(partitions={ROUTE_PARTITION: "5"})
    api = FakeApi(lists={"routes": _ListResult([obj("rt1", "22")], "22")})
    (batch,) = run(connector(api, kind="openshift"), "route_assessment_changes", checkpoint=checkpoint, mode="full")
    assert api.list_calls == [("routes", None)]
    assert api.watches == []
    cursor = batch.checkpoint
    assert isinstance(cursor, KubePartitionCursor)
    assert cursor.resource_version(ROUTE_PARTITION) == "22"


def test_scc_assessment_snapshot_lists_sccs_on_openshift() -> None:
    api = FakeApi(lists={"securitycontextconstraints": _ListResult([obj("scc1")], "30")})
    (batch,) = run(connector(api, kind="openshift"), "scc_assessment_snapshot")
    assert api.list_calls == [("securitycontextconstraints", None)]
    assert batch.complete is True
    assert isinstance(batch.checkpoint, KubeSnapshotCursor)
    assert {record["_record_kind"] for record in batch.records} == {"scc_assessment"}
    assert {record["_partition"] for record in batch.records} == {SCC_PARTITION}


def test_scc_assessment_incremental_resumes_from_watch_on_openshift() -> None:
    checkpoint = KubePartitionCursor(partitions={SCC_PARTITION: "5"})
    watch = SimpleNamespace(
        events=[{"type": "ADDED", "object": obj("scc2", "6")}],
        resource_version="6",
        relisted=False,
    )
    api = FakeApi(watch=watch)
    (batch,) = run(connector(api, kind="openshift"), "scc_assessment_changes", checkpoint=checkpoint, mode="incremental")
    assert api.watches == [("securitycontextconstraints", "5")]
    assert api.list_calls == []
    assert [record["_event"] for record in batch.records] == ["ADDED"]
    cursor = batch.checkpoint
    assert isinstance(cursor, KubePartitionCursor)
    assert cursor.resource_version(SCC_PARTITION) == "6"


def test_scc_assessment_full_mode_relists_even_with_checkpoint() -> None:
    checkpoint = KubePartitionCursor(partitions={SCC_PARTITION: "5"})
    api = FakeApi(lists={"securitycontextconstraints": _ListResult([obj("scc1", "31")], "31")})
    (batch,) = run(connector(api, kind="openshift"), "scc_assessment_changes", checkpoint=checkpoint, mode="full")
    assert api.list_calls == [("securitycontextconstraints", None)]
    assert api.watches == []
    cursor = batch.checkpoint
    assert isinstance(cursor, KubePartitionCursor)
    assert cursor.resource_version(SCC_PARTITION) == "31"


def test_compliance_scan_status_full_mode_relists_scans_and_suites() -> None:
    checkpoint = KubePartitionCursor(partitions={})
    api = FakeApi(
        lists={
            "compliancescans": _ListResult([obj("scan1", "40")], "40"),
            "compliancesuites": _ListResult([obj("suite1", "41")], "41"),
        }
    )
    (batch,) = run(connector(api, kind="openshift"), "compliance_scan_status", checkpoint=checkpoint, mode="full")
    assert api.list_calls == [("compliancescans", None), ("compliancesuites", None)]
    assert api.watches == []
    assert {record["_record_kind"] for record in batch.records} == {"compliance_scan_status"}


def test_every_polled_stream_maps_to_a_record_kind() -> None:
    mapped = {name for names in streams.RECORD_STREAMS.values() for name in names}
    assert set(streams.STREAM_SPECS) <= mapped
