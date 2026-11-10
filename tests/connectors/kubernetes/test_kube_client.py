"""Kubernetes list/watch and discovery behavior."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest

client_module = pytest.importorskip(
    "icuhub.connectors._kube.client", reason="kube client implementation is still in progress"
)
KubeApiClient = client_module.KubeApiClient
ResourceSpec = client_module.ResourceSpec

from icuhub.kit.errors import BudgetExhausted, VendorContractError  # noqa: E402

PODS = ResourceSpec(key="pods", group="", version="v1", resource="pods", kind="Pod")


class FakeHttp:
    def __init__(self, responses: list[tuple[int, Any]]) -> None:
        self.responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    async def request(self, method: str, path: str, **kwargs: Any) -> Any:
        self.calls.append({"method": method, "path": path, **kwargs})
        status, body = self.responses.pop(0)
        content = body if isinstance(body, bytes) else json.dumps(body).encode()
        return type("Result", (), {"status": status, "content": content})()


def client(responses: list[tuple[int, Any]], **config: Any) -> tuple[KubeApiClient, FakeHttp]:
    http = FakeHttp(responses)
    return KubeApiClient(http, page_size=2, max_pages=3, max_watch_events=2, **config), http


def item(uid: str, rv: str = "1") -> dict[str, Any]:
    return {"metadata": {"uid": uid, "name": uid, "resourceVersion": rv}}


def test_paginated_list_deduplicates_by_uid_and_preserves_resource_version() -> None:
    api, http = client([
        (200, {"metadata": {"resourceVersion": "000100", "continue": "next"}, "items": [item("a"), item("b")]}),
        (200, {"metadata": {"resourceVersion": "000100"}, "items": [item("b"), item("c")]}),
    ])
    result = asyncio.run(api.list_all(PODS, namespace="default"))
    assert [obj["metadata"]["uid"] for obj in result.items] == ["a", "b", "c"]
    assert result.resource_version == "000100"
    assert http.calls[0]["params"] == {"limit": 2}
    assert http.calls[1]["params"] == {"limit": 2, "continue": "next"}


def test_expired_continue_restarts_the_partition_without_duplicates() -> None:
    api, http = client([
        (200, {"metadata": {"resourceVersion": "10", "continue": "expired"}, "items": [item("old")]}),
        (410, {"kind": "Status", "reason": "Expired"}),
        (200, {"metadata": {"resourceVersion": "11"}, "items": [item("new")]}),
    ])
    result = asyncio.run(api.list_all(PODS))
    assert [obj["metadata"]["uid"] for obj in result.items] == ["new"]
    assert result.resource_version == "11"
    assert len(http.calls) == 3


def test_repeated_continue_token_fails_closed() -> None:
    page = {"metadata": {"resourceVersion": "1", "continue": "same"}, "items": []}
    api, _ = client([(200, page), (200, page)])
    with pytest.raises(VendorContractError, match="continuation token"):
        asyncio.run(api.list_all(PODS))


def test_resource_versions_are_never_ordered_numerically() -> None:
    api, _ = client([(200, {"metadata": {"resourceVersion": "0009"}, "items": [item("a", "0008")]})])
    result = asyncio.run(api.list_all(PODS))
    assert result.resource_version == "0009"


def test_watch_parses_jsonl_and_enforces_event_bound() -> None:
    lines = b"\n".join(json.dumps({"type": kind, "object": item(kind, str(index))}).encode() for index, kind in enumerate(("ADDED", "MODIFIED", "DELETED")))
    api, _ = client([(200, lines)])
    with pytest.raises(BudgetExhausted, match="watch event"):
        asyncio.run(api.watch(PODS, resource_version="1", timeout_s=1))


def test_watch_returns_last_event_resource_version() -> None:
    lines = b"\n".join([
        json.dumps({"type": "ADDED", "object": item("a", "9")}).encode(),
        json.dumps({"type": "BOOKMARK", "object": item("bookmark", "10")}).encode(),
    ])
    api, _ = client([(200, lines)])
    result = asyncio.run(api.watch(PODS, resource_version="8", timeout_s=1))
    assert result.resource_version == "10"
    assert [event["type"] for event in result.events] == ["ADDED", "BOOKMARK"]


def test_cluster_and_namespaced_paths_are_escaped() -> None:
    assert PODS.path(namespace="a/b") == "/api/v1/namespaces/a%2Fb/pods"
    assert PODS.path(namespace="default", name="pod/1", subresource="status") == "/api/v1/namespaces/default/pods/pod%2F1/status"
