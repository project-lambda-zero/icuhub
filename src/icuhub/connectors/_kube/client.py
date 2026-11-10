"""Kubernetes native HTTP list, watch, and read operations.

Resource versions are opaque strings and are never ordered numerically. A 410 on a
continuation restarts that list from scratch; a 410 on a watch reports a relist so the
caller replaces its partition cache before resuming.
"""

from __future__ import annotations

import json
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import quote

from icuhub.connectors._kube.models import (
    ApiDiscoveryResult,
    ResourceListResult,
    ResourceObjectResult,
    ServerVersionResult,
    WatchResult,
)
from icuhub.kit.errors import BudgetExhausted, VendorContractError
from icuhub.kit.http import HttpResult

__all__ = ["KubeApiClient", "KubeHttp", "ResourceSpec"]

_OK = 200
_GONE = 410
_WATCH_TYPES = frozenset({"ADDED", "MODIFIED", "DELETED", "BOOKMARK"})
_LIST_ATTEMPTS = 2


class KubeHttp(Protocol):
    """The authenticated transport; ``VendorHttp`` satisfies this structurally.

    Only the keywords this client sends are declared; ``VendorHttp`` accepts them with defaults.
    """

    async def request(
        self,
        method: str,
        path_or_url: str,
        *,
        params: Mapping[str, Any] | None = None,
        expected: Collection[int] = (200,),
    ) -> HttpResult: ...


def _segment(value: str) -> str:
    return quote(value, safe="")


@dataclass(frozen=True, slots=True)
class ResourceSpec:
    """One served resource: its API group, version, plural name, and kind."""

    key: str
    group: str
    version: str
    resource: str
    kind: str

    def path(
        self,
        *,
        namespace: str | None = None,
        name: str | None = None,
        subresource: str | None = None,
    ) -> str:
        """Return the escaped API path for this resource, scope, object, or subresource."""
        if subresource is not None and name is None:
            raise ValueError("a subresource path requires an object name")
        base = f"/api/{self.version}" if self.group == "" else f"/apis/{_segment(self.group)}/{_segment(self.version)}"
        parts = [base]
        if namespace is not None:
            parts += ["namespaces", _segment(namespace)]
        parts.append(_segment(self.resource))
        if name is not None:
            parts.append(_segment(name))
        if subresource is not None:
            parts.append(_segment(subresource))
        return "/".join(parts)


def _json_object(content: bytes, where: str) -> dict[str, Any]:
    try:
        body = json.loads(content)
    except ValueError as exc:
        raise VendorContractError(f"{where} returned invalid JSON") from exc
    if not isinstance(body, dict):
        raise VendorContractError(f"{where} returned a non-object body")
    return body


def _metadata(obj: dict[str, Any], where: str) -> dict[str, Any]:
    metadata = obj.get("metadata")
    if not isinstance(metadata, dict):
        raise VendorContractError(f"{where} object has no metadata")
    return metadata


def _uid(obj: dict[str, Any], where: str) -> str:
    uid = _metadata(obj, where).get("uid")
    if not isinstance(uid, str) or not uid:
        raise VendorContractError(f"{where} object has no metadata.uid")
    return uid


class KubeApiClient:
    """List, watch, and read Kubernetes resources over the native HTTP API."""

    def __init__(self, http: KubeHttp, *, page_size: int, max_pages: int, max_watch_events: int) -> None:
        self._http = http
        self._page_size = page_size
        self._max_pages = max_pages
        self._max_watch_events = max_watch_events

    async def list_all(self, spec: ResourceSpec, *, namespace: str | None = None) -> ResourceListResult:
        """Return every object in one partition, restarting once if a continuation expires."""
        path = spec.path(namespace=namespace)
        for _ in range(_LIST_ATTEMPTS):
            result = await self._collect(path)
            if result is not None:
                return result
        raise VendorContractError(f"{path} continuation expired on each of {_LIST_ATTEMPTS} list attempts")

    async def _collect(self, path: str) -> ResourceListResult | None:
        """Collect pages from one list attempt; ``None`` means a continuation expired."""
        items: dict[str, dict[str, Any]] = {}
        seen_tokens: set[str] = set()
        token: str | None = None
        resource_version: str | None = None
        for _ in range(self._max_pages):
            params: dict[str, Any] = {"limit": self._page_size}
            if token is not None:
                params["continue"] = token
            response = await self._http.request("GET", path, params=params, expected=(_OK, _GONE))
            if response.status == _GONE:
                return None
            body = _json_object(response.content, path)
            metadata = body.get("metadata")
            if isinstance(metadata, dict) and isinstance(metadata.get("resourceVersion"), str):
                resource_version = metadata["resourceVersion"]
            for obj in body.get("items") or []:
                if not isinstance(obj, dict):
                    raise VendorContractError(f"{path} returned a non-object item")
                items[_uid(obj, path)] = obj
            next_token = metadata.get("continue") if isinstance(metadata, dict) else None
            if not next_token:
                return ResourceListResult(
                    items=list(items.values()),
                    resource_version=resource_version,
                    continue_token=None,
                    complete=True,
                )
            if not isinstance(next_token, str):
                raise VendorContractError(f"{path} returned a non-string continuation token")
            if next_token in seen_tokens:
                raise VendorContractError(f"{path} repeated a continuation token")
            seen_tokens.add(next_token)
            token = next_token
        raise VendorContractError(f"{path} exceeded {self._max_pages} pages")

    async def watch(
        self,
        spec: ResourceSpec,
        *,
        resource_version: str,
        timeout_s: int,
        namespace: str | None = None,
    ) -> WatchResult:
        """Read one bounded watch window; a 410 or ERROR 410 event requests a relist."""
        path = spec.path(namespace=namespace)
        params = {
            "watch": "true",
            "resourceVersion": resource_version,
            "timeoutSeconds": timeout_s,
            "allowWatchBookmarks": "true",
        }
        response = await self._http.request("GET", path, params=params, expected=(_OK, _GONE))
        if response.status == _GONE:
            return WatchResult(events=[], resource_version=None, relisted=True, objects=[])
        events: list[dict[str, Any]] = []
        objects: list[dict[str, Any]] = []
        last_version = resource_version
        for line in response.content.splitlines():
            if not line.strip():
                continue
            if len(events) >= self._max_watch_events:
                raise BudgetExhausted(f"watch event limit of {self._max_watch_events} exceeded for {path}")
            event = _json_object(line, path)
            kind = event.get("type")
            obj = event.get("object")
            if not isinstance(obj, dict):
                raise VendorContractError(f"{path} watch event has no object")
            if kind == "ERROR":
                if obj.get("code") == _GONE:
                    return WatchResult(events=[], resource_version=None, relisted=True, objects=[])
                raise VendorContractError(f"{path} watch returned an ERROR event")
            if kind not in _WATCH_TYPES:
                raise VendorContractError(f"{path} watch returned unknown event type {kind!r}")
            version = _metadata(obj, path).get("resourceVersion")
            if not isinstance(version, str) or not version:
                raise VendorContractError(f"{path} watch event has no resourceVersion")
            last_version = version
            events.append(event)
            if kind != "BOOKMARK":
                objects.append(obj)
        return WatchResult(events=events, resource_version=last_version, relisted=False, objects=objects)

    async def get(
        self,
        spec: ResourceSpec,
        *,
        name: str,
        namespace: str | None = None,
        subresource: str | None = None,
    ) -> ResourceObjectResult:
        """Read one object or one of its subresources."""
        path = spec.path(namespace=namespace, name=name, subresource=subresource)
        response = await self._http.request("GET", path, expected=(_OK,))
        return ResourceObjectResult(data=_json_object(response.content, path))

    async def server_version(self) -> ServerVersionResult:
        """Read the server version from ``/version``."""
        response = await self._http.request("GET", "/version", expected=(_OK,))
        return ServerVersionResult(data=_json_object(response.content, "/version"))

    async def discover(self) -> ApiDiscoveryResult:
        """Read the core and named-group API lists from ``/api`` and ``/apis``."""
        core = await self._http.request("GET", "/api", expected=(_OK,))
        groups = await self._http.request("GET", "/apis", expected=(_OK,))
        return ApiDiscoveryResult(
            core=_json_object(core.content, "/api"),
            groups=_json_object(groups.content, "/apis"),
        )
