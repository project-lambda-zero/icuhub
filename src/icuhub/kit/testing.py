"""Offline test helpers for connectors: fake transports, a read-only guard, stream and mapper drivers,
golden files, and the conformance check.

Nothing here opens a socket. ``import httpx2`` is confined to this module, ``kit/http.py``, and ``kit/auth.py``.
Connectors are driven through ``make_connector``, which builds the context with fixture secrets and a fixed clock.
"""

from __future__ import annotations

import asyncio
import difflib
import inspect
import json
import os
import typing
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, NamedTuple

import httpx2
from pydantic import BaseModel

from icuhub.kit.auth import AUTH_STRATEGIES
from icuhub.kit.connector import KNOWN_CAPABILITIES, Connector, build_context
from icuhub.kit.errors import ConfigError
from icuhub.kit.http import build_http
from icuhub.kit.manifest import check_manifest
from icuhub.kit.types import MapContext, RawBatch, SecretRef, Target

__all__ = [
    "ReadOnlyGuard",
    "RecordedTransport",
    "RouteTransport",
    "amake_connector",
    "assert_matches_golden",
    "collect_stream",
    "conformance_problems",
    "make_connector",
    "map_all",
]

_FIXED_NOW = datetime(2026, 11, 9, 0, 0, 0, tzinfo=UTC)
_GOLDEN_UPDATE_ENV = "ICUHUB_UPDATE_GOLDEN"
_SECRET_NAME_HINTS = ("token", "secret", "password", "passwd", "credential", "private_key", "api_key")
_BODY_KEYS = ("json", "text", "content", "body_file")
_READ_METHODS = frozenset({"GET", "HEAD"})


def _fixed_clock() -> datetime:
    return _FIXED_NOW


class _FixtureSecrets:
    """Resolves fixture secret refs from a dict. Never includes secret bytes in errors."""

    def __init__(self, secrets: Mapping[str, bytes]) -> None:
        self._secrets = dict(secrets)

    async def resolve(self, ref: SecretRef) -> bytes:
        try:
            return self._secrets[ref.ref]
        except KeyError:
            raise ConfigError(f"test secret ref {ref.ref!r} was not provided to make_connector") from None


async def amake_connector(
    cls: type[Connector],
    config_dict: Mapping[str, Any],
    transport: httpx2.AsyncBaseTransport,
    secrets: Mapping[str, bytes],
) -> Connector:
    """Build ``cls`` with fixture secrets, a fixed clock, and an HTTP client bound to ``transport``.

    Awaitable form for callers already inside an event loop. The auth strategy is built with
    ``build_auth()`` before the HTTP client is attached, matching the runtime order.
    """
    config = cls.config_model.model_validate(dict(config_dict))
    ctx = build_context(
        secrets=_FixtureSecrets(secrets),
        clock=_fixed_clock,
        connection_id="test-connection",
        tenant_id="test-tenant",
    )
    connector = cls(config, ctx)
    auth = await connector.build_auth()
    if cls.uses_http:
        ctx.http = build_http(config, auth, transport=transport, clock=_fixed_clock)
    return connector


def make_connector(
    cls: type[Connector],
    config_dict: Mapping[str, Any],
    transport: httpx2.AsyncBaseTransport,
    secrets: Mapping[str, bytes],
) -> Connector:
    """Synchronous wrapper over ``amake_connector``. Must not be called from a running event loop."""
    return asyncio.run(amake_connector(cls, config_dict, transport, secrets))


def collect_stream(
    connector: Connector,
    stream: str,
    target: Target | None = None,
    checkpoint: BaseModel | None = None,
    mode: str = "incremental",
) -> list[RawBatch]:
    """Run stream ``stream`` to completion and return every batch it yields. Synchronous."""
    specs = connector.streams()
    spec = specs.get(stream)
    if spec is None:
        raise ValueError(f"unknown stream {stream!r}; declared streams: {sorted(specs)}")
    if mode not in spec.modes:
        raise ValueError(f"stream {stream!r} does not support mode {mode!r}; supported: {list(spec.modes)}")
    if spec.requires_target and target is None:
        raise ValueError(f"stream {stream!r} requires a target")
    if checkpoint is not None and not isinstance(checkpoint, spec.cursor):
        raise TypeError(f"stream {stream!r} expects checkpoint {spec.cursor.__name__}, got {type(checkpoint).__name__}")

    async def drain() -> list[RawBatch]:
        return [batch async for batch in spec.fn(connector, target, checkpoint, mode)]

    return asyncio.run(drain())


def map_all(
    connector: Connector,
    stream: str,
    records: Iterable[Mapping[str, Any]],
    target: Target | None = None,
) -> list[BaseModel]:
    """Run the mapper for ``stream`` over ``records`` and return the flattened output. Synchronous."""
    spec = connector.mappers().get(stream)
    if spec is None:
        raise ValueError(f"stream {stream!r} has no mapper")
    context = MapContext(
        connection_id=connector.ctx.connection_id,
        tenant_id=connector.ctx.tenant_id,
        connector_kind=connector.kind,
        target=target,
        received_at=connector.ctx.clock(),
    )
    mapped: list[BaseModel] = []
    for raw in records:
        mapped.extend(spec.fn(connector, raw, context))
    return mapped


def assert_matches_golden(objs: Sequence[BaseModel], path: str | os.PathLike[str]) -> None:
    """Compare ``objs`` (rendered with ``model_dump(mode="json", exclude_none=True)``) to the golden file at ``path``.

    Set ``ICUHUB_UPDATE_GOLDEN=1`` to write the golden file instead of comparing. A mismatch raises
    ``AssertionError`` with a unified diff excerpt.
    """
    golden = Path(path)
    rendered = [obj.model_dump(mode="json", exclude_none=True) for obj in objs]
    text = json.dumps(rendered, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if os.environ.get(_GOLDEN_UPDATE_ENV) == "1":
        golden.parent.mkdir(parents=True, exist_ok=True)
        golden.write_text(text, encoding="utf-8")
        return
    if not golden.exists():
        raise AssertionError(f"golden file {golden} is missing; run with {_GOLDEN_UPDATE_ENV}=1 to create it")
    committed_text = golden.read_text(encoding="utf-8")
    if json.loads(committed_text) == rendered:
        return
    diff = list(
        difflib.unified_diff(
            committed_text.splitlines(),
            text.splitlines(),
            fromfile=f"{golden} (committed)",
            tofile="(current)",
            lineterm="",
        )
    )
    raise AssertionError(f"golden mismatch for {golden}:\n" + "\n".join(diff[:80]))


def _mentions_secret_ref(annotation: Any) -> bool:
    if annotation is SecretRef:
        return True
    return any(_mentions_secret_ref(arg) for arg in typing.get_args(annotation))


def _unmarked_secret_fields(cls: type[Connector]) -> list[str]:
    """Flag config fields whose name suggests a secret but whose annotation is not ``SecretRef``.

    This is a guard for common names, not a classifier: it cannot prove a field is or is not secret.
    """
    problems: list[str] = []
    for name, field in cls.config_model.model_fields.items():
        if any(hint in name.lower() for hint in _SECRET_NAME_HINTS) and not _mentions_secret_ref(field.annotation):
            problems.append(f"{cls.kind}: config field {name!r} looks secret but is not typed SecretRef")
    return problems


def conformance_problems(cls: type[Connector]) -> list[str]:
    """Return every conformance problem for ``cls``; an empty list means the connector conforms."""
    kind = cls.kind
    problems = list(check_manifest(cls))
    if not cls.flows:
        problems.append(f"{kind}: flows is empty; list the COMMATRIX flow ids")
    for capability in cls.capabilities:
        if capability not in KNOWN_CAPABILITIES:
            problems.append(f"{kind}: unknown capability {capability!r}")
    for mode in cls.auth_modes:
        if mode not in AUTH_STRATEGIES:
            problems.append(f"{kind}: unknown auth mode {mode!r}")
    mappers = cls.mappers()
    for name, stream_spec in cls.streams().items():
        if name not in mappers:
            problems.append(f"{kind}: stream {name!r} has no mapper")
        if stream_spec.capability not in KNOWN_CAPABILITIES:
            problems.append(f"{kind}: stream {name!r} has unknown capability {stream_spec.capability!r}")
    for name, operation_spec in cls.operations().items():
        if operation_spec.capability is not None and operation_spec.capability not in KNOWN_CAPABILITIES:
            problems.append(f"{kind}: operation {name!r} has unknown capability {operation_spec.capability!r}")
    for name, action_spec in cls.actions().items():
        if action_spec.capability not in KNOWN_CAPABILITIES:
            problems.append(f"{kind}: action {name!r} has unknown capability {action_spec.capability!r}")
        if not callable(action_spec.apply):
            problems.append(f"{kind}: action {name!r} has no apply")
    for scope in cls.scopes:
        if not scope.probe.strip():
            problems.append(f"{kind}: scope {scope.name!r} has a blank probe")
    problems.extend(_unmarked_secret_fields(cls))
    return problems


class _Exchange(NamedTuple):
    request: Mapping[str, Any]
    response: Mapping[str, Any]


def _check_response(spec: Mapping[str, Any], where: str, *, allow_body_file: bool) -> None:
    if "status" not in spec:
        raise ValueError(f"{where}: response needs 'status'")
    bodies = [key for key in _BODY_KEYS if key in spec]
    if len(bodies) > 1:
        raise ValueError(f"{where}: response takes at most one of json, text, content, body_file")
    if "content" in spec and not isinstance(spec["content"], bytes):
        raise TypeError(f"{where}: content must be bytes")
    if "body_file" in spec and not allow_body_file:
        raise ValueError(f"{where}: body_file needs a cassette file on disk")


def _build_response(spec: Mapping[str, Any], base_dir: Path | None, request: httpx2.Request) -> httpx2.Response:
    _check_response(spec, "response", allow_body_file=base_dir is not None)
    headers = dict(spec.get("headers", {}))
    status = int(spec["status"])
    if "json" in spec:
        return httpx2.Response(status, headers=headers, json=spec["json"], request=request)
    if "text" in spec:
        return httpx2.Response(status, headers=headers, text=str(spec["text"]), request=request)
    if "content" in spec:
        return httpx2.Response(status, headers=headers, content=spec["content"], request=request)
    if "body_file" in spec and base_dir is not None:
        content = (base_dir / str(spec["body_file"])).read_bytes()
        return httpx2.Response(status, headers=headers, content=content, request=request)
    return httpx2.Response(status, headers=headers, request=request)


def _describe(request: Mapping[str, Any]) -> str:
    return f"{str(request['method']).upper()} {request['path']}"


async def _request_mismatch(expected: Mapping[str, Any], actual: httpx2.Request) -> str | None:
    """Return why ``actual`` does not match ``expected``, or None when it matches."""
    if actual.method.upper() != str(expected["method"]).upper():
        return f"method {actual.method} != {expected['method']}"
    if actual.url.path != expected["path"]:
        return f"path {actual.url.path} != {expected['path']}"
    for key, value in dict(expected.get("query", {})).items():
        if actual.url.params.get(key) != str(value):
            return f"query parameter {key!r} differs"
    for key, value in dict(expected.get("headers", {})).items():
        if actual.headers.get(key) != str(value):
            return f"header {key!r} is missing or differs"
    if "json" in expected:
        body = await actual.aread()
        try:
            sent = json.loads(body) if body else None
        except json.JSONDecodeError:
            return "request body is not JSON"
        if sent != expected["json"]:
            return f"JSON body differs: sent {sent!r}, expected {expected['json']!r}"
    return None


class RecordedTransport(httpx2.AsyncBaseTransport):
    """Replays recorded interactions in order.

    Each request must match the next unused interaction on method, path, the ``query`` subset when given, the
    ``headers`` subset when given (case-insensitive names), and the ``json`` body when given. Anything else raises
    ``AssertionError``. Construct from exactly one of ``cassette_path`` (JSON cassette file; ``body_file`` resolves
    relative to its directory) or ``interactions`` (inline; ``body_file`` is not allowed).
    """

    def __init__(
        self,
        cassette_path: str | os.PathLike[str] | None = None,
        *,
        interactions: Sequence[Mapping[str, Any]] | None = None,
    ) -> None:
        if (cassette_path is None) == (interactions is None):
            raise ValueError("RecordedTransport takes exactly one of cassette_path or interactions")
        if cassette_path is not None:
            cassette = Path(cassette_path)
            document = json.loads(cassette.read_text(encoding="utf-8"))
            raw_entries = document.get("interactions") if isinstance(document, Mapping) else None
            if not isinstance(raw_entries, list):
                raise ValueError(f"{cassette}: top level must be an object with an 'interactions' list")
            self._base_dir: Path | None = cassette.parent
            allow_body_file = True
        else:
            raw_entries = list(interactions or ())
            self._base_dir = None
            allow_body_file = False
        self._exchanges = [
            self._exchange(index, raw, allow_body_file) for index, raw in enumerate(raw_entries)
        ]
        self._cursor = 0

    @staticmethod
    def _exchange(index: int, raw: Any, allow_body_file: bool) -> _Exchange:
        if not isinstance(raw, Mapping) or not isinstance(raw.get("request"), Mapping) or not isinstance(
            raw.get("response"), Mapping
        ):
            raise ValueError(f"interaction {index} needs 'request' and 'response' objects")
        request = raw["request"]
        if "method" not in request or "path" not in request:
            raise ValueError(f"interaction {index}: request needs 'method' and 'path'")
        _check_response(raw["response"], f"interaction {index}", allow_body_file=allow_body_file)
        return _Exchange(request=request, response=raw["response"])

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        if self._cursor == len(self._exchanges):
            raise AssertionError(
                f"unrecorded request {request.method} {request.url.path}: every recorded interaction is used"
            )
        exchange = self._exchanges[self._cursor]
        mismatch = await _request_mismatch(exchange.request, request)
        if mismatch is not None:
            raise AssertionError(
                f"request {request.method} {request.url.path} does not match recorded interaction "
                f"{self._cursor} ({_describe(exchange.request)}): {mismatch}"
            )
        self._cursor += 1
        return _build_response(exchange.response, self._base_dir, request)

    def assert_all_used(self) -> None:
        """Raise ``AssertionError`` if any recorded interaction was not consumed."""
        if self._cursor < len(self._exchanges):
            unused = ", ".join(_describe(exchange.request) for exchange in self._exchanges[self._cursor :])
            raise AssertionError(f"recorded interactions were not used: {unused}")


class RouteTransport(httpx2.AsyncBaseTransport):
    """Answers requests by ``(method, path)`` without ordering.

    A route value is a response spec (``status``, optional ``headers``, and one of ``json``, ``text``) or a callable
    taking the ``httpx2.Request``. A callable may be sync or async and returns a response spec or an
    ``httpx2.Response``. Unknown routes raise ``AssertionError``.
    """

    def __init__(self, routes: Mapping[tuple[str, str], Any]) -> None:
        self.requests: list[httpx2.Request] = []
        self._routes: dict[tuple[str, str], Any] = {}
        for (method, path), value in routes.items():
            where = f"route {method.upper()} {path}"
            if isinstance(value, Mapping):
                _check_response(value, where, allow_body_file=False)
            elif not callable(value):
                raise TypeError(f"{where}: value must be a response spec or a callable")
            self._routes[(method.upper(), path)] = value

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        key = (request.method.upper(), request.url.path)
        if key not in self._routes:
            raise AssertionError(f"no route for {request.method} {request.url.path}")
        value = self._routes[key]
        if isinstance(value, Mapping):
            return _build_response(value, None, request)
        result = value(request)
        if inspect.isawaitable(result):
            result = await result
        if isinstance(result, httpx2.Response):
            return result
        if isinstance(result, Mapping):
            return _build_response(result, None, request)
        raise TypeError(
            f"route {key[0]} {key[1]} handler returned {type(result).__name__}; "
            "expected a response spec or httpx2.Response"
        )


class ReadOnlyGuard(httpx2.AsyncBaseTransport):
    """Wraps a transport and allows only reads: GET and HEAD, plus POST to ``allowed_post_paths``.

    Used to prove that a connector's ``plan`` sends no write. Any other request raises ``AssertionError`` before it
    reaches the wrapped transport.
    """

    def __init__(self, transport: httpx2.AsyncBaseTransport, *, allowed_post_paths: Iterable[str] = ()) -> None:
        self._inner = transport
        self._allowed_post_paths = frozenset(allowed_post_paths)

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        method = request.method.upper()
        if method in _READ_METHODS:
            return await self._inner.handle_async_request(request)
        if method == "POST" and request.url.path in self._allowed_post_paths:
            return await self._inner.handle_async_request(request)
        raise AssertionError(f"read-only guard: {request.method} {request.url.path} is not allowed")

    async def aclose(self) -> None:
        await self._inner.aclose()
