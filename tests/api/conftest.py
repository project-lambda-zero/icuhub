"""Drive an ASGI app directly; httpx and fastapi.testclient are not installed in this environment."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping
from typing import Any

import pytest

Response = tuple[int, dict[str, str], bytes]
Call = Callable[..., Response]


async def _request(
    app: Any,
    method: str,
    path: str,
    headers: Mapping[str, str],
    body: bytes,
) -> Response:
    path, _, query = path.partition("?")
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "root_path": "",
        "query_string": query.encode(),
        "headers": [(k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in headers.items()],
        "client": ("testclient", 50000),
        "server": ("testserver", 80),
    }
    sent_body = False
    messages: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        nonlocal sent_body
        if not sent_body:
            sent_body = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        messages.append(message)

    await app(scope, receive, send)
    start = next(m for m in messages if m["type"] == "http.response.start")
    response_headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in start["headers"]}
    payload = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
    return start["status"], response_headers, payload


@pytest.fixture
def asgi() -> Callable[[Any], Call]:
    """Return a factory: ``asgi(app)(method, path, headers=None, body=b"")`` runs one request synchronously."""

    def factory(app: Any) -> Call:
        def call(
            method: str,
            path: str,
            headers: Mapping[str, str] | None = None,
            body: bytes = b"",
        ) -> Response:
            return asyncio.run(_request(app, method, path, headers or {}, body))

        return call

    return factory
