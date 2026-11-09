"""ASGI application assembly and the ``api`` service entrypoint.

Mounts REST ``/v1``, webhook ingress ``/hooks/{endpoint_id}``, MCP ``/mcp``, and the
``/healthz`` and ``/readyz`` probes. The MCP session manager runs for the lifetime of the app.
"""

from __future__ import annotations

import argparse
import logging
from collections.abc import AsyncGenerator, Awaitable, Callable, MutableMapping
from contextlib import asynccontextmanager
from typing import Any

import uvicorn
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from starlette.responses import Response
from starlette.routing import Route

from icuhub.api.auth import authenticate
from icuhub.api.hooks import router as hooks_router
from icuhub.api.mcp import build_session_manager
from icuhub.api.problems import ProblemError, install_problem_handlers, problem_response
from icuhub.api.rest import router as rest_router
from icuhub.storage.db import admin_session

__all__ = ["create_app", "main"]

_log = logging.getLogger(__name__)

Scope = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[MutableMapping[str, Any]]]
Send = Callable[[MutableMapping[str, Any]], Awaitable[None]]


def _headers(scope: Scope) -> dict[str, str]:
    return {key.decode("latin-1").lower(): value.decode("latin-1") for key, value in scope.get("headers", [])}


class _McpEndpoint:
    """Raw ASGI endpoint. A class instance keeps Starlette from wrapping it as request/response."""

    def __init__(self, manager: StreamableHTTPSessionManager) -> None:
        self._manager = manager

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        try:
            await authenticate(_headers(scope))
        except ProblemError as exc:
            await problem_response(exc)(scope, receive, send)
            return
        await self._manager.handle_request(scope, receive, send)


def create_app() -> FastAPI:
    manager = build_session_manager()

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncGenerator[None]:
        async with manager.run():
            yield

    app = FastAPI(
        title="icuhub",
        version="0.1.0",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url="/openapi.json",
    )
    install_problem_handlers(app)
    app.include_router(rest_router)
    app.include_router(hooks_router)
    app.router.routes.append(Route("/mcp", endpoint=_McpEndpoint(manager), include_in_schema=False))

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz", include_in_schema=False)
    async def readyz() -> Response:
        try:
            async with admin_session() as session:
                await session.execute(text("SELECT 1"))
        except (OSError, SQLAlchemyError) as exc:
            _log.warning("readiness check failed: %s", type(exc).__name__)
            return JSONResponse(status_code=503, content={"status": "unavailable"})
        return JSONResponse(status_code=200, content={"status": "ready"})

    return app


def main(argv: list[str] | None = None) -> int:
    """Run the API under uvicorn. ``loop="asyncio"`` avoids Windows Proactor handle leaks."""
    parser = argparse.ArgumentParser(prog="icuhub api")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args(argv)
    uvicorn.run(create_app(), host=args.host, port=args.port, loop="asyncio")
    return 0
