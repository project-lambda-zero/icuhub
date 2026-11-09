"""RFC 9457 problem details for the ICUHUB API.

Every error response is ``application/problem+json`` with ``type`` set to
``https://icuhub/errors/<slug>``. Optional ``action_id`` and ``correlation_id``
members are added where the caller can use them to join audit records.

Exception mapping is explicit: each known exception class maps to one HTTP
status and one slug. Unknown exceptions map to a generic 500 whose body never
contains the exception message, because core messages can echo input.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from icuhub.core.credentials import CredentialError, CredentialNotFound
from icuhub.core.outbox import UnknownTenantError
from icuhub.core.queue import QueueError
from icuhub.core.sync import ConflictError
from icuhub.kit.errors import (
    AuthFailed,
    BudgetExhausted,
    ConfigError,
    Conflict,
    NotFound,
    OutcomeUnknown,
    PaginationLoop,
    PermissionDenied,
    RateLimited,
    StalePlan,
    TransientVendorError,
    UnsafeUrl,
    VendorContractError,
    WebhookRejected,
)

__all__ = [
    "PROBLEM_BASE",
    "PROBLEM_MEDIA_TYPE",
    "AuthenticationError",
    "AuthorizationError",
    "ProblemError",
    "install_problem_handlers",
    "map_exception",
    "problem_body",
    "problem_response",
]

_log = logging.getLogger(__name__)

PROBLEM_BASE = "https://icuhub/errors/"
PROBLEM_MEDIA_TYPE = "application/problem+json"


class ProblemError(Exception):
    """A request failure that is already expressed as an HTTP problem."""

    def __init__(
        self,
        status: int,
        slug: str,
        title: str,
        detail: str,
        *,
        headers: dict[str, str] | None = None,
        **extra: Any,
    ) -> None:
        super().__init__(detail)
        self.status = status
        self.slug = slug
        self.title = title
        self.detail = detail
        self.headers = headers or {}
        self.extra = extra


class AuthenticationError(ProblemError):
    """The request carries no usable credential."""

    def __init__(self, detail: str) -> None:
        super().__init__(401, "unauthenticated", "Unauthenticated", detail, headers={"WWW-Authenticate": "Bearer"})


class AuthorizationError(ProblemError):
    """The caller is authenticated but lacks the role the endpoint requires."""

    def __init__(self, detail: str) -> None:
        super().__init__(403, "forbidden", "Forbidden", detail)


def problem_body(problem: ProblemError) -> dict[str, Any]:
    body: dict[str, Any] = {
        "type": f"{PROBLEM_BASE}{problem.slug}",
        "title": problem.title,
        "status": problem.status,
        "detail": problem.detail,
    }
    body.update({key: value for key, value in problem.extra.items() if value is not None})
    return body


def problem_response(problem: ProblemError) -> JSONResponse:
    return JSONResponse(
        status_code=problem.status,
        content=problem_body(problem),
        media_type=PROBLEM_MEDIA_TYPE,
        headers=problem.headers,
    )


def _retry_headers(seconds: float | None) -> dict[str, str]:
    if seconds is None:
        return {}
    return {"Retry-After": str(max(1, int(seconds)))}


def map_exception(exc: BaseException) -> ProblemError:
    """Translate a known core, kit, or auth exception into a problem.

    Unknown exceptions return a generic 500 problem with no message.
    """
    if isinstance(exc, ProblemError):
        return exc
    if isinstance(exc, PermissionDenied):
        return ProblemError(403, "policy-denied", "Policy denied", str(exc))
    if isinstance(exc, NotFound):
        return ProblemError(404, "not-found", "Not found", str(exc))
    if isinstance(exc, CredentialNotFound):
        return ProblemError(404, "credential-not-found", "Credential not found", "credential not found")
    if isinstance(exc, (Conflict, ConflictError)):
        return ProblemError(409, "conflict", "Conflict", str(exc))
    if isinstance(exc, StalePlan):
        return ProblemError(409, "stale-plan", "Stale plan", str(exc))
    if isinstance(exc, RateLimited):
        return ProblemError(429, "rate-limited", "Vendor rate limit", str(exc), headers=_retry_headers(exc.retry_after_s))
    if isinstance(exc, (BudgetExhausted, TransientVendorError)):
        return ProblemError(503, "vendor-unavailable", "Vendor unavailable", str(exc))
    if isinstance(exc, OutcomeUnknown):
        return ProblemError(502, "outcome-unknown", "Vendor outcome unknown", str(exc))
    if isinstance(exc, (VendorContractError, PaginationLoop)):
        return ProblemError(502, "vendor-contract", "Vendor contract violation", str(exc))
    if isinstance(exc, (ConfigError, UnsafeUrl)):
        return ProblemError(422, "invalid-config", "Invalid configuration", str(exc))
    if isinstance(exc, AuthFailed):
        return ProblemError(401, "vendor-auth-failed", "Vendor authentication failed", str(exc))
    if isinstance(exc, WebhookRejected):
        return ProblemError(401, "webhook-rejected", "Webhook rejected", str(exc))
    if isinstance(exc, (CredentialError, QueueError)):
        return ProblemError(503, "dependency-unavailable", "Dependency unavailable", "a required dependency is unavailable")
    if isinstance(exc, UnknownTenantError):
        return ProblemError(403, "unknown-tenant", "Unknown tenant", "tenant is not provisioned")
    _log.error("unhandled API exception", exc_info=exc)
    return ProblemError(500, "internal", "Internal error", "an internal error occurred")


_MAPPED_TYPES: tuple[type[Exception], ...] = (
    ProblemError,
    PermissionDenied,
    NotFound,
    CredentialNotFound,
    Conflict,
    ConflictError,
    StalePlan,
    RateLimited,
    BudgetExhausted,
    TransientVendorError,
    OutcomeUnknown,
    VendorContractError,
    PaginationLoop,
    ConfigError,
    UnsafeUrl,
    AuthFailed,
    WebhookRejected,
    CredentialError,
    QueueError,
    UnknownTenantError,
)


def install_problem_handlers(app: FastAPI) -> None:
    """Register problem handlers for mapped exceptions, validation, and HTTP errors."""

    async def _mapped(_request: Request, exc: Any) -> JSONResponse:
        return problem_response(map_exception(exc))

    async def _validation(_request: Request, exc: Any) -> JSONResponse:
        # Strip "input" so request values (including credentials) are never echoed back.
        errors = [{k: v for k, v in err.items() if k not in ("input", "ctx")} for err in exc.errors()]
        return problem_response(
            ProblemError(422, "validation", "Validation failed", "request validation failed", errors=errors)
        )

    async def _http(_request: Request, exc: Any) -> JSONResponse:
        detail = exc.detail if isinstance(exc.detail, str) else "request failed"
        return problem_response(ProblemError(exc.status_code, "http-error", "HTTP error", detail))

    for exc_type in (*_MAPPED_TYPES, AuthenticationError, AuthorizationError):
        app.add_exception_handler(exc_type, _mapped)
    app.add_exception_handler(RequestValidationError, _validation)
    app.add_exception_handler(StarletteHTTPException, _http)
    app.add_exception_handler(Exception, _mapped)
