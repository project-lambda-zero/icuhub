"""Typed errors raised by connector kit operations."""

from __future__ import annotations

__all__ = [
    "AuthFailed",
    "BudgetExhausted",
    "ConfigError",
    "Conflict",
    "ConnectorError",
    "NotFound",
    "OutcomeUnknown",
    "PaginationLoop",
    "PermissionDenied",
    "RateLimited",
    "RefreshTokenNotPersisted",
    "StalePlan",
    "TransientVendorError",
    "UnsafeUrl",
    "VendorContractError",
    "WebhookRejected",
]


class ConnectorError(Exception):
    """Base class for expected connector failures."""

    retryable: bool = False


class AuthFailed(ConnectorError):  # noqa: N818 -- name is part of the kit contract
    """The vendor rejected authentication."""


class RefreshTokenNotPersisted(AuthFailed):
    """The vendor rotated a refresh token but the rotated value could not be stored.

    The previous refresh token is no longer valid after rotation, so the connection cannot
    authenticate again until the operator re-authorizes. Raised instead of continuing with a
    memory-only refresh token that would be lost on restart.
    """


class PermissionDenied(ConnectorError):  # noqa: N818 -- name is part of the kit contract
    """The authenticated identity lacks a required scope."""

    def __init__(self, scope: str | None = None, message: str | None = None) -> None:
        self.scope = scope
        super().__init__(message or (f"permission denied for scope {scope}" if scope else "permission denied"))


class RateLimited(ConnectorError):  # noqa: N818 -- name is part of the kit contract
    """The vendor rate limit remains exhausted after bounded retries."""

    retryable = True

    def __init__(self, retry_after_s: float | None = None, message: str | None = None) -> None:
        self.retry_after_s = retry_after_s
        super().__init__(message or "vendor rate limit exhausted")


class TransientVendorError(ConnectorError):
    """A retryable vendor or transport failure exhausted its budget."""

    retryable = True


class VendorContractError(ConnectorError):
    """The vendor response does not satisfy its documented contract."""


class NotFound(ConnectorError):  # noqa: N818 -- name is part of the kit contract
    """The requested vendor resource does not exist."""


class Conflict(ConnectorError):  # noqa: N818 -- name is part of the kit contract
    """The request conflicts with current vendor state."""


class OutcomeUnknown(ConnectorError):  # noqa: N818 -- name is part of the kit contract
    """A non-idempotent request may have been applied but its outcome is unknown."""

    def __init__(
        self,
        idempotency_key: str | None = None,
        hint: str = "reconcile by the vendor natural key before any retry",
    ) -> None:
        self.idempotency_key = idempotency_key
        self.hint = hint
        super().__init__(f"vendor outcome unknown: {hint}")


class StalePlan(ConnectorError):  # noqa: N818 -- name is part of the kit contract
    """An action precondition changed after planning."""


class PaginationLoop(ConnectorError):  # noqa: N818 -- name is part of the kit contract
    """A paginator encountered a continuation token or URL more than once."""


class BudgetExhausted(ConnectorError):  # noqa: N818 -- name is part of the kit contract
    """A configured byte, page, or time budget was exhausted."""

    retryable = True


class UnsafeUrl(ConnectorError):  # noqa: N818 -- name is part of the kit contract
    """A URL would send credentials to an unapproved origin or scheme."""


class ConfigError(ConnectorError):
    """Connector configuration is invalid."""


class WebhookRejected(ConnectorError):  # noqa: N818 -- name is part of the kit contract
    """Webhook authentication or replay-window validation failed."""

    def __init__(self, reason: str = "webhook rejected") -> None:
        self.reason = reason
        super().__init__(reason)
