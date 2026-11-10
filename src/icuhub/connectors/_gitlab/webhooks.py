"""Standard Webhooks verification and reconciliation hints for GitLab."""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal, Protocol, runtime_checkable

from icuhub.kit.errors import ConfigError, VendorContractError, WebhookRejected
from icuhub.kit.types import StreamRecord, WebhookDelivery
from icuhub.kit.webhook import StandardWebhooks, VerifiedDelivery, WebhookVerifier

__all__ = [
    "GitLabWebhookParser",
    "GitLabWebhookProcessor",
    "ProcessedWebhook",
    "RotatingStandardWebhooks",
    "WebhookDeliveryStore",
]

_REDACTED = "[REDACTED]"
_HINTS: dict[str, tuple[str, Literal["incremental", "full"]]] = {
    "merge_request": ("merge_requests", "incremental"),
    "note": ("merge_requests", "incremental"),
    "vulnerability": ("vulnerabilities", "full"),
    "vulnerability_create": ("vulnerabilities", "full"),
    "vulnerability_update": ("vulnerabilities", "full"),
    "vulnerability_delete": ("vulnerabilities", "full"),
    "pipeline": ("pipelines", "incremental"),
    "build": ("jobs", "incremental"),
    "job": ("jobs", "incremental"),
    "audit": ("audit_events", "incremental"),
    "audit_event": ("audit_events", "incremental"),
}


class RotatingStandardWebhooks:
    """Verify Standard Webhooks deliveries against current and previous secrets."""

    __slots__ = ("_verifiers",)

    def __init__(self, secrets: Sequence[str], tolerance_s: float = 300) -> None:
        if isinstance(secrets, (str, bytes)) or not isinstance(secrets, Sequence) or not secrets:
            raise ConfigError("secrets must be a nonempty sequence of whsec_ keys")
        verifiers: list[StandardWebhooks] = []
        for secret in secrets:
            if not isinstance(secret, str) or not secret:
                raise ConfigError("webhook secrets must be nonempty UTF-8 strings")
            try:
                secret.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise ConfigError("webhook secrets must be valid UTF-8") from exc
            if not secret.startswith("whsec_"):
                raise ConfigError("webhook secrets must use the whsec_ prefix")
            if not secret.removeprefix("whsec_"):
                raise ConfigError("webhook secret key material must not be empty")
            verifiers.append(StandardWebhooks(secret, tolerance_s=tolerance_s))
        self._verifiers = tuple(verifiers)

    def verify(self, delivery: WebhookDelivery, *, now: datetime) -> VerifiedDelivery:
        last_rejection: WebhookRejected | None = None
        for verifier in self._verifiers:
            try:
                return verifier.verify(delivery, now=now)
            except WebhookRejected as exc:
                last_rejection = exc
        if last_rejection is not None:
            raise last_rejection
        raise WebhookRejected("invalid webhook signature")


@runtime_checkable
class WebhookDeliveryStore(Protocol):
    """Persistent, host-scoped delivery identity storage."""

    async def contains(self, delivery_id: str) -> bool:
        """Return whether this delivery was completely processed."""
        ...

    async def add(self, delivery_id: str) -> None:
        """Record a completely processed delivery."""
        ...


@dataclass(frozen=True)
class ProcessedWebhook:
    """Result of reconciling one authenticated delivery."""

    status: Literal["processed", "duplicate"]
    delivery_id: str
    records: tuple[StreamRecord, ...]


def _payload(delivery: WebhookDelivery) -> dict[str, Any]:
    try:
        value = json.loads(delivery.body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VendorContractError("GitLab webhook body is not valid JSON") from exc
    if not isinstance(value, dict):
        raise VendorContractError("GitLab webhook body must be an object")
    return value


def _sensitive_key(key: str) -> bool:
    normalized = key.casefold()
    return "secret" in normalized or "token" in normalized


def _without_secrets(value: Any, *, key: str | None = None) -> Any:
    if key is not None and _sensitive_key(key):
        return _REDACTED
    if isinstance(value, dict):
        return {str(item_key): _without_secrets(item, key=str(item_key)) for item_key, item in value.items()}
    if isinstance(value, list):
        return [_without_secrets(item) for item in value]
    return value


def _numeric_id(value: Any) -> str | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str) and value.isascii() and value.isdigit():
        return value
    return None


def _target_uid(payload: dict[str, Any]) -> str | None:
    project_id = _numeric_id(payload.get("project_id"))
    project = payload.get("project")
    if project_id is None and isinstance(project, dict):
        project_id = _numeric_id(project.get("id"))
    return f"project:{project_id}" if project_id is not None else None


def _hint(payload: dict[str, Any]) -> tuple[str, Literal["incremental", "full"]]:
    matches: set[tuple[str, Literal["incremental", "full"]]] = set()
    for field in ("object_kind", "event_name"):
        value = payload.get(field)
        if value is None:
            continue
        if not isinstance(value, str):
            raise VendorContractError(f"GitLab webhook {field} must be a string")
        match = _HINTS.get(value)
        if match is not None:
            matches.add(match)
    if not matches:
        raise VendorContractError("unsupported GitLab webhook event")
    if len(matches) != 1:
        raise VendorContractError("conflicting GitLab webhook event hints")
    return matches.pop()


class GitLabWebhookParser:
    """Parse authenticated bodies into non-authoritative stream reconciliation hints."""

    __slots__ = ("_host",)

    def __init__(self, host: str) -> None:
        self._host = host

    def parse(self, delivery: WebhookDelivery) -> list[StreamRecord]:
        payload = _payload(delivery)
        stream, reconcile = _hint(payload)
        raw = _without_secrets(payload)
        raw["_gitlab_host"] = self._host
        return [
            StreamRecord(
                stream=stream,
                raw=raw,
                target_uid=_target_uid(payload),
                event="upsert",
                reconcile=reconcile,
            )
        ]


class GitLabWebhookProcessor:
    """Authenticate, deduplicate, and reconcile GitLab webhook hints."""

    __slots__ = ("_parser", "_store", "_verifier")

    def __init__(
        self,
        verifier: WebhookVerifier,
        store: WebhookDeliveryStore,
        parser: GitLabWebhookParser,
    ) -> None:
        self._verifier = verifier
        self._store = store
        self._parser = parser

    async def process(
        self,
        delivery: WebhookDelivery,
        reconcile: Callable[[StreamRecord], Awaitable[None]],
        now: datetime,
    ) -> ProcessedWebhook:
        verified = self._verifier.verify(delivery, now=now)
        delivery_id = verified.delivery_id
        if delivery_id is None or not delivery_id.strip():
            raise WebhookRejected("verified webhook delivery has no webhook-id")
        if await self._store.contains(delivery_id):
            return ProcessedWebhook(status="duplicate", delivery_id=delivery_id, records=())
        records = self._parser.parse(delivery)
        for record in records:
            await reconcile(record)
        await self._store.add(delivery_id)
        return ProcessedWebhook(status="processed", delivery_id=delivery_id, records=tuple(records))
