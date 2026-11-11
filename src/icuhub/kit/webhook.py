"""Webhook authentication and replay-window verification."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, Protocol, runtime_checkable

from icuhub.kit.errors import ConfigError, WebhookRejected
from icuhub.kit.types import WebhookDelivery

__all__ = [
    "BasicAuthVerifier",
    "HmacSignature",
    "SharedToken",
    "StandardWebhooks",
    "VerifiedDelivery",
    "WebhookVerifier",
]


@dataclass(frozen=True)
class VerifiedDelivery:
    """Authenticated delivery metadata supplied by webhook headers."""

    delivery_id: str | None
    event_type: str | None
    occurred_at: datetime | None


@runtime_checkable
class WebhookVerifier(Protocol):
    """Authenticates an unmodified webhook delivery."""

    def verify(self, delivery: WebhookDelivery, *, now: datetime) -> VerifiedDelivery:
        """Return verified metadata or raise ``WebhookRejected``."""
        ...


def _required_header(delivery: WebhookDelivery, name: str) -> str:
    value = delivery.headers.get(name)
    if value is None:
        raise WebhookRejected(f"missing webhook header: {name}")
    return value


def _metadata(
    delivery: WebhookDelivery,
    id_header: str | None,
    event_header: str | None,
    *,
    occurred_at: datetime | None = None,
) -> VerifiedDelivery:
    delivery_id = _required_header(delivery, id_header) if id_header is not None else None
    event_type = _required_header(delivery, event_header) if event_header is not None else None
    return VerifiedDelivery(
        delivery_id=delivery_id,
        event_type=event_type,
        occurred_at=delivery.received_at if occurred_at is None else occurred_at,
    )


class HmacSignature:
    """Verifies a body HMAC carried in a vendor signature header."""

    __slots__ = ("_algo", "_encoding", "_event_header", "_header", "_id_header", "_prefix", "_secret")

    def __init__(
        self,
        header: str,
        secret: bytes,
        *,
        algo: str = "sha256",
        encoding: Literal["hex", "base64"] = "hex",
        prefix: str = "sha256=",
        id_header: str | None = None,
        event_header: str | None = None,
    ) -> None:
        if encoding not in {"hex", "base64"}:
            raise ConfigError("encoding must be 'hex' or 'base64'")
        try:
            hashlib.new(algo)
        except ValueError as exc:
            raise ConfigError(f"unsupported HMAC algorithm: {algo!r}") from exc
        self._header = header.lower()
        self._secret = bytes(secret)
        self._algo = algo
        self._encoding = encoding
        self._prefix = prefix
        self._id_header = id_header.lower() if id_header is not None else None
        self._event_header = event_header.lower() if event_header is not None else None

    def verify(self, delivery: WebhookDelivery, *, now: datetime) -> VerifiedDelivery:
        supplied = _required_header(delivery, self._header).strip()
        if not supplied.startswith(self._prefix):
            raise WebhookRejected("invalid webhook signature")
        supplied = supplied[len(self._prefix) :]
        digest = hmac.new(self._secret, delivery.body, self._algo).digest()
        expected = binascii.hexlify(digest) if self._encoding == "hex" else base64.b64encode(digest)
        if not hmac.compare_digest(supplied.encode("utf-8"), expected):
            raise WebhookRejected("invalid webhook signature")
        return _metadata(delivery, self._id_header, self._event_header)


class StandardWebhooks:
    """Verifies Standard Webhooks signatures and their replay window."""

    __slots__ = ("_secret", "_tolerance_s")

    def __init__(self, secret_b64: str, tolerance_s: float = 300) -> None:
        if tolerance_s < 0:
            raise ConfigError("tolerance_s must be non-negative")
        encoded = secret_b64.removeprefix("whsec_")
        try:
            self._secret = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ConfigError("secret_b64 must be valid base64") from exc
        self._tolerance_s = tolerance_s

    def verify(self, delivery: WebhookDelivery, *, now: datetime) -> VerifiedDelivery:
        delivery_id = _required_header(delivery, "webhook-id")
        timestamp_text = _required_header(delivery, "webhook-timestamp")
        signatures = _required_header(delivery, "webhook-signature")
        if not (timestamp_text.isascii() and timestamp_text.isdigit()):
            raise WebhookRejected("invalid webhook timestamp")
        try:
            occurred_at = datetime.fromtimestamp(int(timestamp_text), tz=UTC)
        except (ValueError, OverflowError, OSError) as exc:
            raise WebhookRejected("invalid webhook timestamp") from exc
        if now.tzinfo is None or now.utcoffset() is None:
            raise WebhookRejected("verification time must be timezone-aware")
        if abs((now - occurred_at).total_seconds()) > self._tolerance_s:
            raise WebhookRejected("webhook timestamp outside tolerance")

        signed = delivery_id.encode("utf-8") + b"." + timestamp_text.encode("ascii") + b"." + delivery.body
        expected = base64.b64encode(hmac.new(self._secret, signed, hashlib.sha256).digest())
        matched = False
        for entry in signatures.split():
            version, separator, signature = entry.partition(",")
            if separator and version == "v1" and hmac.compare_digest(signature.encode("utf-8"), expected):
                matched = True
        if not matched:
            raise WebhookRejected("invalid webhook signature")
        return VerifiedDelivery(delivery_id=delivery_id, event_type=None, occurred_at=occurred_at)


class SharedToken:
    """Verifies a shared callback token using a constant-time comparison."""

    __slots__ = ("_event_header", "_header", "_id_header", "_token")

    def __init__(
        self,
        header: str,
        token: str,
        id_header: str | None = None,
        event_header: str | None = None,
    ) -> None:
        self._header = header.lower()
        self._token = token.encode("utf-8")
        self._id_header = id_header.lower() if id_header is not None else None
        self._event_header = event_header.lower() if event_header is not None else None

    def verify(self, delivery: WebhookDelivery, *, now: datetime) -> VerifiedDelivery:
        supplied = _required_header(delivery, self._header).encode("utf-8")
        if not hmac.compare_digest(supplied, self._token):
            raise WebhookRejected("invalid webhook token")
        return _metadata(delivery, self._id_header, self._event_header)


class BasicAuthVerifier:
    """Verifies the Basic authorization scheme on a callback request."""

    __slots__ = ("_password", "_user")

    def __init__(self, user: str, password: str) -> None:
        self._user = user.encode("utf-8")
        self._password = password.encode("utf-8")

    def verify(self, delivery: WebhookDelivery, *, now: datetime) -> VerifiedDelivery:
        authorization = _required_header(delivery, "authorization").strip()
        scheme, separator, credentials = authorization.partition(" ")
        if not separator or scheme.lower() != "basic":
            raise WebhookRejected("invalid basic authorization")
        try:
            decoded = base64.b64decode(credentials, validate=True)
            supplied_user, colon, supplied_password = decoded.partition(b":")
        except (binascii.Error, ValueError) as exc:
            raise WebhookRejected("invalid basic authorization") from exc
        if not colon:
            raise WebhookRejected("invalid basic authorization")
        user_matches = hmac.compare_digest(supplied_user, self._user)
        password_matches = hmac.compare_digest(supplied_password, self._password)
        if not (user_matches and password_matches):
            raise WebhookRejected("invalid basic authorization")
        return VerifiedDelivery(delivery_id=None, event_type=None, occurred_at=delivery.received_at)
