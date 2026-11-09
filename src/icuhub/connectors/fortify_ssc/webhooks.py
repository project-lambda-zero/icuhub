"""SSC webhook verification and delivery parsing.

[UNVERIFIED] The signature header, the HMAC input (raw body plus HTTP ``Date``), and the
delivery schema come from the SSC specification notes in ``docs/VENDOR_CONNECTORS.md``.
They have not been confirmed against a live SSC server. Automatic retry and a unique
delivery header are also unverified, so dedupe uses a derived identity.
"""

from __future__ import annotations

import binascii
import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from typing import Any

from icuhub.kit.errors import ConfigError, VendorContractError, WebhookRejected
from icuhub.kit.types import StreamRecord, WebhookDelivery
from icuhub.kit.webhook import VerifiedDelivery

__all__ = ["FRESHNESS_WINDOW", "SIGNATURE_HEADER", "SscHmacVerifier", "parse_delivery_payload"]

SIGNATURE_HEADER = "x-ssc-signature"
SIGNATURE_PREFIX = "sha256="
FRESHNESS_WINDOW = timedelta(seconds=300)
_CLOCK_SKEW = timedelta(seconds=30)


class SscHmacVerifier:
    """Verifies ``X-SSC-Signature: sha256=<hex>`` over raw body bytes plus the ``Date`` header.

    [UNVERIFIED] Signature scheme and freshness window are unconfirmed against a live server.
    """

    __slots__ = ("_secret",)

    def __init__(self, secret: bytes) -> None:
        if not secret:
            raise ConfigError("webhook secret must not be empty")
        self._secret = bytes(secret)

    def verify(self, delivery: WebhookDelivery, *, now: datetime) -> VerifiedDelivery:
        supplied = delivery.headers.get(SIGNATURE_HEADER)
        if supplied is None:
            raise WebhookRejected("missing webhook header: x-ssc-signature")
        supplied = supplied.strip()
        if not supplied.startswith(SIGNATURE_PREFIX):
            raise WebhookRejected("invalid webhook signature")
        supplied_hex = supplied[len(SIGNATURE_PREFIX) :]

        date_text = delivery.headers.get("date")
        if date_text is None:
            raise WebhookRejected("missing webhook header: date")
        try:
            sent_at = parsedate_to_datetime(date_text)
        except (TypeError, ValueError) as exc:
            raise WebhookRejected("webhook Date header is not RFC 2822") from exc
        if sent_at.tzinfo is None:
            raise WebhookRejected("webhook Date header must carry a timezone")
        sent_at = sent_at.astimezone(UTC)
        if abs(now.astimezone(UTC) - sent_at) > FRESHNESS_WINDOW + _CLOCK_SKEW:
            raise WebhookRejected("webhook Date outside the freshness window")

        signed = delivery.body + date_text.encode("ascii", errors="strict")
        digest = hmac.new(self._secret, signed, hashlib.sha256).digest()
        expected = binascii.hexlify(digest).decode("ascii")
        if not hmac.compare_digest(supplied_hex.encode("ascii", errors="replace"), expected.encode("ascii")):
            raise WebhookRejected("invalid webhook signature")
        identity = _dedupe_identity(delivery.body)
        return VerifiedDelivery(delivery_id=identity, event_type=None, occurred_at=sent_at)


def _dedupe_identity(body: bytes) -> str:
    """Derive a dedupe key from the canonical body digest. The unique delivery header is unverified."""
    try:
        parsed = json.loads(body)
    except ValueError as exc:
        raise WebhookRejected("webhook body is not valid JSON") from exc
    canonical = json.dumps(parsed, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def parse_delivery_payload(delivery: WebhookDelivery) -> list[StreamRecord]:
    """Turn a verified SSC delivery into a stream hint.

    Deliveries are hints only. The record carries the webhook identity fields, and the
    issues stream reconciles the real state through REST.
    """
    try:
        payload: Any = json.loads(delivery.body)
    except ValueError as exc:
        raise VendorContractError("webhook body is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise VendorContractError("webhook body must be a JSON object")
    event = payload.get("event")
    if not isinstance(event, str) or not event:
        raise VendorContractError("webhook body must carry a non-empty 'event'")
    return [StreamRecord(stream="issues", raw=payload, target_uid=None, event="upsert")]

