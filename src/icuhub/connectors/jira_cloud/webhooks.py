"""Authentication for Jira Cloud OAuth 2.0 app webhook deliveries.

Atlassian signs these deliveries with a bearer JWT in the ``Authorization`` header, signed with
the app's client secret. The legacy ``X-Hub-Signature`` scheme belongs to the admin webhook
endpoint and never appears on deliveries registered through ``/rest/api/3/webhook``.

Only the signature and the ``alg`` header are enforced here. The JWT claim set (for example
``exp``, ``iss``, ``qsh``) is not documented on the primary source consulted, so no claim checks
are invented.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
from datetime import datetime

from icuhub.kit.errors import ConfigError, WebhookRejected
from icuhub.kit.types import WebhookDelivery
from icuhub.kit.webhook import VerifiedDelivery

__all__ = ["OAuthBearerJwt"]


def _b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


class OAuthBearerJwt:
    """Verifies the HS256 bearer JWT that Jira attaches to OAuth 2.0 app webhook deliveries."""

    __slots__ = ("_secret",)

    def __init__(self, secret: bytes) -> None:
        if not secret:
            raise ConfigError("Jira Cloud webhook secret must not be empty")
        self._secret = bytes(secret)

    def verify(self, delivery: WebhookDelivery, *, now: datetime) -> VerifiedDelivery:
        authorization = delivery.headers.get("authorization")
        if authorization is None:
            raise WebhookRejected("missing webhook header: authorization")
        scheme, separator, token = authorization.strip().partition(" ")
        if not separator or scheme.lower() != "bearer":
            raise WebhookRejected("invalid bearer authorization")
        token = token.strip()
        if not token.isascii():
            raise WebhookRejected("invalid bearer token")
        segments = token.split(".")
        if len(segments) != 3 or not all(segments):
            raise WebhookRejected("invalid bearer token")
        header_segment, payload_segment, signature_segment = segments
        try:
            header = json.loads(_b64url_decode(header_segment))
        except (binascii.Error, ValueError) as exc:
            raise WebhookRejected("invalid bearer token") from exc
        if not isinstance(header, dict) or header.get("alg") != "HS256":
            raise WebhookRejected("unsupported bearer token algorithm")
        signing_input = f"{header_segment}.{payload_segment}".encode("ascii")
        digest = hmac.new(self._secret, signing_input, hashlib.sha256).digest()
        expected = base64.urlsafe_b64encode(digest).rstrip(b"=")
        if not hmac.compare_digest(signature_segment.encode("ascii"), expected):
            raise WebhookRejected("invalid bearer token signature")
        return VerifiedDelivery(delivery_id=None, event_type=None, occurred_at=delivery.received_at)
