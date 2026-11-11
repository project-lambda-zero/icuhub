"""Webhook verifiers: tampering, replay window, and header handling."""

import base64
import hashlib
import hmac
from datetime import UTC, datetime, timedelta

import pytest

from icuhub.kit.errors import ConfigError, WebhookRejected
from icuhub.kit.types import WebhookDelivery
from icuhub.kit.webhook import BasicAuthVerifier, HmacSignature, SharedToken, StandardWebhooks

NOW = datetime(2026, 11, 9, 12, 0, 0, tzinfo=UTC)
SECRET = b"s3cret-value"
BODY = b'{"action":"opened"}'


def _delivery(headers: dict[str, str], body: bytes = BODY) -> WebhookDelivery:
    return WebhookDelivery(headers=headers, body=body, received_at=NOW)


def _hex_sig(secret: bytes, body: bytes) -> str:
    return "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()


def test_hmac_hex_signature_verifies_and_returns_id_and_event_headers() -> None:
    verifier = HmacSignature(
        "X-Hub-Signature-256",
        SECRET,
        id_header="X-GitHub-Delivery",
        event_header="X-GitHub-Event",
    )
    delivery = _delivery(
        {
            "X-Hub-Signature-256": _hex_sig(SECRET, BODY),
            "X-GitHub-Delivery": "delivery-1",
            "X-GitHub-Event": "issues",
        }
    )

    verified = verifier.verify(delivery, now=NOW)

    assert verified.delivery_id == "delivery-1"
    assert verified.event_type == "issues"


def test_hmac_rejects_a_tampered_body() -> None:
    verifier = HmacSignature("X-Hub-Signature-256", SECRET)
    delivery = _delivery(
        {"X-Hub-Signature-256": _hex_sig(SECRET, BODY)},
        body=b'{"action":"closed"}',
    )

    with pytest.raises(WebhookRejected, match="invalid webhook signature"):
        verifier.verify(delivery, now=NOW)


def test_hmac_rejects_a_signature_made_with_the_wrong_secret() -> None:
    verifier = HmacSignature("X-Hub-Signature-256", SECRET)
    delivery = _delivery({"X-Hub-Signature-256": _hex_sig(b"other", BODY)})

    with pytest.raises(WebhookRejected):
        verifier.verify(delivery, now=NOW)


def test_hmac_rejects_a_missing_prefix() -> None:
    verifier = HmacSignature("X-Hub-Signature-256", SECRET)
    bare_hex = hmac.new(SECRET, BODY, hashlib.sha256).hexdigest()
    delivery = _delivery({"X-Hub-Signature-256": bare_hex})

    with pytest.raises(WebhookRejected):
        verifier.verify(delivery, now=NOW)


def test_hmac_rejects_a_missing_header() -> None:
    verifier = HmacSignature("X-Hub-Signature-256", SECRET)

    with pytest.raises(WebhookRejected):
        verifier.verify(_delivery({}), now=NOW)


def test_hmac_base64_encoding_verifies() -> None:
    verifier = HmacSignature("X-Signature", SECRET, encoding="base64", prefix="")
    digest = base64.b64encode(hmac.new(SECRET, BODY, hashlib.sha256).digest()).decode("ascii")

    verified = verifier.verify(_delivery({"X-Signature": digest}), now=NOW)

    assert verified.delivery_id is None


def test_hmac_rejects_an_unknown_encoding_and_algorithm_at_construction() -> None:
    with pytest.raises(ConfigError, match="encoding must be"):
        HmacSignature("X-Signature", SECRET, encoding="base32")  # type: ignore[arg-type]
    with pytest.raises(ConfigError, match="unsupported HMAC algorithm"):
        HmacSignature("X-Signature", SECRET, algo="not-a-hash")


def _standard_headers(
    secret: bytes, msg_id: str, timestamp: int, body: bytes, *, version: str = "v1"
) -> dict[str, str]:
    signed = msg_id.encode() + b"." + str(timestamp).encode() + b"." + body
    sig = base64.b64encode(hmac.new(secret, signed, hashlib.sha256).digest()).decode("ascii")
    return {
        "webhook-id": msg_id,
        "webhook-timestamp": str(timestamp),
        "webhook-signature": f"{version},{sig}",
    }


def _whsec(secret: bytes) -> str:
    return "whsec_" + base64.b64encode(secret).decode("ascii")


def test_standard_webhooks_verifies_a_fresh_signed_delivery() -> None:
    verifier = StandardWebhooks(_whsec(SECRET))
    timestamp = int(NOW.timestamp())
    headers = _standard_headers(SECRET, "msg_1", timestamp, BODY)

    verified = verifier.verify(_delivery(headers), now=NOW)

    assert verified.delivery_id == "msg_1"
    assert verified.occurred_at == datetime.fromtimestamp(timestamp, tz=UTC)


def test_standard_webhooks_accepts_a_signature_among_several_entries() -> None:
    verifier = StandardWebhooks(_whsec(SECRET))
    timestamp = int(NOW.timestamp())
    headers = _standard_headers(SECRET, "msg_2", timestamp, BODY)
    stale_entry = "v1,AAAA " + headers["webhook-signature"]
    headers["webhook-signature"] = stale_entry

    verified = verifier.verify(_delivery(headers), now=NOW)

    assert verified.delivery_id == "msg_2"


def test_standard_webhooks_rejects_a_tampered_body() -> None:
    verifier = StandardWebhooks(_whsec(SECRET))
    timestamp = int(NOW.timestamp())
    headers = _standard_headers(SECRET, "msg_3", timestamp, BODY)

    with pytest.raises(WebhookRejected, match="invalid webhook signature"):
        verifier.verify(_delivery(headers, body=b'{"action":"closed"}'), now=NOW)


def test_standard_webhooks_rejects_a_timestamp_outside_tolerance() -> None:
    verifier = StandardWebhooks(_whsec(SECRET), tolerance_s=300)
    old = int((NOW - timedelta(seconds=1000)).timestamp())
    headers = _standard_headers(SECRET, "msg_4", old, BODY)

    with pytest.raises(WebhookRejected, match="outside tolerance"):
        verifier.verify(_delivery(headers), now=NOW)


def test_standard_webhooks_rejects_a_non_v1_signature_only() -> None:
    verifier = StandardWebhooks(_whsec(SECRET))
    timestamp = int(NOW.timestamp())
    headers = _standard_headers(SECRET, "msg_5", timestamp, BODY, version="v2")

    with pytest.raises(WebhookRejected, match="invalid webhook signature"):
        verifier.verify(_delivery(headers), now=NOW)


def test_standard_webhooks_rejects_a_non_numeric_timestamp() -> None:
    verifier = StandardWebhooks(_whsec(SECRET))
    headers = _standard_headers(SECRET, "msg_6", int(NOW.timestamp()), BODY)
    headers["webhook-timestamp"] = "12e3"

    with pytest.raises(WebhookRejected, match="invalid webhook timestamp"):
        verifier.verify(_delivery(headers), now=NOW)


def test_standard_webhooks_rejects_an_invalid_secret_at_construction() -> None:
    with pytest.raises(ConfigError, match="secret_b64 must be valid base64"):
        StandardWebhooks("whsec_!!!not-base64!!!")


def test_shared_token_accepts_the_exact_token_and_rejects_others() -> None:
    verifier = SharedToken("X-Gitlab-Token", "tok-123", id_header="X-Gitlab-Event-UUID")

    ok = verifier.verify(
        _delivery({"X-Gitlab-Token": "tok-123", "X-Gitlab-Event-UUID": "evt-1"}),
        now=NOW,
    )
    assert ok.delivery_id == "evt-1"

    with pytest.raises(WebhookRejected, match="invalid webhook token"):
        verifier.verify(_delivery({"X-Gitlab-Token": "tok-124"}), now=NOW)


def test_basic_auth_accepts_matching_credentials_only() -> None:
    verifier = BasicAuthVerifier("hook", "pw")
    good = "Basic " + base64.b64encode(b"hook:pw").decode("ascii")
    bad = "Basic " + base64.b64encode(b"hook:nope").decode("ascii")

    verified = verifier.verify(_delivery({"Authorization": good}), now=NOW)
    assert verified.occurred_at == NOW

    with pytest.raises(WebhookRejected, match="invalid basic authorization"):
        verifier.verify(_delivery({"Authorization": bad}), now=NOW)


def test_basic_auth_rejects_a_non_basic_scheme_and_missing_colon() -> None:
    verifier = BasicAuthVerifier("hook", "pw")
    bearer = _delivery({"Authorization": "Bearer abc"})
    no_colon = _delivery({"Authorization": "Basic " + base64.b64encode(b"hookpw").decode("ascii")})

    with pytest.raises(WebhookRejected):
        verifier.verify(bearer, now=NOW)
    with pytest.raises(WebhookRejected):
        verifier.verify(no_colon, now=NOW)


def test_webhook_delivery_requires_a_timezone_aware_receive_time() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        WebhookDelivery(headers={}, body=b"", received_at=datetime(2026, 11, 9, 12, 0, 0))


def test_webhook_delivery_lowercases_header_names() -> None:
    delivery = _delivery({"X-Hub-Signature-256": "sha256=abc"})

    assert set(delivery.headers) == {"x-hub-signature-256"}
