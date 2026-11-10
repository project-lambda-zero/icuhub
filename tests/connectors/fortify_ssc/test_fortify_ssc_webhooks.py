"""Webhook verification and payload parsing tests for the Fortify SSC connector.

Deliveries are signed in-test with ``X-SSC-Signature: sha256=<hex>`` over the raw
body bytes plus the ``Date`` header, matching ``SscHmacVerifier``. The body is the
synthetic ``webhook_issue_changed.json`` fixture.
"""

from __future__ import annotations

import email.utils
import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from icuhub.connectors.fortify_ssc.connector import FortifySsc
from icuhub.connectors.fortify_ssc.webhooks import SscHmacVerifier, parse_delivery_payload
from icuhub.kit.errors import ConfigError, VendorContractError, WebhookRejected
from icuhub.kit.types import WebhookDelivery

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "fortify_ssc"
BODY = (FIXTURES / "webhook_issue_changed.json").read_bytes()
SECRET = b"synthetic-webhook-secret"
NOW = datetime(2026, 11, 9, 12, 0, 0, tzinfo=UTC)
DATE = "Mon, 09 Nov 2026 12:00:00 +0000"


def _sign(body: bytes, date: str, secret: bytes = SECRET) -> str:
    digest = hmac.new(secret, body + date.encode("ascii"), hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def _signed_headers(
    body: bytes = BODY,
    date: str = DATE,
    secret: bytes = SECRET,
) -> dict[str, str]:
    return {"date": date, "x-ssc-signature": _sign(body, date, secret)}


def _delivery(headers: dict[str, str], body: bytes = BODY) -> WebhookDelivery:
    return WebhookDelivery(headers=headers, body=body, received_at=NOW)


def _verify(headers: dict[str, str], body: bytes = BODY) -> Any:
    return SscHmacVerifier(SECRET).verify(_delivery(headers, body), now=NOW)


# --- verification: success and identity ------------------------------------


def test_valid_signed_delivery_is_verified() -> None:
    result = _verify(_signed_headers())

    assert result.occurred_at == NOW
    assert result.event_type == "ANALYSIS_RESULT_UPLOAD_COMPLETE_SUCCESS"
    delivery_id = result.delivery_id
    assert isinstance(delivery_id, str)
    assert len(delivery_id) == 64
    int(delivery_id, 16)


def test_identity_is_stable_across_key_order_and_whitespace() -> None:
    body_a = (
        b'{"event":"ANALYSIS_RESULT_UPLOAD_COMPLETE_SUCCESS","webhookId":77,'
        b'"triggeredAt":"2026-03-01T10:06:00.000+0000","issueId":1001}'
    )
    body_b = (
        b'{ "issueId": 1001, "triggeredAt": "2026-03-01T10:06:00.000+0000", '
        b'"webhookId": 77, "event": "ANALYSIS_RESULT_UPLOAD_COMPLETE_SUCCESS" }'
    )

    id_a = _verify(_signed_headers(body=body_a), body=body_a).delivery_id
    id_b = _verify(_signed_headers(body=body_b), body=body_b).delivery_id

    assert id_a == id_b


def test_identity_differs_for_different_bodies() -> None:
    other = (
        b'{"event":"ANALYSIS_RESULT_UPLOAD_COMPLETE_SUCCESS","webhookId":77,'
        b'"triggeredAt":"2026-03-01T10:06:00.000+0000","issueId":1002}'
    )

    id_fixture = _verify(_signed_headers()).delivery_id
    id_other = _verify(_signed_headers(body=other), body=other).delivery_id

    assert id_fixture != id_other


def test_identity_differs_when_triggered_at_differs() -> None:
    later = (
        b'{"event":"ANALYSIS_RESULT_UPLOAD_COMPLETE_SUCCESS","webhookId":77,'
        b'"triggeredAt":"2026-03-01T10:07:00.000+0000","projectVersionId":42,"issueId":1001}'
    )

    id_fixture = _verify(_signed_headers()).delivery_id
    id_later = _verify(_signed_headers(body=later), body=later).delivery_id

    assert id_fixture != id_later


def test_delivery_event_dispatches_to_parse_delivery() -> None:
    # Core dispatches when the verified event_type is listed on the webhook spec.
    spec = FortifySsc.webhooks()["parse_delivery"]

    result = _verify(_signed_headers())

    assert result.event_type in spec.event_types


@pytest.mark.parametrize(
    ("body", "match"),
    [
        (
            b'{"webhookId":77,"triggeredAt":"2026-03-01T10:06:00.000+0000"}',
            "non-empty 'event'",
        ),
        (
            b'{"event":7,"webhookId":77,"triggeredAt":"2026-03-01T10:06:00.000+0000"}',
            "non-empty 'event'",
        ),
        (
            b'{"event":"ANALYSIS_RESULT_UPLOAD_COMPLETE_SUCCESS","triggeredAt":"2026-03-01T10:06:00.000+0000"}',
            "must carry a webhookId",
        ),
        (
            b'{"event":"ANALYSIS_RESULT_UPLOAD_COMPLETE_SUCCESS","webhookId":true,"triggeredAt":"2026-03-01T10:06:00.000+0000"}',
            "must carry a webhookId",
        ),
        (
            b'{"event":"ANALYSIS_RESULT_UPLOAD_COMPLETE_SUCCESS","webhookId":77}',
            "must carry a triggeredAt",
        ),
        (b"[]", "must be a JSON object"),
    ],
)
def test_signed_body_missing_dedupe_or_dispatch_fields_is_rejected(body: bytes, match: str) -> None:
    with pytest.raises(WebhookRejected, match=match):
        _verify(_signed_headers(body=body), body=body)


# --- verification: header and date rejections ------------------------------


def test_missing_signature_header_is_rejected() -> None:
    with pytest.raises(WebhookRejected, match="missing webhook header: x-ssc-signature"):
        _verify({"date": DATE})


def test_signature_without_sha256_prefix_is_rejected() -> None:
    with pytest.raises(WebhookRejected, match="invalid webhook signature"):
        _verify({"date": DATE, "x-ssc-signature": "md5=abc"})


def test_missing_date_header_is_rejected() -> None:
    with pytest.raises(WebhookRejected, match="missing webhook header: date"):
        _verify({"x-ssc-signature": "sha256=" + "0" * 64})


def test_non_rfc2822_date_is_rejected() -> None:
    headers = _signed_headers(date="not a date")
    with pytest.raises(WebhookRejected, match="webhook Date header is not RFC 2822"):
        _verify(headers)


def test_naive_date_without_timezone_is_rejected() -> None:
    date = "Mon, 09 Nov 2026 12:00:00 -0000"
    with pytest.raises(WebhookRejected, match="webhook Date header must carry a timezone"):
        _verify(_signed_headers(date=date))


def test_date_outside_freshness_window_is_rejected() -> None:
    stale = email.utils.format_datetime(NOW - timedelta(minutes=10))
    with pytest.raises(WebhookRejected, match="webhook Date outside the freshness window"):
        _verify(_signed_headers(date=stale))


def test_date_inside_freshness_window_is_accepted() -> None:
    recent = email.utils.format_datetime(NOW - timedelta(minutes=4))
    result = _verify(_signed_headers(date=recent))

    assert result.occurred_at == NOW - timedelta(minutes=4)


# --- verification: signature rejections -------------------------------------


def test_tampered_body_is_rejected() -> None:
    headers = _signed_headers(body=BODY)
    tampered = BODY.replace(b"1001", b"9999")

    with pytest.raises(WebhookRejected, match="invalid webhook signature"):
        _verify(headers, body=tampered)


def test_wrong_secret_is_rejected() -> None:
    headers = _signed_headers(secret=b"some-other-secret")

    with pytest.raises(WebhookRejected, match="invalid webhook signature"):
        _verify(headers)


def test_signed_non_json_body_is_rejected_after_signature_passes() -> None:
    body = b"not json"
    headers = _signed_headers(body=body)

    with pytest.raises(WebhookRejected, match="not valid JSON"):
        _verify(headers, body=body)


def test_empty_secret_is_a_config_error() -> None:
    with pytest.raises(ConfigError, match="must not be empty"):
        SscHmacVerifier(b"")


# --- payload parsing -------------------------------------------------------


def test_parse_delivery_payload_emits_issues_upsert_hint() -> None:
    records = parse_delivery_payload(_delivery(_signed_headers()))

    assert len(records) == 1
    record = records[0]
    assert record.stream == "issues"
    assert record.event == "upsert"
    assert record.target_uid is None
    assert record.raw == json.loads(BODY)


def test_parse_delivery_payload_rejects_non_object_body() -> None:
    with pytest.raises(VendorContractError, match="must be a JSON object"):
        parse_delivery_payload(_delivery({}, body=b"[]"))


def test_parse_delivery_payload_requires_event() -> None:
    with pytest.raises(VendorContractError, match="non-empty 'event'"):
        parse_delivery_payload(_delivery({}, body=b"{}"))


def test_parse_delivery_payload_rejects_invalid_json() -> None:
    with pytest.raises(VendorContractError, match="not valid JSON"):
        parse_delivery_payload(_delivery({}, body=b"not json"))
