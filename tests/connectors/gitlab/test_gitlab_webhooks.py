"""Tests for GitLab Standard Webhooks verification, reconciliation hints, and processing."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from icuhub.connectors._gitlab.webhooks import (
    GitLabWebhookParser,
    GitLabWebhookProcessor,
    ProcessedWebhook,
    RotatingStandardWebhooks,
)
from icuhub.kit.errors import ConfigError, VendorContractError, WebhookRejected
from icuhub.kit.types import StreamRecord, WebhookDelivery

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"
GITLAB_FIXTURES = FIXTURES / "gitlab"
SELF_MANAGED_FIXTURES = FIXTURES / "gitlab_self_managed"

KEY = b"synthetic-gitlab-webhook-key-material"
PREVIOUS_KEY = b"synthetic-previous-gitlab-webhook-key"
UNKNOWN_KEY = b"synthetic-unknown-gitlab-webhook-key"
SECRET = "whsec_" + base64.b64encode(KEY).decode("ascii")
PREVIOUS_SECRET = "whsec_" + base64.b64encode(PREVIOUS_KEY).decode("ascii")

NOW = datetime(2026, 11, 9, 12, 0, 0, tzinfo=UTC)
NOW_TS = int(NOW.timestamp())
TS_TEXT = str(NOW_TS)
MSG_ID = "msg_synthetic_0001"


def _fixture(directory: Path, name: str) -> bytes:
    return (directory / name).read_bytes()


def _sign(body: bytes, *, msg_id: str = MSG_ID, timestamp: str = TS_TEXT, key: bytes = KEY) -> str:
    signed = msg_id.encode("utf-8") + b"." + timestamp.encode("ascii") + b"." + body
    digest = hmac.new(key, signed, hashlib.sha256).digest()
    return "v1," + base64.b64encode(digest).decode("ascii")


def _signed_headers(body: bytes, *, msg_id: str = MSG_ID, timestamp: str = TS_TEXT, key: bytes = KEY) -> dict[str, str]:
    return {
        "webhook-id": msg_id,
        "webhook-timestamp": timestamp,
        "webhook-signature": _sign(body, msg_id=msg_id, timestamp=timestamp, key=key),
    }


def _delivery(body: bytes, headers: dict[str, str] | None = None) -> WebhookDelivery:
    return WebhookDelivery(
        headers=_signed_headers(body) if headers is None else headers,
        body=body,
        received_at=NOW,
    )


def _inline(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload).encode("utf-8")


def _verify(delivery: WebhookDelivery, secrets: tuple[str, ...] = (SECRET,), now: datetime = NOW):
    return RotatingStandardWebhooks(list(secrets)).verify(delivery, now=now)


def _parse_one(body: bytes, host: str = "gitlab.com") -> StreamRecord:
    (record,) = GitLabWebhookParser(host).parse(_delivery(body, headers={}))
    return record


class _MemoryStore:
    """In-memory delivery store recording every call in order."""

    def __init__(
        self,
        events: list[tuple[str, str]],
        *,
        seen: tuple[str, ...] = (),
        fail_contains: BaseException | None = None,
        fail_add: BaseException | None = None,
    ) -> None:
        self._events = events
        self._seen = set(seen)
        self._fail_contains = fail_contains
        self._fail_add = fail_add

    async def contains(self, delivery_id: str) -> bool:
        self._events.append(("contains", delivery_id))
        if self._fail_contains is not None:
            raise self._fail_contains
        return delivery_id in self._seen

    async def add(self, delivery_id: str) -> None:
        self._events.append(("add", delivery_id))
        if self._fail_add is not None:
            raise self._fail_add
        self._seen.add(delivery_id)


def _recorder(events: list[tuple[str, str]]):
    async def reconcile(record: StreamRecord) -> None:
        events.append(("reconcile", record.stream))

    return reconcile


def _processor(store: _MemoryStore, host: str = "gitlab.com", secrets: tuple[str, ...] = (SECRET,)):
    return GitLabWebhookProcessor(
        RotatingStandardWebhooks(list(secrets)),
        store,
        GitLabWebhookParser(host),
    )


# --- Raw-body signing and cloud/self-managed parity -------------------------------------


def test_signature_covers_raw_body_bytes_not_reserialized_json():
    body = _fixture(GITLAB_FIXTURES, "merge_request_hook.json")
    reserialized = json.dumps(json.loads(body)).encode("utf-8")
    assert reserialized != body

    assert _verify(_delivery(body)).delivery_id == MSG_ID

    with pytest.raises(WebhookRejected, match="invalid webhook signature"):
        _verify(_delivery(body, headers=_signed_headers(reserialized)))


@pytest.mark.parametrize(
    ("directory", "name", "host", "stream"),
    [
        (GITLAB_FIXTURES, "merge_request_hook.json", "gitlab.com", "merge_requests"),
        (GITLAB_FIXTURES, "pipeline_hook.json", "gitlab.com", "pipelines"),
        (GITLAB_FIXTURES, "audit_event_hook.json", "gitlab.com", "audit_events"),
        (SELF_MANAGED_FIXTURES, "merge_request_hook.json", "gitlab.example.com", "merge_requests"),
        (SELF_MANAGED_FIXTURES, "pipeline_hook.json", "gitlab.example.com", "pipelines"),
        (SELF_MANAGED_FIXTURES, "audit_event_hook.json", "gitlab.example.com", "audit_events"),
    ],
)
def test_cloud_and_self_managed_fixtures_share_one_verification_path(
    directory: Path, name: str, host: str, stream: str
):
    body = _fixture(directory, name)
    events: list[tuple[str, str]] = []
    result = asyncio.run(_processor(_MemoryStore(events), host=host).process(_delivery(body), _recorder(events), NOW))

    assert isinstance(result, ProcessedWebhook)
    assert result.status == "processed"
    assert [record.stream for record in result.records] == [stream]
    assert result.records[0].raw["_gitlab_host"] == host


def test_mixed_case_header_names_are_accepted():
    body = _fixture(GITLAB_FIXTURES, "note_hook.json")
    headers = {
        "Webhook-Id": MSG_ID,
        "Webhook-Timestamp": TS_TEXT,
        "Webhook-Signature": _sign(body),
    }
    assert _verify(_delivery(body, headers=headers)).delivery_id == MSG_ID


# --- Constructor validation ------------------------------------------------------------


@pytest.mark.parametrize(
    "secrets",
    [
        [],
        SECRET,
        [""],
        ["not-a-whsec-key"],
        ["whsec_"],
        [123],
        [KEY],
        ["whsec_\ud800"],
        ["whsec_!!!not-base64!!!"],
    ],
    ids=[
        "empty-list",
        "bare-string",
        "empty-string",
        "missing-prefix",
        "prefix-only",
        "non-str-entry",
        "bytes-entry",
        "non-utf8",
        "bad-base64",
    ],
)
def test_constructor_rejects_invalid_secrets(secrets):
    with pytest.raises(ConfigError):
        RotatingStandardWebhooks(secrets)


def test_constructor_rejects_negative_tolerance():
    with pytest.raises(ConfigError, match="non-negative"):
        RotatingStandardWebhooks([SECRET], tolerance_s=-1)


# --- Key rotation ----------------------------------------------------------------------


@pytest.mark.parametrize("secrets", [(SECRET, PREVIOUS_SECRET), (PREVIOUS_SECRET, SECRET)])
def test_either_configured_key_verifies_during_rotation(secrets: tuple[str, ...]):
    body = _fixture(GITLAB_FIXTURES, "job_hook.json")
    assert _verify(_delivery(body), secrets=secrets).delivery_id == MSG_ID
    previous_signed = _delivery(body, headers=_signed_headers(body, key=PREVIOUS_KEY))
    assert _verify(previous_signed, secrets=secrets).delivery_id == MSG_ID


def test_unknown_key_rejected_during_rotation():
    body = _fixture(GITLAB_FIXTURES, "job_hook.json")
    delivery = _delivery(body, headers=_signed_headers(body, key=UNKNOWN_KEY))
    with pytest.raises(WebhookRejected, match="invalid webhook signature"):
        _verify(delivery, secrets=(SECRET, PREVIOUS_SECRET))


def test_retired_key_rejected_once_removed_from_configuration():
    body = _fixture(GITLAB_FIXTURES, "job_hook.json")
    delivery = _delivery(body, headers=_signed_headers(body, key=PREVIOUS_KEY))
    with pytest.raises(WebhookRejected, match="invalid webhook signature"):
        _verify(delivery, secrets=(SECRET,))


# --- Timestamp handling ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("offset", "accepted"),
    [(0, True), (-300, True), (300, True), (-301, False), (301, False)],
    ids=["exact", "past-boundary", "future-boundary", "past-outside", "future-outside"],
)
def test_timestamp_tolerance_boundaries(offset: int, accepted: bool):
    body = _fixture(GITLAB_FIXTURES, "merge_request_hook.json")
    timestamp = str(NOW_TS + offset)
    delivery = _delivery(body, headers=_signed_headers(body, timestamp=timestamp))
    if accepted:
        result = _verify(delivery)
        assert result.occurred_at == datetime.fromtimestamp(NOW_TS + offset, tz=UTC)
    else:
        with pytest.raises(WebhookRejected, match="outside tolerance"):
            _verify(delivery)


@pytest.mark.parametrize("timestamp", ["12a", "", "-1", "1.5", "+1"])
def test_non_digit_timestamp_rejected(timestamp: str):
    body = _fixture(GITLAB_FIXTURES, "merge_request_hook.json")
    delivery = _delivery(body, headers=_signed_headers(body, timestamp=timestamp))
    with pytest.raises(WebhookRejected, match="invalid webhook timestamp"):
        _verify(delivery)


def test_naive_verification_time_rejected():
    body = _fixture(GITLAB_FIXTURES, "merge_request_hook.json")
    with pytest.raises(WebhookRejected, match="timezone-aware"):
        _verify(_delivery(body), now=datetime(2026, 11, 9, 12, 0, 0))


# --- Malformed headers and signatures --------------------------------------------------


@pytest.mark.parametrize("missing", ["webhook-id", "webhook-timestamp", "webhook-signature"])
def test_missing_standard_webhook_header_rejected(missing: str):
    body = _fixture(GITLAB_FIXTURES, "merge_request_hook.json")
    headers = _signed_headers(body)
    del headers[missing]
    with pytest.raises(WebhookRejected, match=f"missing webhook header: {missing}"):
        _verify(_delivery(body, headers=headers))


def test_gitlab_token_header_alone_is_not_authentication():
    body = _fixture(GITLAB_FIXTURES, "merge_request_hook.json")
    delivery = _delivery(body, headers={"x-gitlab-token": "synthetic-shared-token"})
    with pytest.raises(WebhookRejected, match="missing webhook header: webhook-id"):
        _verify(delivery)


@pytest.mark.parametrize(
    "build_signature",
    [
        lambda _correct: "v1,!!!not-base64!!!",
        lambda _correct: "v1",
        lambda _correct: "",
        lambda correct: "v2," + correct.split(",", 1)[1],
        lambda correct: correct[: len(correct) // 2],
    ],
    ids=["bad-base64", "no-comma", "empty", "wrong-version", "truncated"],
)
def test_malformed_signature_rejected(build_signature):
    body = _fixture(GITLAB_FIXTURES, "merge_request_hook.json")
    headers = _signed_headers(body)
    headers["webhook-signature"] = build_signature(headers["webhook-signature"])
    with pytest.raises(WebhookRejected, match="invalid webhook signature"):
        _verify(_delivery(body, headers=headers))


def test_signature_entry_list_accepts_matching_v1_among_others():
    body = _fixture(GITLAB_FIXTURES, "merge_request_hook.json")
    headers = _signed_headers(body)
    headers["webhook-signature"] = "v1,AAAA " + headers["webhook-signature"]
    assert _verify(_delivery(body, headers=headers)).delivery_id == MSG_ID


# --- Hint parsing: fixtures ------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "stream", "mode"),
    [
        ("merge_request_hook.json", "merge_requests", "incremental"),
        ("note_hook.json", "merge_requests", "incremental"),
        ("vulnerability_hook.json", "vulnerabilities", "full"),
        ("pipeline_hook.json", "pipelines", "incremental"),
        ("job_hook.json", "jobs", "incremental"),
        ("audit_event_hook.json", "audit_events", "incremental"),
    ],
)
def test_supported_fixture_hints(name: str, stream: str, mode: str):
    record = _parse_one(_fixture(GITLAB_FIXTURES, name))
    assert record.stream == stream
    assert record.reconcile == mode
    assert record.event == "upsert"


@pytest.mark.parametrize(
    ("payload", "stream", "mode"),
    [
        ({"object_kind": "job"}, "jobs", "incremental"),
        # GitLab delivers job webhooks with object_kind "build"; both spellings map to jobs.
        ({"object_kind": "build"}, "jobs", "incremental"),
        ({"object_kind": "audit"}, "audit_events", "incremental"),
        ({"object_kind": "audit_event"}, "audit_events", "incremental"),
        ({"object_kind": "vulnerability", "event_name": "vulnerability_update"}, "vulnerabilities", "full"),
        ({"event_name": "vulnerability_delete"}, "vulnerabilities", "full"),
        ({"event_name": "vulnerability_create"}, "vulnerabilities", "full"),
        # Agreeing hints from both fields collapse to one stream family.
        ({"object_kind": "merge_request", "event_name": "note"}, "merge_requests", "incremental"),
    ],
)
def test_inline_hint_mapping(payload: dict[str, Any], stream: str, mode: str):
    record = _parse_one(_inline(payload))
    assert record.stream == stream
    assert record.reconcile == mode


# --- Hint parsing: failure modes -------------------------------------------------------


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ({"object_kind": "push"}, "unsupported GitLab webhook event"),
        ({}, "unsupported GitLab webhook event"),
        ({"object_kind": "note", "event_name": "pipeline"}, "conflicting GitLab webhook event hints"),
        ({"object_kind": 7}, "object_kind must be a string"),
        ({"object_kind": "note", "event_name": ["pipeline"]}, "event_name must be a string"),
    ],
    ids=["unsupported", "no-hint", "conflicting", "non-string-kind", "non-string-event"],
)
def test_unknown_or_conflicting_hints_rejected(payload: dict[str, Any], message: str):
    with pytest.raises(VendorContractError, match=message):
        _parse_one(_inline(payload))


@pytest.mark.parametrize(
    ("body", "message"),
    [
        (b"{not json", "not valid JSON"),
        (b"\xff", "not valid JSON"),
        (b"[1, 2]", "must be an object"),
    ],
    ids=["invalid-json", "invalid-utf8", "non-object"],
)
def test_malformed_body_rejected_after_authentication(body: bytes, message: str):
    with pytest.raises(VendorContractError, match=message):
        GitLabWebhookParser("gitlab.com").parse(_delivery(body))


def test_invalid_body_with_bad_signature_fails_as_rejection_not_contract_error():
    body = b"{not json"
    delivery = _delivery(body, headers=_signed_headers(body, key=UNKNOWN_KEY))
    events: list[tuple[str, str]] = []
    with pytest.raises(WebhookRejected, match="invalid webhook signature"):
        asyncio.run(_processor(_MemoryStore(events)).process(delivery, _recorder(events), NOW))
    assert events == []


def test_unknown_extra_fields_are_tolerated_and_preserved():
    record = _parse_one(_fixture(GITLAB_FIXTURES, "merge_request_hook.json"))
    assert record.raw["synthetic_extension_field"] == {"note": "Unknown fields must be tolerated and preserved."}


# --- target_uid ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        ({"object_kind": "note", "project_id": 5, "project": {"id": 6}}, "project:5"),
        ({"object_kind": "note", "project_id": "40123"}, "project:40123"),
        ({"object_kind": "merge_request", "project": {"id": 40123}}, "project:40123"),
        ({"object_kind": "note", "project_id": "abc"}, None),
        ({"object_kind": "note", "project_id": True}, None),
        ({"object_kind": "note", "project": {"id": "12x"}}, None),
        ({"object_kind": "note"}, None),
    ],
    ids=["top-level-precedence", "numeric-string", "nested-project", "non-numeric", "bool", "non-numeric-nested", "absent"],
)
def test_target_uid_from_numeric_project_id(payload: dict[str, Any], expected: str | None):
    assert _parse_one(_inline(payload)).target_uid == expected


def test_fixture_target_uid_comes_from_project_object():
    assert _parse_one(_fixture(GITLAB_FIXTURES, "merge_request_hook.json")).target_uid == "project:40123"


def test_fixture_target_uid_comes_from_top_level_project_id():
    assert _parse_one(_fixture(GITLAB_FIXTURES, "job_hook.json")).target_uid == "project:40123"


# --- Redaction -------------------------------------------------------------------------


def test_secret_and_token_keys_are_redacted_recursively():
    payload = {
        "object_kind": "pipeline",
        "items": [{"Api_Token": "synthetic-value-a", "id": 1}],
        "secret_settings": {"deep": {"value": 1}},
        "nested": {"private_token": "synthetic-value-b", "keep": "visible"},
    }
    raw = _parse_one(_inline(payload)).raw
    assert raw["items"] == [{"Api_Token": "[REDACTED]", "id": 1}]
    assert raw["secret_settings"] == "[REDACTED]"
    assert raw["nested"] == {"private_token": "[REDACTED]", "keep": "visible"}


def test_runner_token_in_fixture_is_redacted_from_raw_payload():
    raw = _parse_one(_fixture(GITLAB_FIXTURES, "job_hook.json")).raw
    assert raw["runner"]["token"] == "[REDACTED]"
    assert "example-token-placeholder" not in json.dumps(raw)


# --- Processor: replay, ordering, and failure handling ---------------------------------


def test_processed_reconciles_before_recording_delivery():
    events: list[tuple[str, str]] = []
    body = _fixture(GITLAB_FIXTURES, "merge_request_hook.json")
    result = asyncio.run(_processor(_MemoryStore(events)).process(_delivery(body), _recorder(events), NOW))

    assert result.status == "processed"
    assert result.delivery_id == MSG_ID
    assert [record.stream for record in result.records] == ["merge_requests"]
    assert events == [("contains", MSG_ID), ("reconcile", "merge_requests"), ("add", MSG_ID)]


def test_replayed_delivery_is_duplicate_with_zero_reconcile_calls():
    events: list[tuple[str, str]] = []
    body = _fixture(GITLAB_FIXTURES, "merge_request_hook.json")
    store = _MemoryStore(events, seen=(MSG_ID,))
    result = asyncio.run(_processor(store).process(_delivery(body), _recorder(events), NOW))

    assert result.status == "duplicate"
    assert result.records == ()
    assert events == [("contains", MSG_ID)]


def test_reconcile_failure_propagates_and_delivery_is_not_recorded():
    events: list[tuple[str, str]] = []

    async def failing(_record: StreamRecord) -> None:
        raise RuntimeError("reconcile failed")

    body = _fixture(GITLAB_FIXTURES, "pipeline_hook.json")
    with pytest.raises(RuntimeError, match="reconcile failed"):
        asyncio.run(_processor(_MemoryStore(events)).process(_delivery(body), failing, NOW))
    assert ("add", MSG_ID) not in events


def test_store_add_failure_propagates_after_reconcile():
    events: list[tuple[str, str]] = []
    body = _fixture(GITLAB_FIXTURES, "pipeline_hook.json")
    store = _MemoryStore(events, fail_add=OSError("store write failed"))
    with pytest.raises(OSError, match="store write failed"):
        asyncio.run(_processor(store).process(_delivery(body), _recorder(events), NOW))
    assert events == [("contains", MSG_ID), ("reconcile", "pipelines"), ("add", MSG_ID)]


def test_store_contains_failure_propagates_before_reconcile():
    events: list[tuple[str, str]] = []
    body = _fixture(GITLAB_FIXTURES, "pipeline_hook.json")
    store = _MemoryStore(events, fail_contains=OSError("store read failed"))
    with pytest.raises(OSError, match="store read failed"):
        asyncio.run(_processor(store).process(_delivery(body), _recorder(events), NOW))
    assert events == [("contains", MSG_ID)]


def test_verified_delivery_without_usable_webhook_id_never_reaches_store():
    events: list[tuple[str, str]] = []
    body = _fixture(GITLAB_FIXTURES, "pipeline_hook.json")
    headers = _signed_headers(body, msg_id="   ")
    with pytest.raises(WebhookRejected, match="no webhook-id"):
        asyncio.run(_processor(_MemoryStore(events)).process(_delivery(body, headers=headers), _recorder(events), NOW))
    assert events == []


def test_authentication_failure_prevents_store_and_reconcile():
    events: list[tuple[str, str]] = []
    body = _fixture(GITLAB_FIXTURES, "pipeline_hook.json")
    delivery = _delivery(body, headers=_signed_headers(body, key=UNKNOWN_KEY))
    with pytest.raises(WebhookRejected, match="invalid webhook signature"):
        asyncio.run(_processor(_MemoryStore(events)).process(delivery, _recorder(events), NOW))
    assert events == []
