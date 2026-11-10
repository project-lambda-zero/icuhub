"""Pure tests for the Jira DC node-local audit JSONL checkpoint helper.

Covers append resume, per-node and per-file cursor independence, rotation and truncation
recovery, partial trailing lines, blank lines, fallback IDs, timestamp and summary
normalization, metadata tags, and VendorContractError rejections.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest

from icuhub.connectors.jira_dc.audit_files import (
    AuditBatch,
    AuditFilePosition,
    AuditLogCursor,
    parse_audit_batch,
)
from icuhub.kit.errors import VendorContractError

MAX_RECORD = 4096
NODE = "node-a"
PATH = "/var/atlassian/audit/audit-1.jsonl"


def _line(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"


def _parse(
    content: bytes,
    previous: AuditFilePosition | None = None,
    *,
    node: str = NODE,
    path: str = PATH,
    max_record_bytes: int = MAX_RECORD,
) -> AuditBatch:
    return parse_audit_batch(
        node=node,
        path=path,
        content=content,
        previous=previous,
        max_record_bytes=max_record_bytes,
    )


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


FIRST = {"id": 1, "created": "2026-11-09T10:00:00Z", "summary": "Created group"}
SECOND = {"id": 2, "created": "2026-11-09T10:05:00Z", "summary": "Updated user"}
THIRD = {"id": 3, "created": "2026-11-09T10:06:00Z", "summary": "Deleted user"}


# --- append resume and offsets ----------------------------------------------


def test_first_batch_reads_every_complete_record_from_byte_zero() -> None:
    content = _line(FIRST) + _line(SECOND)

    batch = _parse(content)

    assert [record["id"] for record in batch.records] == [1, 2]
    assert batch.recovery == "none"
    assert batch.position.offset == len(content)
    assert batch.position.fingerprint == _sha(content)


def test_append_resumes_at_prior_offset_and_emits_only_new_records() -> None:
    first_content = _line(FIRST)
    first = _parse(first_content)

    second_content = first_content + _line(SECOND)
    second = _parse(second_content, first.position)

    assert [record["id"] for record in second.records] == [2]
    assert second.recovery == "none"
    assert second.records[0]["_jira_file_offset"] == len(first_content)
    assert second.position.offset == len(second_content)
    assert second.position.fingerprint == _sha(second_content)


def test_unchanged_snapshot_produces_no_records_and_same_position() -> None:
    content = _line(FIRST)
    first = _parse(content)

    again = _parse(content, first.position)

    assert again.records == []
    assert again.recovery == "none"
    assert again.position == first.position


def test_multibyte_utf8_offsets_are_byte_based() -> None:
    first_content = _line({"id": 1, "created": "2026-11-09T10:00:00Z", "summary": "caf\u00e9 \u2603"})
    first = _parse(first_content)

    second_content = first_content + _line(SECOND)
    second = _parse(second_content, first.position)

    assert len(first_content) > len(first_content.decode("utf-8"))
    assert second.records[0]["_jira_file_offset"] == len(first_content)


# --- cursor independence ----------------------------------------------------


def test_cursor_positions_are_independent_per_node_and_file() -> None:
    cursor = AuditLogCursor()
    pos_a = AuditFilePosition(offset=10, fingerprint="a" * 64)
    pos_b = AuditFilePosition(offset=20, fingerprint="b" * 64)
    pos_other_file = AuditFilePosition(offset=30, fingerprint="c" * 64)

    advanced = cursor.advance_file("node-a", PATH, pos_a)
    advanced = advanced.advance_file("node-b", PATH, pos_b)
    advanced = advanced.advance_file("node-a", "/other.jsonl", pos_other_file)

    assert advanced.position("node-a", PATH) == pos_a
    assert advanced.position("node-b", PATH) == pos_b
    assert advanced.position("node-a", "/other.jsonl") == pos_other_file
    assert advanced.position("node-b", "/other.jsonl") is None
    assert advanced.seq == 3


def test_cursor_advance_does_not_mutate_the_original_cursor() -> None:
    cursor = AuditLogCursor()

    advanced = cursor.advance_file(NODE, PATH, AuditFilePosition(offset=5, fingerprint="d" * 64))

    assert cursor.files == {}
    assert cursor.seq == 0
    assert cursor.position(NODE, PATH) is None
    assert advanced is not cursor


def test_cursor_seq_increments_once_per_changed_file_batch() -> None:
    cursor = AuditLogCursor()
    position = AuditFilePosition(offset=5, fingerprint="e" * 64)

    once = cursor.advance_file(NODE, PATH, position)
    same = once.advance_file(NODE, PATH, position)

    assert once.seq == 1
    assert same is once
    assert same.seq == 1


def test_cursor_keys_do_not_collide_on_delimiter_characters() -> None:
    cursor = AuditLogCursor()
    colliding = AuditFilePosition(offset=7, fingerprint="f" * 64)

    advanced = cursor.advance_file("a:b", "c", colliding)

    assert advanced.position("a", "b:c") is None
    assert advanced.position("a:b", "c") == colliding


def test_cursor_retains_opaque_string_seq() -> None:
    cursor = AuditLogCursor(seq="opaque-1")
    position = AuditFilePosition(offset=1, fingerprint="0" * 64)

    advanced = cursor.advance_file(NODE, PATH, position)

    assert advanced.seq == "opaque-1"
    assert advanced.position(NODE, PATH) == position


# --- recovery ---------------------------------------------------------------


def test_same_path_rotation_restarts_from_byte_zero() -> None:
    original = _line(FIRST) + _line(SECOND)
    first = _parse(original)

    rotated = (
        _line(THIRD)
        + _line({"id": 4, "created": "2026-11-09T11:00:00Z", "summary": "New file"})
        + _line({"id": 5, "created": "2026-11-09T11:01:00Z", "summary": "Rotated file continues with a longer record"})
    )
    assert len(rotated) > first.position.offset
    batch = _parse(rotated, first.position)

    assert batch.recovery == "rotation"
    assert [record["id"] for record in batch.records] == [3, 4, 5]
    assert all(record["_jira_recovery"] == "rotation" for record in batch.records)
    assert batch.records[0]["_jira_file_offset"] == 0
    assert batch.position.offset == len(rotated)


def test_rotation_is_detected_even_when_new_content_is_longer() -> None:
    original = _line(FIRST)
    first = _parse(original)

    rotated = _line(THIRD) + _line(SECOND) + _line(FIRST)
    batch = _parse(rotated, first.position)

    assert batch.recovery == "rotation"
    assert [record["id"] for record in batch.records] == [3, 2, 1]


def test_truncation_when_prior_offset_exceeds_current_length_resets_to_zero() -> None:
    original = _line(FIRST) + _line(SECOND)
    first = _parse(original)

    truncated = _line(THIRD)
    assert first.position.offset > len(truncated)
    batch = _parse(truncated, first.position)

    assert batch.recovery == "truncation"
    assert [record["id"] for record in batch.records] == [3]
    assert batch.records[0]["_jira_recovery"] == "truncation"
    assert batch.records[0]["_jira_file_offset"] == 0
    assert batch.position.offset == len(truncated)


def test_recovery_flag_is_none_on_normal_resume_even_after_recovery() -> None:
    original = _line(FIRST)
    first = _parse(original)
    rotated = _line(THIRD)
    recovered = _parse(rotated, first.position)

    resumed = _parse(rotated + _line(SECOND), recovered.position)

    assert resumed.recovery == "none"
    assert [record["id"] for record in resumed.records] == [2]
    assert resumed.records[0]["_jira_recovery"] == "none"


# --- partial lines and blank lines ------------------------------------------


def test_incomplete_trailing_line_is_not_consumed() -> None:
    complete = _line(FIRST)
    partial = b'{"id":2,"created":"2026-11-09T10:05:00Z"'

    batch = _parse(complete + partial)

    assert [record["id"] for record in batch.records] == [1]
    assert batch.position.offset == len(complete)
    assert batch.position.fingerprint == _sha(complete)


def test_partial_line_is_emitted_exactly_once_after_completion() -> None:
    complete = _line(FIRST)
    partial = b'{"id":2,"created":"2026-11-09T10:05:00Z",'
    tail = b'"summary":"Updated user"}\n'

    first = _parse(complete + partial)
    second = _parse(complete + partial + tail, first.position)

    assert [record["id"] for record in second.records] == [2]
    assert second.records[0]["_jira_file_offset"] == len(complete)
    assert second.position.offset == len(complete + partial + tail)


def test_blank_complete_lines_advance_offset_without_records() -> None:
    blank_prefix = b"\n  \r\n"
    content = blank_prefix + _line(FIRST)

    batch = _parse(content)

    assert [record["id"] for record in batch.records] == [1]
    assert batch.records[0]["_jira_file_offset"] == len(blank_prefix)
    assert batch.position.offset == len(content)


def test_only_blank_lines_advance_to_their_end() -> None:
    content = b"\n\n\r\n"

    batch = _parse(content)

    assert batch.records == []
    assert batch.position.offset == len(content)


def test_crlf_terminated_records_parse_and_keep_newline_offsets() -> None:
    first_content = json.dumps(FIRST).encode("utf-8") + b"\r\n"
    first = _parse(first_content)

    second_content = first_content + json.dumps(SECOND).encode("utf-8") + b"\r\n"
    second = _parse(second_content, first.position)

    assert [record["id"] for record in second.records] == [2]
    assert second.records[0]["_jira_file_offset"] == len(first_content)


# --- fallback IDs and dedupe ------------------------------------------------


def _no_id(payload: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in payload.items() if key != "id"}


def test_fallback_id_is_stable_sha256_for_identical_source() -> None:
    content = _line(_no_id(FIRST))

    first = _parse(content).records[0]["id"]
    second = _parse(content).records[0]["id"]

    assert first == second
    assert isinstance(first, str)
    assert len(first) == 64
    assert all(char in "0123456789abcdef" for char in first)


def test_fallback_id_differs_by_node_path_offset_and_body() -> None:
    line = _line(_no_id(FIRST))
    base = _parse(line).records[0]["id"]

    other_node = _parse(line, node="node-b").records[0]["id"]
    other_path = _parse(line, path="/other.jsonl").records[0]["id"]
    other_body = _parse(_line(_no_id(SECOND))).records[0]["id"]
    shifted = _parse(_line(FIRST) + line).records[1]["id"]

    assert len({base, other_node, other_path, other_body, shifted}) == 5


def test_fallback_id_is_not_ambiguous_across_field_boundaries() -> None:
    first = _parse(b'{"created":"2026-11-09T10:00:00Z","summary":"x"}\n', node="ab", path="c").records[0]["id"]
    second = _parse(b'{"created":"2026-11-09T10:00:00Z","summary":"x"}\n', node="a", path="bc").records[0]["id"]

    assert first != second


def test_numeric_and_string_ids_are_retained() -> None:
    content = _line(FIRST) + _line({"id": "abc-123", "created": "2026-11-09T10:00:00Z", "summary": "s"})

    batch = _parse(content)

    assert batch.records[0]["id"] == 1
    assert batch.records[1]["id"] == "abc-123"


@pytest.mark.parametrize("bad_id", [None, "", True, [1], {"x": 1}])
def test_unusable_ids_fall_back_to_hash(bad_id: Any) -> None:
    content = _line({"id": bad_id, "created": "2026-11-09T10:00:00Z", "summary": "s"})

    record = _parse(content).records[0]

    assert isinstance(record["id"], str)
    assert len(record["id"]) == 64


# --- timestamp and summary normalization ------------------------------------


def test_iso_created_is_retained_verbatim() -> None:
    record = _parse(_line({"id": 1, "created": "2026-11-09T10:00:00.123+02:00", "summary": "s"})).records[0]

    assert record["created"] == "2026-11-09T10:00:00.123+02:00"


def test_timestamp_iso_maps_to_created_when_created_absent() -> None:
    record = _parse(_line({"id": 1, "timestamp": "2026-11-09T10:00:00Z", "summary": "s"})).records[0]

    assert record["created"] == "2026-11-09T10:00:00Z"


def test_epoch_milliseconds_timestamp_maps_to_iso_created() -> None:
    record = _parse(_line({"id": 1, "timestamp": 1700000000000, "summary": "s"})).records[0]

    assert record["created"] == "2023-11-14T22:13:20Z"


def test_created_epoch_milliseconds_is_converted_to_iso() -> None:
    record = _parse(_line({"id": 1, "created": 1700000000000, "summary": "s"})).records[0]

    assert record["created"] == "2023-11-14T22:13:20Z"


def test_missing_timestamp_is_a_vendor_contract_error() -> None:
    with pytest.raises(VendorContractError, match="created or timestamp"):
        _parse(_line({"id": 1, "summary": "s"}))


def test_summary_is_retained_when_present() -> None:
    record = _parse(_line({"id": 1, "created": "2026-11-09T10:00:00Z", "summary": "Kept", "action": "x"})).records[0]

    assert record["summary"] == "Kept"


def test_summary_falls_back_to_action_then_event_type() -> None:
    content = _line({"id": 1, "created": "2026-11-09T10:00:00Z", "action": "login"}) + _line(
        {"id": 2, "created": "2026-11-09T10:00:00Z", "eventType": "permission_change"}
    )

    batch = _parse(content)

    assert batch.records[0]["summary"] == "login"
    assert batch.records[1]["summary"] == "permission_change"


def test_summary_has_deterministic_fallback_when_absent() -> None:
    content = _line({"id": 1, "created": "2026-11-09T10:00:00Z"})

    first = _parse(content).records[0]["summary"]
    second = _parse(content).records[0]["summary"]

    assert first == second == "Jira audit event"


# --- metadata tags ----------------------------------------------------------


def test_every_record_carries_jira_metadata_tags() -> None:
    content = _line(FIRST) + _line(SECOND)

    batch = _parse(content)

    fingerprint = _sha(content)
    assert [record["_jira_node"] for record in batch.records] == [NODE, NODE]
    assert [record["_jira_file"] for record in batch.records] == [PATH, PATH]
    assert [record["_jira_file_offset"] for record in batch.records] == [0, len(_line(FIRST))]
    assert [record["_jira_file_fingerprint"] for record in batch.records] == [fingerprint, fingerprint]
    assert [record["_jira_recovery"] for record in batch.records] == ["none", "none"]


def test_batch_fingerprint_is_sha256_of_content_through_new_offset() -> None:
    complete = _line(FIRST)
    content = complete + b'{"partial":'

    batch = _parse(content)

    assert batch.position.offset == len(complete)
    assert batch.position.fingerprint == _sha(complete)


def test_original_fields_are_preserved_alongside_normalized_fields() -> None:
    payload = {"id": 9, "created": "2026-11-09T10:00:00Z", "summary": "s", "remoteAddress": "192.0.2.4"}

    record = _parse(_line(payload)).records[0]

    assert record["remoteAddress"] == "192.0.2.4"
    assert record["id"] == 9


# --- rejections -------------------------------------------------------------


@pytest.mark.parametrize(
    "content",
    [
        b'{"id": 1, "created": "2026-11-09T10:00:00Z"\n',
        b"not json at all\n",
        b'{"id": 1, "created": NaN, "summary": "s"}\n',
    ],
    ids=["truncated-object", "garbage", "non-standard-constant"],
)
def test_invalid_json_is_a_vendor_contract_error(content: bytes) -> None:
    with pytest.raises(VendorContractError, match="not valid JSON"):
        _parse(content)


def test_invalid_utf8_is_a_vendor_contract_error() -> None:
    content = b'{"id": 1, "created": "2026-11-09T10:00:00Z", "summary": "\xff\xfe"}\n'

    with pytest.raises(VendorContractError, match="not valid UTF-8"):
        _parse(content)


@pytest.mark.parametrize("content", [b"[1, 2]\n", b'"text"\n', b"42\n", b"null\n"], ids=["array", "string", "number", "null"])
def test_non_object_json_is_a_vendor_contract_error(content: bytes) -> None:
    with pytest.raises(VendorContractError, match="must contain a JSON object"):
        _parse(content)


def test_error_reports_the_offending_line_start_offset() -> None:
    content = _line(FIRST) + b"oops\n"

    with pytest.raises(VendorContractError, match=f"byte {len(_line(FIRST))}"):
        _parse(content)


def test_complete_line_at_max_record_bytes_is_accepted() -> None:
    body = json.dumps({"id": 1, "created": "2026-11-09T10:00:00Z", "summary": "s"}, separators=(",", ":"))
    content = body.encode("utf-8") + b"\n"

    batch = _parse(content, max_record_bytes=len(body))

    assert [record["id"] for record in batch.records] == [1]


def test_complete_line_over_max_record_bytes_is_rejected() -> None:
    content = _line({"id": 1, "created": "2026-11-09T10:00:00Z", "summary": "s" * 200})

    with pytest.raises(VendorContractError, match="exceeds max_record_bytes"):
        _parse(content, max_record_bytes=64)


def test_incomplete_line_over_max_record_bytes_is_rejected_without_waiting() -> None:
    partial = b'{"id": 1, "summary": "' + b"x" * 200

    with pytest.raises(VendorContractError, match="exceeds max_record_bytes"):
        _parse(partial, max_record_bytes=64)


def test_oversized_line_before_a_valid_line_halts_the_batch() -> None:
    content = _line({"id": 1, "created": "2026-11-09T10:00:00Z", "summary": "x" * 200}) + _line(SECOND)

    with pytest.raises(VendorContractError, match="exceeds max_record_bytes"):
        _parse(content, max_record_bytes=64)
