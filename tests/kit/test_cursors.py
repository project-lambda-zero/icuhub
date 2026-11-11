"""TimeIdCursor: monotonic advance, boundary duplicate suppression, overlap window."""

from datetime import UTC, datetime, timedelta

from icuhub.kit.cursors import TimeIdCursor

T0 = datetime(2026, 11, 9, 12, 0, 0, tzinfo=UTC)
T1 = T0 + timedelta(minutes=5)
T2 = T0 + timedelta(minutes=10)


def _ts_of(record: dict) -> datetime:
    return record["ts"]


def _id_of(record: dict) -> str:
    return record["id"]


def test_advance_from_empty_cursor_takes_newest_timestamp_and_its_ids() -> None:
    cursor = TimeIdCursor(ts=None)
    records = [{"ts": T1, "id": "a"}, {"ts": T2, "id": "b"}, {"ts": T2, "id": "c"}]

    advanced = cursor.advance(records, _ts_of, _id_of)

    assert advanced.ts == T2
    assert advanced.last_ids_at_ts == ["b", "c"]


def test_advance_never_moves_the_timestamp_backwards() -> None:
    cursor = TimeIdCursor(ts=T2, last_ids_at_ts=["b"])
    older = [{"ts": T1, "id": "old"}]

    result = cursor.advance(older, _ts_of, _id_of)

    assert result is cursor
    assert result.ts == T2
    assert result.last_ids_at_ts == ["b"]


def test_advance_with_no_records_returns_the_same_cursor() -> None:
    cursor = TimeIdCursor(ts=T1, last_ids_at_ts=["a"])

    assert cursor.advance([], _ts_of, _id_of) is cursor


def test_records_at_the_cursor_timestamp_accumulate_without_duplicates() -> None:
    cursor = TimeIdCursor(ts=T2, last_ids_at_ts=["b"])
    records = [{"ts": T2, "id": "b"}, {"ts": T2, "id": "c"}]

    advanced = cursor.advance(records, _ts_of, _id_of)

    assert advanced.ts == T2
    assert advanced.last_ids_at_ts == ["b", "c"]


def test_a_newer_timestamp_resets_the_id_list() -> None:
    cursor = TimeIdCursor(ts=T1, last_ids_at_ts=["a", "b"])
    records = [{"ts": T2, "id": "c"}]

    advanced = cursor.advance(records, _ts_of, _id_of)

    assert advanced.ts == T2
    assert advanced.last_ids_at_ts == ["c"]


def test_is_duplicate_matches_only_the_committed_timestamp_and_id() -> None:
    cursor = TimeIdCursor(ts=T2, last_ids_at_ts=["b"])

    assert cursor.is_duplicate(T2, "b") is True
    assert cursor.is_duplicate(T2, "c") is False
    assert cursor.is_duplicate(T1, "b") is False


def test_window_start_subtracts_the_overlap() -> None:
    cursor = TimeIdCursor(ts=T2, overlap_s=300)

    assert cursor.window_start() == T2 - timedelta(seconds=300)


def test_window_start_is_none_before_the_first_commit() -> None:
    assert TimeIdCursor(ts=None).window_start() is None
