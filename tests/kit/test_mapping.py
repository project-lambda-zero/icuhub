"""Mapping helpers: timestamp normalization, enum lookup, bounded raw payloads, products."""

import json

import pytest

from icuhub.kit.errors import VendorContractError
from icuhub.kit.mapping import (
    EnumTable,
    bounded_raw,
    epoch_ms,
    get,
    jp,
    product,
    severity_id_from_label,
)

# --- epoch_ms --------------------------------------------------------------


def test_epoch_seconds_are_scaled_to_milliseconds() -> None:
    assert epoch_ms(1700000000) == 1700000000000


def test_epoch_milliseconds_are_kept_as_is() -> None:
    assert epoch_ms(1700000000000) == 1700000000000


def test_fractional_epoch_seconds_keep_millisecond_precision() -> None:
    assert epoch_ms(1700000000.5) == 1700000000500


def test_iso_8601_with_z_suffix_normalizes_to_utc() -> None:
    assert epoch_ms("2023-11-14T22:13:20Z") == 1700000000000


def test_iso_8601_with_offset_normalizes_to_utc() -> None:
    assert epoch_ms("2023-11-15T00:13:20+02:00") == 1700000000000


def test_naive_iso_timestamp_is_treated_as_utc() -> None:
    assert epoch_ms("2023-11-14T22:13:20") == 1700000000000


def test_rfc_2822_timestamp_is_accepted() -> None:
    assert epoch_ms("Tue, 14 Nov 2023 22:13:20 +0000") == 1700000000000


@pytest.mark.parametrize("empty", [None, ""])
def test_missing_or_empty_timestamps_map_to_none(empty: object) -> None:
    assert epoch_ms(empty) is None


def test_boolean_is_not_a_timestamp() -> None:
    with pytest.raises(VendorContractError, match="boolean is not a timestamp"):
        epoch_ms(True)


def test_unparseable_string_is_a_vendor_contract_error() -> None:
    with pytest.raises(VendorContractError, match="unparseable timestamp"):
        epoch_ms("next tuesday-ish")


def test_non_finite_float_is_rejected() -> None:
    with pytest.raises(VendorContractError, match="non-finite timestamp"):
        epoch_ms(float("nan"))


def test_unsupported_container_type_is_rejected() -> None:
    with pytest.raises(VendorContractError, match="unsupported timestamp type"):
        epoch_ms(["2023-11-14"])


# --- EnumTable and severity mapping ----------------------------------------


def test_enum_table_returns_exact_matches_and_default_otherwise() -> None:
    table = EnumTable({"Critical": 5, "High": 4}, 1)

    assert table.lookup("High") == 4
    assert table.lookup("high") == 1  # exact match only, no case folding
    assert table.lookup("Unknown") == 1
    assert table.lookup(None) == 1


def test_severity_uses_the_table_default_for_missing_labels() -> None:
    table = EnumTable({"High": 4}, 0)

    assert severity_id_from_label(None, table) == 0
    assert severity_id_from_label("High", table) == 4


def test_non_integer_severity_table_value_is_rejected() -> None:
    table = EnumTable({"High": "four"}, 0)

    with pytest.raises(VendorContractError, match="non-integer severity_id"):
        severity_id_from_label("High", table)


def test_boolean_severity_table_value_is_rejected() -> None:
    table = EnumTable({"High": True}, 0)

    with pytest.raises(VendorContractError, match="non-integer severity_id"):
        severity_id_from_label("High", table)


# --- JMESPath helpers ------------------------------------------------------


def test_jp_extracts_nested_values_and_none_for_missing_paths() -> None:
    record = {"fields": {"status": {"name": "Open"}}}

    assert get(record, jp("fields.status.name")) == "Open"
    assert get(record, jp("fields.priority.name")) is None


def test_invalid_jmespath_expression_is_a_vendor_contract_error() -> None:
    with pytest.raises(VendorContractError, match="invalid JMESPath expression"):
        jp("fields[")


# --- bounded_raw and product ----------------------------------------------


def test_bounded_raw_returns_full_json_when_under_the_limit() -> None:
    record = {"id": 1, "title": "short"}

    assert json.loads(bounded_raw(record, max_chars=1000)) == record


def test_bounded_raw_truncates_with_a_visible_marker_at_exact_length() -> None:
    record = {"title": "x" * 500}

    bounded = bounded_raw(record, max_chars=100)

    assert len(bounded) == 100
    assert bounded.endswith("...[truncated]")


def test_bounded_raw_rejects_a_limit_smaller_than_the_marker() -> None:
    with pytest.raises(ValueError, match="max_chars must be at least"):
        bounded_raw({"a": 1}, max_chars=3)


def test_product_records_an_absent_version_as_null() -> None:
    assert product("Scanner", "Acme") == {"name": "Scanner", "vendor_name": "Acme", "version": None}
    assert product("Scanner", "Acme", "2.1") == {
        "name": "Scanner",
        "vendor_name": "Acme",
        "version": "2.1",
    }
