"""Behaviour of the CloudEvents 1.0 envelope."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from icuhub_schemas.events import CloudEvent


def _event(**overrides: object) -> CloudEvent:
    fields: dict[str, object] = {
        "id": "evt-1",
        "source": "icuhub://connector/semgrep",
        "type": "icuhub.finding.created",
        "time": datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC),
        "data": {"finding_uid": "f-1"},
    }
    fields.update(overrides)
    return CloudEvent(**fields)  # type: ignore[arg-type]


def test_structured_json_round_trip() -> None:
    event = _event(
        subject="findings/f-1",
        dataschema="https://example.invalid/schema.json",
        tenantid="acme",
        correlationid="run42",
    )

    restored = CloudEvent.from_json(event.to_json())

    assert restored == event
    document = json.loads(event.to_json())
    assert document["specversion"] == "1.0"
    assert document["datacontenttype"] == "application/json"
    assert document["tenantid"] == "acme"


def test_unset_optional_attributes_are_omitted() -> None:
    document = json.loads(_event().to_json())

    assert "subject" not in document
    assert "tenantid" not in document
    assert "correlationid" not in document


def test_from_json_accepts_bytes() -> None:
    event = _event()

    assert CloudEvent.from_json(event.to_json().encode("utf-8")) == event


@pytest.mark.parametrize("bad_type", ["finding.created", "ICUHUB.finding", ""])
def test_type_without_icuhub_prefix_is_rejected(bad_type: str) -> None:
    with pytest.raises(ValidationError):
        _event(type=bad_type)


def test_wrong_specversion_is_rejected() -> None:
    with pytest.raises(ValidationError):
        CloudEvent.from_json(json.dumps({**json.loads(_event().to_json()), "specversion": "0.3"}))


def test_extension_values_carry_consumer_identifiers_verbatim() -> None:
    # CloudEvents naming rules apply to attribute names, not values: consumer IDs keep
    # their own format.
    event = _event(tenantid="Acme-Tenant", correlationid="inv_7f3c-2026-11-07/branch:3")

    document = json.loads(event.to_json())

    assert document["tenantid"] == "Acme-Tenant"
    assert document["correlationid"] == "inv_7f3c-2026-11-07/branch:3"


@pytest.mark.parametrize("field", ["tenantid", "correlationid"])
def test_empty_extension_values_are_rejected(field: str) -> None:
    with pytest.raises(ValidationError):
        _event(**{field: ""})
