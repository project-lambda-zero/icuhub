"""Unit tests for the GraphQL vulnerability node normalizer."""

from __future__ import annotations

from typing import Any

import pytest

from icuhub.connectors._gitlab.graphql import normalize_vulnerability
from icuhub.kit.errors import VendorContractError


def _node(**overrides: Any) -> dict[str, Any]:
    node: dict[str, Any] = {
        "id": "gid://gitlab/Vulnerability/7001",
        "uuid": "b4a7e3c2-1d6f-4a8b-9c0e-2f3a4b5c6d7e",
        "state": "DETECTED",
        "severity": "HIGH",
        "reportType": "SAST",
        "updatedAt": "2026-11-09T10:00:00Z",
        "identifiers": [
            {
                "name": "CVE-2024-12345",
                "externalType": "cve",
                "externalId": "CVE-2024-12345",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-12345",
            }
        ],
        "location": {"file": "src/parser/read.c", "startLine": 14, "endLine": 16},
    }
    node.update(overrides)
    return node


def test_enum_fields_are_lowercased_to_the_rest_vocabulary() -> None:
    normalized = normalize_vulnerability(
        _node(state="CONFIRMED", severity="CRITICAL", reportType="DEPENDENCY_SCANNING")
    )

    assert normalized["state"] == "confirmed"
    assert normalized["severity"] == "critical"
    assert normalized["report_type"] == "dependency_scanning"
    assert normalized["updated_at"] == "2026-11-09T10:00:00Z"


def test_native_id_is_parsed_from_the_vulnerability_gid() -> None:
    normalized = normalize_vulnerability(_node())

    assert normalized["id"] == 7001
    assert normalized["gid"] == "gid://gitlab/Vulnerability/7001"
    assert normalized["uuid"] == "b4a7e3c2-1d6f-4a8b-9c0e-2f3a4b5c6d7e"


@pytest.mark.parametrize(
    "gid",
    [
        "gid://gitlab/Project/42",
        "gid://gitlab/Vulnerability/0",
        "gid://gitlab/Vulnerability/007",
        "gid://gitlab/Vulnerability/abc",
        "gid://gitlab/Vulnerability/7001/extra",
        "7001",
        "",
    ],
)
def test_non_vulnerability_gid_is_rejected(gid: str) -> None:
    with pytest.raises(VendorContractError):
        normalize_vulnerability(_node(id=gid))


def test_non_string_id_is_rejected() -> None:
    with pytest.raises(VendorContractError):
        normalize_vulnerability(_node(id=7001))


def test_sast_location_maps_file_and_lines() -> None:
    normalized = normalize_vulnerability(_node())

    assert normalized["location"] == {"file": "src/parser/read.c", "start_line": 14, "end_line": 16}


def test_absent_or_fileless_location_maps_to_none() -> None:
    assert normalize_vulnerability(_node(location=None))["location"] is None
    assert normalize_vulnerability(_node(location={"startLine": 3}))["location"] is None


def test_identifiers_lowercase_their_type_and_drop_entries_missing_external_fields() -> None:
    identifiers: list[Any] = [
        {"name": "CWE-787", "externalType": "CWE", "externalId": "787", "url": None},
        {"name": "no external id", "externalType": "cve"},
        {"name": "no external type", "externalId": "X-1"},
        "not-an-object",
    ]

    normalized = normalize_vulnerability(_node(identifiers=identifiers))

    assert normalized["identifiers"] == [{"type": "cwe", "value": "787", "name": "CWE-787", "url": None}]


def test_missing_identifiers_normalize_to_an_empty_list() -> None:
    assert normalize_vulnerability(_node(identifiers=None))["identifiers"] == []
