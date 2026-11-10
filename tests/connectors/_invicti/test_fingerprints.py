"""Stable Invicti fingerprint input tests."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from icuhub.connectors._invicti import (
    FINGERPRINT_ALGORITHM,
    canonicalize_url,
    fingerprint_inputs,
    issue_fingerprint,
    parse_issue,
)


def test_canonical_url_normalizes_host_scheme_port_and_query_order() -> None:
    assert canonicalize_url("HTTPS://Shop.Example.TEST:443/products?b=2&a=1#fragment") == (
        "https://shop.example.test/products?a=1&b=2"
    )


def test_fingerprint_inputs_use_website_id_and_version(enterprise_issue_raw: dict[str, Any]) -> None:
    issue = parse_issue(enterprise_issue_raw)

    inputs = fingerprint_inputs(issue)

    assert inputs == {
        "algorithm": FINGERPRINT_ALGORITHM,
        "issue_type": "Invicti",
        "check": "SQL Injection",
        "url": "https://shop.example.test/products?q=1",
        "parameter": "q",
        "website_id": "6dc7a92f-94ab-4f7c-b60f-000000000101",
    }
    assert len(issue_fingerprint(issue)) == 64


def test_website_absent_falls_back_to_canonical_root_url(standard_issue_raw: dict[str, Any]) -> None:
    issue = parse_issue(standard_issue_raw, website_root_url="HTTPS://Blog.Example.TEST:443/")

    inputs = fingerprint_inputs(issue)

    assert "website_id" not in inputs
    assert inputs["canonical_url"] == "https://blog.example.test/"


def test_website_absent_without_root_uses_canonical_vulnerability_url(
    standard_issue_raw: dict[str, Any],
) -> None:
    issue = parse_issue(standard_issue_raw)

    inputs = fingerprint_inputs(issue)

    assert inputs["canonical_url"] == "https://blog.example.test/search?term=example"


def test_equivalent_normalized_locations_have_stable_fingerprints(
    enterprise_issue_raw: dict[str, Any],
) -> None:
    first = deepcopy(enterprise_issue_raw)
    second = deepcopy(enterprise_issue_raw)
    first["Url"] = "HTTPS://SHOP.example.test:443/products?q=1"
    second["Url"] = "https://shop.example.test/products?q=1#other-fragment"

    assert issue_fingerprint(parse_issue(first)) == issue_fingerprint(parse_issue(second))


def test_mutable_state_and_evidence_do_not_change_fingerprint(enterprise_issue_raw: dict[str, Any]) -> None:
    first = deepcopy(enterprise_issue_raw)
    second = deepcopy(enterprise_issue_raw)
    second["State"] = "AcceptedRisk"
    second["Severity"] = "Low"
    second["LastSeenDate"] = "2026-11-09T00:00:00Z"
    second["ProofOfConcept"] = "completely different evidence"

    assert issue_fingerprint(parse_issue(first)) == issue_fingerprint(parse_issue(second))


def test_check_parameter_website_and_algorithm_change_fingerprint(enterprise_issue_raw: dict[str, Any]) -> None:
    issue = parse_issue(enterprise_issue_raw)
    baseline = issue_fingerprint(issue)

    for field, value in [
        ("Title", "Different Check"),
        ("Url", "https://shop.example.test/other?q=1"),
    ]:
        changed = deepcopy(enterprise_issue_raw)
        changed[field] = value
        assert issue_fingerprint(parse_issue(changed)) != baseline

    changed_parameter = deepcopy(enterprise_issue_raw)
    changed_parameter["Parameters"][0]["Name"] = "other"
    assert issue_fingerprint(parse_issue(changed_parameter)) != baseline

    other_website = parse_issue(enterprise_issue_raw, website_id="other-website")
    assert issue_fingerprint(other_website) != baseline
    assert issue_fingerprint(issue, algorithm_version="other-algorithm/1") != baseline
