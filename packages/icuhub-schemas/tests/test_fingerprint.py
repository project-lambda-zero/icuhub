"""Behaviour of finding fingerprints: normalization equivalence and identity distinction."""

from __future__ import annotations

import re

import pytest

from icuhub_schemas.fingerprint import finding_fingerprint


def test_fingerprint_has_prefix_and_sha256_hex_digest() -> None:
    assert re.fullmatch(r"fp_[0-9a-f]{64}", finding_fingerprint("semgrep", "rule.x", "src/a.py", "app"))


def test_normalization_yields_equivalent_identity() -> None:
    canonical = finding_fingerprint("semgrep", "rule.x", "src/a.py", "app")

    assert finding_fingerprint("  Semgrep ", "rule.x", "./src/a.py", "app") == canonical
    assert finding_fingerprint("semgrep", " rule.x ", "src\\a.py", " app ") == canonical


def test_none_fields_normalize_to_empty() -> None:
    assert finding_fingerprint("trivy", None, None, None) == finding_fingerprint("trivy", "", "", "")


@pytest.mark.parametrize(
    "other",
    [
        ("trivy", "rule.x", "src/a.py", "app"),
        ("semgrep", "rule.y", "src/a.py", "app"),
        ("semgrep", "rule.x", "src/b.py", "app"),
        ("semgrep", "rule.x", "src/a.py", "other"),
    ],
)
def test_distinct_identity_fields_change_fingerprint(other: tuple[str, str, str, str]) -> None:
    base = finding_fingerprint("semgrep", "rule.x", "src/a.py", "app")

    assert finding_fingerprint(*other) != base


def test_field_separator_cannot_be_smuggled_into_a_field() -> None:
    with pytest.raises(ValueError, match="must not contain"):
        finding_fingerprint("semgrep", "rule|x", "src/a.py", "app")
