"""Bounded, redacted, hash-linked Invicti evidence tests."""

from __future__ import annotations

import hashlib

import pytest

from icuhub.connectors._invicti import (
    DEFAULT_EVIDENCE_BYTES,
    EvidenceArtifact,
    InvictiProof,
    ProofEvidence,
    sanitize_evidence,
    sanitize_proof,
)


def test_http_credentials_and_token_parameters_are_redacted_before_hashing() -> None:
    raw = (
        "GET /search?q=public&access_token=query-secret HTTP/1.1\r\n"
        "Host: example.test\r\n"
        "Authorization: Bearer header-secret\r\n"
        "Cookie: session=cookie-secret\r\n"
        "X-Api-Key: api-secret\r\n\r\n"
        "password=body-secret&safe=value"
    )

    evidence = sanitize_evidence(raw)

    assert evidence is not None
    for secret in ["query-secret", "header-secret", "cookie-secret", "api-secret", "body-secret"]:
        assert secret not in evidence.content
    assert "q=public" in evidence.content
    assert "safe=value" in evidence.content
    assert "Authorization: [REDACTED]" in evidence.content
    assert "Cookie: [REDACTED]" in evidence.content
    assert "access_token=[REDACTED]" in evidence.content
    assert "password=[REDACTED]" in evidence.content
    assert evidence.redacted is True
    assert evidence.sha256 == hashlib.sha256(evidence.content.encode("utf-8")).hexdigest()


def test_set_cookie_and_proxy_authorization_are_redacted() -> None:
    evidence = sanitize_evidence(
        "HTTP/1.1 200 OK\r\nSet-Cookie: session=secret\r\nProxy-Authorization: Basic secret\r\n\r\nok"
    )

    assert evidence is not None
    assert "secret" not in evidence.content
    assert "Set-Cookie: [REDACTED]" in evidence.content
    assert "Proxy-Authorization: [REDACTED]" in evidence.content


def test_json_token_values_are_redacted() -> None:
    evidence = sanitize_evidence('{"safe": "visible", "refresh_token": "json-secret"}')

    assert evidence is not None
    assert "json-secret" not in evidence.content
    assert '"safe": "visible"' in evidence.content
    assert '"refresh_token": "[REDACTED]"' in evidence.content


def test_evidence_is_bounded_by_utf8_bytes_without_splitting_characters() -> None:
    evidence = sanitize_evidence("aaaaébbbb", max_bytes=5)

    assert evidence is not None
    assert evidence.content == "aaaa"
    assert evidence.truncated is True
    assert evidence.original_bytes == 10
    assert evidence.stored_bytes == 4
    assert len(evidence.content.encode("utf-8")) <= 5
    assert evidence.sha256 == hashlib.sha256(b"aaaa").hexdigest()


def test_default_evidence_cap_is_32_kib() -> None:
    evidence = sanitize_evidence("x" * (DEFAULT_EVIDENCE_BYTES + 1))

    assert evidence is not None
    assert DEFAULT_EVIDENCE_BYTES == 32 * 1024
    assert evidence.stored_bytes == DEFAULT_EVIDENCE_BYTES
    assert evidence.truncated is True


def test_digest_covers_redacted_bounded_content_and_is_stable() -> None:
    first = sanitize_evidence("token=first-secret", max_bytes=18)
    second = sanitize_evidence("token=second-secret", max_bytes=18)

    assert first is not None and second is not None
    assert first.content == second.content == "token=[REDACTED]"
    assert first.sha256 == second.sha256
    assert first.sha256 != hashlib.sha256(b"token=first-secret").hexdigest()


def test_none_and_empty_evidence_remain_distinct() -> None:
    assert sanitize_evidence(None) is None

    evidence = sanitize_evidence("")

    assert evidence is not None
    assert evidence.content == ""
    assert evidence.truncated is False
    assert evidence.redacted is False
    assert evidence.sha256 == hashlib.sha256(b"").hexdigest()


def test_negative_byte_cap_is_rejected() -> None:
    with pytest.raises(ValueError, match="max_bytes"):
        sanitize_evidence("value", max_bytes=-1)


def test_proof_helper_bounds_every_field_and_flags_any_truncation() -> None:
    proof = InvictiProof(
        attack_detail="<script>alert(1)</script>",
        http_request="GET /?token=secret HTTP/1.1",
        http_response="HTTP/1.1 200 OK\r\nSet-Cookie: a=secret",
        proof_of_concept="x" * 100,
    )

    sanitized = sanitize_proof(proof, max_bytes=32)

    assert isinstance(sanitized, ProofEvidence)
    assert sanitized.truncated is True
    assert isinstance(sanitized.attack_detail, EvidenceArtifact)
    assert sanitized.attack_detail.content.startswith("<script>")
    assert "secret" not in (sanitized.http_request.content if sanitized.http_request else "")
    assert "secret" not in (sanitized.http_response.content if sanitized.http_response else "")
    assert sanitized.proof_of_concept is not None
    assert sanitized.proof_of_concept.truncated is True
    for artifact in [
        sanitized.attack_detail,
        sanitized.http_request,
        sanitized.http_response,
        sanitized.proof_of_concept,
    ]:
        assert artifact is not None
        assert artifact.stored_bytes <= 32
        assert artifact.sha256 == hashlib.sha256(artifact.content.encode("utf-8")).hexdigest()
