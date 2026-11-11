"""Bounded, redacted, hash-linked Invicti proof evidence."""

from __future__ import annotations

import hashlib
import re

from pydantic import BaseModel, ConfigDict

from icuhub.connectors._invicti.records import InvictiProof

__all__ = ["DEFAULT_EVIDENCE_BYTES", "EvidenceArtifact", "ProofEvidence", "sanitize_evidence", "sanitize_proof"]

DEFAULT_EVIDENCE_BYTES = 32 * 1024
_REDACTED = "[REDACTED]"
_HEADER = re.compile(
    r"(?im)^(Authorization|Proxy-Authorization|Cookie|Set-Cookie|X-Api-Key):\s*[^\r\n]*"
)
_PARAMETER = re.compile(r"(?i)\b(access_token|refresh_token|token|password|api_key|apikey|session)=([^&\s]+)")
_JSON_SECRET = re.compile(r"(?i)(\"(?:access_token|refresh_token|token|password|api_key|apikey|session)\"\s*:\s*\")([^\"]*)(\")")


class EvidenceArtifact(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    content: str
    sha256: str
    original_bytes: int
    stored_bytes: int
    truncated: bool
    redacted: bool


class ProofEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    attack_detail: EvidenceArtifact | None
    http_request: EvidenceArtifact | None
    http_response: EvidenceArtifact | None
    proof_of_concept: EvidenceArtifact | None
    truncated: bool


def sanitize_evidence(value: str | None, *, max_bytes: int = DEFAULT_EVIDENCE_BYTES) -> EvidenceArtifact | None:
    if value is None:
        return None
    if max_bytes < 0:
        raise ValueError("max_bytes must be non-negative")
    original = value.encode("utf-8")
    redacted, header_count = _HEADER.subn(lambda match: f"{match.group(1)}: {_REDACTED}", value)
    redacted, parameter_count = _PARAMETER.subn(lambda match: f"{match.group(1)}={_REDACTED}", redacted)
    redacted, json_count = _JSON_SECRET.subn(lambda match: f"{match.group(1)}{_REDACTED}{match.group(3)}", redacted)
    encoded = redacted.encode("utf-8")
    truncated = len(encoded) > max_bytes
    stored = encoded[:max_bytes].decode("utf-8", errors="ignore") if truncated else redacted
    stored_bytes = stored.encode("utf-8")
    return EvidenceArtifact(
        content=stored,
        sha256=hashlib.sha256(stored_bytes).hexdigest(),
        original_bytes=len(original),
        stored_bytes=len(stored_bytes),
        truncated=truncated,
        redacted=bool(header_count or parameter_count or json_count),
    )


def sanitize_proof(proof: InvictiProof, *, max_bytes: int = DEFAULT_EVIDENCE_BYTES) -> ProofEvidence:
    artifacts = {
        "attack_detail": sanitize_evidence(proof.attack_detail, max_bytes=max_bytes),
        "http_request": sanitize_evidence(proof.http_request, max_bytes=max_bytes),
        "http_response": sanitize_evidence(proof.http_response, max_bytes=max_bytes),
        "proof_of_concept": sanitize_evidence(proof.proof_of_concept, max_bytes=max_bytes),
    }
    return ProofEvidence(**artifacts, truncated=any(item and item.truncated for item in artifacts.values()))
