"""Stable, vendor-neutral correlation inputs for Invicti findings."""

from __future__ import annotations

import hashlib
import json
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from icuhub.connectors._invicti.records import InvictiIssue

__all__ = ["FINGERPRINT_ALGORITHM", "canonicalize_url", "fingerprint_inputs", "issue_fingerprint"]

FINGERPRINT_ALGORITHM = "invicti-location/1"


def canonicalize_url(value: str) -> str:
    parsed = urlsplit(value.strip())
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    if not scheme or not host:
        raise ValueError("Invicti URL must be absolute")
    port = parsed.port
    netloc = host
    if ":" in host and not host.startswith("["):
        netloc = f"[{host}]"
    if port is not None and not ((scheme == "https" and port == 443) or (scheme == "http" and port == 80)):
        netloc = f"{netloc}:{port}"
    query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)), doseq=True)
    return urlunsplit((scheme, netloc, parsed.path or "/", query, ""))


def fingerprint_inputs(issue: InvictiIssue, *, algorithm_version: str = FINGERPRINT_ALGORITHM) -> dict[str, Any]:
    inputs: dict[str, Any] = {
        "algorithm": algorithm_version,
        "issue_type": issue.issue_type,
        "check": issue.title,
        "url": canonicalize_url(issue.location.url),
    }
    if issue.location.parameter:
        inputs["parameter"] = issue.location.parameter
    if issue.website.id:
        inputs["website_id"] = issue.website.id
    else:
        inputs["canonical_url"] = canonicalize_url(issue.website.root_url or issue.location.url)
    return inputs


def issue_fingerprint(issue: InvictiIssue, *, algorithm_version: str = FINGERPRINT_ALGORITHM) -> str:
    payload = json.dumps(fingerprint_inputs(issue, algorithm_version=algorithm_version), sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()
