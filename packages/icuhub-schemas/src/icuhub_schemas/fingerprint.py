"""Stable finding fingerprints derived from connector kind, rule, location, and component."""

import hashlib

__all__ = ["finding_fingerprint"]

_SEPARATOR = "|"


def _normalize_part(value: str | None) -> str:
    return "" if value is None else value.strip()


def _normalize_location(value: str | None) -> str:
    if value is None:
        return ""
    path = value.strip().replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    return path


def finding_fingerprint(
    connector_kind: str,
    rule_or_check_id: str | None,
    location: str | None,
    component: str | None,
) -> str:
    """Return ``fp_`` followed by the SHA-256 hex digest of the normalized identity fields.

    Normalization, applied before hashing:

    - ``connector_kind`` is stripped and lowercased.
    - ``rule_or_check_id`` and ``component`` are stripped of surrounding whitespace.
    - ``location`` is stripped, backslashes become ``/``, and leading ``./`` segments are removed.
    - ``None`` becomes the empty string.

    The hashed text is the four normalized fields joined with ``|``. A field containing ``|``
    is rejected, since it would make distinct identities hash to the same input.

    Raises:
        ValueError: a normalized field contains ``|``.
    """

    fields = [
        _normalize_part(connector_kind).lower(),
        _normalize_part(rule_or_check_id),
        _normalize_location(location),
        _normalize_part(component),
    ]
    for field in fields:
        if _SEPARATOR in field:
            raise ValueError(f"fingerprint field must not contain {_SEPARATOR!r}: {field!r}")
    digest = hashlib.sha256(_SEPARATOR.join(fields).encode("utf-8")).hexdigest()
    return f"fp_{digest}"
