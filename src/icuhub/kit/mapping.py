"""JMESPath access, enum lookup, timestamp normalization, and OCSF helper values for mappers."""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from typing import Any, TypeAlias

import jmespath
from jmespath.exceptions import JMESPathError
from jmespath.parser import ParsedResult

from icuhub.kit.errors import VendorContractError
from icuhub_schemas.fingerprint import finding_fingerprint

__all__ = [
    "CompiledJmes",
    "EnumTable",
    "bounded_raw",
    "epoch_ms",
    "fingerprint_for",
    "get",
    "jp",
    "product",
    "severity_id_from_label",
]

CompiledJmes: TypeAlias = ParsedResult

# Epoch values at or above this magnitude are milliseconds; below it, seconds.
# 1e11 seconds falls in year 5138 and 1e11 milliseconds in 1973, so real values
# on either side of the threshold are unambiguous.
_EPOCH_MS_THRESHOLD = 100_000_000_000
_NUMERIC_TEXT = re.compile(r"^[+-]?\d+(?:\.\d+)?$")
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_TRUNCATION_MARKER = "...[truncated]"


def jp(expr: str) -> CompiledJmes:
    """Compile a JMESPath expression using only the built-in function set."""
    try:
        return jmespath.compile(expr)
    except JMESPathError as exc:
        raise VendorContractError(f"invalid JMESPath expression {expr!r}: {exc}") from exc


def get(raw: dict[str, Any], compiled: CompiledJmes) -> Any:
    """Evaluate a compiled expression against a raw record; missing paths yield None."""
    try:
        return compiled.search(raw)
    except JMESPathError as exc:
        raise VendorContractError(f"JMESPath evaluation failed: {exc}") from exc


@dataclass(frozen=True)
class EnumTable:
    """Exact-match lookup from vendor labels to normalized values.

    Unmatched and missing (None) labels return ``default``. Connectors choose the
    default explicitly; for OCSF severity the honest choice is the Unknown id 0.
    """

    mapping: dict[str, Any]
    default: Any

    def lookup(self, value: Any) -> Any:
        """Return the mapped value for a string label, or the default."""
        if isinstance(value, str) and value in self.mapping:
            return self.mapping[value]
        return self.default


def severity_id_from_label(label: str | None, table: EnumTable) -> int:
    """Map a vendor severity label to an OCSF ``severity_id`` integer."""
    value = table.lookup(label)
    if isinstance(value, bool) or not isinstance(value, int):
        raise VendorContractError(
            f"severity table produced non-integer severity_id {value!r} for label {label!r}"
        )
    return value


def epoch_ms(value: Any) -> int | None:
    """Normalize a timestamp to epoch milliseconds (UTC).

    Accepts numeric epoch seconds or milliseconds (chosen by magnitude), numeric
    strings of the same form, ISO 8601 (including a trailing ``Z``), and RFC 2822.
    Naive datetimes are interpreted as UTC. ``None`` and empty strings return None;
    anything else that cannot be parsed raises ``VendorContractError``.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        raise VendorContractError(f"boolean is not a timestamp: {value!r}")
    if isinstance(value, int | float):
        return _numeric_epoch_ms(value)
    if not isinstance(value, str):
        raise VendorContractError(f"unsupported timestamp type {type(value).__name__}")

    text = value.strip()
    if not text:
        return None
    if _NUMERIC_TEXT.match(text):
        return _numeric_epoch_ms(float(text) if "." in text else int(text))
    return _datetime_epoch_ms(text)


def _numeric_epoch_ms(value: int | float) -> int:
    if isinstance(value, float) and not math.isfinite(value):
        raise VendorContractError(f"non-finite timestamp {value!r}")
    if abs(value) >= _EPOCH_MS_THRESHOLD:
        return round(value)
    return round(value * 1000)


def _datetime_epoch_ms(text: str) -> int:
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        try:
            parsed = parsedate_to_datetime(text)
        except (TypeError, ValueError) as exc:
            raise VendorContractError(f"unparseable timestamp {text!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return (parsed - _EPOCH) // timedelta(milliseconds=1)


def product(name: str, vendor: str, version: str | None = None) -> dict[str, Any]:
    """Build an OCSF ``product`` object; an absent version is recorded as null."""
    return {"name": name, "vendor_name": vendor, "version": version}


def bounded_raw(raw: dict[str, Any], max_chars: int = 32768) -> str:
    """Serialize a raw record to JSON, truncated to ``max_chars`` with a visible marker."""
    if max_chars < len(_TRUNCATION_MARKER):
        raise ValueError(f"max_chars must be at least {len(_TRUNCATION_MARKER)}")
    text = json.dumps(raw, ensure_ascii=False, default=str)
    if len(text) <= max_chars:
        return text
    return text[: max_chars - len(_TRUNCATION_MARKER)] + _TRUNCATION_MARKER


def fingerprint_for(
    kind: str,
    rule: str | None,
    location: str | None,
    component: str | None,
) -> str:
    """Return the shared finding fingerprint for a connector finding."""
    return finding_fingerprint(kind, rule, location, component)
