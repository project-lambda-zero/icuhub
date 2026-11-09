"""Query-language escapers for untrusted values embedded in vendor query strings."""

from __future__ import annotations

from collections.abc import Iterable

from icuhub.kit.errors import VendorContractError
from icuhub.kit.soap import xml_text

__all__ = [
    "jql_in",
    "jql_string",
    "ldap_filter_value",
    "odata_string",
    "rql_string",
    "xml_text",
]

_LDAP_ESCAPES: dict[str, str] = {
    "\\": "\\5c",
    "*": "\\2a",
    "(": "\\28",
    ")": "\\29",
    "\x00": "\\00",
}


def _reject_control(value: str, *, allow: frozenset[str] = frozenset()) -> None:
    for char in value:
        if char in allow:
            continue
        code = ord(char)
        if code < 0x20 or code == 0x7F:
            raise VendorContractError(f"control character U+{code:04X} is not allowed in a query value")


def _double_quoted(value: str) -> str:
    _reject_control(value)
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def jql_string(value: str) -> str:
    """Return ``value`` as a JQL string literal."""
    return _double_quoted(value)


def jql_in(values: Iterable[str]) -> str:
    """Return a JQL ``IN`` value list such as ``("a","b")``; an empty collection raises ``VendorContractError``."""
    literals = [jql_string(value) for value in values]
    if not literals:
        raise VendorContractError("jql_in requires at least one value")
    return "(" + ",".join(literals) + ")"


def rql_string(value: str) -> str:
    """Return ``value`` as an RQL string literal (double-quoted, backslash escapes)."""
    return _double_quoted(value)


def odata_string(value: str) -> str:
    """Return ``value`` as an OData string literal (single quotes doubled)."""
    _reject_control(value)
    return "'" + value.replace("'", "''") + "'"


def ldap_filter_value(value: str) -> str:
    """Escape ``value`` for an RFC 4515 assertion value; NUL is escaped, other control characters are rejected."""
    _reject_control(value, allow=frozenset("\x00"))
    return "".join(_LDAP_ESCAPES.get(char, char) for char in value)
