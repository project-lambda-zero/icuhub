"""URL normalisation and origin checks for vendor HTTP.

Stdlib only. This module MUST NOT import httpx2.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import SplitResult, urljoin, urlsplit, urlunsplit

from icuhub.kit.errors import ConfigError, ConnectorError, UnsafeUrl

__all__ = [
    "Origin",
    "normalize_base_url",
    "origin_of",
    "require_https",
    "resolve_request_url",
]

_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1"})
_DEFAULT_PORTS = {"https": 443, "http": 80}


@dataclass(frozen=True)
class Origin:
    """Scheme, lower-cased host, and effective port of an absolute URL."""

    scheme: str
    host: str
    port: int


def _split(url: str, error: type[ConnectorError]) -> SplitResult:
    try:
        return urlsplit(url)
    except ValueError as exc:
        raise error("URL is malformed") from exc


def _origin(url: str, error: type[ConnectorError]) -> Origin:
    parts = _split(url, error)
    scheme = parts.scheme.lower()
    host = parts.hostname or ""
    if scheme not in _DEFAULT_PORTS or not host:
        raise error("URL must be an absolute http or https URL")
    if parts.username is not None or parts.password is not None:
        raise error("URL must not embed credentials")
    try:
        explicit = parts.port
    except ValueError as exc:
        raise error("URL port is invalid") from exc
    port = explicit if explicit is not None else _DEFAULT_PORTS[scheme]
    return Origin(scheme=scheme, host=host, port=port)


def _check_scheme(origin: Origin, error: type[ConnectorError], *, allow_plain_http_loopback: bool) -> None:
    if origin.scheme == "https":
        return
    if allow_plain_http_loopback and origin.host in _LOOPBACK_HOSTS:
        return
    raise error("plain http is allowed only for loopback hosts when allow_plain_http_loopback is set")


def origin_of(url: str) -> Origin:
    """Return the origin of an absolute http or https URL."""
    return _origin(url, UnsafeUrl)


def require_https(url: str) -> str:
    """Return ``url`` unchanged when it is an absolute https URL, else raise ``ConfigError``."""
    if _origin(url, ConfigError).scheme != "https":
        raise ConfigError("URL must use https")
    return url


def normalize_base_url(base_url: str, *, allow_plain_http_loopback: bool) -> str:
    """Validate a connector base URL and return it with a trailing slash."""
    parts = _split(base_url, ConfigError)
    if parts.query or parts.fragment:
        raise ConfigError("base_url must not contain a query or fragment")
    origin = _origin(base_url, ConfigError)
    _check_scheme(origin, ConfigError, allow_plain_http_loopback=allow_plain_http_loopback)
    path = parts.path if parts.path.endswith("/") else f"{parts.path}/"
    return urlunsplit((origin.scheme, parts.netloc, path, "", ""))


def resolve_request_url(
    base_url: str,
    path_or_url: str,
    *,
    extra_hosts: frozenset[str],
    allow_plain_http_loopback: bool,
) -> str:
    """Resolve a request path or absolute URL against ``base_url``.

    Relative paths join onto ``base_url``. Absolute URLs must share the base origin
    or name a host in ``extra_hosts`` (any port). Protocol-relative and backslash
    forms are rejected because they can redirect credentials to another host.
    """
    if "\\" in path_or_url or path_or_url.startswith("//"):
        raise UnsafeUrl("protocol-relative or backslash URLs are not allowed")
    parts = _split(path_or_url, UnsafeUrl)
    if not parts.scheme and not parts.netloc:
        return urljoin(base_url, path_or_url.lstrip("/"))
    target = _origin(path_or_url, UnsafeUrl)
    _check_scheme(target, UnsafeUrl, allow_plain_http_loopback=allow_plain_http_loopback)
    if target != _origin(base_url, UnsafeUrl) and target.host not in extra_hosts:
        raise UnsafeUrl("absolute URL origin does not match the connector base_url")
    return path_or_url
