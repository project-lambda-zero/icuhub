"""Bounded, loop-safe pagination over ``VendorHttp``.

Every generator yields ``(items, result)`` for each non-empty page. An empty page or
a missing continuation ends the loop. Each generator counts issued requests against
``max_pages`` and raises ``BudgetExhausted`` before issuing a request beyond the
budget. Repeated continuation tokens or URLs raise ``PaginationLoop``.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from typing import TYPE_CHECKING, Any, TypeAlias

from icuhub.kit.errors import BudgetExhausted, PaginationLoop, VendorContractError

if TYPE_CHECKING:
    from icuhub.kit.http import HttpResult, VendorHttp

__all__ = [
    "BodyItems",
    "Page",
    "body_token_pages",
    "link_header_pages",
    "offset_pages",
    "page_number_pages",
    "token_pages",
]

Page: TypeAlias = "tuple[list[dict[str, Any]], HttpResult]"
BodyItems: TypeAlias = "Callable[[Any], list[dict[str, Any]]]"


def _check_budget(fetched: int, max_pages: int, path: str) -> None:
    if fetched >= max_pages:
        raise BudgetExhausted(f"pagination of {path} exceeded {max_pages} pages")


async def link_header_pages(
    http: VendorHttp,
    path: str,
    params: dict[str, Any] | None,
    *,
    items: BodyItems,
    max_pages: int = 10_000,
) -> AsyncIterator[Page]:
    """Follow RFC 8288 ``rel="next"`` links; each link is an absolute URL."""
    seen_urls: set[str] = {path}
    target = path
    query = params
    fetched = 0
    while True:
        _check_budget(fetched, max_pages, path)
        result = await http.request("GET", target, params=query)
        fetched += 1
        body = result.json()
        page = items(body)
        if not page:
            return
        yield page, result
        next_url = result.links.get("next")
        if not next_url:
            return
        if next_url in seen_urls:
            raise PaginationLoop(f"pagination link repeated for {path}")
        seen_urls.add(next_url)
        target = next_url
        query = None


async def offset_pages(
    http: VendorHttp,
    path: str,
    params: dict[str, Any] | None,
    *,
    offset_param: str,
    limit_param: str,
    limit: int,
    items: BodyItems,
    total: int | None = None,
    max_pages: int = 10_000,
) -> AsyncIterator[Page]:
    """Advance a numeric offset by each page's length; stop on a short page or at ``total``."""
    offset = 0
    fetched = 0
    while True:
        if total is not None and offset >= total:
            return
        _check_budget(fetched, max_pages, path)
        query = {**(params or {}), offset_param: offset, limit_param: limit}
        result = await http.request("GET", path, params=query)
        fetched += 1
        page = items(result.json())
        if not page:
            return
        yield page, result
        offset += len(page)
        if len(page) < limit:
            return


async def page_number_pages(
    http: VendorHttp,
    path: str,
    params: dict[str, Any] | None,
    *,
    page_param: str,
    size_param: str,
    size: int,
    items: BodyItems,
    start: int = 1,
    max_pages: int = 10_000,
) -> AsyncIterator[Page]:
    """Request consecutive page numbers; stop on a short page."""
    page_number = start
    fetched = 0
    while True:
        _check_budget(fetched, max_pages, path)
        query = {**(params or {}), page_param: page_number, size_param: size}
        result = await http.request("GET", path, params=query)
        fetched += 1
        page = items(result.json())
        if not page:
            return
        yield page, result
        if len(page) < size:
            return
        page_number += 1


async def token_pages(
    http: VendorHttp,
    path: str,
    params: dict[str, Any] | None,
    *,
    token_param: str,
    next_token: Callable[[Any], str | None],
    items: BodyItems,
    max_pages: int = 10_000,
) -> AsyncIterator[Page]:
    """Pass the continuation token as a query parameter until the body names none."""
    seen_tokens: set[str] = set()
    token: str | None = None
    fetched = 0
    while True:
        _check_budget(fetched, max_pages, path)
        query = dict(params or {})
        if token is not None:
            query[token_param] = token
        result = await http.request("GET", path, params=query)
        fetched += 1
        body = result.json()
        page = items(body)
        if not page:
            return
        yield page, result
        token = next_token(body)
        if not token:
            return
        if token in seen_tokens:
            raise PaginationLoop(f"pagination token repeated for {path}")
        seen_tokens.add(token)


async def body_token_pages(
    http: VendorHttp,
    *,
    method: str = "POST",
    path: str,
    json_builder: Callable[[str | None], dict[str, Any]],
    token_key: str,
    items: BodyItems,
    max_pages: int = 10_000,
) -> AsyncIterator[Page]:
    """Send the continuation token inside the request JSON body.

    ``json_builder(token)`` returns the request body for a page; ``token`` is None for
    the first page. ``token_key`` names the response field holding the next token.
    """
    seen_tokens: set[str] = set()
    token: str | None = None
    fetched = 0
    while True:
        _check_budget(fetched, max_pages, path)
        result = await http.request(method, path, json=json_builder(token))
        fetched += 1
        body = result.json()
        page = items(body)
        if not page:
            return
        yield page, result
        raw_next = body.get(token_key) if isinstance(body, dict) else None
        if raw_next is None or raw_next == "":
            return
        if not isinstance(raw_next, str):
            raise VendorContractError(f"pagination token {token_key!r} is not a string")
        if raw_next in seen_tokens:
            raise PaginationLoop(f"pagination token repeated for {path}")
        seen_tokens.add(raw_next)
        token = raw_next
