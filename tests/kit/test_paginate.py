"""Pagination generators: termination, budgets, loop detection, and request shape."""

import asyncio
import json
from collections.abc import AsyncIterator, Callable
from typing import Any

import httpx2
import pytest

from icuhub.kit.auth import BearerToken
from icuhub.kit.errors import BudgetExhausted, PaginationLoop, VendorContractError
from icuhub.kit.http import VendorHttp, build_http
from icuhub.kit.paginate import (
    Page,
    body_token_pages,
    link_header_pages,
    offset_pages,
    page_number_pages,
    token_pages,
)
from icuhub.kit.types import ConnectorConfig

BASE = "https://api.example.test"


def _http(handler: Callable[[httpx2.Request], httpx2.Response]) -> VendorHttp:
    return build_http(
        ConnectorConfig(base_url=BASE),
        BearerToken(token="test-token"),
        transport=httpx2.MockTransport(handler),
    )


def _items(body: Any) -> list[dict[str, Any]]:
    return body["items"]


async def _drain(http: VendorHttp, pages: AsyncIterator[Page], sink: list[list[dict[str, Any]]]) -> None:
    try:
        async for items, _result in pages:
            sink.append(items)
    finally:
        await http.aclose()


def _run(http: VendorHttp, pages: AsyncIterator[Page]) -> list[list[dict[str, Any]]]:
    sink: list[list[dict[str, Any]]] = []
    asyncio.run(_drain(http, pages, sink))
    return sink


# --- link_header_pages -----------------------------------------------------


def test_link_header_pages_follow_next_links_until_none_remain() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        page = int(request.url.params.get("page", "1"))
        headers = {}
        if page < 3:
            headers["Link"] = f'<{BASE}/items?page={page + 1}>; rel="next"'
        return httpx2.Response(200, json={"items": [{"n": page}]}, headers=headers)

    http = _http(handler)
    pages = _run(http, link_header_pages(http, "/items", {"page": "1"}, items=_items))

    assert pages == [[{"n": 1}], [{"n": 2}], [{"n": 3}]]


def test_link_header_pages_stop_on_an_empty_page() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(200, json={"items": []})

    http = _http(handler)

    assert _run(http, link_header_pages(http, "/items", None, items=_items)) == []


def test_link_header_pages_detect_a_repeated_link() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        # Every page points at the same next URL, so the second hop repeats it.
        return httpx2.Response(
            200,
            json={"items": [{"n": 1}]},
            headers={"Link": f'<{BASE}/items?page=2>; rel="next"'},
        )

    http = _http(handler)

    with pytest.raises(PaginationLoop, match="pagination link repeated"):
        _run(http, link_header_pages(http, "/items", None, items=_items))


def test_link_header_pages_stop_at_the_page_budget_before_an_extra_request() -> None:
    requests: list[str] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(str(request.url))
        page = int(request.url.params.get("page", "1"))
        return httpx2.Response(
            200,
            json={"items": [{"n": page}]},
            headers={"Link": f'<{BASE}/items?page={page + 1}>; rel="next"'},
        )

    http = _http(handler)
    sink: list[list[dict[str, Any]]] = []

    with pytest.raises(BudgetExhausted, match="exceeded 2 pages"):
        asyncio.run(
            _drain(http, link_header_pages(http, "/items", {"page": "1"}, items=_items, max_pages=2), sink)
        )

    assert len(requests) == 2
    assert sink == [[{"n": 1}], [{"n": 2}]]


# --- offset_pages ----------------------------------------------------------


def test_offset_pages_advance_by_page_length_and_stop_on_a_short_page() -> None:
    offsets: list[int] = []
    corpus = [{"n": n} for n in range(5)]

    def handler(request: httpx2.Request) -> httpx2.Response:
        offset = int(request.url.params["offset"])
        limit = int(request.url.params["limit"])
        offsets.append(offset)
        return httpx2.Response(200, json={"items": corpus[offset : offset + limit]})

    http = _http(handler)
    pages = _run(
        http,
        offset_pages(
            http,
            "/items",
            None,
            offset_param="offset",
            limit_param="limit",
            limit=2,
            items=_items,
        ),
    )

    assert pages == [corpus[0:2], corpus[2:4], corpus[4:5]]
    assert offsets == [0, 2, 4]


def test_offset_pages_stop_at_total_without_requesting_past_it() -> None:
    offsets: list[int] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        offset = int(request.url.params["offset"])
        offsets.append(offset)
        return httpx2.Response(200, json={"items": [{"n": offset}, {"n": offset + 1}]})

    http = _http(handler)
    pages = _run(
        http,
        offset_pages(
            http,
            "/items",
            None,
            offset_param="offset",
            limit_param="limit",
            limit=2,
            items=_items,
            total=4,
        ),
    )

    assert len(pages) == 2
    assert offsets == [0, 2]


def test_offset_pages_stop_at_the_page_budget() -> None:
    requests = 0

    def handler(request: httpx2.Request) -> httpx2.Response:
        nonlocal requests
        requests += 1
        return httpx2.Response(200, json={"items": [{"n": 1}, {"n": 2}]})

    http = _http(handler)
    sink: list[list[dict[str, Any]]] = []

    with pytest.raises(BudgetExhausted):
        asyncio.run(
            _drain(
                http,
                offset_pages(
                    http,
                    "/items",
                    None,
                    offset_param="offset",
                    limit_param="limit",
                    limit=2,
                    items=_items,
                    max_pages=3,
                ),
                sink,
            )
        )

    assert requests == 3
    assert len(sink) == 3


# --- page_number_pages -----------------------------------------------------


def test_page_number_pages_request_consecutive_numbers_and_stop_on_a_short_page() -> None:
    pages_requested: list[int] = []
    corpus = [{"n": n} for n in range(3)]

    def handler(request: httpx2.Request) -> httpx2.Response:
        page = int(request.url.params["page"])
        size = int(request.url.params["size"])
        pages_requested.append(page)
        return httpx2.Response(200, json={"items": corpus[(page - 1) * size : page * size]})

    http = _http(handler)
    pages = _run(
        http,
        page_number_pages(
            http,
            "/items",
            None,
            page_param="page",
            size_param="size",
            size=2,
            items=_items,
        ),
    )

    assert pages == [corpus[0:2], corpus[2:3]]
    assert pages_requested == [1, 2]


# --- token_pages -----------------------------------------------------------


def test_token_pages_send_each_continuation_token_as_a_query_parameter() -> None:
    tokens_sent: list[str | None] = []
    responses = {
        None: {"items": [{"n": 1}], "next": "t2"},
        "t2": {"items": [{"n": 2}], "next": "t3"},
        "t3": {"items": [{"n": 3}], "next": None},
    }

    def handler(request: httpx2.Request) -> httpx2.Response:
        token = request.url.params.get("cursor")
        tokens_sent.append(token)
        return httpx2.Response(200, json=responses[token])

    http = _http(handler)
    pages = _run(
        http,
        token_pages(
            http,
            "/items",
            None,
            token_param="cursor",
            next_token=lambda body: body["next"],
            items=_items,
        ),
    )

    assert pages == [[{"n": 1}], [{"n": 2}], [{"n": 3}]]
    assert tokens_sent == [None, "t2", "t3"]


def test_token_pages_detect_a_repeated_token() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(200, json={"items": [{"n": 1}], "next": "same"})

    http = _http(handler)

    with pytest.raises(PaginationLoop, match="pagination token repeated"):
        _run(
            http,
            token_pages(
                http,
                "/items",
                None,
                token_param="cursor",
                next_token=lambda body: body["next"],
                items=_items,
            ),
        )


# --- body_token_pages ------------------------------------------------------


def test_body_token_pages_send_the_token_in_the_json_body() -> None:
    bodies_sent: list[dict[str, Any]] = []
    responses = [
        {"items": [{"n": 1}], "cursor": "c2"},
        {"items": [{"n": 2}], "cursor": ""},
    ]

    def handler(request: httpx2.Request) -> httpx2.Response:
        assert request.method == "POST"
        bodies_sent.append(json.loads(request.content))
        return httpx2.Response(200, json=responses[len(bodies_sent) - 1])

    http = _http(handler)
    pages = _run(
        http,
        body_token_pages(
            http,
            path="/search",
            json_builder=lambda token: {"query": "x", "cursor": token},
            token_key="cursor",
            items=_items,
        ),
    )

    assert pages == [[{"n": 1}], [{"n": 2}]]
    assert bodies_sent == [{"query": "x", "cursor": None}, {"query": "x", "cursor": "c2"}]


def test_body_token_pages_reject_a_non_string_token() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(200, json={"items": [{"n": 1}], "cursor": 42})

    http = _http(handler)

    with pytest.raises(VendorContractError, match="is not a string"):
        _run(
            http,
            body_token_pages(
                http,
                path="/search",
                json_builder=lambda token: {"cursor": token},
                token_key="cursor",
                items=_items,
            ),
        )


def test_body_token_pages_detect_a_repeated_token() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(200, json={"items": [{"n": 1}], "cursor": "same"})

    http = _http(handler)

    with pytest.raises(PaginationLoop, match="pagination token repeated"):
        _run(
            http,
            body_token_pages(
                http,
                path="/search",
                json_builder=lambda token: {"cursor": token},
                token_key="cursor",
                items=_items,
            ),
        )
