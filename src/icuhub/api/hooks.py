"""Webhook ingress: ``POST /hooks/{endpoint_id}``.

The body is read as bytes, capped at ``webhook_max_body_bytes``, and handed to
``core.webhooks.receive`` unparsed so signature verification sees the exact bytes the
vendor signed. The HTTP status comes from the core ``Receipt`` (202 accepted, 200
duplicate, 401 verification failed, 404 unknown endpoint, 405 no webhook support).
"""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import Response

from icuhub.api.problems import ProblemError
from icuhub.core.webhooks import receive
from icuhub.settings import get_settings

__all__ = ["router"]

router = APIRouter(tags=["webhooks"])


async def _read_capped(request: Request, limit: int) -> bytes:
    declared = request.headers.get("content-length")
    if declared is not None and declared.isdigit() and int(declared) > limit:
        raise ProblemError(413, "payload-too-large", "Payload too large", f"body exceeds {limit} bytes")
    buffer = bytearray()
    async for chunk in request.stream():
        buffer.extend(chunk)
        if len(buffer) > limit:
            raise ProblemError(413, "payload-too-large", "Payload too large", f"body exceeds {limit} bytes")
    return bytes(buffer)


@router.post("/hooks/{endpoint_id}")
async def ingest(endpoint_id: str, request: Request) -> Response:
    limit = get_settings().webhook_max_body_bytes
    body = await _read_capped(request, limit)
    headers = {key.lower(): value for key, value in request.headers.items()}
    receipt = await receive(endpoint_id, headers, body)
    return Response(status_code=receipt.status_code)
