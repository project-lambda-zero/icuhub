"""Webhook ingress: verify, dedupe, rotation window, worker parse (FR-WHK-*)."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import uuid
from datetime import timedelta
from typing import Any

from sqlalchemy import select

import icuhub.core.webhooks as webhooks
from icuhub.core.webhooks import create_endpoint, receive, rotate_endpoint, run_webhook_job
from icuhub.storage.db import session_scope
from icuhub.storage.models import SourceRecord, Tenant, WebhookDelivery
from tests.core.helpers import caller_for, make_services, new_connection, vendor_transport


def _headers(secret: str, body: bytes, delivery: str = "d-1", event: str = "issue_updated") -> dict[str, str]:
    signature = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return {
        "x-sample-signature": f"sha256={signature}",
        "x-sample-delivery": delivery,
        "x-sample-event": event,
        "authorization": "must-not-be-persisted",
    }


def test_verify_dedupe_rotate_and_worker(tmp_path: Any, clean_database: None) -> None:
    async def scenario() -> None:
        services = make_services(vendor_transport({"issues": []}), tmp_path / "kek")
        tenant_id = uuid.uuid4()
        async with session_scope(tenant_id) as session:
            session.add(Tenant(id=tenant_id, slug=f"t-{tenant_id.hex[:8]}", display_name="T"))
            await session.flush()
            tracker = await new_connection(session, services, tenant_id, kind="sample_tracker_core")
            endpoint_id, secret = await create_endpoint(session, caller_for(tenant_id), tracker.id, secret="s-one")
        body = json.dumps({"key": "ISSUE-1", "status": "Done", "status_category": "done", "revision": "r1"}).encode()
        receipt = await receive(endpoint_id, _headers(secret, body), body)
        assert receipt.status_code == 202, receipt
        duplicate = await receive(endpoint_id, _headers(secret, body), body)
        assert duplicate.status_code == 200
        tampered = await receive(endpoint_id, _headers("wrong", body, delivery="d-2"), body)
        assert tampered.status_code == 401
        async with session_scope(tenant_id) as session:
            row = (await session.execute(select(WebhookDelivery))).scalars().one()
            from icuhub.storage.models import Job  # noqa: PLC0415

            job = (await session.execute(select(Job).where(Job.queue == "webhooks"))).scalars().one()
            assert job.payload_json["delivery_id"] == str(row.id)
            assert "authorization" not in job.payload_json.get("headers", {})
            assert job.payload_json["headers"]["x-sample-event"] == "issue_updated"
            result = await run_webhook_job(job.payload_json)
            assert result["status"] == "processed", result
            record = (await session.execute(select(SourceRecord))).scalars().one()
            assert record.uid == "ISSUE-1"
            assert record.data_json["status"] == "Done"
        async with session_scope(tenant_id) as session:
            new_secret = await rotate_endpoint(session, caller_for(tenant_id), endpoint_id, secret="s-two")
        rotated_body = json.dumps({"key": "ISSUE-2", "status": "Open", "status_category": "open"}).encode()
        old = await receive(endpoint_id, _headers(secret, rotated_body, delivery="d-3"), rotated_body)
        assert old.status_code == 202, "previous secret valid inside rotation window"
        new = await receive(endpoint_id, _headers(new_secret, rotated_body, delivery="d-4"), rotated_body)
        assert new.status_code == 202
        real_now = webhooks._now
        webhooks._now = lambda: real_now() + timedelta(seconds=services.settings.webhook_rotation_window_s + 60)
        try:
            expired = await receive(endpoint_id, _headers(secret, rotated_body, delivery="d-5"), rotated_body)
            assert expired.status_code == 401, "previous secret rejected after the window"
        finally:
            webhooks._now = real_now
        missing = await receive("nonexistent", _headers(secret, body), body)
        assert missing.status_code == 404

    asyncio.run(scenario())
