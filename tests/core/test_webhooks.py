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
from icuhub.kit.connector import webhook
from icuhub.kit.types import StreamRecord
from icuhub.kit.types import WebhookDelivery as KitWebhookDelivery
from icuhub.storage.db import session_scope
from icuhub.storage.models import SourceRecord, Target, Tenant, WebhookDelivery
from tests.core.helpers import caller_for, make_services, new_connection, vendor_transport
from tests.core.sample.connector import SampleTracker


class ReconcileTracker(SampleTracker):
    kind = "sample_reconcile_tracker"

    @webhook(event_types=("issue_updated",), header_event="x-sample-event")
    def parse_issue(self, delivery: KitWebhookDelivery) -> list[StreamRecord]:
        return [StreamRecord(stream="findings", raw={"receipt": "hint-only"}, reconcile="full")]


class CommitHintTracker(SampleTracker):
    kind = "sample_commit_hint_tracker"
    target_uid = "proj-1"
    commit_sha = "c" * 40

    @webhook(event_types=("issue_updated",), header_event="x-sample-event")
    def parse_issue(self, delivery: KitWebhookDelivery) -> list[StreamRecord]:
        return [
            StreamRecord(
                stream="findings",
                raw={"commit_sha": self.commit_sha, "event": "check_run"},
                target_uid=self.target_uid,
                reconcile="incremental",
            )
        ]


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


def test_reconciliation_hint_enqueues_full_sync_without_mapping_hint(tmp_path: Any, clean_database: None) -> None:
    async def scenario() -> None:
        from tests.core import helpers  # noqa: PLC0415

        helpers.REGISTRY[ReconcileTracker.kind] = ReconcileTracker
        try:
            services = make_services(vendor_transport({"issues": []}), tmp_path / "kek")
            tenant_id = uuid.uuid4()
            async with session_scope(tenant_id) as session:
                session.add(Tenant(id=tenant_id, slug=f"t-{tenant_id.hex[:8]}", display_name="T"))
                await session.flush()
                tracker = await new_connection(session, services, tenant_id, kind=ReconcileTracker.kind)
                endpoint_id, secret = await create_endpoint(session, caller_for(tenant_id), tracker.id, secret="s-one")
            body = json.dumps({"issue": "configurable-payload"}).encode()
            receipt = await receive(endpoint_id, _headers(secret, body), body)
            assert receipt.status_code == 202
            async with session_scope(tenant_id) as session:
                from icuhub.storage.models import Job  # noqa: PLC0415

                job = (await session.execute(select(Job).where(Job.queue == "webhooks"))).scalars().one()
                result = await run_webhook_job(job.payload_json)
                assert result["status"] == "processed", result
                assert result["reconciliations"] == 1
                sync_job = (await session.execute(select(Job).where(Job.queue == "sync"))).scalars().one()
                assert sync_job.payload_json["mode"] == "full"
                assert sync_job.payload_json["stream"] == "findings"
                assert (await session.execute(select(SourceRecord))).scalars().first() is None
        finally:
            from tests.core import helpers  # noqa: PLC0415

            helpers.REGISTRY.pop(ReconcileTracker.kind, None)

    asyncio.run(scenario())


async def _deliver_commit_hint(tmp_path: Any, *, with_target: bool) -> tuple[dict[str, Any], list[Any], Any]:
    from icuhub.storage.models import Job  # noqa: PLC0415
    from tests.core import helpers  # noqa: PLC0415

    helpers.REGISTRY[CommitHintTracker.kind] = CommitHintTracker
    try:
        services = make_services(vendor_transport({"issues": []}), tmp_path / "kek")
        tenant_id = uuid.uuid4()
        async with session_scope(tenant_id) as session:
            session.add(Tenant(id=tenant_id, slug=f"t-{tenant_id.hex[:8]}", display_name="T"))
            await session.flush()
            connection = await new_connection(session, services, tenant_id, kind=CommitHintTracker.kind)
            target_id: uuid.UUID | None = None
            if with_target:
                target = Target(
                    tenant_id=tenant_id,
                    connection_id=connection.id,
                    source_uid=CommitHintTracker.target_uid,
                    kind="repository",
                    display_name="repo",
                )
                session.add(target)
                await session.flush()
                target_id = target.id
            endpoint_id, secret = await create_endpoint(session, caller_for(tenant_id), connection.id, secret="s-one")
        body = json.dumps({"issue": "commit-hint"}).encode()
        receipt = await receive(endpoint_id, _headers(secret, body), body)
        assert receipt.status_code == 202, receipt
        async with session_scope(tenant_id) as session:
            job = (await session.execute(select(Job).where(Job.queue == "webhooks"))).scalars().one()
            result = await run_webhook_job(job.payload_json)
        async with session_scope(tenant_id) as session:
            sync_jobs = list((await session.execute(select(Job).where(Job.queue == "sync"))).scalars().all())
        return result, sync_jobs, target_id
    finally:
        helpers.REGISTRY.pop(CommitHintTracker.kind, None)


def test_commit_hint_with_declared_target_runs_commit_scoped_incremental_sync(tmp_path: Any, clean_database: None) -> None:
    async def scenario() -> None:
        result, sync_jobs, target_id = await _deliver_commit_hint(tmp_path, with_target=True)
        assert result["status"] == "processed", result
        assert result["reconciliations"] == 1, result
        assert result["unbound_reconciliations"] == 0, result
        assert len(sync_jobs) == 1, sync_jobs
        payload = sync_jobs[0].payload_json
        assert payload["stream"] == "findings"
        assert payload["mode"] == "incremental"
        assert payload["commit_sha"] == CommitHintTracker.commit_sha
        assert str(payload["target_id"]) == str(target_id)

    asyncio.run(scenario())


def test_commit_hint_without_known_target_is_counted_and_not_synced(tmp_path: Any, clean_database: None) -> None:
    async def scenario() -> None:
        result, sync_jobs, _ = await _deliver_commit_hint(tmp_path, with_target=False)
        assert result["status"] == "processed", result
        assert result["reconciliations"] == 0, result
        assert result["unbound_reconciliations"] == 1, result
        assert sync_jobs == [], "a commit SHA with no resolved target must not fan out"

    asyncio.run(scenario())
