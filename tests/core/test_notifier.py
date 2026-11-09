"""Approval notification through the real smtp connector and worker queue (F7)."""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

from sqlalchemy import select

from icuhub.core.actions import submit_action
from icuhub.storage.db import session_scope
from icuhub.storage.models import Notification, Tenant
from icuhub.workers.main import run_once
from tests.core.helpers import caller_for, make_services, new_connection, vendor_transport


class RecordingSmtp:
    sent: list[Any] = []

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs

    async def send(self, message: Any, recipients: list[str]) -> dict[str, Any]:
        RecordingSmtp.sent.append((message, recipients))
        return {"message_id": message["Message-ID"], "refused": {}}

    async def noop(self) -> None:
        return


def test_approval_notification_is_sent_once_without_approval_loop(
    tmp_path: Any, clean_database: None, monkeypatch: Any
) -> None:
    monkeypatch.setattr("icuhub.connectors.smtp.connector.SmtplibClient", RecordingSmtp)
    RecordingSmtp.sent = []

    async def scenario() -> None:
        services = make_services(vendor_transport({"issues": []}), tmp_path / "kek")
        tenant_id = uuid.uuid4()
        async with session_scope(tenant_id) as session:
            session.add(Tenant(id=tenant_id, slug=f"t-{tenant_id.hex[:8]}", display_name="T"))
            await session.flush()
            tracker = await new_connection(session, services, tenant_id, kind="sample_tracker_core")
            await new_connection(
                session,
                services,
                tenant_id,
                kind="smtp",
                slug="smtp-main",
                config={"host": "smtp.example.test", "from_address": "icuhub@example.test"},
                secrets={},
            )
            request = await submit_action(
                session,
                caller_for(tenant_id, "requester"),
                tracker.id,
                "create_issue",
                {"summary": "notify me"},
                idempotency_key="notify-key",
            )
            assert request.state == "pending_approval"
            notifications = (await session.execute(select(Notification))).scalars().all()
            assert len(notifications) == 1
            assert notifications[0].template == "approval_requested"
        processed = await run_once(queues=("notifications", "actions"), max_jobs=10)
        assert processed >= 1
        async with session_scope(tenant_id) as session:
            notification = (await session.execute(select(Notification))).scalars().one()
            from icuhub.storage.models import Job  # noqa: PLC0415
            jobs = [(j.kind, j.state, j.last_error) for j in (await session.execute(select(Job))).scalars().all()]
            assert notification.state == "sent", jobs
            assert len(RecordingSmtp.sent) == 1
            message, recipients = RecordingSmtp.sent[0]
            assert "approval required" in message["Subject"]
            assert recipients == ["approvers@icuhub"]
            assert len((await session.execute(select(Notification))).scalars().all()) == 1, "no send loop"
        assert await run_once(queues=("notifications", "actions"), max_jobs=10) == 0
        assert len(RecordingSmtp.sent) == 1

    asyncio.run(scenario())
