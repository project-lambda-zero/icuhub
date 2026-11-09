"""Worker process: job dispatch table."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from icuhub.core.actions import JOB_HANDLERS as ACTION_HANDLERS
from icuhub.core.notifier import JOB_HANDLERS as NOTIFY_HANDLERS
from icuhub.core.sync import JOB_HANDLERS as SYNC_HANDLERS
from icuhub.core.tickets import JOB_HANDLERS as TICKET_HANDLERS
from icuhub.core.webhooks import JOB_HANDLERS as WEBHOOK_HANDLERS

__all__ = ["HANDLERS", "QUEUES"]

Handler = Callable[..., Any]

HANDLERS: dict[str, Handler] = {
    **SYNC_HANDLERS,
    **ACTION_HANDLERS,
    **WEBHOOK_HANDLERS,
    **TICKET_HANDLERS,
    **NOTIFY_HANDLERS,
}

QUEUES: tuple[str, ...] = ("sync", "imports", "actions", "webhooks", "tickets", "notifications")
