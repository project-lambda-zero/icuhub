"""SMTP client protocol and the stdlib smtplib implementation (TLS always verified)."""

from __future__ import annotations

import asyncio
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from typing import Any, Protocol

__all__ = ["SmtpClient", "SmtplibClient"]


class SmtpClient(Protocol):
    """Minimal send/probe surface; tests substitute a fake, never a live socket."""

    async def send(self, message: EmailMessage, recipients: list[str]) -> dict[str, Any]: ...

    async def noop(self) -> None: ...


class SmtplibClient:
    """smtplib over ``asyncio.to_thread`` with STARTTLS or implicit TLS."""

    def __init__(
        self,
        *,
        host: str,
        port: int,
        security: str,
        from_address: str,
        username: str | None,
        password: str | None,
        timeout_s: float,
    ) -> None:
        self._host = host
        self._port = port
        self._security = security
        self._from = from_address
        self._username = username
        self._password = password
        self._timeout = timeout_s

    def _connect(self) -> smtplib.SMTP:
        context = ssl.create_default_context()
        if self._security == "ssl":
            client: smtplib.SMTP = smtplib.SMTP_SSL(
                self._host, self._port, timeout=self._timeout, context=context
            )
        else:
            client = smtplib.SMTP(self._host, self._port, timeout=self._timeout)
            client.starttls(context=context)
        if self._username is not None:
            client.login(self._username, self._password or "")
        return client

    async def send(self, message: EmailMessage, recipients: list[str]) -> dict[str, Any]:
        def _send() -> dict[str, Any]:
            with self._connect() as client:
                refused = client.send_message(message, to_addrs=recipients)
            return {"message_id": message["Message-ID"], "refused": refused}

        return await asyncio.to_thread(_send)

    async def noop(self) -> None:
        def _noop() -> None:
            with self._connect() as client:
                client.noop()

        await asyncio.to_thread(_noop)


def build_message(from_address: str, recipients: list[str], subject: str, body: str) -> EmailMessage:
    """Build the exact message; the Message-ID is the action's vendor reference."""
    message = EmailMessage()
    message["From"] = from_address
    message["To"] = ", ".join(recipients)
    message["Subject"] = subject
    message["Date"] = formatdate(localtime=False)
    message["Message-ID"] = make_msgid(domain=from_address.rsplit("@", 1)[-1])
    message.set_content(body)
    return message
