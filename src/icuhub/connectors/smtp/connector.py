"""SMTP ``Notifier`` connector: the ``send_notification`` action (MVP 4.20, FR-NTF-01..03)."""

from __future__ import annotations

import hashlib
from typing import Any, ClassVar

from icuhub.connectors.smtp.client import SmtpClient, SmtplibClient, build_message
from icuhub.connectors.smtp.models import SendNotificationArgs, SmtpConfig
from icuhub.kit.connector import Connector, action
from icuhub.kit.errors import PermissionDenied
from icuhub.kit.types import ActionOutcome, ActionPlan, CapabilityHealth, HealthReport, Scope

__all__ = ["Smtp"]


class _NoAuth:
    """SMTP has no HTTP auth strategy; the runtime attaches no HTTP client."""

    async def apply(self, request_headers: dict[str, str], method: str, url: str) -> None:
        return

    async def refresh(self) -> bool:
        return False


class Smtp(Connector):
    kind: ClassVar[str] = "smtp"
    version: ClassVar[str] = "0.1.0"
    display_name: ClassVar[str] = "SMTP Notifier"
    config_model: ClassVar[type[SmtpConfig]] = SmtpConfig
    auth_modes: ClassVar[tuple[str, ...]] = ("optional_smtp_auth",)
    capabilities: ClassVar[tuple[str, ...]] = ("Notifier",)
    uses_http: ClassVar[bool] = False
    flows: ClassVar[tuple[str, ...]] = ()
    scopes: ClassVar[tuple[Scope, ...]] = ()

    def __init__(self, config: SmtpConfig, ctx: Any) -> None:
        super().__init__(config, ctx)
        self._client: SmtpClient | None = None

    async def build_auth(self) -> _NoAuth:
        return _NoAuth()

    async def _smtp(self) -> SmtpClient:
        if self._client is None:
            config = self.config
            assert isinstance(config, SmtpConfig)
            username = (await self.ctx.secrets.resolve(config.username)).decode() if config.username else None
            password = (await self.ctx.secrets.resolve(config.password)).decode() if config.password else None
            self._client = SmtplibClient(
                host=config.host,
                port=config.port,
                security=config.security,
                from_address=config.from_address,
                username=username,
                password=password,
                timeout_s=config.timeout_s,
            )
        return self._client

    async def check(self) -> HealthReport:
        try:
            client = await self._smtp()
            await client.noop()
        except (OSError, TimeoutError, RuntimeError) as exc:
            return HealthReport(
                status="degraded",
                capabilities={"Notifier": CapabilityHealth(status="degraded", reason=type(exc).__name__)},
            )
        return HealthReport(status="healthy", capabilities={"Notifier": CapabilityHealth(status="healthy")})

    @action(
        "send_notification",
        classification="write",
        capability="Notifier",
        input_model=SendNotificationArgs,
        idempotency="natural_key",
    )
    async def plan_send(self, args: SendNotificationArgs) -> ActionPlan:
        config = self.config
        assert isinstance(config, SmtpConfig)
        rejected = [address for address in args.recipients if not config.recipient_allowed(address)]
        if rejected:
            raise PermissionDenied(f"recipients outside the allowlist: {', '.join(sorted(rejected))}")
        digest = hashlib.sha256(
            "\n".join([*args.recipients, args.subject, args.body]).encode("utf-8")
        ).hexdigest()
        return ActionPlan(
            action="send_notification",
            target_ref=f"smtp:{config.host}:{config.port}",
            diff={"subject": args.subject, "recipients": sorted(args.recipients), "body_sha256": digest},
            preconditions={"allowed_recipients": sorted(config.allowed_recipients)},
            idempotency_key=f"sha256:{digest}",
            changed=True,
            request={"recipients": args.recipients, "subject": args.subject, "body": args.body},
        )

    @plan_send.apply
    async def apply_send(self, plan: ActionPlan) -> ActionOutcome:
        config = self.config
        assert isinstance(config, SmtpConfig)
        request = plan.request
        message = build_message(config.from_address, request["recipients"], request["subject"], request["body"])
        client = await self._smtp()
        result = await client.send(message, request["recipients"])
        refused = result.get("refused") or {}
        if refused and len(refused) == len(request["recipients"]):
            return ActionOutcome(status="failed", error="every recipient was refused", result=result)
        return ActionOutcome(
            status="succeeded",
            vendor_ref=str(result.get("message_id") or ""),
            result={**result, "refused": refused},
        )
