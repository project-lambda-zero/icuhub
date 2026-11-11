"""Native Google Threat Intelligence / VirusTotal v3 ``lookup`` (MVP 4.19)."""

from __future__ import annotations

import base64
from typing import ClassVar

from icuhub.connectors.google_threat_intelligence.models import GtiConfig, Indicator, IntelReport
from icuhub.kit.auth import HeaderToken
from icuhub.kit.connector import Connector, operation
from icuhub.kit.types import CapabilityHealth, HealthReport, Scope

__all__ = ["GoogleThreatIntelligence"]


class GoogleThreatIntelligence(Connector):
    kind: ClassVar[str] = "google_threat_intelligence"
    version: ClassVar[str] = "0.1.0"
    display_name: ClassVar[str] = "Google Threat Intelligence"
    config_model: ClassVar[type[GtiConfig]] = GtiConfig
    auth_modes: ClassVar[tuple[str, ...]] = ("x-apikey",)
    capabilities: ClassVar[tuple[str, ...]] = ("ThreatIntel",)
    scopes: ClassVar[tuple[Scope, ...]] = (
        Scope(name="lookup", probe="GET /users/current", required_by=("ThreatIntel",)),
    )
    flows: ClassVar[tuple[str, ...]] = ()
    #: Public GTI quota is 4 requests per minute; enterprise keys can raise it per connection.
    rate_limits: ClassVar[dict[str, tuple[float, float]]] = {"default": (4, 60)}

    async def build_auth(self) -> HeaderToken:
        config = self.config
        assert isinstance(config, GtiConfig)
        return HeaderToken("x-apikey", (await self.ctx.secrets.resolve(config.api_key)).decode())

    async def check(self) -> HealthReport:
        try:
            await self.http.request("GET", "/users/current")
        except (OSError, TimeoutError, RuntimeError) as exc:
            return HealthReport(
                status="degraded",
                capabilities={"ThreatIntel": CapabilityHealth(status="degraded", reason=type(exc).__name__)},
            )
        return HealthReport(status="healthy", capabilities={"ThreatIntel": CapabilityHealth(status="healthy")})

    def _path(self, indicator: Indicator) -> str:
        value = indicator.value.strip()
        if indicator.type == "file":
            return f"/files/{value}"
        if indicator.type == "url":
            encoded = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
            return f"/urls/{encoded}"
        if indicator.type == "domain":
            return f"/domains/{value}"
        return f"/ip_addresses/{value}"

    @operation(
        "lookup",
        classification="read",
        capability="ThreatIntel",
        input_model=Indicator,
        output_model=IntelReport,
        egress_class="third_party_shared",
    )
    async def lookup(self, args: Indicator) -> IntelReport:
        result = await self.http.request("GET", self._path(args))
        data = result.json().get("data") or {}
        attributes = data.get("attributes") or {}
        stats = attributes.get("last_analysis_stats") or {}
        return IntelReport(
            indicator=args.value,
            type=args.type,
            malicious=int(stats.get("malicious") or 0),
            suspicious=int(stats.get("suspicious") or 0),
            harmless=int(stats.get("harmless") or 0),
            undetected=int(stats.get("undetected") or 0),
            timeout=int(stats.get("timeout") or 0),
            reputation=attributes.get("reputation"),
            last_analysis_date=attributes.get("last_analysis_date"),
            categories=dict(attributes.get("categories") or {}),
            tags=list(attributes.get("tags") or []),
            reference=data.get("links", {}).get("self") if isinstance(data.get("links"), dict) else None,
        )
