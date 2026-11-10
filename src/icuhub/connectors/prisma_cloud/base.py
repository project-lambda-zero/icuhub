"""Shared runtime, authentication, and pagination helpers for Prisma Cloud."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlparse

from icuhub.connectors.prisma_cloud.auth import ProfileAuth
from icuhub.connectors.prisma_cloud.models import PrismaCloudConfig
from icuhub.kit.auth import AuthStrategy, BasicAuth, SessionLogin
from icuhub.kit.connector import Connector
from icuhub.kit.errors import (
    AuthFailed,
    ConfigError,
    ConnectorError,
    PermissionDenied,
    VendorContractError,
)
from icuhub.kit.types import CapabilityHealth, HealthReport, Scope, TargetRecord

__all__ = ["PrismaBase"]


class PrismaBase(Connector):
    kind = "prisma_cloud"
    version = "1.0.0"
    display_name = "Prisma Cloud"
    config_model = PrismaCloudConfig
    auth_modes = ("SessionLogin", "BasicAuth")
    capabilities = ("FindingSource", "TelemetrySource", "Enforcer")
    flows = ("F-214", "F-229")
    scopes = (
        Scope(name="cspm_alerts", probe="POST /v2/alert", required_by=("FindingSource",)),
        Scope(name="cspm_audit", probe="GET /audit/event", required_by=("TelemetrySource",)),
        Scope(name="cspm_policy_rql", probe="POST /v2/config", required_by=("FindingSource",)),
        Scope(name="cspm_inventory", probe="POST /v3/inventory", required_by=("FindingSource",)),
        Scope(name="cspm_accounts", probe="GET /cloud", required_by=("FindingSource",)),
        Scope(name="cspm_export", probe="POST /alert/export", required_by=("FindingSource",)),
        Scope(name="compute_version", probe="GET /api/v1/version", required_by=("FindingSource",)),
        Scope(name="compute_images", probe="GET /api/v1/images", required_by=("FindingSource",)),
        Scope(name="compute_runtime", probe="GET /api/v1/audits/runtime/container", required_by=("TelemetrySource",)),
        Scope(name="compute_collections", probe="GET /api/v1/collections", required_by=("Enforcer",)),
    )

    def __init__(self, config: PrismaCloudConfig, ctx: Any) -> None:
        super().__init__(config, ctx)
        hosts = [config.base_url, config.cspm_base_url, config.compute_base_url]
        extra = list(config.extra_hosts)
        for value in hosts[1:]:
            if value:
                host = urlparse(value).netloc
                if host and host not in extra:
                    extra.append(host)
        config.extra_hosts = tuple(extra)

    def _cfg(self) -> PrismaCloudConfig:
        return self.config  # type: ignore[return-value]

    def require_destructive(self, action_name: str) -> None:
        if not self._cfg().destructive_enabled:
            raise ConfigError(f"{action_name} requires destructive_enabled=true")

    def _require_edition(self, edition: str) -> None:
        if edition not in self._cfg().editions:
            raise ConfigError(f"Prisma {edition} edition is not enabled for this connection")

    def _profile_base(self, profile: str) -> str:
        configured = self._cfg().cspm_base_url if profile == "cspm" else self._cfg().compute_base_url
        return (configured or self._cfg().base_url).rstrip("/")

    def _url(self, profile: str, path: str) -> str:
        return f"{self._profile_base(profile)}/{path.lstrip('/')}"

    def _compute_path(self, path: str) -> str:
        return f"/api/v{self._cfg().compute_api_version}/{path.lstrip('/')}"

    async def _request(self, profile: str, method: str, path: str, **kwargs: Any) -> Any:
        self._require_edition(profile)
        return await self.http.request(method, self._url(profile, path), **kwargs)

    @staticmethod
    def _object(result: Any, where: str) -> dict[str, Any]:
        body = result.json()
        if not isinstance(body, dict):
            raise VendorContractError(f"{where} response must be an object")
        return body

    @staticmethod
    def _array(body: Any, where: str, keys: tuple[str, ...] = ("items", "results", "data")) -> list[dict[str, Any]]:
        if isinstance(body, list):
            values = body
        elif isinstance(body, dict):
            values = None
            for key in keys:
                candidate = body.get(key)
                if isinstance(candidate, list):
                    values = candidate
                    break
                if key == "data" and isinstance(candidate, dict):
                    nested = candidate.get("items")
                    if isinstance(nested, list):
                        values = nested
                        break
            if values is None:
                raise VendorContractError(f"{where} response has no result array")
        else:
            raise VendorContractError(f"{where} response must be an array or object")
        if not all(isinstance(item, dict) for item in values):
            raise VendorContractError(f"{where} result array contains a non-object item")
        return values

    @staticmethod
    def _digest(value: Any) -> str:
        return hashlib.sha256(json.dumps(value, sort_keys=True, default=str, separators=(",", ":")).encode()).hexdigest()

    async def _secret(self, ref: Any) -> str:
        value = await self.ctx.secrets.resolve(ref)
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ConfigError("Prisma credentials must be UTF-8") from exc

    async def build_auth(self) -> AuthStrategy:
        cfg = self._cfg()
        strategies: dict[str, AuthStrategy] = {}
        hosts: dict[str, str] = {}
        if "cspm" in cfg.editions:
            key_id = cfg.cspm_access_key_id
            key_secret = await self._secret(cfg.cspm_access_key_secret)

            async def cspm_login() -> tuple[str, str, datetime | None]:
                result = await self.http.request(
                    "POST",
                    self._url("cspm", "/login"),
                    json={"username": key_id, "password": key_secret},
                    idempotency="non_idempotent",
                    authenticate=False,
                )
                body = self._object(result, "CSPM login")
                token = body.get("token")
                if not isinstance(token, str) or not token:
                    raise VendorContractError("CSPM login returned no token")
                expires_in = float(body.get("expires_in") or 600)
                return "x-redlock-auth", token, datetime.now(UTC) + timedelta(seconds=max(1, expires_in - 30))

            strategies["cspm"] = SessionLogin(cspm_login, clock=self.ctx.clock)
            hosts["cspm"] = urlparse(self._profile_base("cspm")).netloc
        if "compute" in cfg.editions:
            username = cfg.compute_username or ""
            password = await self._secret(cfg.compute_password)
            if cfg.compute_auth_mode == "basic":
                strategies["compute"] = BasicAuth(username, password)
            else:

                async def compute_login() -> tuple[str, str, datetime | None]:
                    result = await self.http.request(
                        "POST",
                        self._url("compute", self._compute_path("/authenticate")),
                        json={"username": username, "password": password},
                        idempotency="non_idempotent",
                        authenticate=False,
                    )
                    body = self._object(result, "Compute login")
                    token = body.get("token")
                    if not isinstance(token, str) or not token:
                        raise VendorContractError("Compute login returned no token")
                    expires_in = float(body.get("expires_in") or 1800)
                    return "Authorization", f"Bearer {token}", datetime.now(UTC) + timedelta(seconds=max(1, expires_in - 60))

                strategies["compute"] = SessionLogin(compute_login, clock=self.ctx.clock)
            hosts["compute"] = urlparse(self._profile_base("compute")).netloc
        if len(strategies) == 1:
            return next(iter(strategies.values()))
        return ProfileAuth(strategies, hosts)

    async def check(self) -> HealthReport:
        capabilities: dict[str, CapabilityHealth] = {}
        details: dict[str, Any] = {"editions": self._cfg().editions}
        healthy = True
        for edition in self._cfg().editions:
            try:
                if edition == "cspm":
                    result = await self._request("cspm", "POST", "/v2/alert", json={"detailed": True, "limit": 1})
                    body = self._object(result, "CSPM health")
                    if not isinstance(body.get("items"), list):
                        raise VendorContractError("CSPM health response has no items")
                    capabilities["FindingSource"] = CapabilityHealth(status="healthy")
                else:
                    result = await self._request("compute", "GET", self._compute_path("/version"))
                    body = self._object(result, "Compute version")
                    details["compute_version"] = body.get("version")
                    capabilities["TelemetrySource"] = CapabilityHealth(status="healthy")
                    capabilities["FindingSource"] = CapabilityHealth(status="healthy")
            except PermissionDenied as exc:
                healthy = False
                capabilities["FindingSource"] = CapabilityHealth(status="not_evaluated", reason=str(exc))
            except (AuthFailed, ConnectorError) as exc:
                healthy = False
                capabilities["FindingSource"] = CapabilityHealth(status="failing", reason=str(exc))
        return HealthReport(
            status="healthy" if healthy else "degraded",
            capabilities=capabilities,
            vendor_version=str(details.get("compute_version")) if details.get("compute_version") else None,
            detail=details,
        )

    async def discover(self):
        if "cspm" in self._cfg().editions:
            result = await self._request("cspm", "GET", "/cloud")
            for account in self._array(result.json(), "cloud accounts", ("cloudAccounts", "items", "data")):
                account_id = str(account.get("accountId") or account.get("id") or "")
                if not account_id:
                    continue
                yield TargetRecord(
                    source_uid=account_id,
                    kind="cloud_account",
                    display_name=str(account.get("name") or account_id),
                    attributes={"cloud_type": account.get("cloudType"), "enabled": account.get("enabled"), "status": account.get("status")},
                )
