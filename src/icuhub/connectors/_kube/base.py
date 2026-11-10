"""Behavior shared by the Kubernetes and OpenShift connectors.

Both editions speak the same native API server contract. Edition packages supply the
``target_kind`` and their edition-specific stream and action bindings. This module owns
credential resolution, the cached API client, health probing, cluster discovery, the audit
webhook verifier, and the stable identity used for action plans.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar, Literal

import yaml

from icuhub.connectors._kube.client import KubeApiClient
from icuhub.connectors._kube.models import KubeConfig
from icuhub.kit.auth import AuthStrategy, BearerToken
from icuhub.kit.connector import Connector
from icuhub.kit.errors import AuthFailed, ConfigError, ConnectorError, PermissionDenied
from icuhub.kit.types import CapabilityHealth, HealthReport, TargetRecord
from icuhub.kit.webhook import SharedToken, WebhookVerifier

__all__ = ["CLUSTER_CAPABILITY", "KubeBase"]

CLUSTER_CAPABILITY = "ClusterOps"
_IN_CLUSTER_TOKEN = "/var/run/secrets/kubernetes.io/serviceaccount/token"
_MAX_KUBECONFIG_BYTES = 1024 * 1024


@dataclass(frozen=True)
class _TransportAuth:
    """Adds no header: X.509 client authentication happens in the TLS handshake.

    ``client_cert`` and ``client_key`` are transport configuration on ``ConnectorConfig``; the kit
    loads them into the TLS context. This strategy exists only because the kit requires one.
    """

    async def apply(self, request_headers: dict[str, str], method: str, url: str) -> None:
        """No header is written; the TLS layer carries the client identity."""

    async def refresh(self) -> bool:
        return False


def _ascii_token(raw: bytes, source: str) -> str:
    token = raw.strip()
    if not token:
        raise ConfigError(f"Kubernetes {source} is empty")
    try:
        return token.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ConfigError(f"Kubernetes {source} must be ASCII") from exc


def _named_entry(items: object, name: str, key: str, what: str) -> dict[str, Any]:
    if isinstance(items, list):
        for item in items:
            if isinstance(item, dict) and item.get("name") == name and isinstance(item.get(key), dict):
                return item[key]
    raise ConfigError(f"kubeconfig {what} {name!r} not found")


class _StrictKubeconfigLoader(yaml.SafeLoader):
    """``SafeLoader`` that rejects duplicate mapping keys; no other object construction is added."""


def _construct_unique_mapping(loader: yaml.SafeLoader, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
    seen: set[Any] = set()
    for key_node, _value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in seen
        except TypeError as exc:
            raise ConfigError("kubeconfig mapping key is not hashable") from exc
        if duplicate:
            raise ConfigError(f"kubeconfig has duplicate key {key!r}")
        seen.add(key)
    return loader.construct_mapping(node, deep=deep)


_StrictKubeconfigLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping)


def _parse_kubeconfig(raw: bytes) -> dict[str, Any]:
    """Parse a standard YAML or JSON kubeconfig through ``yaml.safe_load`` with duplicate-key rejection.

    JSON is a YAML subset, so one validated path covers both. Size, document shape, and unsafe tags
    are rejected here, before any credential is read from the document.
    """
    if len(raw) > _MAX_KUBECONFIG_BYTES:
        raise ConfigError(f"kubeconfig exceeds {_MAX_KUBECONFIG_BYTES} bytes")
    try:
        # Subclass of SafeLoader: only safe tags construct, plus duplicate-key rejection.
        document = yaml.load(raw, Loader=_StrictKubeconfigLoader)
    except yaml.YAMLError as exc:
        raise ConfigError("kubeconfig is not a valid single YAML or JSON document") from exc
    if not isinstance(document, dict):
        raise ConfigError("kubeconfig must be a single mapping document")
    return document


def _kubeconfig_token(raw: bytes, context_name: str | None) -> str:
    """Read the bearer token of the selected context's user from a YAML or JSON kubeconfig.

    Certificate-only users are handled by ``client_cert`` and ``client_key``, not by this path.
    """
    document = _parse_kubeconfig(raw)
    selected = context_name or document.get("current-context")
    if not isinstance(selected, str) or not selected:
        raise ConfigError("kubeconfig selects no context; set kubeconfig_context")
    context = _named_entry(document.get("contexts"), selected, "context", "context")
    user = _named_entry(document.get("users"), str(context.get("user", "")), "user", "user")
    token = user.get("token")
    if not isinstance(token, str):
        raise ConfigError(
            "kubeconfig user has no bearer token; use client_cert and client_key for certificate authentication"
        )
    return _ascii_token(token.encode("utf-8"), "kubeconfig token")


class KubeBase(Connector):
    """Shared Kubernetes connector behavior. Edition packages set ``target_kind``."""

    target_kind: ClassVar[str]
    config: KubeConfig
    _api_client: KubeApiClient | None = None

    @property
    def api(self) -> KubeApiClient:
        """The API client over the attached HTTP transport, created once per connector instance."""
        if self._api_client is None:
            self._api_client = KubeApiClient(
                self.http,
                page_size=self.config.page_size,
                max_pages=self.config.max_pages,
                max_watch_events=self.config.max_watch_events,
            )
        return self._api_client

    async def build_auth(self) -> AuthStrategy:
        token = await self._bearer_token()
        if token is None:
            # KubeConfig rejects a configuration with neither a token source nor a client certificate.
            return _TransportAuth()
        return BearerToken(token)

    async def _bearer_token(self) -> str | None:
        cfg = self.config
        if cfg.bearer_token is not None:
            return _ascii_token(await self.ctx.secrets.resolve(cfg.bearer_token), "bearer token")
        if cfg.bearer_file is not None:
            return _ascii_token(await _read_file(cfg.bearer_file), "bearer token path")
        if cfg.kubeconfig is not None:
            raw = await self.ctx.secrets.resolve(cfg.kubeconfig)
            return _kubeconfig_token(raw, cfg.kubeconfig_context)
        if cfg.in_cluster:
            return _ascii_token(await _read_file(_IN_CLUSTER_TOKEN), "in-cluster service account token")
        return None

    async def check(self) -> HealthReport:
        detail: dict[str, Any] = {"cluster": self.config.cluster_name, "api_server": self.config.base_url}
        try:
            version = await self.api.server_version()
        except AuthFailed as exc:
            return HealthReport(status="failing", capabilities=self._cluster_only(exc, "failing"), detail=detail)
        except PermissionDenied as exc:
            return HealthReport(status="degraded", capabilities=self._cluster_only(exc, "degraded"), detail=detail)
        except (ConnectorError, OSError, TimeoutError, RuntimeError) as exc:
            return HealthReport(status="degraded", capabilities=self._cluster_only(exc, "degraded"), detail=detail)
        git_version = version.data.get("gitVersion")
        capabilities = {
            name: CapabilityHealth(status="healthy")
            if name == CLUSTER_CAPABILITY
            else CapabilityHealth(status="not_evaluated", reason="not probed by the cluster health check")
            for name in self.capabilities
        }
        return HealthReport(
            status="healthy",
            capabilities=capabilities,
            vendor_version=git_version if isinstance(git_version, str) else None,
            detail=detail,
        )

    def _cluster_only(self, exc: BaseException, status: Literal["failing", "degraded"]) -> dict[str, CapabilityHealth]:
        """Only the cluster capability was probed; every other declared capability is not evaluated."""
        reason = type(exc).__name__
        return {
            name: CapabilityHealth(status=status, reason=reason)
            if name == CLUSTER_CAPABILITY
            else CapabilityHealth(status="not_evaluated", reason=reason)
            for name in self.capabilities
        }

    async def discover(self) -> AsyncIterator[TargetRecord]:
        """Yield the one cluster this connection addresses; the cluster name is the stable source UID."""
        cluster = self.config.cluster_name
        yield TargetRecord(
            source_uid=cluster,
            kind=self.target_kind,
            display_name=cluster,
            attributes={"cluster": cluster, "api_server": self.config.base_url},
        )

    def webhook_verifier(self, secret: bytes) -> WebhookVerifier | None:
        """Bearer audit deliveries are checked against the shared token; mTLS deliveries carry no header check."""
        if self.config.audit_webhook_auth == "mtls":
            return None
        if not secret:
            raise ConfigError("Kubernetes audit webhook bearer secret must not be empty")
        return SharedToken("authorization", f"Bearer {_ascii_token(secret, 'audit webhook secret')}")

    def action_identity(self, action: str, natural_key: Mapping[str, Any]) -> str:
        """Idempotency key bound to the cluster, the target object, and the desired diff.

        ``natural_key`` carries the cluster GVR, namespace, name, UID and resourceVersion precondition,
        and a hash of the redacted desired diff. It MUST NOT carry request bodies or secret material.
        Two plans for the same object and diff collide; a changed UID, resourceVersion, or diff does not.
        """
        canonical = json.dumps(
            {"cluster": self.config.cluster_name, "action": action, "key": natural_key},
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        material = f"{self.ctx.tenant_id}\x1f{canonical}".encode()
        return hashlib.sha256(material).hexdigest()


async def _read_file(path: str) -> bytes:
    try:
        return await asyncio.to_thread(Path(path).read_bytes)
    except OSError as exc:
        raise ConfigError(f"cannot read Kubernetes credential file {path!r}") from exc
