"""Behavior shared by the github.com and GitHub Enterprise Server connectors.

Both editions speak the same REST contract. Edition-specific parts stay in each package: the
base URL and host shape, and the enterprise audit scope. This module owns REST URL
construction, the API-version header, the body-HMAC webhook verifier, and the stable identity
used for action plans.
"""

from __future__ import annotations

import hashlib
from abc import abstractmethod

from icuhub.connectors._github.models import GitHubConfig
from icuhub.kit.connector import Connector
from icuhub.kit.errors import ConfigError
from icuhub.kit.webhook import HmacSignature, WebhookVerifier

__all__ = ["GITHUB_EVENT_HEADER", "GITHUB_DELIVERY_HEADER", "GITHUB_SIGNATURE_HEADER", "GitHubBase"]

GITHUB_SIGNATURE_HEADER = "x-hub-signature-256"
GITHUB_EVENT_HEADER = "x-github-event"
GITHUB_DELIVERY_HEADER = "x-github-delivery"


class GitHubBase(Connector):
    """Shared GitHub connector behavior. Subclasses supply ``installation_id`` and the API root."""

    config: GitHubConfig

    @abstractmethod
    def installation_id(self) -> str:
        """Stable identifier of the GitHub installation, used in record UIDs and dedupe keys."""

    @abstractmethod
    def api_root(self) -> str:
        """Absolute REST root without a trailing slash, e.g. ``https://api.github.com``."""

    def rest_url(self, path: str) -> str:
        """Build ``<api root><path>``; ``path`` must start with ``/``."""
        if not path.startswith("/"):
            raise ConfigError("GitHub REST path must start with '/'")
        return f"{self.api_root()}{path}"

    def api_headers(self) -> dict[str, str]:
        """Headers pinned on every request: the REST media type and the API version date."""
        return {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": self.config.api_version,
        }

    def webhook_verifier(self, secret: bytes) -> WebhookVerifier | None:
        if not secret:
            raise ConfigError("GitHub webhook secret must not be empty")
        return HmacSignature(
            GITHUB_SIGNATURE_HEADER,
            secret,
            id_header=GITHUB_DELIVERY_HEADER,
            event_header=GITHUB_EVENT_HEADER,
        )

    def action_identity(self, action: str, route_key: str) -> str:
        """Idempotency key for an action: stable across retries of the same route and tenant."""
        material = f"{self.ctx.tenant_id}\x1f{action}\x1f{route_key}".encode()
        return hashlib.sha256(material).hexdigest()

    def repo_uid(self, repository_id: int, alert_number: int | None = None) -> str:
        """Record UID keyed by numeric repository ID, so renames never split identity."""
        base = f"{self.installation_id()}:repository:{repository_id}"
        return base if alert_number is None else f"{base}:alert:{alert_number}"
