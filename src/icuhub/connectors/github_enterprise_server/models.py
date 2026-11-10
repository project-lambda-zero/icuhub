"""GitHub Enterprise Server configuration: the shared GitHub config pinned to a self-hosted API root."""

from __future__ import annotations

from urllib.parse import urlsplit

from pydantic import model_validator

from icuhub.connectors._github.models import GitHubConfig

__all__ = ["GitHubEnterpriseServerConfig"]


class GitHubEnterpriseServerConfig(GitHubConfig):
    """GHES configuration; requires a configured self-hosted host with the /api/v3 REST root."""

    @model_validator(mode="after")
    def _require_ghes_root(self) -> GitHubEnterpriseServerConfig:
        parts = urlsplit(self.base_url)
        hostname = (parts.hostname or "").rstrip(".").lower()
        if hostname in ("api.github.com", "github.com", "") or hostname.endswith(".github.com"):
            raise ValueError(
                "GitHubEnterpriseServerConfig requires a self-hosted GHES API root; "
                "use github for GitHub.com and Enterprise Cloud"
            )
        if parts.path.rstrip("/") != "/api/v3":
            raise ValueError("GitHubEnterpriseServerConfig base_url must end with /api/v3")
        return self
