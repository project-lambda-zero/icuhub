"""github.com configuration: the shared GitHub config pinned to the public API root."""

from __future__ import annotations

from urllib.parse import urlsplit

from pydantic import model_validator

from icuhub.connectors._github.models import GitHubConfig

__all__ = ["GitHubComConfig"]


class GitHubComConfig(GitHubConfig):
    """github.com configuration; rejects any API root that is not api.github.com."""

    @model_validator(mode="after")
    def _require_github_com(self) -> GitHubComConfig:
        parts = urlsplit(self.base_url)
        hostname = (parts.hostname or "").rstrip(".").lower()
        if hostname != "api.github.com" or parts.path not in ("", "/"):
            raise ValueError(
                "GitHubComConfig requires the https://api.github.com API root; "
                "use github_enterprise_server for other hosts"
            )
        return self
