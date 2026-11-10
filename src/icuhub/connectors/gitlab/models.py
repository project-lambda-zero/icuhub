"""GitLab.com configuration: the shared GitLab config pinned to the gitlab.com API root."""

from __future__ import annotations

from urllib.parse import urlsplit

from pydantic import model_validator

from icuhub.connectors._gitlab.models import GitLabConfig

__all__ = ["GitLabComConfig"]


class GitLabComConfig(GitLabConfig):
    """GitLab.com configuration; rejects any API root that is not the gitlab.com host."""

    @model_validator(mode="after")
    def _require_gitlab_com(self) -> GitLabComConfig:
        hostname = (urlsplit(self.base_url).hostname or "").rstrip(".").lower()
        if hostname != "gitlab.com":
            raise ValueError("GitLabComConfig requires the gitlab.com API root; use gitlab_self_managed for other hosts")
        return self
