"""GitHub.com connector edition: the shared GitHub family pinned to api.github.com."""

from __future__ import annotations

from typing import ClassVar

from icuhub.connectors._github.connector import GitHubConnectorBase
from icuhub.connectors.github.models import GitHubComConfig

__all__ = ["GitHub"]


class GitHub(GitHubConnectorBase):
    """GitHub.com: shared GitHub behavior with the api.github.com API root enforced by config."""

    kind: ClassVar[str] = "github"
    display_name: ClassVar[str] = "GitHub.com"
    config_model: ClassVar[type[GitHubComConfig]] = GitHubComConfig
    flows: ClassVar[tuple[str, ...]] = ("F-021", "F-200")
