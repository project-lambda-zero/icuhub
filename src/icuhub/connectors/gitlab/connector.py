"""GitLab.com connector edition: the shared GitLab family pinned to gitlab.com."""

from __future__ import annotations

from typing import ClassVar

from icuhub.connectors._gitlab import mappers, streams
from icuhub.connectors._gitlab.connector import GitLabConnectorBase
from icuhub.connectors.gitlab.models import GitLabComConfig

__all__ = ["GitLab"]


class GitLab(GitLabConnectorBase):
    """GitLab.com: shared GitLab behavior with the gitlab.com API root enforced by config."""

    kind: ClassVar[str] = "gitlab"
    display_name: ClassVar[str] = "GitLab.com"
    config_model: ClassVar[type[GitLabComConfig]] = GitLabComConfig
    flows: ClassVar[tuple[str, ...]] = ("F-022", "F-201")

    # GitLab.com-only batched audit delivery; self-managed does not inherit it (docs/MVP.md).
    audit_stream_objects = streams.audit_stream_objects
    map_audit_stream_object = mappers.map_audit_stream_object
