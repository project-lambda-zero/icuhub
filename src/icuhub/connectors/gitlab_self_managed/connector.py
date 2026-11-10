"""GitLab Self-Managed connector edition: shared GitLab family plus a per-host version probe."""

from __future__ import annotations

from typing import Any, ClassVar

from icuhub.connectors._gitlab.connector import GitLabConnectorBase
from icuhub.connectors._gitlab.models import SelfManagedGitLabConfig
from icuhub.kit import HealthReport
from icuhub.kit.errors import ConnectorError, VendorContractError

__all__ = ["GitLabSelfManaged"]


def _instance_version(body: Any) -> str:
    if not isinstance(body, dict) or not isinstance(body.get("version"), str) or not body["version"]:
        raise VendorContractError("GitLab /version response has no version string")
    return str(body["version"])


class GitLabSelfManaged(GitLabConnectorBase):
    """GitLab Self-Managed and Dedicated: explicit API root, per-host version, shared GitLab behavior."""

    kind: ClassVar[str] = "gitlab_self_managed"
    display_name: ClassVar[str] = "GitLab Self-Managed"
    config_model: ClassVar[type[SelfManagedGitLabConfig]] = SelfManagedGitLabConfig
    flows: ClassVar[tuple[str, ...]] = ("F-027", "F-101")

    async def check(self) -> HealthReport:
        report = await super().check()
        try:
            version = _instance_version(await self._get("/version"))
        except ConnectorError as exc:
            detail = {**report.detail, "version_error": type(exc).__name__}
            return report.model_copy(update={"status": "degraded", "detail": detail})
        return report.model_copy(update={"vendor_version": version})
