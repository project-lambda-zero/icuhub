"""GitHub Enterprise Server connector edition: the shared GitHub family pinned to a self-hosted API root."""

from __future__ import annotations

from typing import ClassVar

from icuhub.connectors._github.connector import GitHubConnectorBase
from icuhub.connectors.github_enterprise_server.models import GitHubEnterpriseServerConfig
from icuhub.kit import HealthReport
from icuhub.kit.errors import ConnectorError, VendorContractError
from icuhub.kit.http import HttpResult

__all__ = ["GitHubEnterpriseServer"]

GHES_VERSION_HEADER = "x-github-enterprise-version"


def _installed_version(response: HttpResult) -> str:
    """The documented ``installed_version`` string from the ``GET /meta`` body."""
    body = response.json()
    version = body.get("installed_version") if isinstance(body, dict) else None
    if not isinstance(version, str) or not version:
        raise VendorContractError("GHES /meta response requires a non-empty installed_version string")
    return version


def _header_version_matches(response: HttpResult, version: str) -> bool:
    """Cross-check the undocumented header only when a server sends it; absence is not an error."""
    header = response.headers.get(GHES_VERSION_HEADER)
    return header is None or header == version


class GitHubEnterpriseServer(GitHubConnectorBase):
    """GitHub Enterprise Server: shared GitHub behavior on the configured GHES host."""

    kind: ClassVar[str] = "github_enterprise_server"
    display_name: ClassVar[str] = "GitHub Enterprise Server"
    config_model: ClassVar[type[GitHubEnterpriseServerConfig]] = GitHubEnterpriseServerConfig
    flows: ClassVar[tuple[str, ...]] = ("F-103",)

    async def check(self) -> HealthReport:
        report = await super().check()
        try:
            meta = await self.request("GET", "/meta")
            version = _installed_version(meta)
            if not _header_version_matches(meta, version):
                raise VendorContractError(f"GHES {GHES_VERSION_HEADER} header disagrees with installed_version")
        except ConnectorError as exc:
            status = "failing" if report.status == "failing" else "degraded"
            detail = {**report.detail, "ghes_version_error": type(exc).__name__}
            return report.model_copy(update={"status": status, "detail": detail})
        detail = {**report.detail, "ghes_version": version}
        return report.model_copy(update={"vendor_version": version, "detail": detail})
