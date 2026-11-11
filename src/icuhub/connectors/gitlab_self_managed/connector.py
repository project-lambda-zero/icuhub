"""GitLab Self-Managed connector edition: shared GitLab family plus instance-level health probes."""

from __future__ import annotations

import re
from typing import Any, ClassVar

from icuhub.connectors._gitlab.connector import ULTIMATE_CAPABILITIES, ULTIMATE_PLAN, GitLabConnectorBase
from icuhub.connectors._gitlab.models import SelfManagedGitLabConfig
from icuhub.kit import CapabilityHealth, HealthReport, NotFound
from icuhub.kit.errors import ConnectorError, PermissionDenied, VendorContractError

__all__ = ["GitLabSelfManaged"]

# Standard Webhooks signatures (``webhook-signature``) were introduced in GitLab 19.0 and generally
# available in 19.1. Earlier instances only send ``X-Gitlab-Token``.
_STANDARD_WEBHOOKS_MIN_VERSION = (19, 0)
_VERSION_PATTERN = re.compile(r"^(\d+)\.(\d+)")


def _instance_version(body: Any) -> str:
    if not isinstance(body, dict) or not isinstance(body.get("version"), str) or not body["version"]:
        raise VendorContractError("GitLab /version response has no version string")
    return str(body["version"])


def _standard_webhooks_state(version: str) -> str:
    match = _VERSION_PATTERN.match(version)
    if match is None:
        return "not_evaluated"
    numeric = (int(match.group(1)), int(match.group(2)))
    return "available" if numeric >= _STANDARD_WEBHOOKS_MIN_VERSION else "not_evaluated"


class GitLabSelfManaged(GitLabConnectorBase):
    """GitLab Self-Managed and Dedicated: explicit API root, per-host version, shared GitLab behavior."""

    kind: ClassVar[str] = "gitlab_self_managed"
    display_name: ClassVar[str] = "GitLab Self-Managed"
    config_model: ClassVar[type[SelfManagedGitLabConfig]] = SelfManagedGitLabConfig
    flows: ClassVar[tuple[str, ...]] = ("F-027", "F-101")

    async def _instance_plan(self) -> str | None:
        """Return the instance plan from ``GET /license``, which is documented for Self-Managed and Dedicated."""
        try:
            body = await self._get("/license")
        except NotFound as exc:
            raise PermissionDenied("GitLab license endpoint is unavailable; Ultimate cannot be verified") from exc
        plan = body.get("plan") if isinstance(body, dict) else None
        return plan if isinstance(plan, str) else None

    async def _plan_for_project(self, project_id: int) -> str | None:
        # The instance license applies to every project on the host, so the target id is not needed.
        del project_id
        return await self._instance_plan()

    async def _audit_events_state(self) -> str:
        """Probe the administrator-only audit events endpoint used by the audit stream reader."""
        try:
            await self._get("/audit_events", params={"per_page": 1})
        except (PermissionDenied, NotFound) as exc:
            return f"not_evaluated:{type(exc).__name__}"
        return "available"

    async def check(self) -> HealthReport:
        report = await super().check()
        capabilities = dict(report.capabilities)
        detail = dict(report.detail)
        status = report.status
        vendor_version: str | None = None
        try:
            plan = await self._instance_plan()
        except PermissionDenied as exc:
            for name in ULTIMATE_CAPABILITIES:
                capabilities[name] = CapabilityHealth(status="not_evaluated", reason=type(exc).__name__)
        except (ConnectorError, OSError, TimeoutError, RuntimeError) as exc:
            for name in ULTIMATE_CAPABILITIES:
                capabilities[name] = CapabilityHealth(status="degraded", reason=type(exc).__name__)
            status = "degraded"
        else:
            for name in ULTIMATE_CAPABILITIES:
                if plan == ULTIMATE_PLAN:
                    capabilities[name] = CapabilityHealth(status="healthy")
                else:
                    capabilities[name] = CapabilityHealth(status="not_evaluated", reason="PlanNotUltimate")

        try:
            vendor_version = _instance_version(await self._get("/version"))
        except ConnectorError as exc:
            detail["version_error"] = type(exc).__name__
            status = "degraded"
        else:
            detail["standard_webhooks"] = _standard_webhooks_state(vendor_version)

        try:
            detail["audit_events"] = await self._audit_events_state()
        except (ConnectorError, OSError, TimeoutError, RuntimeError) as exc:
            detail["audit_events"] = f"degraded:{type(exc).__name__}"
            status = "degraded"

        detail["ca_bundle"] = "configured" if self._config().ca_bundle_pem else "system_trust"
        return report.model_copy(
            update={
                "status": status,
                "capabilities": capabilities,
                "detail": detail,
                "vendor_version": vendor_version,
            }
        )
