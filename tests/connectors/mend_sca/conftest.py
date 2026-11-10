"""Shared Mend SCA connector test factory (offline; kit RouteTransport, no network)."""

from collections.abc import Mapping
from typing import Any

from icuhub.connectors.mend_sca.connector import MendSca
from icuhub.kit.testing import RouteTransport as _RouteTransport
from icuhub.kit.testing import make_connector
from icuhub.kit.types import Target

ORG_UUID = "00000000-0000-4000-8000-000000000002"
BASE_URL = "https://mend.example.test"
LOGIN = ("POST", "/api/v3.0/login")
REFRESH = ("POST", "/api/v3.0/login/accessToken")
BASE_CONFIG: dict[str, Any] = {
    "base_url": BASE_URL,
    "api_version": "3.0",
    "email": "api-user@example.test",
    "user_key": {"ref": "vault:mend-user-key"},
    "org_uuid": ORG_UUID,
}
SECRETS = {"vault:mend-user-key": b"test-user-key"}
# Shapes per https://api-docs.mend.io/platform/3.0/access-management/login.md (refreshToken, jwtTTL)
# and .../refreshaccesstoken.md (jwtToken, tokenTTL).
LOGIN_ROUTE: dict[tuple[str, str], Any] = {
    LOGIN: {"json": {"response": {"userUuid": ORG_UUID, "refreshToken": "example-refresh", "jwtTTL": 1800}}},
    REFRESH: {"json": {"response": {"orgUuid": ORG_UUID, "jwtToken": "example-jwt", "tokenTTL": 1800}}},
}


def _with_default_status(routes: Mapping[Any, Any]) -> dict[Any, Any]:
    """Fill the RouteTransport-required ``status`` key, defaulting to 200."""
    out: dict[Any, Any] = {}
    for key, value in routes.items():
        if isinstance(value, Mapping):
            out[key] = {"status": 200, **value}
        elif callable(value):

            def wrap(request: Any, _fn: Any = value) -> Any:
                result = _fn(request)
                if isinstance(result, Mapping):
                    return {"status": 200, **result}
                return result

            out[key] = wrap
        else:
            out[key] = value
    return out


def RouteTransport(routes: Mapping[Any, Any]) -> _RouteTransport:  # noqa: N802 - mirrors the kit factory name
    """RouteTransport with the login route preinstalled and response ``status`` defaulting to 200."""
    return _RouteTransport(_with_default_status({**LOGIN_ROUTE, **routes}))


def make_mend(transport: Any, *, config_overrides: Mapping[str, Any] | None = None, secrets: Any = None) -> MendSca:
    """Build a Mend SCA connector wired to a route mapping or a kit transport."""
    if isinstance(transport, Mapping):
        transport = RouteTransport(transport)
    cfg = {**BASE_CONFIG, **(config_overrides or {})}
    return make_connector(MendSca, cfg, transport, secrets or SECRETS)  # type: ignore[return-value]


def project_target(source_uid: str = "00000000-0000-4000-8000-000000000101", name: str = "example-project-one") -> Target:
    return Target(
        id=f"project-{source_uid}",
        source_uid=source_uid,
        kind="project",
        display_name=name,
        attributes={},
    )
