"""Shared Archer connector test factory."""

from collections.abc import Mapping

from icuhub.connectors.archer.connector import Archer
from icuhub.kit.testing import RouteTransport as _RouteTransport
from icuhub.kit.testing import make_connector

BASE_CONFIG = {
    "base_url": "https://archer.example.test",
    "instance_name": "default",
    "user": "api-user",
    "password": {"ref": "vault:archer-password"},
}
SECRETS = {"vault:archer-password": b"test-password"}


def _with_default_status(routes: Mapping) -> dict:
    """Fill the RouteTransport-required ``status`` key, defaulting to 200."""
    out = {}
    for key, value in routes.items():
        if isinstance(value, Mapping):
            out[key] = {"status": 200, **value}
        elif callable(value):

            def wrap(request, _fn=value):
                result = _fn(request)
                if isinstance(result, Mapping):
                    return {"status": 200, **result}
                return result

            out[key] = wrap
        else:
            out[key] = value
    return out


def RouteTransport(routes: Mapping) -> _RouteTransport:  # noqa: N802 - mirrors the kit factory name
    """RouteTransport with response ``status`` defaulting to 200."""
    return _RouteTransport(_with_default_status(routes))


def make_archer(transport, *, config_overrides=None, secrets=None) -> Archer:
    """Build an Archer connector wired to routes or a kit transport."""
    if isinstance(transport, Mapping):
        transport = RouteTransport(_with_default_status(transport))
    cfg = {**BASE_CONFIG, **(config_overrides or {})}
    return make_connector(Archer, cfg, transport, secrets or SECRETS)
