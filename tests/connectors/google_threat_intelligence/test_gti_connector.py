"""Offline GTI lookup tests (MVP 4.19)."""

from __future__ import annotations

import asyncio
import base64
import json
from pathlib import Path

from icuhub.connectors.google_threat_intelligence import GoogleThreatIntelligence
from icuhub.connectors.google_threat_intelligence.models import Indicator
from icuhub.kit.testing import RouteTransport, make_connector

FIXTURE = json.loads(
    (Path(__file__).resolve().parents[2] / "fixtures" / "google_threat_intelligence" / "domain_report.json").read_text()
)


def _connector() -> GoogleThreatIntelligence:
    routes = {
        ("GET", "/api/v3/domains/evil.example"): {"status": 200, "json": FIXTURE},
        ("GET", "/api/v3/users/current"): {"status": 200, "json": {"data": {"id": "user"}}},
    }
    return make_connector(
        GoogleThreatIntelligence, {"api_key": {"ref": "gti"}}, RouteTransport(routes), {"gti": b"key"}
    )  # type: ignore[return-value]


def test_lookup_maps_report_and_verdict() -> None:
    connector = _connector()
    report = asyncio.run(connector.lookup(Indicator(type="domain", value="evil.example")))
    assert report.malicious == 7 and report.suspicious == 2
    assert report.harmless == 60 and report.undetected == 20 and report.timeout == 1
    assert report.reputation == -3
    assert report.categories["Forcepoint"] == "Malicious Websites"
    assert report.tags == ["phishing"]
    assert report.verdict == "malicious"
    assert report.reference and report.reference.endswith("/domains/example")


def test_url_indicator_uses_unpadded_base64url() -> None:
    connector = _connector()
    path = connector._path(Indicator(type="url", value="https://evil.example/path?q=1"))
    expected = base64.urlsafe_b64encode(b"https://evil.example/path?q=1").decode().rstrip("=")
    assert path == f"/urls/{expected}"
    assert "=" not in path


def test_indicator_paths_and_validation() -> None:
    connector = _connector()
    assert connector._path(Indicator(type="file", value="AA11")) == "/files/AA11"
    assert connector._path(Indicator(type="ip", value="192.0.2.1")) == "/ip_addresses/192.0.2.1"


def test_health() -> None:
    connector = _connector()
    assert asyncio.run(connector.check()).status == "healthy"


def test_declarations() -> None:
    spec = GoogleThreatIntelligence.operations()["lookup"]
    assert spec.egress_class == "third_party_shared"
    assert GoogleThreatIntelligence.rate_limits["default"] == (4, 60)
    assert not GoogleThreatIntelligence.actions()
    assert not GoogleThreatIntelligence.streams()
