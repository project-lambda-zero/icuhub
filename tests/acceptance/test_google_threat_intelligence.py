"""Live GTI acceptance: health and one real indicator lookup (read-only)."""

from __future__ import annotations

import asyncio

from icuhub.connectors.google_threat_intelligence import GoogleThreatIntelligence
from icuhub.connectors.google_threat_intelligence.models import Indicator
from icuhub.kit.testing import RouteTransport, make_connector

ACCEPTANCE_KIND = "google_threat_intelligence"


def _connector(acceptance) -> GoogleThreatIntelligence:
    return make_connector(GoogleThreatIntelligence, acceptance.config, RouteTransport({}), acceptance.secrets)  # type: ignore[return-value]


def test_health(acceptance) -> None:
    report = asyncio.run(_connector(acceptance).check())
    acceptance.record("health", report.status == "healthy", report.status)
    assert report.status == "healthy"


def test_lookup_known_indicator(acceptance) -> None:
    connector = _connector(acceptance)
    indicator = Indicator(
        type=acceptance.params.get("type", "domain"),
        value=acceptance.params.get("value", "example.com"),
    )
    report = asyncio.run(connector.lookup(indicator))
    acceptance.record(
        "lookup",
        report.indicator == indicator.value,
        report.verdict,
        malicious=report.malicious,
        suspicious=report.suspicious,
    )
    assert report.indicator == indicator.value
