"""Compute authentication, snapshot, and mapping tests."""

from __future__ import annotations

import asyncio
from typing import Any

from icuhub.connectors.prisma_cloud import PrismaCloud
from icuhub.kit.testing import collect_stream, map_all
from icuhub_schemas.ocsf import ComplianceFinding, DetectionFinding, VulnerabilityFinding

from .conftest import COMPUTE_CONFIG, compute_connector, load_fixture


def test_compute_basic_auth_uses_no_login_request() -> None:
    config = dict(COMPUTE_CONFIG)
    config["compute_auth_mode"] = "basic"
    seen: list[str | None] = []

    def images(request: Any) -> dict[str, Any]:
        seen.append(request.headers.get("authorization"))
        return {"status": 200, "json": []}

    from icuhub.kit.testing import RouteTransport, make_connector  # noqa: PLC0415

    from .conftest import SECRETS  # noqa: PLC0415

    connector = make_connector(PrismaCloud, config, RouteTransport({("GET", "/api/v1/images"): images}), SECRETS)
    assert collect_stream(connector, "compute_image_vulnerabilities", mode="full")[-1].complete is True
    assert seen[0] is not None and seen[0].startswith("Basic ")


def test_compute_session_token_is_applied_to_version_and_images() -> None:
    seen: list[str | None] = []

    def record(request: Any, body: Any) -> dict[str, Any]:
        seen.append(request.headers.get("authorization"))
        return {"status": 200, "json": body}

    connector = compute_connector({
        ("GET", "/api/v1/version"): lambda request: record(request, {"version": "34.0"}),
        ("GET", "/api/v1/images"): lambda request: record(request, []),
    })
    from icuhub.connectors.prisma_cloud.models import EmptyInput  # noqa: PLC0415

    asyncio.run(connector.get_compute_version(EmptyInput()))
    collect_stream(connector, "compute_image_vulnerabilities", mode="full")
    assert seen == ["Bearer compute-jwt", "Bearer compute-jwt", "Bearer compute-jwt"]


def test_image_snapshot_emits_asset_then_terminal_batch() -> None:
    image = load_fixture("compute_image.json")
    connector = compute_connector({("GET", "/api/v1/images"): {"status": 200, "json": [image]}})
    batches = collect_stream(connector, "compute_image_vulnerabilities", mode="full")
    assert len(batches) == 2
    assert batches[0].records[0]["_asset"]["_id"] == image["_id"]
    assert batches[-1].records == [] and batches[-1].complete is True


def test_image_vulnerability_and_compliance_are_distinct_findings() -> None:
    image = load_fixture("compute_image.json")
    connector = compute_connector({})
    vulnerabilities = map_all(connector, "compute_image_vulnerabilities", [{"_asset": image, "_finding": image["vulnerabilities"][0]}])
    compliance = map_all(connector, "compute_image_compliance", [{"_asset": image, "_finding": image["complianceIssues"][0]}])
    assert len(vulnerabilities) == 1 and isinstance(vulnerabilities[0], VulnerabilityFinding)
    assert vulnerabilities[0].vulnerabilities[0].cve is not None
    assert vulnerabilities[0].vulnerabilities[0].cve.uid == "CVE-2026-1000"
    assert vulnerabilities[0].vulnerabilities[0].affected_packages is not None
    assert vulnerabilities[0].vulnerabilities[0].affected_packages[0].name == "openssl"
    assert len(compliance) == 1 and isinstance(compliance[0], ComplianceFinding)
    vulnerabilities[0].to_ocsf()
    compliance[0].to_ocsf()


def test_runtime_audit_maps_to_detection_finding() -> None:
    connector = compute_connector({})
    mapped = map_all(connector, "compute_runtime_container_audits", [load_fixture("compute_audit.json")])
    assert len(mapped) == 1 and isinstance(mapped[0], DetectionFinding)
    assert mapped[0].finding_info.uid == "audit-1"
    assert mapped[0].unmapped is not None and mapped[0].unmapped["acknowledged"] is False
    mapped[0].to_ocsf()


def test_disabled_edition_stream_fails_before_network() -> None:
    connector = compute_connector({})
    import pytest  # noqa: PLC0415

    from icuhub.kit.errors import ConfigError  # noqa: PLC0415

    with pytest.raises(ConfigError, match="edition"):
        collect_stream(connector, "cspm_config_alerts")
