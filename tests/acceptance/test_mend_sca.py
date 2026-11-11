"""Opt-in Mend SCA acceptance with live HTTP and separately gated writes."""

from __future__ import annotations

import asyncio
import base64
import hashlib
from pathlib import Path
from typing import Any

import httpx2

from icuhub.connectors.mend_sca.connector import MendSca
from icuhub.connectors.mend_sca.models import ImportSbomArgs, SetAlertStatusArgs
from icuhub.kit.testing import collect_stream, make_connector, map_all
from icuhub.kit.types import SourceRecord, Target
from icuhub_schemas.ocsf import VulnerabilityFinding

ACCEPTANCE_KIND = "mend_sca"
_PLAN_HASH_PLACEHOLDER = "0" * 64
_SUCCESS = {"succeeded", "no_op", "accepted_async"}


def _connector(acceptance) -> MendSca:
    config = {**acceptance.config, "write_enabled": acceptance.allow_writes}
    return make_connector(MendSca, config, httpx2.AsyncHTTPTransport(), acceptance.secrets)  # type: ignore[return-value]


def _target(project_uuid: str) -> Target:
    return Target(
        id=f"project-{project_uuid}",
        source_uid=project_uuid,
        kind="project",
        display_name=f"Project {project_uuid}",
        attributes={},
    )


def _run(connector: MendSca, name: str, probe: Any) -> tuple[Any, Any]:
    """Plan, bind approval, apply once, and reconcile the resulting vendor state."""
    spec = connector.actions()[name]
    plan = asyncio.run(spec.plan(connector, probe))
    approved = probe.model_copy(update={"approved_plan_hash": plan.plan_hash})
    replanned = asyncio.run(spec.plan(connector, approved))
    assert replanned.plan_hash == plan.plan_hash, "plan changed between approval rounds"
    outcome = asyncio.run(spec.apply(connector, replanned))
    assert spec.reconcile is not None
    outcome = asyncio.run(spec.reconcile(connector, replanned, outcome))
    return replanned, outcome


def _payload(path: Path) -> tuple[str, str, int]:
    content = path.read_bytes()
    return base64.b64encode(content).decode("ascii"), hashlib.sha256(content).hexdigest(), len(content)


def test_health(acceptance) -> None:
    report = asyncio.run(_connector(acceptance).check())
    capability = report.capabilities.get("FindingSource")
    passed = report.status == "healthy" and capability is not None and capability.status == "healthy"
    acceptance.record("health", passed, report.status)
    assert passed


def test_projects_read(acceptance) -> None:
    connector = _connector(acceptance)
    batches = collect_stream(connector, "projects", mode="full")
    records = [record for batch in batches for record in batch.records]
    projects = map_all(connector, "projects", records)
    passed = bool(records) and any(
        isinstance(project, SourceRecord) and project.record_type == "project" for project in projects
    )
    acceptance.record("projects_read", passed, f"{len(records)} projects", mapped_records=len(projects))
    assert passed


def test_security_findings_read(acceptance) -> None:
    connector = _connector(acceptance)
    target = _target(str(acceptance.params["project_uuid"]))
    batches = collect_stream(connector, "security_findings", target=target, mode="full")
    records = [record for batch in batches for record in batch.records]
    findings = map_all(connector, "security_findings", records, target=target)
    passed = bool(records) and bool(findings)
    passed = passed and all(isinstance(finding, VulnerabilityFinding) for finding in findings)
    acceptance.record("security_findings_read", passed, f"{len(records)} findings", mapped_findings=len(findings))
    assert passed


def test_gated_alert_triage(acceptance) -> None:
    acceptance.require_writes()
    connector = _connector(acceptance)
    args = SetAlertStatusArgs(
        project_token=str(acceptance.params["project_token"]),
        alert_uuid=str(acceptance.params["alert_uuid"]),
        desired_status=acceptance.params["desired_status"],
        approved_plan_hash=_PLAN_HASH_PLACEHOLDER,
    )
    plan, outcome = _run(connector, "set_alert_status", args)
    passed = outcome.status in _SUCCESS
    acceptance.record(
        "set_alert_status", passed, outcome.status, changed=plan.changed, result=outcome.result
    )
    assert passed


def test_gated_sbom_import(acceptance) -> None:
    acceptance.require_writes()
    connector = _connector(acceptance)
    path = Path(str(acceptance.params["sbom_path"]))
    encoded, sha256, size = _payload(path)
    args = ImportSbomArgs(
        project_uuid=str(acceptance.params["project_uuid"]),
        filename=path.name,
        sbom_base64=encoded,
        sbom_sha256=sha256,
        approved_plan_hash=_PLAN_HASH_PLACEHOLDER,
    )
    plan, outcome = _run(connector, "import_sbom", args)
    passed = outcome.status in _SUCCESS
    acceptance.record(
        "import_sbom",
        passed,
        outcome.status,
        changed=plan.changed,
        payload_bytes=size,
        result=outcome.result,
    )
    assert passed
