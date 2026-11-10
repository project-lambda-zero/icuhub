"""Cross-scanner correlation (FR-COR-01..03, MVP.md section 3).

A stored finding is one source observation with its own per-connector fingerprint. The
correlation key is vendor-neutral: it never contains the connector kind, so a Fortify
observation and a Mend observation of the same problem land on one case. Observations
without a strong key each get their own case; near-miss findings must not merge.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from icuhub.core.audit import append as audit_append
from icuhub.core.auth_types import Caller
from icuhub.core.outbox import add_event
from icuhub.storage.models import CaseMember, CorrelationCase, EvidenceItem, Finding, RawBatch

__all__ = [
    "KEY_VERSION",
    "canonical_asset_key",
    "correlation_key",
    "link_finding",
    "merge_cases",
    "record_raw_evidence",
    "split_finding",
]

KEY_VERSION = 1


def _norm(value: str | None) -> str:
    return (value or "").strip().lower()


def _norm_path(path: str) -> str:
    p = path.strip().replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p


def _purl_base(purl: str) -> str:
    """Package URL without version or qualifiers: SCA findings for one package correlate."""
    base = purl.split("?", 1)[0].split("#", 1)[0]
    if base.startswith("pkg:") and "@" in base.rsplit("/", 1)[-1]:
        head, _, last = base.rpartition("/")
        base = f"{head}/{last.split('@', 1)[0]}"
    return _norm(base)


def canonical_asset_key(ocsf: dict[str, Any]) -> tuple[str, str] | None:
    """Return ``(kind, key)`` for the strongest asset identity in the observation."""
    resources = ocsf.get("resources") or []
    for res in resources:
        if not isinstance(res, dict):
            continue
        labels = {_norm(x) for x in (res.get("labels") or [])}
        uid = res.get("uid") or ""
        name = res.get("name") or ""
        hostname = res.get("hostname") or ""
        ip = res.get("ip") or ""
        for label in labels:
            if label.startswith("repo:"):
                return ("repository", _norm(label[5:]).removesuffix(".git"))
            if label.startswith("image:"):
                return ("image", _norm(label[6:]))
        if uid.startswith("pkg:"):
            return ("package", _purl_base(uid))
        if uid.startswith("arn:") or uid.startswith("crn:"):
            return ("cloud_resource", _norm(uid))
        if uid.startswith("sha256:"):
            return ("image", uid)
        if uid.startswith("http://") or uid.startswith("https://"):
            return ("url", _norm(uid).rstrip("/"))
        if uid.startswith("git") or uid.endswith(".git"):
            return ("repository", _norm(uid).removesuffix(".git"))
        if res.get("type") == "cloud_resource" and uid:
            return ("cloud_resource", _norm(uid))
        if hostname:
            return ("host", _norm(hostname))
        if ip:
            return ("host", ip.strip())
        if uid:
            return ("resource", _norm(uid))
        if name:
            return ("resource_name", _norm(name))
    vulns = ocsf.get("vulnerabilities") or []
    for vuln in vulns:
        for pkg in vuln.get("affected_packages") or []:
            if pkg.get("purl"):
                return ("package", _purl_base(pkg["purl"]))
            if pkg.get("name"):
                return ("package_name", _norm(pkg["name"]))
        for code in vuln.get("affected_code") or []:
            file = code.get("file") or {}
            if file.get("path"):
                return ("file", _norm_path(file["path"]))
    return None


def _vulnerability_ids(ocsf: dict[str, Any]) -> tuple[str | None, str | None, str | None]:
    """Return ``(cve, cwe, component)`` from the first vulnerability entry."""
    vulns = ocsf.get("vulnerabilities") or []
    if not vulns:
        return (None, None, None)
    vuln = vulns[0]
    cve = (vuln.get("cve") or {}).get("uid")
    cwe = (vuln.get("cwe") or {}).get("uid")
    component = None
    for pkg in vuln.get("affected_packages") or []:
        if pkg.get("purl"):
            component = _purl_base(pkg["purl"])
            break
        if pkg.get("name"):
            component = _norm(pkg["name"])
            break
    if component is None:
        for code in vuln.get("affected_code") or []:
            file = code.get("file") or {}
            if file.get("path"):
                line = code.get("start_line") or 0
                component = f"{_norm_path(file['path'])}#{line // 50}"
                break
    return (cve.upper() if cve else None, cwe.upper() if cwe else None, component)


def correlation_key(ocsf: dict[str, Any], *, connector_kind: str) -> tuple[str, int] | None:
    """Compute the versioned vendor-neutral key, or ``None`` when identity is too weak."""
    asset = canonical_asset_key(ocsf)
    if asset is None:
        return None
    asset_kind, asset_key = asset
    if not asset_key:
        return None
    cve, cwe, component = _vulnerability_ids(ocsf)
    if ocsf.get("class_uid") == 2003:
        compliance = ocsf.get("compliance") or {}
        control = compliance.get("control") or ""
        checks = compliance.get("checks") or []
        check_uid = checks[0].get("uid") if checks and isinstance(checks[0], dict) else None
        rule = _norm(check_uid or control)
        if not rule:
            return None
        return (f"v1|compliance|{rule}|{asset_kind}:{asset_key}", KEY_VERSION)
    if cve:
        suffix = f"|{component}" if component and asset_kind in ("package", "package_name") else ""
        return (f"v1|cve|{cve}|{asset_kind}:{asset_key}{suffix}", KEY_VERSION)
    if cwe:
        if not component:
            return None
        return (f"v1|cwe|{cwe}|{component}|{asset_kind}:{asset_key}", KEY_VERSION)
    # Detection findings without CVE/CWE: rule identity must be explicit, else no merge.
    info = ocsf.get("finding_info") or {}
    types = [_norm(t) for t in (info.get("types") or [])]
    rule = next((t for t in types if t and t not in ("vulnerability", "detection", "compliance")), "")
    if not rule or not component:
        return None
    return (f"v1|rule|{rule}|{component}|{asset_kind}:{asset_key}", KEY_VERSION)


def _case_event(case: CorrelationCase, event_type: str) -> Any:
    from icuhub_schemas.events import CloudEvent  # noqa: PLC0415

    return CloudEvent(
        id=f"case-{case.id}-{case.updated_at.timestamp()}",
        source=f"icuhub://cases/{case.id}",
        type=event_type,
        subject=str(case.id),
        time=case.updated_at,
        data={
            "tenant_id": str(case.tenant_id),
            "case_id": str(case.id),
            "correlation_key": case.correlation_key,
            "severity_id": case.severity_id,
            "detection_state": case.detection_state,
            "remediation_state": case.remediation_state,
            # Outbox identity hashes ``data``; a per-revision timestamp keeps a reopen distinct from the original open event.
            "updated_at": case.updated_at.isoformat(),
        },
    )


async def link_finding(session: AsyncSession, finding: Finding) -> CorrelationCase:
    """Link one observation to its case inside the caller's transaction."""
    key = correlation_key(finding.ocsf_json, connector_kind="")  # kind intentionally unused: keys are vendor-neutral
    if key is None:
        key = (f"v1|own|{finding.id}", KEY_VERSION)
    key_text, key_version = key
    finding.correlation_key = key_text
    case = (
        await session.execute(
            select(CorrelationCase).where(
                CorrelationCase.tenant_id == finding.tenant_id,
                CorrelationCase.correlation_key == key_text,
                CorrelationCase.merged_into.is_(None),
            )
        )
    ).scalar_one_or_none()
    now = datetime.now(UTC)
    if case is None:
        case = CorrelationCase(
            tenant_id=finding.tenant_id,
            correlation_key=key_text,
            key_version=key_version,
            title=finding.title or key_text,
            severity_id=finding.severity_id,
        )
        session.add(case)
        await session.flush()
        changed = True
    else:
        changed = False
        if finding.severity_id > case.severity_id:
            case.severity_id = finding.severity_id
            changed = True
        if finding.title and (not case.title or case.title == case.correlation_key):
            case.title = finding.title
            changed = True
    if finding.status == "resolved_by_source" and case.detection_state != "resolved_by_source":
        # Only a complete authoritative snapshot may have set this status upstream.
        others = (
            await session.execute(
                select(Finding.id).where(
                    Finding.tenant_id == finding.tenant_id,
                    Finding.correlation_key == key_text,
                    Finding.status != "resolved_by_source",
                    Finding.id != finding.id,
                )
            )
        ).first()
        if others is None:
            case.detection_state = "resolved_by_source"
            changed = True
    elif finding.status != "resolved_by_source" and case.detection_state != "open":
        # One open member keeps the case open; reappearing evidence reopens the aggregate.
        case.detection_state = "open"
        changed = True
    reason = "key_match" if not key_text.startswith("v1|own|") else "own_case"
    member = (await session.execute(select(CaseMember).where(CaseMember.finding_id == finding.id))).scalar_one_or_none()
    if member is None:
        session.add(CaseMember(finding_id=finding.id, tenant_id=finding.tenant_id, case_id=case.id, reason=reason, linked_by="correlation"))
    elif member.case_id != case.id:
        # A changed document can move its correlation key; re-linking must move the existing membership.
        member.case_id = case.id
        member.reason = reason
        member.linked_by = "correlation"
    if changed:
        case.updated_at = now
        await add_event(session, finding.tenant_id, _case_event(case, "icuhub.case.updated"))
    return case


async def record_raw_evidence(session: AsyncSession, case: CorrelationCase, raw: RawBatch) -> None:
    """Keep a raw batch that fed ``case`` as digest-addressed evidence, once per case.

    ``Finding.raw_batch_id`` names only the latest observation. This row is what keeps a
    superseded observation reachable from the case export.
    """
    present = (
        await session.execute(
            select(EvidenceItem.id).where(
                EvidenceItem.case_id == case.id,
                EvidenceItem.ref_table == "raw_batch",
                EvidenceItem.ref_id == raw.id,
            )
        )
    ).first()
    if present is None:
        session.add(
            EvidenceItem(
                tenant_id=case.tenant_id,
                case_id=case.id,
                kind="raw_batch",
                digest=raw.digest,
                ref_table="raw_batch",
                ref_id=raw.id,
            )
        )


async def merge_cases(session: AsyncSession, caller: Caller, source_id: uuid.UUID, target_id: uuid.UUID) -> CorrelationCase:
    """Move every member of ``source`` onto ``target`` (FR-COR-03). Audited."""
    source = await session.get(CorrelationCase, source_id)
    target = await session.get(CorrelationCase, target_id)
    if source is None or target is None or source.tenant_id != caller.tenant_id or target.tenant_id != caller.tenant_id:
        raise LookupError("case not found in caller tenant")
    if source.id == target.id:
        raise ValueError("cannot merge a case into itself")
    members = (await session.execute(select(CaseMember).where(CaseMember.case_id == source.id))).scalars().all()
    for member in members:
        member.case_id = target.id
        member.reason = "manual_merge"
        member.linked_by = caller.id
    source.merged_into = target.id
    target.severity_id = max(target.severity_id, source.severity_id)
    target.updated_at = datetime.now(UTC)
    await audit_append(
        session,
        caller.tenant_id,
        ts=datetime.now(UTC),
        caller_id=caller.id,
        operation="case.merge",
        status="succeeded",
        detail_json={"source": str(source_id), "target": str(target_id), "members": len(members)},
    )
    await add_event(session, caller.tenant_id, _case_event(target, "icuhub.case.updated"))
    return target


async def split_finding(session: AsyncSession, caller: Caller, finding_id: uuid.UUID) -> CorrelationCase:
    """Move one observation into a case of its own (FR-COR-03). Audited."""
    finding = await session.get(Finding, finding_id)
    if finding is None or finding.tenant_id != caller.tenant_id:
        raise LookupError("finding not found in caller tenant")
    member = (await session.execute(select(CaseMember).where(CaseMember.finding_id == finding.id))).scalar_one_or_none()
    if member is None:
        raise LookupError("finding is not linked to a case")
    key = f"v1|own|{finding.id}"
    previous = await session.get(CorrelationCase, member.case_id)
    case = CorrelationCase(
        tenant_id=finding.tenant_id,
        correlation_key=key,
        key_version=KEY_VERSION,
        title=finding.title or key,
        severity_id=finding.severity_id,
        remediation_state=previous.remediation_state if previous else "new",
    )
    session.add(case)
    await session.flush()
    member.case_id = case.id
    member.reason = "manual_split"
    member.linked_by = caller.id
    finding.correlation_key = key
    if finding.raw_batch_id is not None:
        # Batch-level evidence stays on the origin case; the split case carries the finding's current observation.
        raw = await session.get(RawBatch, finding.raw_batch_id)
        if raw is not None:
            await record_raw_evidence(session, case, raw)
    await audit_append(
        session,
        caller.tenant_id,
        ts=datetime.now(UTC),
        caller_id=caller.id,
        operation="case.split",
        status="succeeded",
        detail_json={"finding": str(finding_id), "new_case": str(case.id)},
    )
    await add_event(session, caller.tenant_id, _case_event(case, "icuhub.case.updated"))
    return case



