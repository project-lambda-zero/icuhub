"""Finding-to-ticket routing, one external record per (route, case) (ADR-0015, FR-COR-04)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from icuhub.core.actions import submit_action
from icuhub.core.auth_types import Caller
from icuhub.core.outbox import add_event
from icuhub.kit.types import TicketRecord
from icuhub.storage.models import (
    ActionRequest,
    CaseMember,
    Connection,
    CorrelationCase,
    Finding,
    TicketLink,
    TicketRoute,
)
from icuhub_schemas.events import CloudEvent

__all__ = [
    "JOB_HANDLERS",
    "case_event",
    "evaluate_routes",
    "on_action_terminal",
    "on_ticket_record",
    "render_arg",
    "render_ticket",
    "route_matches",
]

_REMEDIATION = {"open": "open", "in_progress": "in_progress", "done": "done", "unknown": "unknown"}


def route_matches(
    route: TicketRoute,
    case: CorrelationCase,
    findings: list[Finding],
    kind_by_connection: dict[uuid.UUID, str] | None = None,
) -> bool:
    """Match a route against the case and its observations."""
    match = route.match_json or {}
    findings = [finding for finding in findings if finding.status != "resolved_by_source"]
    if not findings:
        return False
    if match.get("require_correlation_key", True) and case.correlation_key.startswith("v1|own|"):
        return False
    if (classes := match.get("ocsf_class_uids")) and not any(f.ocsf_class_uid in classes for f in findings):
        return False
    if (kinds := match.get("connector_kinds")) and not any(
        (kind_by_connection or {}).get(f.connection_id) in kinds for f in findings
    ):
        return False
    if (min_severity := match.get("min_severity_id")) is not None and case.severity_id < min_severity:
        return False
    if (connections := match.get("finding_connection_ids")) and not any(
        str(f.connection_id) in connections for f in findings
    ):
        return False
    return True


def render_ticket(route: TicketRoute, case: CorrelationCase, findings: list[Finding]) -> dict[str, Any]:
    """Render tracker create arguments from the route template and the case evidence."""
    template = route.template_json or {}
    observations = sorted(
        (
            {
                "connector": f.connection_id,
                "source_uid": f.source_uid,
                "severity_id": f.severity_id,
                "title": f.title,
                "url": (f.ocsf_json.get("finding_info") or {}).get("src_url"),
            }
            for f in findings
        ),
        key=lambda o: str(o["source_uid"]),
    )
    lines = [
        f"Correlation case: {case.id}",
        f"Correlation key: {case.correlation_key}",
        f"Highest severity id: {case.severity_id}",
        "",
        "Source observations:",
    ]
    for obs in observations:
        lines.append(f"- {obs['title'] or obs['source_uid']} ({obs['source_uid']})")
        if obs["url"]:
            lines.append(f"  {obs['url']}")
    summary = (case.title or case.correlation_key)[:240]
    route_key = f"route:{route.id}:case:{case.id}"
    if route.action == "create_finding_or_exception":
        field_values = dict(template.get("field_values", {}))
        field_values[str(template["title_field"])] = summary
        field_values[str(template["description_field"])] = "\n".join(lines)[:30000]
        return {
            "record_type": template["record_type"],
            "correlation_value": route_key,
            "field_values": field_values,
        }
    labels = sorted(set(template.get("labels", [])) | {"icuhub", f"case-{str(case.id)[:8]}"})
    args: dict[str, Any] = {
        "summary": summary,
        "description": "\n".join(lines)[:30000],
        "labels": labels,
        "route_key": route_key,
    }
    for field in ("project", "project_key", "issue_type", "priority", "assignee", "fields"):
        if field in template:
            args[field] = template[field]
    return args


async def case_event(session: AsyncSession, case: CorrelationCase) -> None:
    await add_event(
        session,
        case.tenant_id,
        CloudEvent(
            id=f"case-{case.id}-{uuid.uuid4()}",
            source=f"icuhub://cases/{case.id}",
            type="icuhub.case.updated",
            subject=str(case.id),
            time=datetime.now(UTC),
            data={"remediation_state": case.remediation_state, "detection_state": case.detection_state},
        ),
    )


async def evaluate_routes(session: AsyncSession, case: CorrelationCase) -> list[uuid.UUID]:
    """Create at most one ticket per (route, case); repeated evaluation is a no-op."""
    members = (
        (await session.execute(select(CaseMember).where(CaseMember.case_id == case.id))).scalars().all()
    )
    findings = [
        finding
        for finding in (
            await session.execute(select(Finding).where(Finding.id.in_([m.finding_id for m in members])))
        )
        .scalars()
        .all()
        if finding.status != "resolved_by_source"
    ]
    routes = (
        (await session.execute(select(TicketRoute).where(TicketRoute.tenant_id == case.tenant_id)))
        .scalars()
        .all()
    )
    kind_by_connection = {
        row.id: row.kind
        for row in (
            await session.execute(select(Connection).where(Connection.tenant_id == case.tenant_id))
        )
        .scalars()
        .all()
    }
    created: list[uuid.UUID] = []
    for route in routes:
        if not route.enabled or not route_matches(route, case, findings, kind_by_connection):
            continue
        existing = (
            await session.execute(
                select(TicketLink).where(TicketLink.tenant_id == case.tenant_id, TicketLink.route_id == route.id,
                                         TicketLink.case_id == case.id)
            )
        ).scalar_one_or_none()
        if existing is not None:
            continue
        link = TicketLink(
            tenant_id=case.tenant_id,
            route_id=route.id,
            case_id=case.id,
            connection_id=route.connection_id,
            state="pending",
        )
        session.add(link)
        await session.flush()
        caller = Caller(id=f"route:{route.name}", tenant_id=case.tenant_id, roles=frozenset({"system"}))
        request = await submit_action(
            session,
            caller,
            route.connection_id,
            route.action,
            render_ticket(route, case, findings),
            idempotency_key=f"route:{route.id}:case:{case.id}",
            correlation_id=str(case.id),
        )
        link.action_request_id = request.id
        link.state = request.state
        if request.state in ("succeeded", "no_op"):
            await on_action_terminal(session, request)
        created.append(link.id)
    if case.remediation_state == "new" and created:
        case.remediation_state = "routed"
        await case_event(session, case)
    return created


async def on_action_terminal(session: AsyncSession, request: ActionRequest) -> TicketLink | None:
    """Record the created remote object once the create action reached a terminal state."""
    from icuhub.core.exceptions import CALLER_ID, converge_after_terminal  # noqa: PLC0415

    if request.caller_id == CALLER_ID:
        await converge_after_terminal(session, request)
        return None
    link = (
        await session.execute(select(TicketLink).where(TicketLink.action_request_id == request.id))
    ).scalar_one_or_none()
    if link is None:
        return None
    link.state = request.state
    result = request.result_json or {}
    vendor_raw = result.get("result")
    vendor: dict[str, Any] = vendor_raw if isinstance(vendor_raw, dict) else result
    remote_key = vendor.get("key") or vendor.get("issue_key") or result.get("vendor_ref")
    if remote_key:
        link.remote_key = str(remote_key)
        link.last_outbound_revision = str(vendor.get("revision") or vendor.get("id") or remote_key)
    remote_url = vendor.get("url") or vendor.get("self")
    if remote_url:
        link.remote_url = str(remote_url)
    if vendor.get("id"):
        link.remote_id = str(vendor["id"])
    if request.state == "succeeded":
        link.last_synced_at = datetime.now(UTC)
    return link


async def on_ticket_record(session: AsyncSession, connection: Any, record: TicketRecord) -> TicketLink | None:
    """Status sync from a tracker stream or webhook. Echoes are suppressed (FR-TKT-09).

    Remediation state follows the tracker; detection state is never touched (FR-COR-05).
    """
    link = (
        await session.execute(
            select(TicketLink).where(TicketLink.connection_id == connection.id, TicketLink.remote_key == record.key)
        )
    ).scalar_one_or_none()
    if link is None:
        return None
    revision = record.revision or (record.updated_at.isoformat() if record.updated_at else None)
    if revision is not None and revision == link.last_inbound_revision:
        return link
    if revision is not None and revision == link.last_outbound_revision:
        link.last_inbound_revision = revision
        return link
    previous_category = link.status_category
    link.remote_status = record.status
    link.status_category = record.status_category
    link.remote_url = record.url or link.remote_url
    if revision is not None:
        link.last_inbound_revision = revision
    link.last_synced_at = datetime.now(UTC)
    case = await session.get(CorrelationCase, link.case_id)
    if case is None:
        return link
    new_state = _REMEDIATION.get(record.status_category, "unknown")
    route = await session.get(TicketRoute, link.route_id)
    policy = (route.status_policy_json if route else {}) or {}
    if new_state == "done" and policy.get("ignore_done", False):
        new_state = case.remediation_state
    if case.remediation_state == "done" and new_state in ("open", "in_progress"):
        if not policy.get("allow_reopen", True):
            new_state = case.remediation_state
    if new_state != case.remediation_state:
        case.remediation_state = new_state
        case.updated_at = datetime.now(UTC)
        await case_event(session, case)
    if route is not None and previous_category != record.status_category:
        await _request_source_actions(session, link, case, route, record.status_category)
    return link


async def _request_source_actions(
    session: AsyncSession,
    link: TicketLink,
    case: CorrelationCase,
    route: TicketRoute,
    status_category: str,
) -> None:
    """Turn an authoritative tracker transition into governed source actions (F2).

    Only a category transition into a configured trigger creates a request. Repeated
    revisions within the same category and echoes never reach this point. The request
    goes through ``submit_action``, so a separate approval and the source plan's
    revision check still gate the write. Tracker state never writes ``Finding.status``.
    """
    config = (route.status_policy_json or {}).get("source_action")
    if not config or status_category not in config["status_categories"]:
        return
    members = (
        await session.execute(
            select(Finding)
            .join(CaseMember, CaseMember.finding_id == Finding.id)
            .where(CaseMember.case_id == case.id)
            .order_by(Finding.id)
        )
    ).scalars().all()
    caller = Caller(id=f"route:{route.name}", tenant_id=case.tenant_id, roles=frozenset({"system"}))
    for finding in members:
        revision = _dotted_get(finding.ocsf_json or {}, config["source_revision_path"])
        if revision is None:
            continue
        values = {"source_uid": finding.source_uid or "", "source_revision": str(revision)}
        args = {key: render_arg(value, values) for key, value in config["args"].items()}
        await submit_action(
            session,
            caller,
            uuid.UUID(config["connection_id"]),
            config["action"],
            args,
            idempotency_key=f"f2:{link.id}:{finding.id}:{config['mapping_version']}",
            correlation_id=str(case.id),
        )


def _dotted_get(document: dict[str, Any], path: str) -> Any:
    node: Any = document
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def render_arg(value: Any, values: dict[str, str]) -> Any:
    if isinstance(value, str):
        rendered = value
        for key, replacement in values.items():
            rendered = rendered.replace("{" + key + "}", replacement)
        return rendered
    return value


async def run_route_case_job(payload: dict[str, Any], lease: Any = None) -> dict[str, Any]:
    """Worker handler for the ``route_case`` job kind."""
    from icuhub.storage.db import session_scope  # noqa: PLC0415

    async with session_scope(uuid.UUID(payload["tenant_id"])) as session:
        case = await session.get(CorrelationCase, uuid.UUID(payload["case_id"]))
        if case is None:
            return {"skipped": True}
        created = await evaluate_routes(session, case)
    return {"links": [str(x) for x in created]}


JOB_HANDLERS = {"route_case": run_route_case_job}
