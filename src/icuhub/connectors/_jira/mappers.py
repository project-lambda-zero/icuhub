"""Pure Jira vendor-record to ICUHUB record mapping."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from icuhub.kit.errors import VendorContractError
from icuhub.kit.mapping import bounded_raw, epoch_ms
from icuhub.kit.types import MapContext, SourceRecord, TicketRecord
from icuhub_schemas.ocsf import (
    Actor,
    Api,
    ApiActivity,
    Cloud,
    Metadata,
    NetworkEndpoint,
    Product,
    ResourceDetails,
    Service,
    User,
)

_STATUS_CATEGORY = {
    "new": "open",
    "indeterminate": "in_progress",
    "done": "done",
}


def required_str(raw: dict[str, Any], key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value:
        raise VendorContractError(f"Jira {key} must be a non-empty string")
    return value


def parse_time(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise VendorContractError(f"Jira {field} must be an ISO-8601 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise VendorContractError(f"Jira {field} must be an ISO-8601 string") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise VendorContractError(f"Jira {field} must include a timezone")
    return parsed.astimezone(UTC)


def installation_id(raw: dict[str, Any], ctx: MapContext) -> str:
    supplied = raw.get("_jira_installation")
    if isinstance(supplied, str) and supplied:
        return supplied
    if ctx.target is not None:
        target_value = ctx.target.attributes.get("installation")
        if isinstance(target_value, str) and target_value:
            return target_value
    return ctx.connection_id


def project_parts(raw: dict[str, Any]) -> tuple[str | None, str | None]:
    fields = raw.get("fields")
    if not isinstance(fields, dict):
        return None, None
    project = fields.get("project")
    if not isinstance(project, dict):
        return None, None
    project_id = project.get("id")
    project_key = project.get("key")
    return (
        str(project_id) if project_id is not None else None,
        project_key if isinstance(project_key, str) else None,
    )


def issue_url(raw: dict[str, Any], key: str) -> str | None:
    base = raw.get("_jira_base_url")
    if isinstance(base, str) and base:
        return base.rstrip("/") + "/browse/" + key
    value = raw.get("self")
    return value if isinstance(value, str) else None


def map_issue(raw: dict[str, Any], ctx: MapContext) -> TicketRecord:
    issue_id = required_str(raw, "id")
    key = required_str(raw, "key")
    fields = raw.get("fields")
    if not isinstance(fields, dict):
        raise VendorContractError("Jira issue fields must be an object")
    status = fields.get("status")
    if not isinstance(status, dict):
        raise VendorContractError("Jira issue status must be an object")
    status_name = required_str(status, "name")
    category = status.get("statusCategory")
    category_key = category.get("key") if isinstance(category, dict) else None
    status_category = _STATUS_CATEGORY.get(category_key, "unknown") if isinstance(category_key, str) else "unknown"
    updated_text = required_str(fields, "updated")
    updated = parse_time(updated_text, "fields.updated")
    resolution = fields.get("resolution")
    resolution_name = resolution.get("name") if isinstance(resolution, dict) else None
    labels = fields.get("labels", [])
    if not isinstance(labels, list) or not all(isinstance(label, str) for label in labels):
        raise VendorContractError("Jira issue labels must be an array of strings")
    project_id, project_key = project_parts(raw)
    installation = installation_id(raw, ctx)
    fingerprint_links = [label.removeprefix("icuhub-fp-") for label in labels if label.startswith("icuhub-fp-")]
    links: dict[str, str] = {"self": required_str(raw, "self")} if isinstance(raw.get("self"), str) else {}
    if project_id:
        links["project"] = f"jira_project:{installation}/{project_id}"
    return TicketRecord(
        uid=f"jira_issue:{installation}/{issue_id}",
        key=key,
        revision=f"{issue_id}:{updated_text}",
        status=status_name,
        status_category=status_category,
        resolution=resolution_name if isinstance(resolution_name, str) else None,
        url=issue_url(raw, key),
        updated_at=updated,
        labels=labels,
        fingerprint_links=fingerprint_links,
        data={
            "summary": fields.get("summary"),
            "description": fields.get("description"),
            "project_id": project_id,
            "project_key": project_key,
            "issue_type": fields.get("issuetype"),
            "assignee": fields.get("assignee"),
            "reporter": fields.get("reporter"),
            "raw_data": bounded_raw(raw),
        },
        links=links,
    )


def map_project(raw: dict[str, Any], ctx: MapContext) -> SourceRecord:
    project_id = required_str(raw, "id")
    key = required_str(raw, "key")
    installation = installation_id(raw, ctx)
    return SourceRecord(
        record_type="project",
        uid=f"jira_project:{installation}/{project_id}",
        revision=str(raw.get("version")) if raw.get("version") is not None else None,
        data={
            "key": key,
            "name": raw.get("name"),
            "project_type_key": raw.get("projectTypeKey"),
            "lead": raw.get("lead"),
            "raw_data": bounded_raw(raw),
        },
        links={"self": required_str(raw, "self")} if isinstance(raw.get("self"), str) else {},
    )


def map_comment(raw: dict[str, Any], ctx: MapContext) -> SourceRecord:
    comment_id = required_str(raw, "id")
    issue = raw.get("_jira_issue")
    if not isinstance(issue, dict):
        raise VendorContractError("Jira comment is missing its parent issue")
    issue_id = required_str(issue, "id")
    installation = installation_id(raw, ctx)
    updated = raw.get("updated") or raw.get("created")
    revision = parse_time(updated, "comment.updated").isoformat()
    return SourceRecord(
        record_type="comment",
        uid=f"jira_comment:{installation}/{issue_id}/{comment_id}",
        revision=revision,
        data={
            "issue_id": issue_id,
            "issue_key": issue.get("key"),
            "body": raw.get("body"),
            "author": raw.get("author"),
            "created": raw.get("created"),
            "updated": raw.get("updated"),
            "properties": raw.get("properties"),
            "raw_data": bounded_raw(raw),
        },
        links={"self": required_str(raw, "self")} if isinstance(raw.get("self"), str) else {},
    )


def map_attachment(raw: dict[str, Any], ctx: MapContext) -> SourceRecord:
    attachment_id = required_str(raw, "id")
    issue = raw.get("_jira_issue")
    if not isinstance(issue, dict):
        raise VendorContractError("Jira attachment is missing its parent issue")
    issue_id = required_str(issue, "id")
    installation = installation_id(raw, ctx)
    links: dict[str, str] = {}
    for source, target in (("self", "self"), ("content", "content"), ("thumbnail", "thumbnail")):
        value = raw.get(source)
        if isinstance(value, str):
            links[target] = value
    return SourceRecord(
        record_type="evidence",
        uid=f"jira_attachment:{installation}/{issue_id}/{attachment_id}",
        revision=str(raw.get("created")) if raw.get("created") is not None else None,
        data={
            "issue_id": issue_id,
            "issue_key": issue.get("key"),
            "filename": required_str(raw, "filename"),
            "size": raw.get("size"),
            "media_type": raw.get("mimeType"),
            "author": raw.get("author"),
            "created": raw.get("created"),
            "raw_data": bounded_raw(raw),
        },
        links=links,
    )


def _actor(raw: dict[str, Any]) -> Actor:
    author = raw.get("author")
    if not isinstance(author, dict):
        author = raw.get("_jira_author")
    if isinstance(author, dict):
        uid = author.get("accountId") or author.get("key") or author.get("name")
        display = author.get("displayName")
        if uid is not None or display is not None:
            return Actor(
                user=User(
                    uid=str(uid) if uid is not None else None,
                    name=str(uid) if uid is not None else None,
                    display_name=str(display) if display is not None else None,
                    email_addr=author.get("emailAddress") if isinstance(author.get("emailAddress"), str) else None,
                )
            )
    source = raw.get("eventSource")
    return Actor(app_name=source if isinstance(source, str) and source else "not measured")


def _activity(
    raw: dict[str, Any],
    ctx: MapContext,
    *,
    activity_id: int,
    operation: str,
    occurred_at: str,
    resources: list[ResourceDetails],
) -> ApiActivity:
    milliseconds = epoch_ms(occurred_at)
    if milliseconds is None:
        raise VendorContractError("Jira activity timestamp is invalid")
    remote = raw.get("remoteAddress")
    source_name = raw.get("eventSource")
    if isinstance(remote, str) and remote:
        src = NetworkEndpoint(ip=remote)
    else:
        src = NetworkEndpoint(name=source_name if isinstance(source_name, str) and source_name else "not measured")
    return ApiActivity(
        activity_id=activity_id,
        type_uid=ApiActivity.CLASS_UID * 100 + activity_id,
        time=milliseconds,
        severity_id=0,
        metadata=Metadata(product=Product(name="Jira", vendor_name="Atlassian")),
        cloud=Cloud(provider="Atlassian"),
        osint=[],
        actor=_actor(raw),
        api=Api(operation=operation, service=Service(name="Jira", uid=installation_id(raw, ctx))),
        src_endpoint=src,
        resources=resources,
        message=raw.get("summary") if isinstance(raw.get("summary"), str) else None,
        raw_data=bounded_raw(raw),
        unmapped={
            "category": raw.get("category"),
            "changed_values": raw.get("changedValues") or raw.get("items"),
            "associated_items": raw.get("associatedItems"),
        },
    )


def map_changelog(raw: dict[str, Any], ctx: MapContext) -> ApiActivity:
    history_id = required_str(raw, "id")
    issue = raw.get("_jira_issue")
    if not isinstance(issue, dict):
        raise VendorContractError("Jira changelog is missing its parent issue")
    issue_id = required_str(issue, "id")
    installation = installation_id(raw, ctx)
    return _activity(
        raw,
        ctx,
        activity_id=3,
        operation="issue.update",
        occurred_at=required_str(raw, "created"),
        resources=[
            ResourceDetails(
                uid=f"jira_issue:{installation}/{issue_id}",
                name=str(issue.get("key") or issue_id),
                type="jira_issue",
                labels=[f"changelog:{history_id}"],
            )
        ],
    )


def map_audit(raw: dict[str, Any], ctx: MapContext) -> ApiActivity:
    record_id = required_str(raw, "id")
    resources: list[ResourceDetails] = []
    associated = raw.get("associatedItems", [])
    if isinstance(associated, list):
        for index, item in enumerate(associated):
            if not isinstance(item, dict):
                continue
            identifier = item.get("id") or item.get("name") or f"{record_id}:{index}"
            resources.append(
                ResourceDetails(
                    uid=str(identifier),
                    name=str(item.get("name") or identifier),
                    type=str(item.get("typeName")) if item.get("typeName") is not None else None,
                )
            )
    if not resources:
        resources.append(ResourceDetails(uid=f"jira_audit:{installation_id(raw, ctx)}/{record_id}", type="jira_audit"))
    return _activity(
        raw,
        ctx,
        activity_id=99,
        operation=required_str(raw, "summary"),
        occurred_at=required_str(raw, "created"),
        resources=resources,
    )
