"""Live Jira Data Center acceptance: discovery, bounded reads, attachments, and comments."""

from __future__ import annotations

import asyncio
import base64
import hashlib

import httpx2
import pytest

from icuhub.connectors._jira.helpers import comment_marker
from icuhub.connectors._jira.models import AddCommentInput, IssueInput
from icuhub.connectors.jira_dc import JiraDataCenter
from icuhub.connectors.jira_dc.attachments import DownloadAttachmentArgs, GetAttachmentArgs
from icuhub.connectors.jira_dc.comments_links import ListCommentsArgs, ListRemoteLinksArgs, UpdateCommentArgs
from icuhub.connectors.jira_dc.connector import SearchIssuesArgs
from icuhub.kit.testing import make_connector

ACCEPTANCE_KIND = "jira_dc"


def _connector(acceptance) -> JiraDataCenter:
    return make_connector(JiraDataCenter, acceptance.config, httpx2.AsyncHTTPTransport(), acceptance.secrets)  # type: ignore[return-value]


def _required_param(acceptance, name: str) -> str:
    if name not in acceptance.params:
        pytest.skip(f"jira_dc: params.{name} is required")
    return str(acceptance.params[name])


def test_server_and_discovery(acceptance) -> None:
    report = asyncio.run(_connector(acceptance).check())
    healthy = report.status in ("healthy", "degraded")
    acceptance.record("server_and_discovery", healthy, report.status, version=report.vendor_version)
    assert healthy


def test_search_and_read_issue(acceptance) -> None:
    jql = _required_param(acceptance, "jql")
    issue_key = _required_param(acceptance, "issue_key")
    connector = _connector(acceptance)
    found = asyncio.run(connector.search_issues(SearchIssuesArgs(jql=jql, max_results=10)))
    bounded = len(found.issues) <= 10
    acceptance.record("search_issues", bounded, f"{len(found.issues)} issues", total=found.total)
    assert bounded

    result = asyncio.run(connector.get_issue(IssueInput(issue_id_or_key=issue_key)))
    issue_id = result.issue.revision.split(":", 1)[0] if result.issue.revision else ""
    stable_id = issue_id.isdigit() and result.issue.uid.endswith(f"/{issue_id}")
    acceptance.record("get_issue", stable_id, result.issue.key, issue_id=issue_id)
    assert stable_id


def test_comments_and_changelog_read(acceptance) -> None:
    issue_key = _required_param(acceptance, "issue_key")
    connector = _connector(acceptance)
    comments = asyncio.run(
        connector.list_comments(ListCommentsArgs(issue_id_or_key=issue_key, max_results=100))
    )
    links = asyncio.run(connector.list_remote_links(ListRemoteLinksArgs(issue_id_or_key=issue_key)))
    bounded = len(comments.comments) <= 100
    acceptance.record(
        "comments_and_remote_links",
        bounded,
        f"{len(comments.comments)} comments, {len(links.links)} remote links",
        comment_count=len(comments.comments),
        remote_link_count=len(links.links),
    )
    assert bounded


def test_attachment_download_bounded(acceptance) -> None:
    attachment_id = acceptance.params.get("attachment_id")
    if attachment_id is None:
        pytest.skip("jira_dc: params.attachment_id is required")
    attachment_id = str(attachment_id)
    connector = _connector(acceptance)
    metadata = asyncio.run(connector.get_attachment(GetAttachmentArgs(attachment_id=attachment_id)))
    download = asyncio.run(connector.download_attachment(DownloadAttachmentArgs(attachment_id=attachment_id)))
    content = base64.b64decode(download.content_base64, validate=True)
    digest = hashlib.sha256(content).hexdigest()
    valid = (
        digest == download.sha256
        and len(content) == download.size == metadata.size
        and download.attachment_id == metadata.attachment_id == attachment_id
    )
    acceptance.record(
        "attachment_download_bounded",
        valid,
        f"{len(content)} bytes",
        attachment_id=attachment_id,
        sha256=download.sha256,
    )
    assert digest == download.sha256
    assert valid


def test_update_comment_roundtrip(acceptance) -> None:
    if acceptance.params.get("write_enabled") is not True:
        pytest.skip("jira_dc: params.write_enabled is not true")
    acceptance.require_writes()
    issue_key = _required_param(acceptance, "issue_key")
    connector = _connector(acceptance)
    action_key = "icuhub-live-acceptance-comment"
    add_args = AddCommentInput(
        issue_id_or_key=issue_key,
        action_key=action_key,
        body="icuhub live acceptance comment",
    )
    add_plan = asyncio.run(connector.plan_add_comment(add_args))
    added = asyncio.run(connector.apply_add_comment(add_plan))
    add_ok = added.status in ("succeeded", "no_op")
    acceptance.record("add_comment", add_ok, added.status)
    assert add_ok
    assert added.vendor_ref is not None and added.vendor_ref.startswith("jira_comment:")
    comment_id = added.vendor_ref.removeprefix("jira_comment:")

    current_page = asyncio.run(
        connector.list_comments(ListCommentsArgs(issue_id_or_key=issue_key, max_results=1000))
    )
    current = next((item for item in current_page.comments if str(item.get("id")) == comment_id), None)
    assert current is not None
    expected_updated = current.get("updated")
    assert isinstance(expected_updated, str)
    updated_body = f"icuhub live acceptance comment updated\n\n{comment_marker(action_key)}"
    update_plan = asyncio.run(
        connector.plan_update_comment(
            UpdateCommentArgs(
                issue_id_or_key=issue_key,
                comment_id=comment_id,
                expected_updated=expected_updated,
                body=updated_body,
            )
        )
    )
    updated = asyncio.run(connector.apply_update_comment(update_plan))
    assert updated.status in ("succeeded", "no_op")

    read_back = asyncio.run(
        connector.list_comments(ListCommentsArgs(issue_id_or_key=issue_key, max_results=1000))
    )
    persisted = next((item for item in read_back.comments if str(item.get("id")) == comment_id), None)
    body_matches = persisted is not None and persisted.get("body") == updated_body
    acceptance.record("update_comment_roundtrip", body_matches, updated.status, comment_id=comment_id)
    assert body_matches
