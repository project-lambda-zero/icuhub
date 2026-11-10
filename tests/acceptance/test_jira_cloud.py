"""Live Jira Cloud acceptance: discovery, bounded reads, attachments, and comments."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json

import httpx2
import pytest

from icuhub.connectors._jira.helpers import comment_marker
from icuhub.connectors._jira.models import (
    AddCommentInput,
    DownloadAttachmentInput,
    IssueCommentsInput,
    IssueInput,
    SearchInput,
    UpdateCommentInput,
)
from icuhub.connectors.jira_cloud.connector import IssueRefArgs, JiraCloud
from icuhub.kit.testing import make_connector
from icuhub.kit.types import SourceRecord

ACCEPTANCE_KIND = "jira_cloud"


def _connector(acceptance) -> JiraCloud:
    return make_connector(JiraCloud, acceptance.config, httpx2.AsyncHTTPTransport(), acceptance.secrets)  # type: ignore[return-value]


def _required_param(acceptance, name: str) -> str:
    if name not in acceptance.params:
        pytest.skip(f"jira_cloud: params.{name} is required")
    return str(acceptance.params[name])


def _find_comment(connector: JiraCloud, issue_key: str, comment_id: str) -> SourceRecord:
    page = asyncio.run(
        connector.list_issue_comments(IssueCommentsInput(issue_id_or_key=issue_key, max_results=1000))
    )
    match = next((item for item in page.comments if item.uid.endswith(f"/{comment_id}")), None)
    assert match is not None
    return match


def test_server_and_discovery(acceptance) -> None:
    report = asyncio.run(_connector(acceptance).check())
    healthy = report.status in ("healthy", "degraded")
    acceptance.record("server_and_discovery", healthy, report.status, version=report.vendor_version)
    assert healthy


def test_search_and_read_issue(acceptance) -> None:
    jql = _required_param(acceptance, "jql")
    issue_key = _required_param(acceptance, "issue_key")
    connector = _connector(acceptance)
    found = asyncio.run(connector.search_issues(SearchInput(jql=jql, max_results=10)))
    bounded = len(found.issues) <= 10
    acceptance.record("search_issues", bounded, f"{len(found.issues)} issues")
    assert bounded

    result = asyncio.run(connector.get_issue(IssueInput(issue_id_or_key=issue_key)))
    issue_id = result.issue.uid.rsplit("/", 1)[-1]
    stable_id = issue_id.isdigit() and bool(result.issue.key)
    acceptance.record("get_issue", stable_id, result.issue.key, issue_id=issue_id)
    assert stable_id


def test_comments_and_remote_links_read(acceptance) -> None:
    issue_key = _required_param(acceptance, "issue_key")
    connector = _connector(acceptance)
    comments = asyncio.run(
        connector.list_issue_comments(IssueCommentsInput(issue_id_or_key=issue_key, max_results=100))
    )
    links = asyncio.run(connector.list_remote_links(IssueRefArgs(issue_id_or_key=issue_key)))
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
    attachment_id = _required_param(acceptance, "attachment_id")
    connector = _connector(acceptance)
    download = asyncio.run(connector.download_attachment(DownloadAttachmentInput(attachment_id=attachment_id)))
    content = base64.b64decode(download.content_base64, validate=True)
    digest = hashlib.sha256(content).hexdigest()
    valid = digest == download.sha256 and len(content) == download.size and download.attachment_id == attachment_id
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
        pytest.skip("jira_cloud: params.write_enabled is not true")
    acceptance.require_writes()
    issue_key = _required_param(acceptance, "issue_key")
    connector = _connector(acceptance)
    action_key = "icuhub-live-acceptance-comment"
    add_plan = asyncio.run(
        connector.plan_add_comment(
            AddCommentInput(
                issue_id_or_key=issue_key,
                action_key=action_key,
                body="icuhub live acceptance comment",
            )
        )
    )
    added = asyncio.run(connector.apply_add_comment(add_plan))
    add_ok = added.status in ("succeeded", "no_op")
    acceptance.record("add_comment", add_ok, added.status)
    assert add_ok
    assert added.vendor_ref is not None and added.vendor_ref.startswith("jira_comment:")
    comment_id = added.vendor_ref.removeprefix("jira_comment:")

    current = _find_comment(connector, issue_key, comment_id)
    expected_updated = current.data.get("updated")
    assert isinstance(expected_updated, str)
    updated_body = f"icuhub live acceptance comment updated\n\n{comment_marker(action_key)}"
    update_plan = asyncio.run(
        connector.plan_update_comment(
            UpdateCommentInput(
                issue_id_or_key=issue_key,
                comment_id=comment_id,
                expected_updated=expected_updated,
                body=updated_body,
            )
        )
    )
    updated = asyncio.run(connector.apply_update_comment(update_plan))
    assert updated.status in ("succeeded", "no_op")

    persisted = _find_comment(connector, issue_key, comment_id)
    serialized = json.dumps(persisted.data.get("body"))
    body_matches = "icuhub live acceptance comment updated" in serialized and comment_marker(action_key) in serialized
    acceptance.record("update_comment_roundtrip", body_matches, updated.status, comment_id=comment_id)
    assert body_matches
