"""Connector-level tests for the Jira Data Center connector.

Covers auth wiring, health checks, the ``issues``, ``projects``, ``comments``,
``issue_changelogs``, and ``audit_records`` streams, the mappers, the
``search_issues`` operation, the destructive-write gate, and webhook verification
and parsing. Requests are answered by ``RouteTransport`` from the synthetic
fixtures in ``tests/fixtures/jira_dc/``.

Fixtures for ``/rest/api/2/auditing/record``, ``/rest/api/2/project``, and
``/rest/api/2/myself`` follow the unverified shapes the connector itself marks
``[UNVERIFIED]``; these tests pin the behavior the connector implements, not a
live Data Center response.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import httpx2
import pytest

from icuhub.connectors._jira.models import DeleteIssueInput
from icuhub.connectors._jira.webhooks import JiraDeliveryVerifier
from icuhub.connectors.jira_dc import JiraDataCenter
from icuhub.connectors.jira_dc.connector import SearchIssuesArgs
from icuhub.kit.errors import ConfigError, VendorContractError, WebhookRejected
from icuhub.kit.testing import RouteTransport, collect_stream, make_connector, map_all
from icuhub.kit.types import SourceRecord, WebhookDelivery
from icuhub.kit.webhook import SharedToken
from icuhub_schemas.ocsf import ApiActivity

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "jira_dc"
BASE = "https://jira.example.test"
PAT_REF = "jira-pat"
SECRETS = {PAT_REF: b"synthetic-pat"}
HMAC_SECRET = b"synthetic-webhook-secret"
NOW = datetime(2026, 11, 9, 12, 0, 0, tzinfo=UTC)
CONNECTION_ID = "test-connection"


def _load(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _bytes(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def _config(**extra: Any) -> dict[str, Any]:
    return {"base_url": BASE, "personal_access_token": {"ref": PAT_REF}, **extra}


def _connector(routes: dict[tuple[str, str], Any], **config_extra: Any) -> JiraDataCenter:
    return cast(
        JiraDataCenter,
        make_connector(JiraDataCenter, _config(**config_extra), RouteTransport(routes), SECRETS),
    )


def _recording(payload: Any, log: list[httpx2.Request], status: int = 200) -> Callable[[httpx2.Request], dict[str, Any]]:
    def handler(request: httpx2.Request) -> dict[str, Any]:
        log.append(request)
        return {"status": status, "json": payload}

    return handler


def _delivery(body: bytes, headers: dict[str, str] | None = None) -> WebhookDelivery:
    return WebhookDelivery(headers=headers or {}, body=body, received_at=NOW)


def _hmac_headers(body: bytes, secret: bytes = HMAC_SECRET) -> dict[str, str]:
    digest = hmac.new(secret, body, hashlib.sha256).hexdigest()
    return {"x-hub-signature": f"sha256={digest}"}


# --- auth and health --------------------------------------------------------


def test_non_ascii_personal_access_token_is_rejected() -> None:
    with pytest.raises(ConfigError, match="ASCII"):
        make_connector(
            JiraDataCenter,
            _config(),
            RouteTransport({}),
            {PAT_REF: b"\xff\xfe"},
        )


def test_health_is_healthy_when_identity_probe_succeeds() -> None:
    connector = _connector({("GET", "/rest/api/2/myself"): {"status": 200, "json": _load("myself.json")}})

    report = asyncio.run(connector.check())

    assert report.status == "healthy"


def test_health_is_failing_when_vendor_rejects_credentials() -> None:
    connector = _connector({("GET", "/rest/api/2/myself"): {"status": 401, "json": {"errorMessages": ["denied"]}}})

    report = asyncio.run(connector.check())

    assert report.status == "failing"


def test_health_is_degraded_when_permission_is_denied() -> None:
    connector = _connector({("GET", "/rest/api/2/myself"): {"status": 403, "json": {"errorMessages": ["forbidden"]}}})

    report = asyncio.run(connector.check())

    assert report.status == "degraded"


# --- issues stream ----------------------------------------------------------


def test_issues_full_stream_pages_search_and_returns_every_issue() -> None:
    seen: list[httpx2.Request] = []
    connector = _connector(
        {("GET", "/rest/api/2/search"): _recording(_load("search_issues.json"), seen)},
        jql="project = PROJ",
    )

    batches = collect_stream(connector, "issues", mode="full")

    records = [record for batch in batches for record in batch.records]
    assert [record["key"] for record in records] == ["PROJ-1", "PROJ-2"]
    assert batches[-1].complete is True
    assert seen[0].url.params["fields"] == "*all"


def test_issues_full_mode_applies_user_jql_without_window() -> None:
    seen: list[httpx2.Request] = []
    connector = _connector(
        {("GET", "/rest/api/2/search"): _recording(_load("search_issues.json"), seen)},
        jql="project = PROJ",
    )

    collect_stream(connector, "issues", mode="full")

    jql = seen[0].url.params["jql"]
    assert jql.startswith("(project = PROJ)")
    assert "updated >=" not in jql


def test_search_issues_operation_returns_mapped_issues_and_total() -> None:
    seen: list[httpx2.Request] = []
    connector = _connector({("GET", "/rest/api/2/search"): _recording(_load("search_issues.json"), seen)})

    output = asyncio.run(connector.search_issues(SearchIssuesArgs(jql="project = PROJ")))

    assert output.total == 2
    assert [issue.key for issue in output.issues] == ["PROJ-1", "PROJ-2"]
    assert seen[0].url.params["jql"] == "project = PROJ"


def test_projects_stream_rejects_incremental_mode() -> None:
    connector = _connector({})

    with pytest.raises(ValueError, match="does not support mode"):
        collect_stream(connector, "projects", mode="incremental")


def test_issue_mapper_produces_ticket_records() -> None:
    connector = _connector({})
    records = _load("search_issues.json")["issues"]

    mapped = map_all(connector, "issues", records)

    assert len(mapped) == 2


# --- projects stream --------------------------------------------------------


def test_projects_stream_maps_bare_array_listing() -> None:
    connector = _connector({("GET", "/rest/api/2/project"): {"status": 200, "json": _load("projects.json")}})

    batches = collect_stream(connector, "projects", mode="full")

    records = [record for batch in batches for record in batch.records]
    assert len(records) == 1
    (source,) = map_all(connector, "projects", records)
    assert cast(SourceRecord, source).uid == f"jira_project:{CONNECTION_ID}/10000"


def test_projects_stream_rejects_non_array_listing() -> None:
    connector = _connector({("GET", "/rest/api/2/project"): {"status": 200, "json": {"values": []}}})

    with pytest.raises(VendorContractError, match="must be an array"):
        collect_stream(connector, "projects", mode="full")


# --- comments stream --------------------------------------------------------


def test_comments_stream_fetches_each_issue_and_tags_parent() -> None:
    comments = _load("comments.json")
    search_seen: list[httpx2.Request] = []
    comment_seen: list[httpx2.Request] = []
    connector = _connector(
        {
            ("GET", "/rest/api/2/search"): _recording(_load("search_issues.json"), search_seen),
            ("GET", "/rest/api/2/issue/10001/comment"): _recording(comments, comment_seen),
            ("GET", "/rest/api/2/issue/10002/comment"): _recording(comments, comment_seen),
        }
    )

    batches = collect_stream(connector, "comments", mode="full")

    records = [record for batch in batches for record in batch.records]
    assert len(comment_seen) == 2
    assert [record["_jira_issue"]["id"] for record in records] == ["10001", "10002"]
    assert search_seen[0].url.params["fields"] == "id,key"


def test_comment_mapper_uses_parent_issue_in_uid() -> None:
    connector = _connector({})
    raw = {**_load("comments.json")["comments"][0], "_jira_issue": {"id": "10001", "key": "PROJ-1"}}

    (record,) = map_all(connector, "comments", [raw])

    assert cast(SourceRecord, record).uid == f"jira_comment:{CONNECTION_ID}/10001/30001"


# --- issue changelogs stream ------------------------------------------------


def test_changelog_stream_requests_expanded_search_and_flattens_histories() -> None:
    seen: list[httpx2.Request] = []
    connector = _connector(
        {("GET", "/rest/api/2/search"): _recording(_load("search_changelog.json"), seen)},
    )

    batches = collect_stream(connector, "issue_changelogs", mode="full")

    records = [record for batch in batches for record in batch.records]
    assert seen[0].url.params["expand"] == "changelog"
    assert [record["id"] for record in records] == ["20001"]
    assert records[0]["_jira_issue"] == {"id": "10001", "key": "PROJ-1"}


# --- audit records stream ---------------------------------------------------


def test_audit_stream_pages_auditing_endpoint() -> None:
    seen: list[httpx2.Request] = []
    connector = _connector(
        {("GET", "/rest/api/2/auditing/record"): _recording(_load("audit.json"), seen)},
    )

    batches = collect_stream(connector, "audit_records", mode="full")

    records = [record for batch in batches for record in batch.records]
    assert [record["id"] for record in records] == [40001, 40002]
    assert seen[0].url.params["offset"] == "0"


def test_audit_mapper_accepts_numeric_record_id() -> None:
    connector = _connector({})
    raw = _load("audit.json")["records"][0]
    assert isinstance(raw["id"], int)

    (activity,) = map_all(connector, "audit_records", [raw])

    assert [resource.name for resource in cast(ApiActivity, activity).resources or []] == ["synthetic.user"]


def test_audit_mapper_accepts_string_record_id() -> None:
    connector = _connector({})
    raw = {**_load("audit.json")["records"][0], "id": "40001"}

    (activity,) = map_all(connector, "audit_records", [raw])

    assert [resource.name for resource in cast(ApiActivity, activity).resources or []] == ["synthetic.user"]


# --- destructive gate -------------------------------------------------------


def test_delete_issue_is_refused_when_destructive_writes_are_disabled() -> None:
    connector = _connector({}, destructive_enabled=False)

    with pytest.raises(ConfigError, match="destructive_enabled is false"):
        asyncio.run(
            connector.plan_delete_issue(DeleteIssueInput(issue_id_or_key="PROJ-1", expected_id="10001"))
        )


# --- webhooks: HMAC ---------------------------------------------------------


def test_hmac_webhook_verifies_signed_body() -> None:
    connector = _connector({})
    body = _bytes("webhook_issue_updated.json")
    verifier = connector.webhook_verifier(HMAC_SECRET)
    assert verifier is not None

    result = verifier.verify(_delivery(body, _hmac_headers(body)), now=NOW)

    assert result.occurred_at == NOW


def test_hmac_webhook_rejects_wrong_signature() -> None:
    connector = _connector({})
    body = _bytes("webhook_issue_updated.json")
    verifier = connector.webhook_verifier(HMAC_SECRET)
    assert verifier is not None

    with pytest.raises(WebhookRejected, match="invalid webhook signature"):
        verifier.verify(_delivery(body, _hmac_headers(body, secret=b"other-secret")), now=NOW)


def test_hmac_webhook_rejects_missing_signature_header() -> None:
    connector = _connector({})
    body = _bytes("webhook_issue_updated.json")
    verifier = connector.webhook_verifier(HMAC_SECRET)
    assert verifier is not None

    with pytest.raises(WebhookRejected, match="missing webhook header: x-hub-signature"):
        verifier.verify(_delivery(body, {}), now=NOW)


def test_empty_hmac_secret_is_refused() -> None:
    connector = _connector({})

    with pytest.raises(ConfigError, match="must not be empty"):
        connector.webhook_verifier(b"")


# --- webhooks: shared token -------------------------------------------------


def test_shared_token_mode_returns_delivery_verifier_wrapping_shared_token() -> None:
    connector = _connector({}, webhook_verifier_mode="shared_token")

    verifier = connector.webhook_verifier(b"synthetic-token")

    assert isinstance(verifier, JiraDeliveryVerifier)
    assert isinstance(verifier._inner, SharedToken)


def test_shared_token_webhook_accepts_matching_token_and_rejects_mismatch() -> None:
    connector = _connector({}, webhook_verifier_mode="shared_token")
    body = _bytes("webhook_issue_updated.json")
    verifier = connector.webhook_verifier(b"synthetic-token")
    assert verifier is not None

    verifier.verify(_delivery(body, {"x-icuhub-token": "synthetic-token"}), now=NOW)
    with pytest.raises(WebhookRejected, match="invalid webhook token"):
        verifier.verify(_delivery(body, {"x-icuhub-token": "wrong"}), now=NOW)


def test_shared_token_secret_must_be_utf8() -> None:
    connector = _connector({}, webhook_verifier_mode="shared_token")

    with pytest.raises(ConfigError, match="UTF-8"):
        connector.webhook_verifier(b"\xff\xfe")


# --- webhooks: parsing ------------------------------------------------------


def test_issue_updated_delivery_yields_issue_and_changelog_records() -> None:
    connector = _connector({})
    delivery = _delivery(_bytes("webhook_issue_updated.json"))

    records = connector.receive_event(delivery)

    assert [record.stream for record in records] == ["issues", "issue_changelogs"]
    assert all(record.event == "upsert" for record in records)
    assert records[0].target_uid == f"jira_project:{CONNECTION_ID}/10000"


def test_comment_created_delivery_yields_only_comment_record() -> None:
    connector = _connector({})
    delivery = _delivery(_bytes("webhook_comment_created.json"))

    records = connector.receive_event(delivery)

    assert [record.stream for record in records] == ["comments"]
    assert records[0].raw["_jira_issue"] == {"id": "10001", "key": "PROJ-1"}


def test_unsupported_webhook_event_is_rejected() -> None:
    connector = _connector({})
    body = json.dumps({"webhookEvent": "jira:version_created"}).encode("utf-8")

    with pytest.raises(VendorContractError, match="unsupported Jira webhook event"):
        connector.receive_event(_delivery(body))
