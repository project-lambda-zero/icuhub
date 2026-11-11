"""Connector-level tests for the Jira Cloud connector.

Covers auth wiring through the kit auth strategies, health checks, the ``issues``,
``projects``, ``comments``, ``issue_changelogs``, ``attachments``, and
``audit_records`` streams, the mappers, the ``search_issues`` and
``download_attachment`` operations, the destructive-write gate, webhook
verification and parsing, and webhook registration expiry. Requests are answered
by ``RouteTransport`` from the synthetic fixtures in ``tests/fixtures/jira_cloud/``;
webhook payloads and the changelog search shape are built inline.

Fixtures for ``/rest/api/3/auditing/record``, ``/rest/api/3/project/search``,
``/rest/api/3/webhook``, and the attachment metadata and content paths follow the
unverified shapes the connector itself marks ``[UNVERIFIED]``; these tests pin the
behavior the connector implements, not a live Jira Cloud response.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import httpx2
import pytest

from icuhub.connectors._jira.models import (
    DeleteIssueInput,
    DownloadAttachmentInput,
    EmptyInput,
    SearchInput,
)
from icuhub.connectors.jira_cloud.connector import JiraCloud
from icuhub.kit.auth import BasicAuth, BearerToken, OAuth2RefreshToken
from icuhub.kit.errors import ConfigError, ConnectorError, PermissionDenied, VendorContractError, WebhookRejected
from icuhub.kit.testing import RouteTransport, collect_stream, make_connector, map_all
from icuhub.kit.types import SourceRecord, WebhookDelivery
from icuhub_schemas.ocsf import ApiActivity

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "jira_cloud"
BASE = "https://jira.example.test"
OAUTH_BASE = "https://api.atlassian.com/ex/jira/cloud-1"
ACCOUNT = "svc-automation@example.test"
API_REF = "jira-api-token"
ACCESS_REF = "jira-access-token"
CLIENT_SECRET_REF = "jira-client-secret"
REFRESH_REF = "jira-refresh-token"
SECRETS = {
    API_REF: b"synthetic-api-token",
    ACCESS_REF: b"synthetic-access-token",
    CLIENT_SECRET_REF: b"synthetic-client-secret",
    REFRESH_REF: b"synthetic-refresh-token",
}
JWT_SECRET = b"synthetic-client-secret"
NOW = datetime(2026, 11, 9, 12, 0, 0, tzinfo=UTC)
CONNECTION_ID = "test-connection"
ATTACHMENT_CONTENT = "Synthetic evidence\n"


def _load(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _bytes(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def _config(**extra: Any) -> dict[str, Any]:
    return {
        "base_url": BASE,
        "auth_method": "basic",
        "account_email": ACCOUNT,
        "api_token": {"ref": API_REF},
        **extra,
    }


def _connector(routes: dict[tuple[str, str], Any], **config_extra: Any) -> JiraCloud:
    return cast(
        JiraCloud,
        make_connector(JiraCloud, _config(**config_extra), RouteTransport(routes), SECRETS),
    )


def _recording(payload: Any, log: list[httpx2.Request], status: int = 200) -> Callable[[httpx2.Request], dict[str, Any]]:
    def handler(request: httpx2.Request) -> dict[str, Any]:
        log.append(request)
        return {"status": status, "json": payload}

    return handler


def _search_handler(log: list[httpx2.Request]) -> Callable[[httpx2.Request], dict[str, Any]]:
    """Serves search_page1, then search_page2 when the request carries page 1's nextPageToken."""
    pages = {None: _load("search_page1.json"), "cursor-page-2": _load("search_page2.json")}

    def handler(request: httpx2.Request) -> dict[str, Any]:
        log.append(request)
        return {"status": 200, "json": pages[request.url.params.get("nextPageToken")]}

    return handler


def _delivery(body: bytes, headers: dict[str, str] | None = None) -> WebhookDelivery:
    return WebhookDelivery(headers=headers or {}, body=body, received_at=NOW)


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _bearer_token(payload: dict[str, Any], secret: bytes, alg: str = "HS256") -> str:
    header = _b64url(json.dumps({"alg": alg, "typ": "JWT"}).encode())
    body = _b64url(json.dumps(payload).encode())
    signature = _b64url(hmac.new(secret, f"{header}.{body}".encode("ascii"), hashlib.sha256).digest())
    return f"{header}.{body}.{signature}"


def _bearer_headers(secret: bytes = JWT_SECRET) -> dict[str, str]:
    return {"authorization": f"Bearer {_bearer_token({'sub': 'synthetic'}, secret)}"}


def _issue_updated_body() -> bytes:
    payload = {
        "timestamp": 1793628000000,
        "webhookEvent": "jira:issue_updated",
        "issue": {
            "id": "10001",
            "key": "PROJ-1",
            "fields": {
                "project": {"id": "20001", "key": "PROJ"},
                "labels": ["icuhub-route-label"],
                "updated": "2026-11-01T10:00:00.000+0000",
            },
        },
        "changelog": {
            "id": "60001",
            "created": "2026-11-01T10:04:00.000+0000",
            "items": [{"field": "status", "fromString": "To Do", "toString": "In Progress"}],
        },
    }
    return json.dumps(payload).encode("utf-8")


def _comment_created_body() -> bytes:
    payload = {
        "timestamp": 1793628000000,
        "webhookEvent": "comment_created",
        "issue": {
            "id": "10001",
            "key": "PROJ-1",
            "fields": {"project": {"id": "20001", "key": "PROJ"}, "updated": "2026-11-01T10:03:00.000+0000"},
        },
        "comment": {
            "id": "40001",
            "body": {"type": "doc", "version": 1, "content": []},
            "created": "2026-11-01T10:02:00.000+0000",
            "updated": "2026-11-01T10:03:00.000+0000",
        },
    }
    return json.dumps(payload).encode("utf-8")


# --- auth and health --------------------------------------------------------


def test_non_ascii_api_token_is_rejected() -> None:
    with pytest.raises(ConfigError, match="ASCII"):
        make_connector(JiraCloud, _config(), RouteTransport({}), {API_REF: b"\xff\xfe"})


def test_basic_auth_uses_account_email_and_api_token() -> None:
    connector = _connector({})

    auth = asyncio.run(connector.build_auth())

    assert isinstance(auth, BasicAuth)
    assert auth.user == ACCOUNT
    assert auth.password == "synthetic-api-token"


def test_basic_auth_requires_account_email() -> None:
    with pytest.raises(ValueError, match="basic auth requires account_email"):
        make_connector(
            JiraCloud,
            {"base_url": BASE, "auth_method": "basic", "api_token": {"ref": API_REF}},
            RouteTransport({}),
            SECRETS,
        )


def test_bearer_auth_uses_access_token() -> None:
    connector = _connector({}, auth_method="bearer", access_token={"ref": ACCESS_REF})

    auth = asyncio.run(connector.build_auth())

    assert isinstance(auth, BearerToken)


def test_oauth2_3lo_builds_kit_refresh_token_against_atlassian() -> None:
    connector = _connector(
        {},
        base_url=OAUTH_BASE,
        auth_method="oauth2_3lo",
        cloud_id="cloud-1",
        client_id="synthetic-client",
        client_secret={"ref": CLIENT_SECRET_REF},
        refresh_token={"ref": REFRESH_REF},
    )

    auth = asyncio.run(connector.build_auth())

    assert isinstance(auth, OAuth2RefreshToken)
    assert auth.token_url == "https://auth.atlassian.com/oauth/token"
    assert auth.client_id == "synthetic-client"


def test_health_is_healthy_when_identity_probe_succeeds() -> None:
    connector = _connector({("GET", "/rest/api/3/myself"): {"status": 200, "json": _load("myself.json")}})

    report = asyncio.run(connector.check())

    assert report.status == "healthy"


def test_health_is_failing_when_vendor_rejects_credentials() -> None:
    connector = _connector({("GET", "/rest/api/3/myself"): {"status": 401, "json": {"errorMessages": ["denied"]}}})

    report = asyncio.run(connector.check())

    assert report.status == "failing"


def test_health_is_degraded_when_permission_is_denied() -> None:
    connector = _connector({("GET", "/rest/api/3/myself"): {"status": 403, "json": {"errorMessages": ["forbidden"]}}})

    report = asyncio.run(connector.check())

    assert report.status == "degraded"


# --- issues stream ----------------------------------------------------------


def test_issues_full_stream_pages_search_and_returns_every_issue() -> None:
    seen: list[httpx2.Request] = []
    connector = _connector({("GET", "/rest/api/3/search/jql"): _search_handler(seen)}, jql="project = PROJ")

    batches = collect_stream(connector, "issues", mode="full")

    records = [record for batch in batches for record in batch.records]
    assert [record["key"] for record in records] == ["PROJ-1", "PROJ-2"]
    assert len(seen) == 2
    assert batches[-1].complete is True
    assert seen[0].url.params["fields"] == "*all"


def test_issues_full_mode_applies_user_jql_without_window() -> None:
    seen: list[httpx2.Request] = []
    connector = _connector({("GET", "/rest/api/3/search/jql"): _search_handler(seen)}, jql="project = PROJ")

    collect_stream(connector, "issues", mode="full")

    jql = seen[0].url.params["jql"]
    assert jql.startswith("(project = PROJ)")
    assert "updated >=" not in jql


def test_issue_mapper_produces_ticket_records() -> None:
    seen: list[httpx2.Request] = []
    connector = _connector({("GET", "/rest/api/3/search/jql"): _search_handler(seen)}, jql="project = PROJ")
    records = [record for batch in collect_stream(connector, "issues", mode="full") for record in batch.records]

    mapped = map_all(connector, "issues", records)

    assert len(mapped) == 2
    assert cast(SourceRecord, mapped[0]).uid == f"jira_issue:{CONNECTION_ID}/10001"


# --- projects stream --------------------------------------------------------


def test_projects_stream_reads_paged_values_and_maps_project_uid() -> None:
    seen: list[httpx2.Request] = []
    connector = _connector({("GET", "/rest/api/3/project/search"): _recording(_load("projects.json"), seen)})

    batches = collect_stream(connector, "projects", mode="full")

    records = [record for batch in batches for record in batch.records]
    assert len(records) == 1
    (source,) = map_all(connector, "projects", records)
    assert cast(SourceRecord, source).uid == f"jira_project:{CONNECTION_ID}/20001"


def test_projects_stream_rejects_incremental_mode() -> None:
    connector = _connector({})

    with pytest.raises(ValueError, match="does not support mode"):
        collect_stream(connector, "projects", mode="incremental")


# --- comments stream --------------------------------------------------------


def test_issues_stream_raises_when_timestamp_ties_exceed_max_tie_ids() -> None:
    issues = [
        {"id": str(10000 + index), "key": f"PROJ-{index}", "fields": {"updated": "2026-11-01T10:00:00.000+0000"}}
        for index in range(101)
    ]
    connector = _connector(
        {("GET", "/rest/api/3/search/jql"): {"status": 200, "json": {"issues": issues}}},
        jql="project = PROJ",
        max_tie_ids=100,
    )

    with pytest.raises(ConnectorError, match="max_tie_ids"):
        collect_stream(connector, "issues", mode="full")


def test_comments_stream_fetches_each_issue_comments_with_parent() -> None:
    search_seen: list[httpx2.Request] = []
    comment_seen: list[httpx2.Request] = []
    empty_page = {"startAt": 0, "maxResults": 50, "total": 0, "comments": []}
    connector = _connector(
        {
            ("GET", "/rest/api/3/search/jql"): _search_handler(search_seen),
            ("GET", "/rest/api/3/issue/10001/comment"): _recording(_load("comments.json"), comment_seen),
            ("GET", "/rest/api/3/issue/10002/comment"): _recording(empty_page, comment_seen),
        },
        jql="project = PROJ",
    )

    batches = collect_stream(connector, "comments", mode="full")

    records = [record for batch in batches for record in batch.records]
    assert len(comment_seen) == 2
    assert [record["id"] for record in records] == ["40001"]
    assert records[0]["_jira_issue"] == {"id": "10001", "key": "PROJ-1"}
    (mapped,) = map_all(connector, "comments", records)
    comment = cast(SourceRecord, mapped)
    assert comment.uid == f"jira_comment:{CONNECTION_ID}/10001/40001"
    assert comment.data["body"] == _load("comments.json")["comments"][0]["body"]


# --- issue_changelogs stream ------------------------------------------------


def test_issue_changelogs_stream_expands_history_with_parent() -> None:
    seen: list[httpx2.Request] = []
    histories = _load("changelogs.json")["values"]
    payload = {"issues": [{"id": "10001", "key": "PROJ-1", "changelog": {"histories": histories}}]}
    connector = _connector({("GET", "/rest/api/3/search/jql"): _recording(payload, seen)}, jql="project = PROJ")

    batches = collect_stream(connector, "issue_changelogs", mode="full")

    records = [record for batch in batches for record in batch.records]
    assert seen[0].url.params["expand"] == "changelog"
    assert [record["id"] for record in records] == ["60001"]
    assert records[0]["_jira_issue"] == {"id": "10001", "key": "PROJ-1"}
    (activity,) = map_all(connector, "issue_changelogs", records)
    assert isinstance(activity, ApiActivity)


# --- attachments stream -----------------------------------------------------


def test_attachments_stream_reads_issue_attachment_field() -> None:
    seen: list[httpx2.Request] = []
    connector = _connector({("GET", "/rest/api/3/search/jql"): _search_handler(seen)}, jql="project = PROJ")

    batches = collect_stream(connector, "attachments", mode="full")

    records = [record for batch in batches for record in batch.records]
    assert [str(record["id"]) for record in records] == ["50001"]
    assert records[0]["_jira_issue"] == {"id": "10001", "key": "PROJ-1"}
    (source,) = map_all(connector, "attachments", records)
    assert cast(SourceRecord, source).uid == f"jira_attachment:{CONNECTION_ID}/10001/50001"


# --- audit_records stream ---------------------------------------------------


def test_audit_records_stream_reads_records_envelope() -> None:
    seen: list[httpx2.Request] = []
    connector = _connector({("GET", "/rest/api/3/auditing/record"): _recording(_load("audit.json"), seen)})

    batches = collect_stream(connector, "audit_records", mode="full")

    records = [record for batch in batches for record in batch.records]
    assert [str(record["id"]) for record in records] == ["70001", "70002"]
    mapped = map_all(connector, "audit_records", records)
    assert len(mapped) == 2
    assert all(isinstance(activity, ApiActivity) for activity in mapped)


def test_audit_records_permission_denied_propagates() -> None:
    connector = _connector(
        {("GET", "/rest/api/3/auditing/record"): {"status": 403, "json": {"errorMessages": ["forbidden"]}}}
    )

    with pytest.raises(PermissionDenied):
        collect_stream(connector, "audit_records", mode="full")


# --- search_issues operation ------------------------------------------------


def test_search_issues_operation_returns_first_page_ticket_records() -> None:
    seen: list[httpx2.Request] = []
    connector = _connector({("GET", "/rest/api/3/search/jql"): _recording(_load("search_page1.json"), seen)})

    output = asyncio.run(connector.search_issues(SearchInput(jql="project = PROJ")))

    assert [issue.key for issue in output.issues] == ["PROJ-1"]
    assert seen[0].url.params["jql"] == "project = PROJ"
    assert seen[0].url.params["fields"] == "id,key,summary,status,updated"


# --- download_attachment operation -----------------------------------------


def test_download_attachment_returns_content_matching_metadata() -> None:
    connector = _connector(
        {
            ("GET", "/rest/api/3/attachment/50001"): {"status": 200, "json": _load("attachment.json")},
            ("GET", "/rest/api/3/attachment/content/50001"): {"status": 200, "text": _bytes("attachment.txt").decode("utf-8")},
        }
    )

    result = asyncio.run(connector.download_attachment(DownloadAttachmentInput(attachment_id="50001")))

    content = _bytes("attachment.txt")
    assert result.attachment_id == "50001"
    assert result.filename == "evidence.txt"
    assert result.size == 18
    assert base64.b64decode(result.content_base64) == content
    assert result.sha256 == hashlib.sha256(content).hexdigest()


def test_download_attachment_rejects_content_that_disagrees_with_metadata() -> None:
    connector = _connector(
        {
            ("GET", "/rest/api/3/attachment/50001"): {"status": 200, "json": _load("attachment.json")},
            ("GET", "/rest/api/3/attachment/content/50001"): {"status": 200, "text": "short"},
        }
    )

    with pytest.raises(VendorContractError, match="size mismatch"):
        asyncio.run(connector.download_attachment(DownloadAttachmentInput(attachment_id="50001")))


def test_download_attachment_rejects_declared_size_over_configured_limit() -> None:
    connector = _connector(
        {("GET", "/rest/api/3/attachment/50001"): {"status": 200, "json": _load("attachment.json")}},
        attachment_max_bytes=10,
    )

    with pytest.raises(ConfigError, match="exceeds"):
        asyncio.run(connector.download_attachment(DownloadAttachmentInput(attachment_id="50001")))


# --- webhooks: OAuth bearer JWT ----------------------------------------------


def test_oauth_bearer_jwt_webhook_verifies_signed_token() -> None:
    connector = _connector({})
    body = _issue_updated_body()
    verifier = connector.webhook_verifier(JWT_SECRET)
    assert verifier is not None

    result = verifier.verify(_delivery(body, _bearer_headers()), now=NOW)

    assert result.occurred_at == NOW


def test_oauth_bearer_jwt_webhook_rejects_wrong_signature() -> None:
    connector = _connector({})
    verifier = connector.webhook_verifier(JWT_SECRET)

    with pytest.raises(WebhookRejected, match="invalid bearer token signature"):
        verifier.verify(_delivery(_issue_updated_body(), _bearer_headers(b"other-secret")), now=NOW)


def test_oauth_bearer_jwt_webhook_rejects_missing_authorization() -> None:
    connector = _connector({})
    verifier = connector.webhook_verifier(JWT_SECRET)

    with pytest.raises(WebhookRejected, match="missing webhook header: authorization"):
        verifier.verify(_delivery(_issue_updated_body()), now=NOW)


def test_oauth_bearer_jwt_webhook_rejects_unsupported_algorithm() -> None:
    connector = _connector({})
    verifier = connector.webhook_verifier(JWT_SECRET)
    token = _bearer_token({"sub": "synthetic"}, JWT_SECRET, alg="none")

    with pytest.raises(WebhookRejected, match="unsupported bearer token algorithm"):
        verifier.verify(_delivery(_issue_updated_body(), {"authorization": f"Bearer {token}"}), now=NOW)


def test_oauth_bearer_jwt_secret_must_not_be_empty() -> None:
    connector = _connector({})

    with pytest.raises(ConfigError, match="must not be empty"):
        connector.webhook_verifier(b"")


@pytest.mark.parametrize("field", ["webhook_verifier_mode", "webhook_shared_header", "webhook_secret"])
def test_unsourced_webhook_configuration_is_rejected(field: str) -> None:
    values = _config()
    values[field] = "shared_token" if field == "webhook_verifier_mode" else {"ref": "legacy"}

    with pytest.raises(ValueError):
        JiraCloud.config_model.model_validate(values)


# --- webhooks: parsing ------------------------------------------------------


def test_issue_updated_delivery_yields_issue_and_changelog_records() -> None:
    connector = _connector({})

    records = connector.receive_event(_delivery(_issue_updated_body()))

    assert [record.stream for record in records] == ["issues", "issue_changelogs"]
    assert all(record.event == "upsert" for record in records)
    assert records[0].target_uid == f"jira_project:{CONNECTION_ID}/20001"


def test_comment_created_delivery_yields_only_comment_record() -> None:
    connector = _connector({})

    records = connector.receive_event(_delivery(_comment_created_body()))

    assert [record.stream for record in records] == ["comments"]
    assert records[0].raw["_jira_issue"] == {"id": "10001", "key": "PROJ-1"}


def test_webhook_issue_without_string_id_is_rejected() -> None:
    connector = _connector({})
    body = json.dumps({"webhookEvent": "jira:issue_updated", "issue": {"key": "PROJ-1"}}).encode("utf-8")

    with pytest.raises(VendorContractError, match="stable id"):
        connector.receive_event(_delivery(body))


def test_unsupported_webhook_event_is_rejected() -> None:
    connector = _connector({})
    body = json.dumps({"webhookEvent": "jira:version_created"}).encode("utf-8")

    with pytest.raises(VendorContractError, match="unsupported Jira webhook event"):
        connector.receive_event(_delivery(body))


# --- destructive gate -------------------------------------------------------


def test_delete_issue_plan_is_blocked_when_destructive_writes_are_disabled() -> None:
    connector = _connector({})

    with pytest.raises(ConfigError, match="destructive_enabled is false"):
        asyncio.run(
            connector.plan_delete_issue(DeleteIssueInput(issue_id_or_key="PROJ-1", expected_id="10001"))
        )


# --- list_webhooks ----------------------------------------------------------


def test_list_webhooks_flags_registrations_near_expiry_or_without_expiry() -> None:
    seen: list[httpx2.Request] = []
    payload = {
        "startAt": 0,
        "maxResults": 50,
        "total": 3,
        "isLast": True,
        "values": [
            {
                "id": 1,
                "url": "https://hooks.example.test/a",
                "events": ["jira:issue_updated"],
                "expirationDate": "2026-11-12T00:00:00.000+0000",
            },
            {
                "id": 2,
                "url": "https://hooks.example.test/b",
                "events": ["comment_created"],
                "expirationDate": "2026-12-30T00:00:00.000+0000",
            },
            {"id": 3, "url": "https://hooks.example.test/c", "events": ["comment_updated"]},
        ],
    }
    connector = _connector({
        ("GET", "/rest/api/3/webhook"): _recording(payload, seen),
        ("GET", "/rest/api/3/webhook/failed"): {"status": 200, "json": {"values": []}},
    })

    output = asyncio.run(connector.list_webhooks(EmptyInput()))

    by_id = {registration.id: registration for registration in output.registrations}
    assert set(by_id) == {"1", "2", "3"}
    assert by_id["1"].events == ["jira:issue_updated"]
    assert by_id["1"].needs_refresh is True
    assert by_id["2"].needs_refresh is False
    assert by_id["3"].expiration_date is None
    assert by_id["3"].needs_refresh is True
