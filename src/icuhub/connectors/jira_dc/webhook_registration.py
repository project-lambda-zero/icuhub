"""Jira Data Center webhook catalog and registration lifecycle.

Typed event declarations, registration family resolution from the server version, request bodies,
registration parsing, and health for the DC webhook region of ``connector.py``. The registration
endpoint, body shape, and response fields are [UNVERIFIED] until a live Data Center instance
confirms them. DC registrations persist until deleted, so health is structural only.
"""

from __future__ import annotations

from typing import Any, Literal
from urllib.parse import quote

from pydantic import Field, field_validator

from icuhub.connectors._jira.models import StrictModel
from icuhub.connectors._jira.webhooks import EVENT_TYPES
from icuhub.kit.errors import ConfigError, VendorContractError

__all__ = [
    "REGISTRATION_PATH",
    "CreateDcWebhookInput",
    "DcWebhookRegistration",
    "DcWebhooksOutput",
    "ListWebhooksArgs",
    "RegistrationFamily",
    "create_body",
    "create_statuses",
    "delete_path",
    "find_by_id",
    "find_registration",
    "parse_registrations",
    "registration_health",
    "registration_id",
    "resolve_family",
    "server_version_numbers",
]

# [UNVERIFIED] Jira DC webhook plugin registration collection; not sourced in docs/VENDOR_CONNECTORS.md.
REGISTRATION_PATH = "/rest/webhooks/1.0/webhook"

RegistrationFamily = Literal["pre_10", "jira_10"]
RegistrationStatus = Literal["healthy", "degraded"]


class ListWebhooksArgs(StrictModel):
    """No arguments: lists every registration on the installation."""


class CreateDcWebhookInput(StrictModel):
    name: str = Field(min_length=1, max_length=255)
    url: str = Field(min_length=1, max_length=2048)
    events: list[str] = Field(min_length=1)
    jql_filter: str = ""

    @field_validator("events")
    @classmethod
    def _supported_events(cls, values: list[str]) -> list[str]:
        unknown = sorted(set(values) - set(EVENT_TYPES))
        if unknown:
            raise ValueError(f"unsupported Jira DC webhook events: {','.join(unknown)}")
        return sorted(set(values))


class DcWebhookRegistration(StrictModel):
    id: str
    name: str
    url: str
    events: list[str]
    jql_filter: str
    enabled: bool | None
    unknown_events: list[str]


class DcWebhooksOutput(StrictModel):
    family: RegistrationFamily
    status: RegistrationStatus
    registrations: list[DcWebhookRegistration]


def server_version_numbers(body: Any) -> list[int]:
    """Return ``serverInfo.versionNumbers``. [UNVERIFIED] field name and integer list shape."""
    if not isinstance(body, dict):
        raise VendorContractError("Jira serverInfo response must be an object")
    numbers = body.get("versionNumbers")
    if (
        not isinstance(numbers, list)
        or not numbers
        or not all(isinstance(n, int) and not isinstance(n, bool) for n in numbers)
    ):
        raise VendorContractError("Jira serverInfo versionNumbers must be a non-empty integer list")
    return numbers


def resolve_family(
    configured: Literal["auto", "pre_10", "jira_10"], version_numbers: list[int]
) -> RegistrationFamily:
    """Pick the registration family from the probed major version.

    An explicit setting that disagrees with the probed major version is refused rather than
    silently overridden, so a misconfigured family cannot register against the wrong API.
    """
    probed: RegistrationFamily = "jira_10" if version_numbers[0] >= 10 else "pre_10"
    if configured == "auto":
        return probed
    if configured != probed:
        raise ConfigError(
            f"webhook_registration_family={configured} does not match Jira major version {version_numbers[0]}"
        )
    return probed


def create_statuses(family: RegistrationFamily) -> tuple[int, ...]:
    """Accepted create statuses. [UNVERIFIED] Jira 10 may answer 202 for asynchronous registration."""
    if family == "jira_10":
        return (200, 201, 202)
    return (200, 201)


def create_body(args: CreateDcWebhookInput) -> dict[str, Any]:
    """Create request body. [UNVERIFIED] field names, including the ``filters`` key for the JQL filter."""
    return {
        "name": args.name,
        "url": args.url,
        "events": list(args.events),
        "excludeBody": False,
        "filters": {"issue-related-events-section": args.jql_filter},
    }


def delete_path(webhook_id: str) -> str:
    """Delete path for one registration. [UNVERIFIED] path shape; the id is percent-encoded."""
    return f"{REGISTRATION_PATH}/{quote(webhook_id, safe='')}"


def parse_registrations(body: Any) -> list[DcWebhookRegistration]:
    """Parse the registration list. [UNVERIFIED] the list is a plain JSON array of objects."""
    if not isinstance(body, list):
        raise VendorContractError("Jira DC webhook list must be an array")
    return [_parse_registration(raw) for raw in body]


def registration_id(raw: dict[str, Any]) -> str | None:
    """Registration id as a string; the vendor may send an integer. [UNVERIFIED] ``id`` field name."""
    value = raw.get("id")
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str) and value:
        return value
    return None


def _parse_registration(raw: Any) -> DcWebhookRegistration:
    if not isinstance(raw, dict):
        raise VendorContractError("Jira DC webhook registration must be an object")
    webhook_id = registration_id(raw)
    if webhook_id is None:
        raise VendorContractError("Jira DC webhook registration id must be a non-empty string or integer")
    name = raw.get("name")
    url = raw.get("url")
    events = raw.get("events")
    if not isinstance(name, str) or not isinstance(url, str):
        raise VendorContractError("Jira DC webhook registration name and url must be strings")
    if not isinstance(events, list) or not all(isinstance(e, str) for e in events):
        raise VendorContractError("Jira DC webhook registration events must be a string list")
    filters = raw.get("filters")
    jql_filter = ""
    if isinstance(filters, dict):
        value = filters.get("issue-related-events-section", "")
        jql_filter = value if isinstance(value, str) else ""
    enabled = raw.get("enabled")
    return DcWebhookRegistration(
        id=webhook_id,
        name=name,
        url=url,
        events=list(events),
        jql_filter=jql_filter,
        enabled=enabled if isinstance(enabled, bool) else None,
        unknown_events=[event for event in events if event not in EVENT_TYPES],
    )


def find_registration(
    registrations: list[DcWebhookRegistration], url: str, events: list[str], jql_filter: str
) -> DcWebhookRegistration | None:
    """Return the registration matching the create natural key: URL, event set, and JQL filter."""
    wanted = sorted(set(events))
    for registration in registrations:
        if (
            registration.url == url
            and sorted(set(registration.events)) == wanted
            and registration.jql_filter == jql_filter
        ):
            return registration
    return None


def find_by_id(registrations: list[DcWebhookRegistration], webhook_id: str) -> DcWebhookRegistration | None:
    for registration in registrations:
        if registration.id == webhook_id:
            return registration
    return None


def registration_health(registrations: list[DcWebhookRegistration]) -> RegistrationStatus:
    """Degraded when a registration is disabled or carries events outside the typed catalog."""
    for registration in registrations:
        if registration.enabled is False or registration.unknown_events:
            return "degraded"
    return "healthy"
