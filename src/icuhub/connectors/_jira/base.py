"""Behavior shared by the Jira Cloud and Jira Data Center connectors.

Edition-specific parts stay in each package: authentication, search pagination (Cloud enhanced
search uses ``nextPageToken``; Data Center uses ``startAt``), and the REST API version. This
module owns relative REST path construction, offset-paged reads, issue state assertions, the
webhook verifier selection, the destructive-action gate, and the stable identity used for
action plans.
"""

from __future__ import annotations

import hashlib
from abc import abstractmethod
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime
from typing import Any, ClassVar, Literal

from icuhub.connectors._jira.helpers import issue_state, list_field, seg, strip_order
from icuhub.connectors._jira.models import JiraConfig
from icuhub.kit.connector import Connector
from icuhub.kit.cursors import TimeIdCursor
from icuhub.kit.errors import ConfigError, ConnectorError, NotFound, StalePlan, VendorContractError
from icuhub.kit.http import IdempotencyMode
from icuhub.kit.paginate import offset_pages
from icuhub.kit.types import MapContext
from icuhub.kit.webhook import WebhookVerifier

__all__ = ["JiraBase"]
_ISSUE_STATE_FIELDS = "id,updated,status"


class JiraBase(Connector):
    """Shared Jira connector behavior. Subclasses supply the REST version, search order, and auth."""

    config: JiraConfig
    api_version: ClassVar[Literal["2", "3"]]
    search_order: ClassVar[str]

    @abstractmethod
    def installation_id(self) -> str:
        """Stable identifier of the Jira installation, used in record UIDs and dedupe keys."""

    # ------------------------------------------------------------ plumbing

    def _map_ctx(self) -> MapContext:
        return MapContext(
            connection_id=self.ctx.connection_id,
            tenant_id=self.ctx.tenant_id,
            connector_kind=self.kind,
            received_at=self.ctx.clock(),
        )

    def _api_path(self, path: str) -> str:
        """Relative REST path under ``/rest/api/<version>``; ``path`` must start with ``/``."""
        if not path.startswith("/"):
            raise ConfigError("Jira REST path must start with '/'")
        return f"/rest/api/{self.api_version}{path}"

    def _issue_path(self, ref: str) -> str:
        return self._api_path(f"/issue/{seg(ref)}")

    async def _json(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json: Any = None,
        idempotency: IdempotencyMode = "safe_read",
        expected: tuple[int, ...] = (200,),
    ) -> Any:
        result = await self.http.request(
            method, path, params=params, json=json, idempotency=idempotency, expected=expected
        )
        return result.json()

    async def _get_object(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        body = await self._json("GET", path, params=params)
        if not isinstance(body, dict):
            raise VendorContractError(f"Jira response from {path} must be an object")
        return body

    async def _is_absent(self, path: str) -> bool:
        try:
            await self.http.request("GET", path)
        except NotFound:
            return True
        return False

    def _paged(
        self,
        path: str,
        params: dict[str, Any] | None,
        key: str,
        *,
        offset_param: str,
        limit_param: str,
    ) -> AsyncIterator[Any]:
        cfg = self.config
        return offset_pages(
            self.http,
            path,
            params,
            offset_param=offset_param,
            limit_param=limit_param,
            limit=cfg.page_size,
            items=lambda body: list_field(body, key),
            max_pages=cfg.max_pages,
        )

    def advance_cursor(
        self,
        cursor: TimeIdCursor,
        records: list[dict[str, Any]],
        ts_of: Callable[[dict[str, Any]], datetime],
        id_of: Callable[[dict[str, Any]], str],
    ) -> TimeIdCursor:
        """Advance a replay cursor, failing before the batch is emitted when tie IDs exceed ``max_tie_ids``.

        The checkpoint stays at the last emitted batch, so the read is incomplete and no record is
        dropped. Truncating the tie set would re-emit or skip boundary records without any signal.
        """
        advanced = cursor.advance(records, ts_of=ts_of, id_of=id_of)
        limit = self.config.max_tie_ids
        if len(advanced.last_ids_at_ts) > limit:
            raise ConnectorError(
                f"Jira replay window has {len(advanced.last_ids_at_ts)} records at one timestamp, "
                f"above max_tie_ids={limit}; raise max_tie_ids and rerun the read"
            )
        return advanced

    def _search_jql(self, window: datetime | None) -> str:
        clauses: list[str] = []
        if window is not None:
            clauses.append(f'updated >= "{window.astimezone(UTC):%Y-%m-%d %H:%M}"')
        user_filter = strip_order(self.config.jql)
        if user_filter:
            clauses.append(f"({user_filter})")
        return f"{' AND '.join(clauses)} {self.search_order}" if clauses else self.search_order

    async def _get_issue(self, ref: str, *, fields: str, expand: str | None = None) -> dict[str, Any]:
        params: dict[str, Any] = {"fields": fields}
        if expand is not None:
            params["expand"] = expand
        return await self._get_object(self._issue_path(ref), params)

    async def _assert_state(self, ref: str, expected: dict[str, Any]) -> None:
        state = issue_state(await self._get_issue(ref, fields=_ISSUE_STATE_FIELDS))
        for key, value in expected.items():
            if state.get(key) != value:
                raise StalePlan(f"Jira issue {key} changed since the plan was made")

    async def _transitions(self, issue_id: str) -> list[dict[str, Any]]:
        body = await self._get_object(f"{self._issue_path(issue_id)}/transitions")
        return list_field(body, "transitions")

    async def _find_comment(self, issue_id: str, marker: str) -> dict[str, Any] | None:
        # The marker is plain ASCII, so it survives both DC plain-text bodies and Cloud ADF
        # documents when the body is searched by its string form.
        pages = self._paged(
            f"{self._issue_path(issue_id)}/comment",
            None,
            "comments",
            offset_param="startAt",
            limit_param="maxResults",
        )
        async for page, _result in pages:
            for comment in page:
                if marker in str(comment.get("body", "")):
                    return comment
        return None

    async def _find_attachment(self, issue_id: str, filename: str, size: int) -> dict[str, Any] | None:
        body = await self._get_object(self._issue_path(issue_id), {"fields": "attachment"})
        fields = body.get("fields")
        attachments = fields.get("attachment", []) if isinstance(fields, dict) else []
        for attachment in attachments if isinstance(attachments, list) else []:
            if isinstance(attachment, dict) and attachment.get("filename") == filename and attachment.get("size") == size:
                return attachment
        return None

    # ------------------------------------------------------------ webhooks + gates

    def webhook_verifier(self, _secret: bytes) -> WebhookVerifier | None:
        # Jira Cloud overrides this with its OAuth bearer JWT contract. Data Center has no
        # sourced signature contract, so its deliveries stay disabled and synchronization polls.
        return None

    def require_destructive(self, action: str) -> None:
        """Refuse a destructive action unless the connection explicitly enables destructive writes."""
        if not self.config.destructive_enabled:
            raise ConfigError(f"{action} is destructive and destructive_enabled is false for this connection")

    def action_identity(self, action: str, route_key: str) -> str:
        """Idempotency key for an action: stable across retries of the same route and tenant."""
        material = f"{self.ctx.tenant_id}\x1f{action}\x1f{route_key}".encode()
        return hashlib.sha256(material).hexdigest()
