"""Archer REST Content API and SOAP Web Services client.

REST envelopes follow the documented Archer shape ``{"RequestedObject": ...,
"IsSuccessful": bool, "ValidationMessages": [...]}``; list endpoints return an
array of such envelopes. Reads use POST with ``X-Http-Method-Override: GET`` so
OData body parameters are honored. SOAP calls carry ``sessionToken`` as a body
element (not a SOAP header) and regenerate the token once on HTTP 500.
"""

import re
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any
from xml.etree.ElementTree import Element

from icuhub.kit import (
    AuthFailed,
    AuthStrategy,
    ConfigError,
    TransientVendorError,
    VendorContractError,
    VendorHttp,
    parse_soap,
    soap_envelope,
    xml_text,
)
from icuhub.kit.http import IdempotencyMode

from .models import ArcherConfig, VersionOutput

__all__ = ["ArcherClient", "domain_login", "rest_login"]

_NS = "http://archer-tech.com/webservices/"
_TOKEN_RE = re.compile(r'session-id="([^"]+)"')

_LOGIN = "/platformapi/core/security/login"
_APPLICATION = "/platformapi/core/system/application"
_APP_INFO = "/platformapi/core/system/applicationinfo"
_CONTENT = "/platformapi/core/content"
_CONTENT_API = "/contentapi/"
_GENERAL_ASMX = "/ws/general.asmx"
_SEARCH_ASMX = "/ws/search.asmx"
_RECORD_ASMX = "/ws/record.asmx"


def _validation_messages(payload: Any) -> str:
    if isinstance(payload, dict):
        messages = payload.get("ValidationMessages") or []
        parts = [str(m.get("ResourcedMessage", m)) for m in messages if isinstance(m, dict)]
        if parts:
            return "; ".join(parts)
    return ""


def _envelope(payload: Any) -> dict[str, Any]:
    """Unwrap a single-object envelope, raising on IsSuccessful=false."""
    if not isinstance(payload, dict):
        raise VendorContractError(f"Archer envelope expected object, got {type(payload).__name__}")
    if payload.get("IsSuccessful") is False:
        raise VendorContractError(f"Archer request failed: {_validation_messages(payload) or 'unknown'}")
    obj = payload.get("RequestedObject")
    return obj if isinstance(obj, dict) else payload


def _envelope_list(payload: Any) -> list[dict[str, Any]]:
    """Unwrap a list-of-envelopes response.

    Items with IsSuccessful=false are omitted: Archer filters entities the
    session user cannot see, which maps to not_evaluated, never to failure.
    """
    if isinstance(payload, dict):
        return [_envelope(payload)]
    if not isinstance(payload, list):
        raise VendorContractError("Archer list response expected an array of envelopes")
    out: list[dict[str, Any]] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        if item.get("IsSuccessful") is False:
            continue
        obj = item.get("RequestedObject")
        if isinstance(obj, dict):
            out.append(obj)
    return out


def _session_header(token: str) -> tuple[str, str, None]:
    return ("Authorization", f'Archer session-id="{token}"', None)


async def rest_login(http: VendorHttp, cfg: ArcherConfig, password: str) -> tuple[str, str, None]:
    """POST /platformapi/core/security/login. Skips auth apply and 401 refresh."""
    result = await http.request(
        "POST",
        _LOGIN,
        json={
            "InstanceName": cfg.instance_name,
            "Username": cfg.user,
            "UserDomain": cfg.user_domain or "",
            "Password": password,
        },
        idempotency="non_idempotent",
        authenticate=False,
    )
    payload = result.json()
    if not isinstance(payload, dict) or not payload.get("IsSuccessful"):
        raise AuthFailed(f"Archer login rejected: {_validation_messages(payload) or 'IsSuccessful=false'}")
    token = (payload.get("RequestedObject") or {}).get("SessionToken")
    if not token:
        raise AuthFailed("Archer login response carried no SessionToken")
    return _session_header(str(token))


async def domain_login(http: VendorHttp, cfg: ArcherConfig, password: str) -> tuple[str, str, None]:
    """SOAP CreateDomainUserSessionFromInstance on ws/general.asmx.

    Falls back to CreateUserSessionFromInstance only when no user_domain is
    configured. No session exists yet, so the envelope carries no sessionToken.
    """
    op = "CreateDomainUserSessionFromInstance" if cfg.user_domain else "CreateUserSessionFromInstance"
    body = (
        f"<userName>{xml_text(cfg.user)}</userName>"
        f"<instanceName>{xml_text(cfg.instance_name)}</instanceName>"
        f"<password>{xml_text(password)}</password>"
    )
    if cfg.user_domain:
        body += f"<usersDomain>{xml_text(cfg.user_domain)}</usersDomain>"
    envelope = soap_envelope(f'<{op} xmlns="{_NS}">{body}</{op}>')
    result = await http.request(
        "POST",
        _GENERAL_ASMX,
        content=envelope.encode("utf-8"),
        headers={
            "SOAPAction": f"{_NS}{op}",
            "Content-Type": "text/xml; charset=utf-8",
        },
        idempotency="non_idempotent",
        authenticate=False,
    )
    body_el = parse_soap(result.content)
    token_el = body_el.find(f".//{{{_NS}}}{op}Result")
    token = token_el.text if token_el is not None else None
    if not token:
        raise AuthFailed(f"Archer {op} returned no session token")
    return _session_header(token)


class ArcherClient:
    """Typed Archer API surface shared by streams, operations, and actions."""

    def __init__(
        self,
        http: VendorHttp | Callable[[], VendorHttp],
        config: ArcherConfig,
        session: AuthStrategy,
    ) -> None:
        self._http_source = http
        self.config = config
        self.session = session
        self._cache: dict[tuple[str, int], Any] = {}

    @property
    def http(self) -> VendorHttp:
        return self._http_source() if callable(self._http_source) else self._http_source

    def invalidate_metadata(self) -> None:
        self._cache.clear()

    async def _cached(self, kind: str, key: int, loader: Callable[[], Awaitable[Any]]) -> Any:
        cache_key = (kind, key)
        if cache_key not in self._cache:
            self._cache[cache_key] = await loader()
        return self._cache[cache_key]

    async def json(
        self,
        method: str,
        path: str,
        *,
        body: Any = None,
        idempotency: IdempotencyMode = "safe_read",
        expected: tuple[int, ...] = (200,),
        authenticate: bool = True,
    ) -> Any:
        result = await self.http.request(
            method,
            path,
            json=body,
            idempotency=idempotency,
            expected=expected,
            authenticate=authenticate,
        )
        if result.status == 204 or not result.content:
            return None
        return result.json()

    async def post_get(self, path: str, body: Any = None) -> Any:
        result = await self.http.request(
            "POST",
            path,
            json=body if body is not None else {},
            headers={"X-Http-Method-Override": "GET"},
            idempotency="safe_read",
        )
        return result.json()

    async def session_token(self) -> str:
        headers: dict[str, str] = {}
        await self.session.apply(headers, "POST", self.config.base_url)
        match = _TOKEN_RE.search(headers.get("Authorization", ""))
        if not match:
            raise AuthFailed("Archer session strategy did not yield a session-id token")
        return match.group(1)

    async def soap(self, path: str, operation: str, body_xml: str) -> Element:
        """Invoke one SOAP operation, returning its <Op>Result element.

        sessionToken is injected as the first body child. On HTTP 500 the token
        is regenerated once and the call retried, matching vendor behavior for
        expired SOAP sessions.
        """
        for attempt in (0, 1):
            token = await self.session_token()
            inner = f"<sessionToken>{xml_text(token)}</sessionToken>{body_xml}"
            envelope = soap_envelope(f'<{operation} xmlns="{_NS}">{inner}</{operation}>')
            result = await self.http.request(
                "POST",
                path,
                content=envelope.encode("utf-8"),
                headers={
                    "SOAPAction": f"{_NS}{operation}",
                    "Content-Type": "text/xml; charset=utf-8",
                },
                idempotency="non_idempotent",
                expected=(200, 500),
            )
            if result.status == 500 and attempt == 0:
                await self.session.refresh()
                continue
            if result.status == 500:
                raise TransientVendorError(f"Archer SOAP {operation} returned HTTP 500 after token refresh")
            body_el = parse_soap(result.content)
            result_el = body_el.find(f".//{{{_NS}}}{operation}Result")
            if result_el is None:
                raise VendorContractError(f"Archer SOAP {operation} response missing {operation}Result")
            return result_el
        raise TransientVendorError(f"Archer SOAP {operation} exhausted retries")  # pragma: no cover

    # -- metadata ---------------------------------------------------------

    async def version(self) -> VersionOutput:
        obj = _envelope(await self.post_get(_APP_INFO))
        for key in ("Version", "ApplicationVersion", "BuildNumber"):  # [UNVERIFIED] key name
            if obj.get(key):
                return VersionOutput(version=str(obj[key]), raw=obj)
        raise VendorContractError("Archer applicationinfo carried no version field")

    async def applications(self) -> list[dict[str, Any]]:
        return _envelope_list(await self.post_get(_APPLICATION))

    async def levels(self, application_id: int) -> list[dict[str, Any]]:
        return _envelope_list(await self.post_get(f"/platformapi/core/system/level/module/{application_id}"))

    async def fields_for_level(self, level_id: int) -> list[dict[str, Any]]:
        return await self._cached(
            "level_fields",
            level_id,
            lambda: self._load_fields(f"/platformapi/core/system/fielddefinition/level/{level_id}"),
        )

    async def fields_for_application(self, application_id: int) -> list[dict[str, Any]]:
        return _envelope_list(
            await self.post_get(f"/platformapi/core/system/fielddefinition/application/{application_id}")
        )

    async def _load_fields(self, path: str) -> list[dict[str, Any]]:
        return _envelope_list(await self.post_get(path))

    async def field_definition(self, field_id: int) -> dict[str, Any]:
        return await self._cached(
            "field",
            field_id,
            lambda: self._load_field(field_id),
        )

    async def _load_field(self, field_id: int) -> dict[str, Any]:
        return _envelope(await self.post_get(f"/platformapi/core/system/fielddefinition/{field_id}"))

    async def values_list(self, values_list_id: int) -> dict[str, Any]:
        return await self._cached(
            "values_list",
            values_list_id,
            lambda: self._load_values_list(values_list_id),
        )

    async def _load_values_list(self, values_list_id: int) -> dict[str, Any]:
        return _envelope(
            await self.post_get(f"/platformapi/core/system/valueslistvalue/valueslist/{values_list_id}")
        )

    # -- content ----------------------------------------------------------

    async def content(self, content_id: int) -> dict[str, Any]:
        return _envelope(await self.post_get(f"{_CONTENT}/contentid?id={content_id}"))

    async def content_api(self) -> tuple[bool, int]:
        """Anonymous discovery of the newer Content API. [UNVERIFIED] surface."""
        result = await self.http.request(
            "GET",
            _CONTENT_API,
            idempotency="safe_read",
            expected=(200, 401, 403, 404),
            authenticate=False,
        )
        return result.status == 200, result.status

    async def search_records(
        self,
        *,
        level_id: int,
        application_id: int | None = None,
        page_number: int = 1,
        page_size: int = 100,
        display_fields: dict[str, int] | None = None,
        modified_since: datetime | None = None,
        time_field_id: int | None = None,
        text_filter: tuple[int, str] | None = None,
    ) -> list[dict[str, Any]]:
        """SOAP ExecuteSearch. Returns [{content_id, fields: {logical_name: value}}]."""
        display = display_fields or {}
        display_xml = "".join(
            f'<DisplayField name="{xml_text(name)}">{fid}</DisplayField>' for name, fid in display.items()
        )
        criteria = ""
        if application_id is not None:
            criteria = (
                f'<ModuleCriteria><Module name="{application_id}">{application_id}</Module></ModuleCriteria>'
            )
        conditions = ""
        if modified_since is not None and time_field_id is not None:
            stamp = modified_since.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
            conditions += (
                "<DateComparisonFilterCondition><Operator>GreaterThan</Operator>"
                f'<Field name="{time_field_id}">{time_field_id}</Field><Value>{stamp}</Value>'
                "<TimeZoneId>UTC</TimeZoneId><IsTimeIncluded>1</IsTimeIncluded>"
                "</DateComparisonFilterCondition>"
            )
        if text_filter is not None:
            fid, value = text_filter
            conditions += (
                "<TextFilterCondition><Operator>Equals</Operator>"
                f'<Field name="{fid}">{fid}</Field><Value>{xml_text(value)}</Value>'
                "</TextFilterCondition>"
            )
        if conditions:
            criteria += f"<Filter><Conditions>{conditions}</Conditions></Filter>"
        search_report = (
            "<SearchReport>"
            f"<PageSize>{page_size}</PageSize><PageNumber>{page_number}</PageNumber>"
            "<MaxRecordCount>0</MaxRecordCount><ShowStatSummaries>false</ShowStatSummaries>"
            f"<DisplayFields>{display_xml}</DisplayFields><Criteria>{criteria}</Criteria>"
            "</SearchReport>"
        )
        body = f"<searchOptions><![CDATA[{search_report}]]></searchOptions><pageNumber>{page_number}</pageNumber>"
        result_el = await self.soap(_SEARCH_ASMX, "ExecuteSearch", body)
        names_by_id = {str(fid): name for name, fid in display.items()}
        records: list[dict[str, Any]] = []
        for record_el in _iter_local(result_el, "Record"):
            content_id = record_el.get("contentId")
            if content_id is None:
                continue
            fields: dict[str, Any] = {}
            for field_el in _iter_local(record_el, "Field"):
                fid = field_el.get("id") or ""
                name = names_by_id.get(fid, fid)
                fields[name] = _soap_field_value(field_el)
            records.append({"content_id": int(content_id), "level_id": level_id, "fields": fields})
        return records

    async def record_soap(self, content_id: int) -> dict[str, Any]:
        """SOAP GetRecordById. [UNVERIFIED] operation name on all release trains."""
        result_el = await self.soap(_RECORD_ASMX, "GetRecordById", f"<contentId>{content_id}</contentId>")
        fields: dict[str, Any] = {}
        for field_el in _iter_local(result_el, "Field"):
            fid = field_el.get("id") or ""
            fields[fid] = _soap_field_value(field_el)
        return {"content_id": content_id, "fields": fields}

    async def history(self, content_id: int) -> list[dict[str, Any]]:
        """REST content history. [UNVERIFIED] path and monotonic history id."""
        payload = await self.post_get(f"{_CONTENT}/history/{content_id}")
        if isinstance(payload, list):
            return _envelope_list(payload)
        obj = _envelope(payload)
        entries = obj.get("History") or obj.get("Entries") or []
        return list(entries) if isinstance(entries, list) else []

    async def attachment_bytes(self, attachment_id: int) -> bytes:
        return await self.http.stream_download(
            "POST",
            f"{_CONTENT}/attachment/{attachment_id}",
            max_bytes=self.config.attachment_max_bytes,
            headers={"X-Http-Method-Override": "GET"},
        )

    async def data_feed_history(self) -> list[dict[str, Any]]:
        """Data-feed execution history. [UNVERIFIED] response shape."""
        payload = await self.post_get("/platformapi/core/datafeed/history")
        if isinstance(payload, list):
            return _envelope_list(payload)
        obj = _envelope(payload)
        runs = obj.get("Runs") or obj.get("History") or []
        return list(runs) if isinstance(runs, list) else []

    # -- writes -----------------------------------------------------------

    async def create_content(self, level_id: int, field_contents: dict[str, Any]) -> int:
        payload = await self.json(
            "POST",
            _CONTENT,
            body={"LevelId": level_id, "FieldContents": field_contents},
            idempotency="non_idempotent",
            expected=(200, 201),
        )
        obj = _envelope(payload)
        new_id = obj.get("Id")
        if new_id is None:
            raise VendorContractError("Archer create content response carried no Id")
        return int(new_id)

    async def update_content(
        self, content_id: int, level_id: int, field_contents: dict[str, Any], version: int
    ) -> dict[str, Any]:
        payload = await self.json(
            "PUT",
            _CONTENT,
            body={
                "Id": content_id,
                "LevelId": level_id,
                "Version": version,
                "FieldContents": field_contents,
            },
            idempotency="idempotent_write",
        )
        return _envelope(payload) if payload is not None else {}

    async def delete_content(self, content_id: int) -> None:
        # [UNVERIFIED] delete endpoint and expected status set. Never retried: an
        # ambiguous delete is reported as outcome_unknown, not replayed.
        await self.json(
            "DELETE",
            f"{_CONTENT}/{content_id}",
            idempotency="non_idempotent",
            expected=(200, 204),
        )

    async def upload_attachment(
        self, content_id: int, field_id: int, filename: str, content_base64: str
    ) -> dict[str, Any]:
        # [UNVERIFIED] body shape: /content/attachment versus /content/multipartattachment.
        payload = await self.json(
            "POST",
            f"{_CONTENT}/attachment",
            body={
                "ContentId": content_id,
                "FieldId": field_id,
                "FileName": filename,
                "FileContent": content_base64,
            },
            idempotency="non_idempotent",
            expected=(200, 201),
        )
        return _envelope(payload)

    async def execute_data_feed(self, guid: str, include_reference_feeds: bool) -> dict[str, Any]:
        # [UNVERIFIED] DataFeedGuid body key; endpoint and IsReferenceFeedsIncluded per spec.
        payload = await self.json(
            "POST",
            "/platformapi/core/datafeed/execution",
            body={"DataFeedGuid": guid, "IsReferenceFeedsIncluded": include_reference_feeds},
            idempotency="non_idempotent",
            expected=(200, 201, 202),
        )
        return _envelope(payload) if payload is not None else {}

    # -- field encoding ---------------------------------------------------

    async def encode_fields(self, level_id: int, values: dict[str, Any]) -> dict[str, dict[str, Any]]:
        """Encode logical field values into Archer FieldContents write shape."""
        fields = await self.fields_for_level(level_id)
        by_name = {str(f.get("Name")): f for f in fields}
        encoded: dict[str, dict[str, Any]] = {}
        for name, value in values.items():
            field = by_name.get(name)
            if field is None:
                raise ConfigError(f"Archer level {level_id} has no field named {name!r}")
            field_id = int(field["Id"])
            field_type = int(field.get("Type") or 0)
            key, encoded_value = await self._encode_value(field, field_type, value)
            encoded[str(field_id)] = {"Type": field_type, key: encoded_value, "FieldId": field_id}
        return encoded

    async def _encode_value(self, field: dict[str, Any], field_type: int, value: Any) -> tuple[str, Any]:
        if field_type == 4:  # Values List: names must resolve to ValuesListIds
            list_id = field.get("RelatedValuesListId")
            if list_id is None:
                raise ConfigError(f"Archer values-list field {field.get('Id')} has no RelatedValuesListId")
            tree = await self.values_list(int(list_id))
            names_to_ids = _flatten_values_list(tree)
            items = value if isinstance(value, list) else [value]
            ids: list[int] = []
            for item in items:
                if isinstance(item, int):
                    ids.append(item)
                elif str(item) in names_to_ids:
                    ids.append(names_to_ids[str(item)])
                else:
                    raise ConfigError(f"Archer values list has no entry named {item!r}")
            return "Value", {"ValuesListIds": ids}
        if field_type == 7:  # External Links
            links = [{"Name": i.get("value"), "URL": i.get("link")} for i in value]
            return "Value", links
        if field_type == 8:  # Users/Groups List
            users = value.get("users") or []
            groups = value.get("groups") or []
            return "Value", {
                "UserList": [{"ID": u} for u in users],
                "GroupList": [{"ID": g} for g in groups],
            }
        if field_type == 9:  # Cross-Reference
            refs = value if isinstance(value, list) else [value]
            return "Value", [{"ContentID": r} for r in refs]
        if field_type == 19:  # IP Address
            return "IpAddressBytes", value
        return "Value", value


def _iter_local(element: Element, name: str):
    """Iterate descendants by local tag name (Archer qualifies response elements)."""
    for child in element.iter():
        tag = child.tag
        if isinstance(tag, str) and tag.rsplit("}", 1)[-1] == name:
            yield child


def _soap_field_value(field_el: Element) -> Any:
    field_type = field_el.get("type")
    if field_type == "3":  # Date
        return field_el.get("xmlConvertedValue") or field_el.text
    if field_type == "4":  # Values List
        names = [lv.get("displayName") for lv in _iter_local(field_el, "ListValue")]
        return [n for n in names if n is not None]
    return field_el.text


def _flatten_values_list(tree: dict[str, Any]) -> dict[str, int]:
    """Flatten the values-list Children tree into {name: id}."""
    flat: dict[str, int] = {}

    def walk(nodes: Any) -> None:
        for node in nodes or []:
            data = node.get("Data") or {}
            name, node_id = data.get("Name"), data.get("Id")
            if name is not None and node_id is not None:
                flat[str(name)] = int(node_id)
            walk(node.get("Children"))

    walk(tree.get("Children"))
    return flat
