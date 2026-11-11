"""Managed control-plane audit transports for EKS, AKS, and GKE clusters.

Managed Kubernetes services run the API server outside the customer's nodes, so the API audit
stream reaches the customer through the provider's log or messaging service instead of a node
file or a webhook. Each adapter reads that service over the kit HTTP client, decodes every
audit.k8s.io/v1 Event it finds, and emits an ``audit_event`` record carrying the same
``_dedupe_key`` as the file and webhook paths. ``AuditCursor.observe`` suppresses identities already
committed, so an overlapping re-read never duplicates an event.

Credentials are resolved by the caller and passed as bytes. The connector's HTTP client carries the
cluster bearer token, so every cloud request uses ``authenticate=False`` and carries its own
signature or token. The cloud host must also be listed in that client's ``extra_hosts``; the caller
builds the client.

Sources (each wire rule below is taken from one of these pages):
- CloudWatch Logs FilterLogEvents: https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_FilterLogEvents.html
- AWS Signature Version 4: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv4.html
- EKS control plane logging: https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html
- Event Hubs Capture overview: https://learn.microsoft.com/en-us/azure/event-hubs/event-hubs-capture-overview
- Captured Avro schema: https://learn.microsoft.com/en-us/azure/event-hubs/explore-captured-avro-files
- Blob List Blobs: https://learn.microsoft.com/en-us/rest/api/storageservices/list-blobs
- Blob Get Blob: https://learn.microsoft.com/en-us/rest/api/storageservices/get-blob
- Avro 1.11 specification: https://avro.apache.org/docs/1.11.1/specification/
- Service-account JWT bearer grant: https://developers.google.com/identity/protocols/oauth2/service-account
- Pub/Sub subscriptions.pull: https://cloud.google.com/pubsub/docs/reference/rest/v1/projects.subscriptions/pull
- Pub/Sub subscriptions.acknowledge: https://cloud.google.com/pubsub/docs/reference/rest/v1/projects.subscriptions/acknowledge
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import struct
import zlib
from collections.abc import AsyncIterator, Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qsl, quote, urlencode

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from icuhub.connectors._kube.models import AuditCursor
from icuhub.connectors._kube.webhooks import KUBE_AUDIT_RECORD_KIND
from icuhub.kit.errors import BudgetExhausted, ConfigError, VendorContractError
from icuhub.kit.http import VendorHttp
from icuhub.kit.types import RawBatch
from icuhub.kit.xml import local, parse_xml

__all__ = [
    "CloudWatchSource",
    "EventHubCaptureSource",
    "PubSubSource",
    "normalize_audit_event",
    "stream_cloudwatch_audit",
    "stream_event_hub_audit",
    "stream_pubsub_audit",
]

# CloudWatch Logs FilterLogEvents accepts limit 1-10000 (API reference). The overlap is a design
# choice: a restarted run re-reads this window and identity dedupe removes the repeats.
_CLOUDWATCH_PAGE_LIMIT = 10000
_CLOUDWATCH_OVERLAP_MS = 5 * 60 * 1000
_CLOUDWATCH_CONTENT_TYPE = "application/x-amz-json-1.1"
_CLOUDWATCH_TARGET = "Logs_20140328.FilterLogEvents"

_PUBSUB_API = "https://pubsub.googleapis.com/v1/"
_PUBSUB_TOKEN_URI = "https://oauth2.googleapis.com/token"
_PUBSUB_SCOPE = "https://www.googleapis.com/auth/pubsub"
_JWT_BEARER_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer"
# The service-account JWT guide allows at most one hour between iat and exp.
_PUBSUB_JWT_LIFETIME_S = 3600
_PUBSUB_PULL_MAX = 100  # design choice: messages per pull

# [INFERENCE: pinned Blob service version; confirm against the Blob service version list before release]
_BLOB_API_VERSION = "2020-10-02"
_BLOB_LIST_MAX_PAGES = 1000
# Design choice: the whole file is held in memory, so the bound is sized near the default Capture window.
_MAX_CAPTURE_BYTES = 300 * 1024 * 1024

_AVRO_MAGIC = b"Obj\x01"
_AVRO_SYNC_BYTES = 16
_MAX_AVRO_ITEMS = 1_000_000

_AWS_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-\d+")
_LOG_GROUP = re.compile(r"[A-Za-z0-9._/#-]{1,512}")
_STORAGE_ACCOUNT = re.compile(r"[a-z0-9]{3,24}")
_BLOB_CONTAINER = re.compile(r"[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])")
_PUBSUB_SUBSCRIPTION = re.compile(
    r"projects/[a-z][a-z0-9-]{4,61}[a-z0-9]/subscriptions/[A-Za-z][A-Za-z0-9._~+%-]{2,254}"
)


@dataclass(frozen=True)
class CloudWatchSource:
    """An EKS control-plane log group. Only streams whose name starts with ``stream_prefix`` are audit."""

    region: str
    log_group: str
    stream_prefix: str
    credential: bytes  # JSON: access_key_id, secret_access_key, optional session_token
    api_source: str


@dataclass(frozen=True)
class EventHubCaptureSource:
    """An Event Hubs Capture destination in Blob storage. ``prefix`` is the capture path under the container."""

    account: str
    container: str
    prefix: str
    credential: bytes  # SAS query string carrying at least ``sig``
    api_source: str


@dataclass(frozen=True)
class PubSubSource:
    """A Pub/Sub subscription that receives the control-plane audit log through a log sink."""

    subscription: str  # projects/<project>/subscriptions/<name>
    credential: bytes  # service-account key JSON
    api_source: str


@dataclass(frozen=True)
class _AwsCredentials:
    access_key_id: str
    secret_access_key: str
    session_token: str | None


@dataclass(frozen=True)
class _ServiceAccount:
    client_email: str
    private_key: RSAPrivateKey


def normalize_audit_event(event: Any, *, api_source: str, cluster: str) -> dict[str, Any]:
    """Return the ``audit_event`` record for one audit.k8s.io/v1 Event.

    Flat Event fields are kept unchanged; the mapper validates them. ``_dedupe_key`` is
    ``api_source:auditID:stage``, the same identity the webhook and file paths produce.
    """
    if not isinstance(event, dict):
        raise VendorContractError("Kubernetes audit event is not a JSON object")
    audit_id = _text_field(event, "auditID")
    stage = _text_field(event, "stage")
    return {
        **event,
        "_record_kind": KUBE_AUDIT_RECORD_KIND,
        "_api_source": api_source,
        "_dedupe_key": f"{api_source}:{audit_id}:{stage}",
        "_cluster": cluster,
    }


def _text_field(event: dict[str, Any], key: str) -> str:
    value = event.get(key)
    if not isinstance(value, str) or not value:
        raise VendorContractError(f"Kubernetes audit event has no {key}")
    return value


def _events_from_bytes(raw: bytes, *, api_source: str, cluster: str) -> list[dict[str, Any]]:
    try:
        document = json.loads(raw)
    except ValueError as exc:
        raise VendorContractError("managed audit payload is not JSON") from exc
    if not isinstance(document, dict):
        raise VendorContractError("managed audit payload is not a JSON object")
    kind = document.get("kind")
    if kind == "Event":
        return [normalize_audit_event(document, api_source=api_source, cluster=cluster)]
    if kind != "EventList":
        raise VendorContractError("managed audit payload is neither an Event nor an EventList")
    listed = document.get("items")
    if not isinstance(listed, list):
        raise VendorContractError("Kubernetes audit EventList has no items list")
    return [normalize_audit_event(item, api_source=api_source, cluster=cluster) for item in listed]


def _fresh(cursor: AuditCursor, records: list[dict[str, Any]]) -> tuple[AuditCursor, list[dict[str, Any]]]:
    fresh: list[dict[str, Any]] = []
    for record in records:
        cursor, seen = cursor.observe(record["_dedupe_key"])
        if not seen:
            fresh.append(record)
    return cursor, fresh


def _config_object(raw: bytes, what: str) -> dict[str, Any]:
    try:
        document = json.loads(raw)
    except ValueError as exc:
        raise ConfigError(f"{what} is not valid JSON") from exc
    if not isinstance(document, dict):
        raise ConfigError(f"{what} must be a JSON object")
    return document


def _config_text(document: dict[str, Any], key: str, what: str) -> str:
    value = document.get(key)
    if not isinstance(value, str) or not value:
        raise ConfigError(f"{what} has no {key}")
    return value


def _require_match(pattern: re.Pattern[str], value: str, what: str) -> None:
    if pattern.fullmatch(value) is None:
        raise ConfigError(f"{what} is not valid: {value!r}")


def _response_object(value: Any, what: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise VendorContractError(f"{what} is not a JSON object")
    return value


def _list_field(document: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = document.get(key, [])
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise VendorContractError(f"response field {key} is not a list of objects")
    return value


def _optional_text(document: dict[str, Any], key: str) -> str | None:
    value = document.get(key)
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise VendorContractError(f"response field {key} is not text")
    return value


def _compact_json(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


# ---------------------------------------------------------------- CloudWatch Logs (EKS)


def _aws_credentials(raw: bytes) -> _AwsCredentials:
    what = "AWS credential"
    document = _config_object(raw, what)
    token = document.get("session_token")
    if token is not None and not isinstance(token, str):
        raise ConfigError(f"{what} session_token must be text")
    return _AwsCredentials(
        access_key_id=_config_text(document, "access_key_id", what),
        secret_access_key=_config_text(document, "secret_access_key", what),
        session_token=token or None,
    )


def _hmac_bytes(key: bytes, message: str) -> bytes:
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()


def _sign_v4(
    creds: _AwsCredentials,
    *,
    region: str,
    host: str,
    payload: bytes,
    headers: dict[str, str],
    now: datetime,
) -> dict[str, str]:
    """Return the outgoing headers for one ``POST /`` to the regional logs endpoint, signed with SigV4."""
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date = now.strftime("%Y%m%d")
    signed: dict[str, str] = {"host": host, "x-amz-date": amz_date}
    signed.update({name.lower(): value for name, value in headers.items()})
    if creds.session_token:
        signed["x-amz-security-token"] = creds.session_token
    names = sorted(signed)
    canonical_headers = "".join(f"{name}:{signed[name].strip()}\n" for name in names)
    signed_names = ";".join(names)
    canonical_request = "\n".join(
        ["POST", "/", "", canonical_headers, signed_names, hashlib.sha256(payload).hexdigest()]
    )
    scope = f"{date}/{region}/logs/aws4_request"
    string_to_sign = "\n".join(
        ["AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()]
    )
    signing_key = _hmac_bytes(f"AWS4{creds.secret_access_key}".encode(), date)
    for part in (region, "logs", "aws4_request"):
        signing_key = _hmac_bytes(signing_key, part)
    signature = hmac.new(signing_key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    outgoing = {name: value for name, value in signed.items() if name != "host"}
    outgoing["authorization"] = (
        f"AWS4-HMAC-SHA256 Credential={creds.access_key_id}/{scope}, "
        f"SignedHeaders={signed_names}, Signature={signature}"
    )
    return outgoing


async def _filter_log_events(
    http: VendorHttp,
    creds: _AwsCredentials,
    source: CloudWatchSource,
    body: dict[str, Any],
    now: datetime,
) -> dict[str, Any]:
    host = f"logs.{source.region}.amazonaws.com"
    payload = _compact_json(body)
    headers = _sign_v4(
        creds,
        region=source.region,
        host=host,
        payload=payload,
        headers={"content-type": _CLOUDWATCH_CONTENT_TYPE, "x-amz-target": _CLOUDWATCH_TARGET},
        now=now,
    )
    result = await http.request(
        "POST",
        f"https://{host}/",
        content=payload,
        headers=headers,
        idempotency="safe_read",
        authenticate=False,
    )
    return _response_object(result.json(), "CloudWatch FilterLogEvents response")


async def stream_cloudwatch_audit(
    http: VendorHttp,
    source: CloudWatchSource,
    cursor: AuditCursor,
    *,
    cluster: str,
    clock: Callable[[], datetime],
    max_pages: int,
) -> AsyncIterator[RawBatch]:
    """Read one EKS audit log group from the committed position, one FilterLogEvents page per batch.

    FilterLogEvents pages are not timestamp-ordered across log streams, so the stored position (the
    newest audit timestamp) moves only when a run reaches its last page. A run that stops early
    re-reads from the previous position and identity dedupe removes what was already committed.
    """
    _require_match(_AWS_REGION, source.region, "CloudWatch region")
    _require_match(_LOG_GROUP, source.log_group, "CloudWatch log group")
    creds = _aws_credentials(source.credential)
    key = f"cloudwatch/{source.region}/{source.log_group}"
    previous = cursor.managed_positions.get(key)
    newest: int | None = None if previous is None else int(previous)
    start_ms = None if newest is None else newest - _CLOUDWATCH_OVERLAP_MS
    token: str | None = None
    for _ in range(max_pages):
        body: dict[str, Any] = {"logGroupName": source.log_group, "limit": _CLOUDWATCH_PAGE_LIMIT}
        if start_ms is not None:
            body["startTime"] = start_ms
        if token is not None:
            body["nextToken"] = token
        page = await _filter_log_events(http, creds, source, body, clock().astimezone(UTC))
        records: list[dict[str, Any]] = []
        for event in _list_field(page, "events"):
            stream_name = event.get("logStreamName")
            timestamp = event.get("timestamp")
            message = event.get("message")
            if not isinstance(stream_name, str) or not isinstance(timestamp, int) or not isinstance(message, str):
                raise VendorContractError("CloudWatch event lacks logStreamName, timestamp, or message")
            if not stream_name.startswith(source.stream_prefix):
                continue
            newest = timestamp if newest is None else max(newest, timestamp)
            records.extend(_events_from_bytes(message.encode("utf-8"), api_source=source.api_source, cluster=cluster))
        cursor, fresh = _fresh(cursor, records)
        token = _optional_text(page, "nextToken")
        complete = token is None
        if complete and newest is not None:
            cursor = cursor.advance_managed("cloudwatch", key, str(newest))
        yield RawBatch(records=fresh, checkpoint=cursor, complete=complete)
        if complete:
            return
    raise BudgetExhausted("CloudWatch FilterLogEvents exceeded the page budget before its last page")


# ---------------------------------------------------------------- Event Hubs Capture (AKS)


def _sas_params(raw: bytes) -> dict[str, str]:
    what = "Event Hubs Capture SAS"
    try:
        pairs = parse_qsl(raw.decode("ascii").strip().removeprefix("?"), keep_blank_values=False, strict_parsing=True)
    except ValueError as exc:
        raise ConfigError(f"{what} is not a query string") from exc
    params = dict(pairs)
    if len(params) != len(pairs) or "sig" not in params:
        raise ConfigError(f"{what} must carry a signature and no repeated parameter")
    return params


async def _list_blob_names(http: VendorHttp, *, url: str, sas: dict[str, str], prefix: str) -> list[str]:
    names: list[str] = []
    marker = ""
    for _ in range(_BLOB_LIST_MAX_PAGES):
        params: dict[str, str] = {**sas, "restype": "container", "comp": "list", "prefix": prefix}
        if marker:
            params["marker"] = marker
        result = await http.request(
            "GET",
            url,
            params=params,
            headers={"x-ms-version": _BLOB_API_VERSION},
            idempotency="safe_read",
            authenticate=False,
        )
        root = parse_xml(result.content)
        names.extend(_blob_names(root))
        marker = _child_text(root, "NextMarker") or ""
        if not marker:
            return names
    raise BudgetExhausted("Blob listing exceeded the page budget")


def _blob_names(root: Any) -> list[str]:
    names: list[str] = []
    for element in root.iter():
        if local(element.tag) != "Blob":
            continue
        name = _child_text(element, "Name")
        if name is None:
            raise VendorContractError("Blob listing entry has no Name")
        names.append(name)
    return names


def _child_text(element: Any, name: str) -> str | None:
    for child in element:
        if local(child.tag) == name:
            return child.text or None
    return None


async def _download_blob(http: VendorHttp, *, url: str, sas: dict[str, str], name: str) -> bytes:
    result = await http.request(
        "GET",
        f"{url}/{quote(name, safe='/')}",
        params=sas,
        headers={"x-ms-version": _BLOB_API_VERSION},
        idempotency="safe_read",
        authenticate=False,
    )
    if len(result.content) > _MAX_CAPTURE_BYTES:
        raise BudgetExhausted(f"Capture file exceeds the {_MAX_CAPTURE_BYTES} byte budget")
    return result.content


def _capture_events(records: list[Any], *, api_source: str, cluster: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for record in records:
        if not isinstance(record, dict):
            raise VendorContractError("Event Hubs Capture record is not a record")
        body = record.get("Body")
        if not isinstance(body, bytes):
            raise VendorContractError("Event Hubs Capture record has no Body bytes")
        events.extend(_events_from_bytes(body, api_source=api_source, cluster=cluster))
    return events


async def stream_event_hub_audit(
    http: VendorHttp,
    source: EventHubCaptureSource,
    cursor: AuditCursor,
    *,
    cluster: str,
    max_files: int,
) -> AsyncIterator[RawBatch]:
    """Decode Capture files under ``prefix`` in blob-name order, committing one file per batch.

    The position is the name of the last fully committed file. This assumes Capture finishes files
    in name order within a container; a file whose name sorts before the position is not read.
    [UNVERIFIED: Capture completion order under the default path template]
    """
    _require_match(_STORAGE_ACCOUNT, source.account, "storage account")
    _require_match(_BLOB_CONTAINER, source.container, "Blob container")
    sas = _sas_params(source.credential)
    url = f"https://{source.account}.blob.core.windows.net/{source.container}"
    key = f"event_hub/{source.account}/{source.container}"
    position = cursor.managed_positions.get(key)
    listed = await _list_blob_names(http, url=url, sas=sas, prefix=source.prefix)
    pending = [name for name in sorted(listed) if position is None or name > position]
    selected = pending[:max_files]
    if not selected:
        yield RawBatch(records=[], checkpoint=cursor, complete=True)
        return
    for index, name in enumerate(selected):
        payload = await _download_blob(http, url=url, sas=sas, name=name)
        events = _capture_events(
            _decode_capture_file(payload), api_source=source.api_source, cluster=cluster
        )
        cursor, fresh = _fresh(cursor, events)
        cursor = cursor.advance_managed("event_hub", key, name)
        complete = index == len(selected) - 1 and len(pending) == len(selected)
        yield RawBatch(records=fresh, checkpoint=cursor, complete=complete)


def _decode_capture_file(data: bytes) -> list[Any]:
    """Decode one Avro object-container file written by Event Hubs Capture. Null and deflate codecs only."""
    if len(data) > _MAX_CAPTURE_BYTES:
        raise BudgetExhausted(f"Capture file exceeds the {_MAX_CAPTURE_BYTES} byte budget")
    reader = _AvroReader(data)
    if reader.take(len(_AVRO_MAGIC)) != _AVRO_MAGIC:
        raise VendorContractError("Event Hubs Capture file is not an Avro object container")
    metadata = _read_value(reader, {"type": "map", "values": "bytes"})
    if not isinstance(metadata, dict) or not isinstance(metadata.get("avro.schema"), bytes):
        raise VendorContractError("Avro header has no schema")
    try:
        schema = json.loads(metadata["avro.schema"])
    except ValueError as exc:
        raise VendorContractError("Avro schema is not JSON") from exc
    codec = metadata.get("avro.codec", b"null")
    if codec not in (b"null", b"deflate"):
        raise VendorContractError(f"unsupported Avro codec {codec!r}")
    sync = reader.take(_AVRO_SYNC_BYTES)
    records: list[Any] = []
    while reader.remaining():
        count = reader.long()
        size = reader.long()
        if count < 0 or size < 0:
            raise VendorContractError("Avro block header is negative")
        if count > _MAX_AVRO_ITEMS - len(records):
            raise BudgetExhausted("Avro file exceeds the record budget")
        block = reader.take(size)
        if codec == b"deflate":
            block = _inflate(block)
        block_reader = _AvroReader(block)
        for _ in range(count):
            records.append(_read_value(block_reader, schema))
        if block_reader.remaining():
            raise VendorContractError("Avro block has trailing bytes")
        if reader.take(_AVRO_SYNC_BYTES) != sync:
            raise VendorContractError("Avro sync marker does not match the header")
    return records


def _inflate(block: bytes) -> bytes:
    decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
    try:
        inflated = decompressor.decompress(block, _MAX_CAPTURE_BYTES + 1)
    except zlib.error as exc:
        raise VendorContractError("Avro deflate block is corrupt") from exc
    if len(inflated) > _MAX_CAPTURE_BYTES:
        raise BudgetExhausted(f"Capture block inflates beyond the {_MAX_CAPTURE_BYTES} byte budget")
    if not decompressor.eof:
        raise VendorContractError("Avro deflate block is truncated")
    return inflated


class _AvroReader:
    """Bounds-checked reader over one Avro byte buffer. Every read fails before it passes the end."""

    __slots__ = ("_data", "_pos")

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    def remaining(self) -> int:
        return len(self._data) - self._pos

    def take(self, size: int) -> bytes:
        if size < 0 or size > self.remaining():
            raise VendorContractError("Avro data ends before its declared length")
        start = self._pos
        self._pos += size
        return self._data[start : self._pos]

    def long(self) -> int:
        """Read a zigzag-encoded variable-length integer (Avro int and long)."""
        shift = 0
        accumulated = 0
        while True:
            byte = self.take(1)[0]
            accumulated |= (byte & 0x7F) << shift
            if not byte & 0x80:
                break
            shift += 7
            if shift > 63:
                raise VendorContractError("Avro variable-length integer is too long")
        return (accumulated >> 1) ^ -(accumulated & 1)


def _read_value(reader: _AvroReader, schema: Any) -> Any:
    if isinstance(schema, list):
        index = reader.long()
        if not 0 <= index < len(schema):
            raise VendorContractError("Avro union index is out of range")
        return _read_value(reader, schema[index])
    if isinstance(schema, str):
        return _read_primitive(reader, schema)
    if not isinstance(schema, dict):
        raise VendorContractError("Avro schema node is not a type name, union, or object")
    kind = schema.get("type")
    if kind == "record":
        return _read_record(reader, schema)
    if kind == "map":
        return _read_map(reader, schema.get("values"))
    if kind == "array":
        return _read_array(reader, schema.get("items"))
    if kind == "enum":
        symbols = schema.get("symbols")
        index = reader.long()
        if not isinstance(symbols, list) or not 0 <= index < len(symbols):
            raise VendorContractError("Avro enum index is out of range")
        return symbols[index]
    if kind == "fixed" and isinstance(schema.get("size"), int):
        return reader.take(schema["size"])
    if isinstance(kind, str):
        return _read_primitive(reader, kind)
    raise VendorContractError(f"unsupported Avro type {kind!r}")


def _read_record(reader: _AvroReader, schema: dict[str, Any]) -> dict[str, Any]:
    fields = schema.get("fields")
    if not isinstance(fields, list):
        raise VendorContractError("Avro record has no fields list")
    record: dict[str, Any] = {}
    for field in fields:
        if not isinstance(field, dict) or not isinstance(field.get("name"), str) or "type" not in field:
            raise VendorContractError("Avro record field is malformed")
        record[field["name"]] = _read_value(reader, field["type"])
    return record


def _block_counts(reader: _AvroReader) -> Iterator[int]:
    """Yield item counts for each Avro array or map block, honouring negative-count blocks."""
    total = 0
    while True:
        count = reader.long()
        if count == 0:
            return
        if count < 0:
            count = -count
            reader.long()  # block byte size; items are decoded in place
        total += count
        if total > _MAX_AVRO_ITEMS:
            raise BudgetExhausted("Avro collection exceeds the item budget")
        yield count


def _read_map(reader: _AvroReader, values: Any) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for count in _block_counts(reader):
        for _ in range(count):
            key = _read_primitive(reader, "string")
            result[key] = _read_value(reader, values)
    return result


def _read_array(reader: _AvroReader, items: Any) -> list[Any]:
    result: list[Any] = []
    for count in _block_counts(reader):
        for _ in range(count):
            result.append(_read_value(reader, items))
    return result


def _read_primitive(reader: _AvroReader, name: str) -> Any:
    if name == "null":
        return None
    if name == "boolean":
        byte = reader.take(1)
        if byte not in (b"\x00", b"\x01"):
            raise VendorContractError("Avro boolean is neither 0 nor 1")
        return byte == b"\x01"
    if name in ("int", "long"):
        return reader.long()
    if name == "float":
        return struct.unpack("<f", reader.take(4))[0]
    if name == "double":
        return struct.unpack("<d", reader.take(8))[0]
    if name == "bytes":
        return reader.take(reader.long())
    if name == "string":
        raw = reader.take(reader.long())
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise VendorContractError("Avro string is not UTF-8") from exc
    raise VendorContractError(f"unsupported Avro primitive {name!r}")


# ---------------------------------------------------------------- Pub/Sub (GKE)


def _service_account(raw: bytes) -> _ServiceAccount:
    what = "Pub/Sub service account key"
    document = _config_object(raw, what)
    if document.get("token_uri", _PUBSUB_TOKEN_URI) != _PUBSUB_TOKEN_URI:
        raise ConfigError(f"{what} token_uri must be {_PUBSUB_TOKEN_URI}")
    pem = _config_text(document, "private_key", what).encode("utf-8")
    try:
        key = serialization.load_pem_private_key(pem, password=None)
    except (ValueError, UnsupportedAlgorithm) as exc:
        raise ConfigError(f"{what} private_key is not a usable PEM key") from exc
    if not isinstance(key, RSAPrivateKey):
        raise ConfigError(f"{what} private_key must be an RSA key")
    return _ServiceAccount(client_email=_config_text(document, "client_email", what), private_key=key)


def _signed_assertion(account: _ServiceAccount, now: datetime) -> str:
    issued = int(now.timestamp())
    header = _b64url(_compact_json({"alg": "RS256", "typ": "JWT"}))
    claims = _b64url(
        _compact_json(
            {
                "iss": account.client_email,
                "scope": _PUBSUB_SCOPE,
                "aud": _PUBSUB_TOKEN_URI,
                "iat": issued,
                "exp": issued + _PUBSUB_JWT_LIFETIME_S,
            }
        )
    )
    signing_input = f"{header}.{claims}".encode("ascii")
    signature = account.private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{header}.{claims}.{_b64url(signature)}"


async def _access_token(http: VendorHttp, account: _ServiceAccount, now: datetime) -> str:
    form = urlencode({"grant_type": _JWT_BEARER_GRANT, "assertion": _signed_assertion(account, now)})
    result = await http.request(
        "POST",
        _PUBSUB_TOKEN_URI,
        content=form.encode("ascii"),
        headers={"content-type": "application/x-www-form-urlencoded"},
        idempotency="safe_read",
        authenticate=False,
    )
    token = _response_object(result.json(), "OAuth token response").get("access_token")
    if not isinstance(token, str) or not token:
        raise VendorContractError("OAuth token response has no access_token")
    return token


async def _pull(http: VendorHttp, token: str, subscription: str) -> list[Any]:
    # Pull leases messages but a repeated pull only redelivers unacknowledged ones, which dedupe removes.
    result = await http.request(
        "POST",
        f"{_PUBSUB_API}{subscription}:pull",
        json={"maxMessages": _PUBSUB_PULL_MAX},
        headers={"authorization": f"Bearer {token}"},
        idempotency="safe_read",
        authenticate=False,
    )
    messages = _response_object(result.json(), "Pub/Sub pull response").get("receivedMessages", [])
    if not isinstance(messages, list):
        raise VendorContractError("Pub/Sub pull receivedMessages is not a list")
    return messages


async def _acknowledge(http: VendorHttp, token: str, subscription: str, ack_ids: list[str]) -> None:
    await http.request(
        "POST",
        f"{_PUBSUB_API}{subscription}:acknowledge",
        json={"ackIds": ack_ids},
        headers={"authorization": f"Bearer {token}"},
        idempotency="idempotent_write",
        authenticate=False,
    )


def _pubsub_records(
    messages: list[Any], *, api_source: str, cluster: str
) -> tuple[list[dict[str, Any]], list[str]]:
    records: list[dict[str, Any]] = []
    ack_ids: list[str] = []
    for received in messages:
        if (
            not isinstance(received, dict)
            or not isinstance(received.get("ackId"), str)
            or not isinstance(received.get("message"), dict)
        ):
            raise VendorContractError("Pub/Sub receivedMessages entry is malformed")
        data = received["message"].get("data")
        if not isinstance(data, str):
            raise VendorContractError("Pub/Sub message has no data")
        try:
            payload = base64.b64decode(data, validate=True)
        except ValueError as exc:
            raise VendorContractError("Pub/Sub message data is not base64") from exc
        records.extend(_events_from_bytes(payload, api_source=api_source, cluster=cluster))
        ack_ids.append(received["ackId"])
    return records, ack_ids


async def stream_pubsub_audit(
    http: VendorHttp,
    source: PubSubSource,
    cursor: AuditCursor,
    *,
    cluster: str,
    clock: Callable[[], datetime],
    max_pulls: int,
) -> AsyncIterator[RawBatch]:
    """Drain the subscription until a pull returns no messages, acknowledging each batch after commit.

    The host requests the next batch only after it has committed the current one, so the previous
    batch's ack IDs are acknowledged at the top of the next iteration. A message that fails to decode
    is never acknowledged, so Pub/Sub redelivers it and the run fails closed.
    """
    _require_match(_PUBSUB_SUBSCRIPTION, source.subscription, "Pub/Sub subscription")
    account = _service_account(source.credential)
    token = await _access_token(http, account, clock().astimezone(UTC))
    pending: list[str] = []
    for _ in range(max_pulls):
        if pending:
            await _acknowledge(http, token, source.subscription, pending)
            pending = []
        messages = await _pull(http, token, source.subscription)
        if not messages:
            yield RawBatch(records=[], checkpoint=cursor, complete=True)
            return
        records, ack_ids = _pubsub_records(messages, api_source=source.api_source, cluster=cluster)
        cursor, fresh = _fresh(cursor, records)
        pending = ack_ids
        yield RawBatch(records=fresh, checkpoint=cursor, complete=False)
    if pending:
        await _acknowledge(http, token, source.subscription, pending)
