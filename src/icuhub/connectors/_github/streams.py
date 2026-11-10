"""GitHub REST streams with deterministic checkpoints and bounded file evidence."""

from __future__ import annotations

import base64
import binascii
import gzip
import hashlib
import json
from collections.abc import AsyncIterator, Callable, Mapping
from datetime import UTC, datetime
from io import BytesIO
from typing import Any
from urllib.parse import quote

from icuhub.kit.cursors import SequenceCursor, SnapshotCursor, TimeIdCursor
from icuhub.kit.errors import BudgetExhausted, ConfigError, NotFound, VendorContractError
from icuhub.kit.mapping import epoch_ms
from icuhub.kit.types import RawBatch, Target

_PAGE_SIZE = 100
_BATCH_SIZE = 100
_STREAM_NAMES = frozenset(
    {
        "code_scanning_alerts",
        "dependabot_alerts",
        "secret_scanning_alerts",
        "branch_protection",
        "pull_requests",
        "reviews",
        "review_comments",
        "audit_events",
        "audit_stream_files",
        "repositories",
        "organizations",
        "users",
        "teams",
        "team_members",
        "team_repositories",
        "collaborators",
        "organization_external_identities",
        "branches",
        "tags",
        "commits",
        "repository_files",
        "workflows",
        "workflow_runs",
        "workflow_jobs",
        "workflow_artifacts",
        "actions_caches",
        "actions_runners",
        "commit_statuses",
        "check_runs",
    }
)


def _segment(value: str) -> str:
    return quote(value, safe="")


def _repository(connector, target: Target | None) -> tuple[Any, int, str]:
    if target is None:
        raise ConfigError("GitHub repository stream requires a repository target")
    reference = connector.target_repository(target)
    try:
        repository_id = int(target.id)
    except (TypeError, ValueError) as exc:
        raise ConfigError("GitHub repository target id must be numeric") from exc
    path = f"/repos/{_segment(reference.owner)}/{_segment(reference.repo)}"
    return reference, repository_id, path


def _repository_context(reference: Any, repository_id: int) -> dict[str, Any]:
    full_name = f"{reference.owner}/{reference.repo}"
    return {
        "_repository_id": repository_id,
        "_repository_owner": reference.owner,
        "_repository_name": reference.repo,
        "_repository_full_name": full_name,
        "_repository": {
            "id": repository_id,
            "owner": reference.owner,
            "name": reference.repo,
            "full_name": full_name,
        },
    }


def _inject(raw: Mapping[str, Any], context: Mapping[str, Any]) -> dict[str, Any]:
    return {**dict(raw), **dict(context)}


def _object(value: Any, source: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise VendorContractError(f"GitHub {source} response must be an object")
    return value


async def _one(connector, path: str, context: Mapping[str, Any] | None = None) -> dict[str, Any]:
    result = await connector.request("GET", path)
    raw = _object(result.json(), path)
    return _inject(raw, context or {})


async def _paged(
    connector,
    path: str,
    *,
    params: Mapping[str, Any] | None = None,
    items_key: str | None = None,
    context: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    query = {"per_page": _PAGE_SIZE, **dict(params or {})}
    records: list[dict[str, Any]] = []
    async for page, _ in connector.pages(path, params=query, items_key=items_key):
        for item in page:
            if not isinstance(item, dict):
                raise VendorContractError(f"GitHub {path} page contains a non-object record")
            records.append(_inject(item, context or {}))
    return records


def _time_value(raw: Mapping[str, Any], *paths: tuple[str, ...]) -> datetime:
    value: Any = None
    for path in paths:
        current: Any = raw
        for key in path:
            if not isinstance(current, Mapping):
                current = None
                break
            current = current.get(key)
        if current not in (None, ""):
            value = current
            break
    if value is None:
        raise VendorContractError("GitHub time_id record has no usable vendor timestamp")
    try:
        milliseconds = epoch_ms(value)
    except VendorContractError as exc:
        raise VendorContractError("GitHub time_id record has an invalid vendor timestamp") from exc
    if milliseconds is None:
        raise VendorContractError("GitHub time_id record has no usable vendor timestamp")
    try:
        return datetime.fromtimestamp(milliseconds / 1000, tz=UTC)
    except (OverflowError, OSError, ValueError) as exc:
        raise VendorContractError("GitHub time_id record timestamp is outside the supported range") from exc


def _updated_time(raw: Mapping[str, Any]) -> datetime:
    return _time_value(raw, ("updated_at",), ("created_at",))


def _commit_time(raw: Mapping[str, Any]) -> datetime:
    return _time_value(
        raw,
        ("commit", "committer", "date"),
        ("commit", "author", "date"),
        ("updated_at",),
        ("created_at",),
    )


def _review_time(raw: Mapping[str, Any]) -> datetime:
    return _time_value(
        raw,
        ("submitted_at",),
        ("updated_at",),
        ("created_at",),
        ("_pull_request_updated_at",),
    )


def _job_time(raw: Mapping[str, Any]) -> datetime:
    return _time_value(
        raw,
        ("updated_at",),
        ("completed_at",),
        ("started_at",),
        ("created_at",),
        ("_workflow_run_updated_at",),
    )


def _audit_time(raw: Mapping[str, Any]) -> datetime:
    return _time_value(raw, ("@timestamp",), ("created_at",), ("timestamp",), ("time",))


def _string_id(raw: Mapping[str, Any], *keys: str) -> str:
    for key in keys:
        value = raw.get(key)
        if value is not None and not isinstance(value, (dict, list)) and str(value):
            return str(value)
    canonical = json.dumps(raw, sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _alert_id(raw: Mapping[str, Any]) -> str:
    return f"{raw.get('_repository_id')}:{_string_id(raw, 'number', 'id')}"


def _audit_id(raw: Mapping[str, Any]) -> str | None:
    for key in ("_document_id", "document_id", "event_id", "id"):
        value = raw.get(key)
        if value is not None and not isinstance(value, (dict, list)) and str(value):
            return str(value)
    return None


def _required_audit_id(raw: Mapping[str, Any]) -> str:
    value = _audit_id(raw)
    return value if value is not None else _string_id(raw)


def _snapshot_cursor(connector, stream_name: str, scope: str) -> SnapshotCursor:
    started_at = connector.ctx.clock()
    material = f"{connector.ctx.connection_id}\x1f{stream_name}\x1f{scope}\x1f{started_at.isoformat()}"
    return SnapshotCursor(
        snapshot_id=hashlib.sha256(material.encode("utf-8")).hexdigest()[:32],
        started_at=started_at,
        targets_done=[scope],
    )


def _identity_key(raw: Mapping[str, Any]) -> tuple[Any, ...]:
    repository = str(raw.get("_repository_id") or raw.get("_organization") or "")
    parent = str(raw.get("_team_id") or raw.get("_pull_request_number") or raw.get("_workflow_run_id") or "")
    for key in ("id", "number", "sha", "path", "name", "login", "key"):
        value = raw.get(key)
        if value is not None and not isinstance(value, (dict, list)):
            if isinstance(value, int) and not isinstance(value, bool):
                return repository, parent, 0, value, ""
            return repository, parent, 1, 0, str(value)
    return repository, parent, 2, 0, _string_id(raw)


async def _snapshot_batches(
    connector,
    stream_name: str,
    scope: str,
    records: list[dict[str, Any]],
    *,
    complete: bool = True,
) -> AsyncIterator[RawBatch]:
    cursor = _snapshot_cursor(connector, stream_name, scope)
    ordered = sorted(records, key=_identity_key)
    for offset in range(0, len(ordered), _BATCH_SIZE):
        yield RawBatch(records=ordered[offset : offset + _BATCH_SIZE], checkpoint=cursor, complete=False)
    yield RawBatch(records=[], checkpoint=cursor, complete=complete)


async def _time_id_batches(
    records: list[dict[str, Any]],
    checkpoint: Any,
    mode: str,
    *,
    time_of: Callable[[Mapping[str, Any]], datetime] = _updated_time,
    id_of: Callable[[Mapping[str, Any]], str] = lambda raw: _string_id(raw, "id", "number", "sha"),
) -> AsyncIterator[RawBatch]:
    cursor = checkpoint if isinstance(checkpoint, TimeIdCursor) else TimeIdCursor(ts=None)
    latest: dict[str, tuple[datetime, dict[str, Any]]] = {}
    for raw in records:
        timestamp = time_of(raw)
        record_id = id_of(raw)
        previous = latest.get(record_id)
        if previous is None or timestamp > previous[0]:
            latest[record_id] = (timestamp, raw)
    ordered = sorted((timestamp, record_id, raw) for record_id, (timestamp, raw) in latest.items())
    selected: list[tuple[datetime, str, dict[str, Any]]] = []
    window = cursor.window_start() if mode == "incremental" else None
    for timestamp, record_id, raw in ordered:
        if window is not None and timestamp < window:
            continue
        if mode == "incremental" and cursor.is_duplicate(timestamp, record_id):
            continue
        selected.append((timestamp, record_id, raw))
    cursor = cursor.advance(
        selected,
        ts_of=lambda row: row[0],
        id_of=lambda row: row[1],
    )
    output = [row[2] for row in selected]
    for offset in range(0, len(output), _BATCH_SIZE):
        yield RawBatch(records=output[offset : offset + _BATCH_SIZE], checkpoint=cursor, complete=False)
    yield RawBatch(records=[], checkpoint=cursor, complete=True)


async def _repository_time_stream(
    connector,
    stream_name: str,
    target: Target | None,
    checkpoint: Any,
    mode: str,
    *,
    path_suffix: str,
    params: Mapping[str, Any] | None = None,
    items_key: str | None = None,
    time_of: Callable[[Mapping[str, Any]], datetime] = _updated_time,
    id_of: Callable[[Mapping[str, Any]], str] = lambda raw: _string_id(raw, "id", "number", "sha"),
) -> AsyncIterator[RawBatch]:
    reference, repository_id, repository_path = _repository(connector, target)
    context = _repository_context(reference, repository_id)
    query = dict(params or {})
    cursor = checkpoint if isinstance(checkpoint, TimeIdCursor) else None
    window = cursor.window_start() if mode == "incremental" and cursor is not None else None
    if stream_name in {"commits", "review_comments"} and window is not None:
        query["since"] = window.isoformat().replace("+00:00", "Z")
    if stream_name == "workflow_runs" and window is not None:
        query["created"] = f">={window.isoformat().replace('+00:00', 'Z')}"
    records = await _paged(
        connector,
        f"{repository_path}/{path_suffix.lstrip('/')}",
        params=query,
        items_key=items_key,
        context=context,
    )

    def scoped_id(raw: Mapping[str, Any]) -> str:
        return f"{repository_id}:{id_of(raw)}"

    async for batch in _time_id_batches(records, checkpoint, mode, time_of=time_of, id_of=scoped_id):
        yield batch


async def _reviews_stream(connector, target: Target | None, checkpoint: Any, mode: str) -> AsyncIterator[RawBatch]:
    reference, repository_id, repository_path = _repository(connector, target)
    context = _repository_context(reference, repository_id)
    pulls: list[dict[str, Any]] = []
    pull_numbers: list[int]
    supplied = target.attributes.get("pull_number") if target is not None else None
    if supplied is not None:
        try:
            pull_numbers = [int(supplied)]
        except (TypeError, ValueError) as exc:
            raise ConfigError("GitHub pull_number target attribute must be numeric") from exc
    else:
        pulls = await _paged(
            connector,
            f"{repository_path}/pulls",
            params={"state": "all", "sort": "updated", "direction": "asc"},
            context=context,
        )
        pull_numbers = sorted(int(pull["number"]) for pull in pulls)
    records: list[dict[str, Any]] = []
    pulls_by_number = {int(pull["number"]): pull for pull in pulls}
    for pull_number in pull_numbers:
        pull = pulls_by_number.get(pull_number, {})
        nested = {
            "_pull_request_number": pull_number,
            "_pull_request_id": pull.get("id"),
            "_pull_request_updated_at": pull.get("updated_at"),
        }
        records.extend(
            await _paged(
                connector,
                f"{repository_path}/pulls/{pull_number}/reviews",
                context={**context, **nested},
            )
        )
    async for batch in _time_id_batches(records, checkpoint, mode, time_of=_review_time):
        yield batch


async def _workflow_jobs_stream(
    connector, target: Target | None, checkpoint: Any, mode: str
) -> AsyncIterator[RawBatch]:
    reference, repository_id, repository_path = _repository(connector, target)
    context = _repository_context(reference, repository_id)
    supplied = target.attributes.get("run_id") if target is not None else None
    if supplied is not None:
        try:
            run_ids = [int(supplied)]
        except (TypeError, ValueError) as exc:
            raise ConfigError("GitHub run_id target attribute must be numeric") from exc
        runs: list[dict[str, Any]] = []
    else:
        runs = await _paged(
            connector,
            f"{repository_path}/actions/runs",
            items_key="workflow_runs",
            context=context,
        )
        run_ids = sorted(int(run["id"]) for run in runs)
    runs_by_id = {int(run["id"]): run for run in runs}
    records: list[dict[str, Any]] = []
    for run_id in run_ids:
        run = runs_by_id.get(run_id, {})
        nested = {
            "_workflow_run_id": run_id,
            "_workflow_run_updated_at": run.get("updated_at"),
        }
        records.extend(
            await _paged(
                connector,
                f"{repository_path}/actions/runs/{run_id}/jobs",
                params={"filter": "all"},
                items_key="jobs",
                context={**context, **nested},
            )
        )
    async for batch in _time_id_batches(records, checkpoint, mode, time_of=_job_time):
        yield batch


def _organization(connector, target: Target | None) -> str:
    attributes = target.attributes if target is not None else {}
    for key in ("organization", "org", "login", "owner"):
        value = attributes.get(key)
        if isinstance(value, str) and value:
            return value
    if connector.config.organization:
        return connector.config.organization
    raise ConfigError("GitHub organization must be supplied by target attributes or configuration")


async def _teams(connector, organization: str) -> list[dict[str, Any]]:
    context = {"_organization": organization}
    return await _paged(connector, f"/orgs/{_segment(organization)}/teams", context=context)


async def _nested_team_stream(
    connector,
    stream_name: str,
    target: Target | None,
    *,
    suffix: str,
) -> AsyncIterator[RawBatch]:
    organization = _organization(connector, target)
    attributes = target.attributes if target is not None else {}
    supplied_slug = attributes.get("team_slug") or attributes.get("slug")
    if supplied_slug is not None:
        team = await _one(
            connector,
            f"/orgs/{_segment(organization)}/teams/{_segment(str(supplied_slug))}",
            {"_organization": organization},
        )
        teams = [team]
    else:
        teams = await _teams(connector, organization)
    records: list[dict[str, Any]] = []
    for team in sorted(teams, key=lambda item: str(item.get("slug") or item.get("id") or "")):
        slug = team.get("slug")
        if not isinstance(slug, str) or not slug:
            raise VendorContractError("GitHub team is missing its slug")
        context = {"_organization": organization, "_team_id": team.get("id"), "_team_slug": slug}
        records.extend(
            await _paged(
                connector,
                f"/orgs/{_segment(organization)}/teams/{_segment(slug)}/{suffix}",
                params={"role": "all"} if suffix == "members" else None,
                context=context,
            )
        )
    async for batch in _snapshot_batches(connector, stream_name, organization, records):
        yield batch


async def _external_identities(connector, target: Target | None) -> tuple[str, list[dict[str, Any]]]:
    organization = _organization(connector, target)
    path = f"/scim/v2/organizations/{_segment(organization)}/Users"
    records: list[dict[str, Any]] = []
    start_index = 1
    total: int | None = None
    while total is None or start_index <= total:
        result = await connector.request(
            "GET",
            path,
            params={"startIndex": start_index, "count": _PAGE_SIZE},
        )
        body = _object(result.json(), path)
        resources = body.get("Resources", [])
        if not isinstance(resources, list):
            raise VendorContractError("GitHub SCIM Resources must be an array")
        for item in resources:
            if not isinstance(item, dict):
                raise VendorContractError("GitHub SCIM Resources contains a non-object record")
            records.append(_inject(item, {"_organization": organization}))
        declared_total = body.get("totalResults")
        if declared_total is not None:
            try:
                total = int(declared_total)
            except (TypeError, ValueError) as exc:
                raise VendorContractError("GitHub SCIM totalResults must be numeric") from exc
        if not resources:
            if total is not None and start_index <= total:
                raise VendorContractError("GitHub SCIM pagination ended before totalResults")
            break
        start_index += len(resources)
        if total is None and len(resources) < _PAGE_SIZE:
            break
    return organization, records


async def _audit_events_stream(connector, checkpoint: Any, mode: str) -> AsyncIterator[RawBatch]:
    enterprise = connector.config.enterprise
    if not enterprise:
        raise ConfigError("GitHub audit_events requires enterprise configuration")
    params: dict[str, Any] = {"include": "all", "order": "asc"}
    cursor = checkpoint if isinstance(checkpoint, TimeIdCursor) else None
    window = cursor.window_start() if mode == "incremental" and cursor is not None else None
    if window is not None:
        params["phrase"] = f"created:>={window.date().isoformat()}"
    records = await _paged(
        connector,
        f"/enterprises/{_segment(enterprise)}/audit-log",
        params=params,
        context={"_enterprise": enterprise},
    )
    async for batch in _time_id_batches(
        records,
        checkpoint,
        mode,
        time_of=_audit_time,
        id_of=_required_audit_id,
    ):
        yield batch


def _audit_objects(target: Target | None) -> tuple[list[dict[str, Any]], bool]:
    if target is None:
        raise ConfigError("GitHub audit_stream_files requires a destination target")
    attributes = target.attributes
    supplied: Any = None
    for key in ("objects", "audit_stream_objects", "files"):
        if key in attributes:
            supplied = attributes[key]
            break
    if isinstance(supplied, Mapping):
        supplied = supplied.get("objects", supplied.get("files"))
    if not isinstance(supplied, list):
        raise ConfigError("GitHub audit destination target must supply an objects array")
    objects: list[dict[str, Any]] = []
    for item in supplied:
        if not isinstance(item, dict):
            raise ConfigError("GitHub audit destination objects must be objects")
        key = item.get("key") or item.get("object_key") or item.get("name") or item.get("path")
        url = item.get("url") or item.get("download_url") or item.get("content_url")
        if not isinstance(key, str) or not key or not isinstance(url, str) or not url:
            raise ConfigError("Each GitHub audit destination object needs a key and URL")
        objects.append({**item, "key": key, "url": url})
    objects.sort(key=lambda item: str(item["key"]))
    complete = attributes.get("complete", True) is not False and attributes.get("truncated", False) is not True
    return objects, complete


def _bounded_gzip(content: bytes, key: str, max_bytes: int) -> bytes:
    try:
        with gzip.GzipFile(fileobj=BytesIO(content)) as compressed:
            output = compressed.read(max_bytes + 1)
            if len(output) > max_bytes or compressed.read(1):
                raise BudgetExhausted(f"decompressed GitHub audit object exceeded {max_bytes} bytes")
    except (OSError, EOFError) as exc:
        raise VendorContractError(f"GitHub audit object {key!r} is not valid gzip") from exc
    return output


def _audit_payload(content: bytes, key: str, max_bytes: int) -> list[dict[str, Any]]:
    if key.lower().endswith(".gz") or content.startswith(b"\x1f\x8b"):
        content = _bounded_gzip(content, key, max_bytes)
    if len(content) > max_bytes:
        raise BudgetExhausted(f"GitHub audit object exceeded {max_bytes} bytes")
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise VendorContractError(f"GitHub audit object {key!r} is not UTF-8") from exc
    stripped = text.lstrip()
    values: list[Any]
    if stripped.startswith("["):
        try:
            decoded = json.loads(text)
        except ValueError as exc:
            raise VendorContractError(f"GitHub audit object {key!r} is invalid JSON") from exc
        if not isinstance(decoded, list):
            raise VendorContractError(f"GitHub audit object {key!r} must contain events")
        values = decoded
    elif stripped.startswith("{") and "\n" not in stripped.rstrip():
        try:
            decoded = json.loads(text)
        except ValueError as exc:
            raise VendorContractError(f"GitHub audit object {key!r} is invalid JSON") from exc
        if isinstance(decoded, dict) and isinstance(decoded.get("events"), list):
            values = decoded["events"]
        else:
            values = [decoded]
    else:
        values = []
        for line_number, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                values.append(json.loads(line))
            except ValueError as exc:
                raise VendorContractError(
                    f"GitHub audit object {key!r} has invalid JSON on line {line_number}"
                ) from exc
    events: list[dict[str, Any]] = []
    for value in values:
        if not isinstance(value, dict):
            raise VendorContractError(f"GitHub audit object {key!r} contains a non-object event")
        events.append(value)
    return events


async def _audit_files_stream(connector, target: Target | None, checkpoint: Any, mode: str) -> AsyncIterator[RawBatch]:
    objects, target_complete = _audit_objects(target)
    current = checkpoint if isinstance(checkpoint, SequenceCursor) else SequenceCursor(seq="")
    previous = str(current.seq) if mode == "incremental" else ""
    seen_event_ids: set[str] = set()
    complete = target_complete
    enterprise = connector.config.enterprise or (
        target.attributes.get("enterprise") if target is not None else None
    )
    for item in objects:
        key = str(item["key"])
        if previous and key <= previous:
            continue
        try:
            content = await connector.http.stream_download(
                "GET",
                str(item["url"]),
                max_bytes=connector.config.max_download_bytes,
            )
            events = _audit_payload(content, key, connector.config.max_download_bytes)
        except BudgetExhausted as exc:
            error = {
                "_audit_object_key": key,
                "_audit_object": dict(item),
                "_enterprise": enterprise,
                "_partial_coverage": True,
                "_stream_error": {"kind": "budget_exhausted", "message": str(exc)},
            }
            yield RawBatch(records=[error], checkpoint=current, complete=False)
            complete = False
            break
        records: list[dict[str, Any]] = []
        for event in events:
            event_id = _audit_id(event)
            if event_id is not None and event_id in seen_event_ids:
                continue
            if event_id is not None:
                seen_event_ids.add(event_id)
            records.append(
                _inject(
                    event,
                    {
                        "_audit_object_key": key,
                        "_audit_object": dict(item),
                        "_audit_object_url": str(item["url"]),
                        "_enterprise": enterprise,
                    },
                )
            )
        current = current.advance(key)
        yield RawBatch(records=records, checkpoint=current, complete=False)
    yield RawBatch(records=[], checkpoint=current, complete=complete)


async def _repository_files_stream(connector, target: Target | None) -> AsyncIterator[RawBatch]:
    reference, repository_id, repository_path = _repository(connector, target)
    context = _repository_context(reference, repository_id)
    attributes = target.attributes if target is not None else {}
    tree_ref = attributes.get("tree_sha") or attributes.get("commit_sha") or attributes.get("sha") or attributes.get("ref") or "HEAD"
    if not isinstance(tree_ref, str) or not tree_ref:
        raise ConfigError("GitHub repository file tree reference must be a non-empty string")
    tree_path = f"{repository_path}/git/trees/{_segment(tree_ref)}"
    partial = False
    records: list[dict[str, Any]] = []
    try:
        tree_bytes = await connector.http.stream_download(
            "GET",
            connector.rest_url(tree_path),
            max_bytes=connector.config.max_download_bytes,
            headers=connector.api_headers(),
        )
    except BudgetExhausted as exc:
        partial = True
        records.append(
            {
                **context,
                "_record_kind": "coverage",
                "_tree_ref": tree_ref,
                "_partial_coverage": True,
                "_stream_error": {"kind": "budget_exhausted", "message": str(exc)},
            }
        )
        tree_bytes = b""
    if tree_bytes:
        try:
            tree = _object(json.loads(tree_bytes), tree_path)
        except ValueError as exc:
            raise VendorContractError("GitHub repository tree is not valid JSON") from exc
        entries = tree.get("tree")
        if not isinstance(entries, list):
            raise VendorContractError("GitHub repository tree response lacks a tree array")
        partial = partial or tree.get("truncated") is True
        blobs = sorted(
            (entry for entry in entries if isinstance(entry, dict) and entry.get("type") == "blob"),
            key=lambda entry: str(entry.get("path") or ""),
        )
        selected = blobs[: connector.config.max_repository_files]
        if len(selected) < len(blobs):
            partial = True
        for entry in selected:
            path = entry.get("path")
            if not isinstance(path, str) or not path:
                partial = True
                continue
            record = _inject(
                entry,
                {
                    **context,
                    "_tree_ref": tree_ref,
                    "_tree_sha": tree.get("sha"),
                    "_tree_truncated": tree.get("truncated") is True,
                },
            )
            size = entry.get("size")
            if isinstance(size, int) and not isinstance(size, bool) and size > connector.config.max_file_bytes:
                record.update(
                    {
                        "content": None,
                        "content_truncated": True,
                        "_partial_coverage": True,
                        "_stream_error": {
                            "kind": "file_too_large",
                            "message": f"declared size {size} exceeds {connector.config.max_file_bytes} bytes",
                        },
                    }
                )
                partial = True
                records.append(record)
                continue
            content_path = f"{repository_path}/contents/{quote(path, safe='/')}"
            json_cap = min(
                connector.config.max_download_bytes,
                max(4096, connector.config.max_file_bytes * 2 + 4096),
            )
            try:
                content_bytes = await connector.http.stream_download(
                    "GET",
                    connector.rest_url(content_path),
                    max_bytes=json_cap,
                    headers=connector.api_headers(),
                )
                content_body = _object(json.loads(content_bytes), content_path)
                encoded = content_body.get("content")
                if not isinstance(encoded, str) or content_body.get("encoding") != "base64":
                    raise VendorContractError("GitHub repository content is not base64 encoded")
                try:
                    decoded = base64.b64decode("".join(encoded.split()), validate=False)
                except (binascii.Error, ValueError) as exc:
                    raise VendorContractError("GitHub repository content has invalid base64") from exc
                if len(decoded) > connector.config.max_file_bytes:
                    raise BudgetExhausted(
                        f"decoded GitHub repository file exceeded {connector.config.max_file_bytes} bytes"
                    )
                record.update(
                    {
                        "content": decoded.decode("utf-8", errors="replace"),
                        "content_bytes": len(decoded),
                        "content_sha256": hashlib.sha256(decoded).hexdigest(),
                        "content_truncated": False,
                        "download_url": content_body.get("download_url"),
                        "html_url": content_body.get("html_url"),
                        "url": content_body.get("url") or entry.get("url"),
                    }
                )
            except (BudgetExhausted, NotFound, VendorContractError, ValueError) as exc:
                record.update(
                    {
                        "content": None,
                        "content_truncated": True,
                        "_partial_coverage": True,
                        "_stream_error": {"kind": type(exc).__name__, "message": str(exc)},
                    }
                )
                partial = True
            records.append(record)
        coverage = {
            "complete": not partial,
            "tree_truncated": tree.get("truncated") is True,
            "tree_files": len(blobs),
            "files_returned": len(records),
            "files_omitted": max(0, len(blobs) - len(selected)),
        }
        for record in records:
            record["_coverage"] = coverage
        if not records and partial:
            records.append(
                {
                    **context,
                    "_record_kind": "coverage",
                    "_tree_ref": tree_ref,
                    "_tree_sha": tree.get("sha"),
                    "_partial_coverage": True,
                    "_coverage": coverage,
                }
            )
    async for batch in _snapshot_batches(
        connector,
        "repository_files",
        f"{repository_id}:{tree_ref}",
        records,
        complete=not partial,
    ):
        yield batch


async def _branch_protection_stream(connector, target: Target | None) -> AsyncIterator[RawBatch]:
    reference, repository_id, repository_path = _repository(connector, target)
    context = _repository_context(reference, repository_id)
    attributes = target.attributes if target is not None else {}
    supplied_branch = attributes.get("branch")
    if supplied_branch is not None:
        branches = [{"name": str(supplied_branch), "protected": True}]
    else:
        branches = await _paged(connector, f"{repository_path}/branches", context=context)
    records: list[dict[str, Any]] = []
    for branch in sorted(branches, key=lambda item: str(item.get("name") or "")):
        name = branch.get("name")
        if not isinstance(name, str) or not name or branch.get("protected") is not True:
            continue
        raw = await _one(
            connector,
            f"{repository_path}/branches/{_segment(name)}/protection",
            {**context, "_branch": name, "_protected": True},
        )
        records.append(raw)
    async for batch in _snapshot_batches(connector, "branch_protection", str(repository_id), records):
        yield batch


async def _snapshot_dispatch(
    connector, stream_name: str, target: Target | None
) -> AsyncIterator[RawBatch]:
    if stream_name == "branch_protection":
        async for batch in _branch_protection_stream(connector, target):
            yield batch
        return
    if stream_name == "repository_files":
        async for batch in _repository_files_stream(connector, target):
            yield batch
        return
    if stream_name == "team_members":
        async for batch in _nested_team_stream(connector, stream_name, target, suffix="members"):
            yield batch
        return
    if stream_name == "team_repositories":
        async for batch in _nested_team_stream(connector, stream_name, target, suffix="repos"):
            yield batch
        return
    if stream_name == "organization_external_identities":
        organization, records = await _external_identities(connector, target)
        async for batch in _snapshot_batches(connector, stream_name, organization, records):
            yield batch
        return

    scope = "connection"
    records: list[dict[str, Any]] = []
    if stream_name == "repositories":
        if target is not None and target.attributes.get("owner") and target.attributes.get("repo"):
            reference, repository_id, repository_path = _repository(connector, target)
            records = [await _one(connector, repository_path, _repository_context(reference, repository_id))]
            scope = str(repository_id)
        else:
            organization = connector.config.organization or (
                _organization(connector, target) if target is not None else None
            )
            if organization:
                path = f"/orgs/{_segment(organization)}/repos"
                params: dict[str, Any] = {"type": "all", "sort": "full_name", "direction": "asc"}
                scope = organization
            else:
                path = "/user/repos"
                params = {
                    "visibility": "all",
                    "affiliation": "owner,collaborator,organization_member",
                    "sort": "full_name",
                    "direction": "asc",
                }
            records = await _paged(connector, path, params=params)
    elif stream_name == "organizations":
        organization = connector.config.organization or (
            _organization(connector, target) if target is not None else None
        )
        if organization:
            records = [await _one(connector, f"/orgs/{_segment(organization)}", {"_organization": organization})]
            scope = organization
        else:
            records = await _paged(connector, "/user/orgs")
    elif stream_name == "users":
        if target is not None and target.attributes.get("owner") and target.attributes.get("repo"):
            reference, repository_id, repository_path = _repository(connector, target)
            records = await _paged(
                connector,
                f"{repository_path}/collaborators",
                params={"affiliation": "all"},
                context=_repository_context(reference, repository_id),
            )
            scope = str(repository_id)
        else:
            organization = connector.config.organization or (
                _organization(connector, target) if target is not None else None
            )
            if organization:
                records = await _paged(
                    connector,
                    f"/orgs/{_segment(organization)}/members",
                    params={"role": "all"},
                    context={"_organization": organization},
                )
                scope = organization
            else:
                records = [await _one(connector, "/user")]
    elif stream_name == "teams":
        organization = _organization(connector, target)
        records = await _teams(connector, organization)
        scope = organization
    elif stream_name == "collaborators":
        reference, repository_id, repository_path = _repository(connector, target)
        records = await _paged(
            connector,
            f"{repository_path}/collaborators",
            params={"affiliation": "all"},
            context=_repository_context(reference, repository_id),
        )
        scope = str(repository_id)
    elif stream_name in {"branches", "tags", "workflow_artifacts", "actions_caches", "commit_statuses", "check_runs"}:
        reference, repository_id, repository_path = _repository(connector, target)
        context = _repository_context(reference, repository_id)
        scope = str(repository_id)
        if stream_name in {"branches", "tags"}:
            records = await _paged(connector, f"{repository_path}/{stream_name}", context=context)
        elif stream_name == "workflow_artifacts":
            run_id = target.attributes.get("run_id") if target is not None else None
            suffix = f"/actions/runs/{int(run_id)}/artifacts" if run_id is not None else "/actions/artifacts"
            records = await _paged(
                connector,
                f"{repository_path}{suffix}",
                items_key="artifacts",
                context=context,
            )
        elif stream_name == "actions_caches":
            records = await _paged(
                connector,
                f"{repository_path}/actions/caches",
                params={"sort": "created_at", "direction": "asc"},
                items_key="caches",
                context=context,
            )
        else:
            attributes = target.attributes if target is not None else {}
            sha = attributes.get("commit_sha") or attributes.get("sha")
            if not isinstance(sha, str) or not sha:
                raise ConfigError(f"GitHub {stream_name} requires a target commit_sha attribute")
            scope = f"{repository_id}:{sha}"
            context = {**context, "_target_commit_sha": sha}
            if stream_name == "commit_statuses":
                records = await _paged(
                    connector,
                    f"{repository_path}/commits/{_segment(sha)}/statuses",
                    context=context,
                )
            else:
                records = await _paged(
                    connector,
                    f"{repository_path}/commits/{_segment(sha)}/check-runs",
                    params={"filter": "all"},
                    items_key="check_runs",
                    context=context,
                )
    elif stream_name == "actions_runners":
        if target is not None and target.attributes.get("owner") and target.attributes.get("repo"):
            _reference, repository_id, repository_path = _repository(connector, target)
            records = await _paged(
                connector,
                f"{repository_path}/actions/runners",
                items_key="runners",
                context=_repository_context(_reference, repository_id),
            )
            scope = str(repository_id)
        else:
            organization = _organization(connector, target)
            records = await _paged(
                connector,
                f"/orgs/{_segment(organization)}/actions/runners",
                items_key="runners",
                context={"_organization": organization},
            )
            scope = organization
    else:
        raise ConfigError(f"Unsupported GitHub snapshot stream {stream_name!r}")
    async for batch in _snapshot_batches(connector, stream_name, scope, records):
        yield batch


async def run_stream(connector, stream_name: str, target, checkpoint, mode: str) -> AsyncIterator[RawBatch]:
    """Read one declared GitHub stream and yield durable raw batches."""
    if stream_name not in _STREAM_NAMES:
        raise ConfigError(f"Unknown GitHub stream {stream_name!r}")
    if stream_name in {"code_scanning_alerts", "dependabot_alerts", "secret_scanning_alerts"}:
        suffix = {
            "code_scanning_alerts": "code-scanning/alerts",
            "dependabot_alerts": "dependabot/alerts",
            "secret_scanning_alerts": "secret-scanning/alerts",
        }[stream_name]
        params = {"sort": "updated", "direction": "asc"} if stream_name == "code_scanning_alerts" else None
        async for batch in _repository_time_stream(
            connector,
            stream_name,
            target,
            checkpoint,
            mode,
            path_suffix=suffix,
            params=params,
            id_of=_alert_id,
        ):
            yield batch
        return
    if stream_name == "pull_requests":
        async for batch in _repository_time_stream(
            connector,
            stream_name,
            target,
            checkpoint,
            mode,
            path_suffix="pulls",
            params={"state": "all", "sort": "updated", "direction": "asc"},
            id_of=lambda raw: _string_id(raw, "number", "id"),
        ):
            yield batch
        return
    if stream_name == "reviews":
        async for batch in _reviews_stream(connector, target, checkpoint, mode):
            yield batch
        return
    if stream_name == "review_comments":
        async for batch in _repository_time_stream(
            connector,
            stream_name,
            target,
            checkpoint,
            mode,
            path_suffix="pulls/comments",
            params={"sort": "updated", "direction": "asc"},
        ):
            yield batch
        return
    if stream_name == "commits":
        async for batch in _repository_time_stream(
            connector,
            stream_name,
            target,
            checkpoint,
            mode,
            path_suffix="commits",
            time_of=_commit_time,
            id_of=lambda raw: _string_id(raw, "sha", "id", "node_id"),
        ):
            yield batch
        return
    if stream_name == "workflows":
        async for batch in _repository_time_stream(
            connector,
            stream_name,
            target,
            checkpoint,
            mode,
            path_suffix="actions/workflows",
            items_key="workflows",
        ):
            yield batch
        return
    if stream_name == "workflow_runs":
        async for batch in _repository_time_stream(
            connector,
            stream_name,
            target,
            checkpoint,
            mode,
            path_suffix="actions/runs",
            items_key="workflow_runs",
        ):
            yield batch
        return
    if stream_name == "workflow_jobs":
        async for batch in _workflow_jobs_stream(connector, target, checkpoint, mode):
            yield batch
        return
    if stream_name == "audit_events":
        async for batch in _audit_events_stream(connector, checkpoint, mode):
            yield batch
        return
    if stream_name == "audit_stream_files":
        async for batch in _audit_files_stream(connector, target, checkpoint, mode):
            yield batch
        return
    async for batch in _snapshot_dispatch(connector, stream_name, target):
        yield batch
