"""Pure checkpoint parsing for node-local Jira Data Center audit JSONL files."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from icuhub.kit.cursors import SequenceCursor
from icuhub.kit.errors import VendorContractError

__all__ = ["AuditBatch", "AuditFilePosition", "AuditLogCursor", "parse_audit_batch"]

_Recovery = Literal["none", "rotation", "truncation"]


class AuditFilePosition(BaseModel):
    """A committed byte offset and the SHA-256 of the file prefix before it."""

    offset: int = Field(ge=0)
    fingerprint: str


class AuditLogCursor(SequenceCursor):
    """Independent audit-file checkpoints for every Jira node and path."""

    seq: int | str = 0
    files: dict[str, AuditFilePosition] = Field(default_factory=dict)

    @staticmethod
    def _key(node: str, path: str) -> str:
        return json.dumps([node, path], ensure_ascii=False, separators=(",", ":"))

    def position(self, node: str, path: str) -> AuditFilePosition | None:
        """Return the committed position for one node-local file."""
        return self.files.get(self._key(node, path))

    def advance_file(self, node: str, path: str, position: AuditFilePosition) -> AuditLogCursor:
        """Commit one changed file batch without modifying any other position.

        Returns ``self`` when the position is unchanged. A numeric ``seq`` increments by
        one per changed batch; an opaque string ``seq`` is retained as-is.
        """
        key = self._key(node, path)
        if self.files.get(key) == position:
            return self
        seq: int | str = self.seq + 1 if isinstance(self.seq, int) else self.seq
        return self.model_copy(update={"files": {**self.files, key: position}, "seq": seq})


class AuditBatch(BaseModel):
    """Normalized records and the new committed position for one file snapshot."""

    records: list[dict[str, Any]]
    position: AuditFilePosition
    recovery: _Recovery


def _fallback_id(node: str, path: str, line_start: int, body: bytes) -> str:
    digest = hashlib.sha256()
    for part in (node.encode("utf-8"), path.encode("utf-8"), str(line_start).encode("ascii"), body):
        digest.update(len(part).to_bytes(8, "big"))
        digest.update(part)
    return digest.hexdigest()


def _created_text(record: dict[str, Any]) -> str:
    value = record.get("created")
    if value is None or value == "":
        value = record.get("timestamp")
    if isinstance(value, str) and value:
        return value
    if isinstance(value, int | float) and not isinstance(value, bool):
        try:
            moment = datetime.fromtimestamp(value / 1000, tz=UTC)
        except (OSError, OverflowError, ValueError) as exc:
            raise VendorContractError("Jira audit epoch-millisecond timestamp is invalid") from exc
        return moment.isoformat().replace("+00:00", "Z")
    raise VendorContractError("Jira audit record requires created or timestamp as ISO text or epoch milliseconds")


def _summary_text(record: dict[str, Any]) -> str:
    for key in ("summary", "action", "eventType"):
        value = record.get(key)
        if isinstance(value, str) and value:
            return value
    return "Jira audit event"


def _normalize_record(
    parsed: dict[str, Any],
    *,
    node: str,
    path: str,
    line_start: int,
    body: bytes,
    recovery: _Recovery,
) -> dict[str, Any]:
    record = dict(parsed)
    record_id = record.get("id")
    if isinstance(record_id, bool) or not isinstance(record_id, int | float | str) or record_id == "":
        record["id"] = _fallback_id(node, path, line_start, body)
    record["created"] = _created_text(record)
    record["summary"] = _summary_text(record)
    record.update(
        {
            "_jira_node": node,
            "_jira_file": path,
            "_jira_file_offset": line_start,
            "_jira_recovery": recovery,
        }
    )
    return record


def _reject_json_constant(value: str) -> Any:
    raise ValueError(f"non-standard JSON constant {value}")


def parse_audit_batch(
    *,
    node: str,
    path: str,
    content: bytes,
    previous: AuditFilePosition | None,
    max_record_bytes: int,
) -> AuditBatch:
    """Parse complete JSONL lines from one bounded current-file snapshot.

    A prior offset past the snapshot end is truncation; a prefix fingerprint mismatch is
    rotation. Either resets parsing to byte zero. Otherwise parsing resumes at the prior
    offset. Only newline-terminated lines are consumed, so an incomplete trailing line is
    left for a later snapshot.
    """
    recovery: _Recovery = "none"
    offset = 0
    if previous is not None:
        if previous.offset > len(content):
            recovery = "truncation"
        elif hashlib.sha256(content[: previous.offset]).hexdigest() != previous.fingerprint:
            recovery = "rotation"
        else:
            offset = previous.offset

    records: list[dict[str, Any]] = []
    while True:
        newline = content.find(b"\n", offset)
        if newline < 0:
            if len(content) - offset > max_record_bytes:
                raise VendorContractError(
                    f"Jira audit source line at byte {offset} exceeds max_record_bytes {max_record_bytes}"
                )
            break
        line_start = offset
        body = content[line_start:newline]
        if body.endswith(b"\r"):
            body = body[:-1]
        if len(body) > max_record_bytes:
            raise VendorContractError(
                f"Jira audit source line at byte {line_start} exceeds max_record_bytes {max_record_bytes}"
            )
        offset = newline + 1
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise VendorContractError(f"Jira audit source line at byte {line_start} is not valid UTF-8") from exc
        if not text.strip():
            continue
        try:
            parsed = json.loads(text, parse_constant=_reject_json_constant)
        except ValueError as exc:
            raise VendorContractError(f"Jira audit source line at byte {line_start} is not valid JSON") from exc
        if not isinstance(parsed, dict):
            raise VendorContractError(f"Jira audit source line at byte {line_start} must contain a JSON object")
        records.append(
            _normalize_record(parsed, node=node, path=path, line_start=line_start, body=body, recovery=recovery)
        )

    position = AuditFilePosition(offset=offset, fingerprint=hashlib.sha256(content[:offset]).hexdigest())
    for record in records:
        record["_jira_file_fingerprint"] = position.fingerprint
    return AuditBatch(records=records, position=position, recovery=recovery)
