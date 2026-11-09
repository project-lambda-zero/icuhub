"""Versioned connector checkpoint models and cursor transition helpers."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from datetime import datetime, timedelta
from typing import Literal, TypeAlias, TypeVar

from pydantic import BaseModel, Field

__all__ = [
    "Cursor",
    "PageTokenCursor",
    "ResourceVersionCursor",
    "SequenceCursor",
    "SnapshotCursor",
    "TimeIdCursor",
]

_Record = TypeVar("_Record")


class TimeIdCursor(BaseModel):
    """A timestamp checkpoint with duplicate suppression at its upper boundary."""

    schema_version: int = 1
    kind: Literal["time_id"] = "time_id"
    ts: datetime | None
    last_ids_at_ts: list[str] = Field(default_factory=list)
    overlap_s: int = 300

    def window_start(self) -> datetime | None:
        """Return the inclusive replay-window start, including overlap."""
        if self.ts is None:
            return None
        return self.ts - timedelta(seconds=self.overlap_s)

    def advance(
        self,
        records: Iterable[_Record],
        ts_of: Callable[[_Record], datetime],
        id_of: Callable[[_Record], str],
    ) -> TimeIdCursor:
        """Advance to the newest record timestamp; the timestamp never moves backwards.

        Records older than the cursor are ignored. Records at the cursor timestamp
        that carry unseen IDs are added to ``last_ids_at_ts`` so the next overlap
        replay suppresses them. Returns ``self`` when nothing changes.
        """
        new_ts = self.ts
        ids: list[str] = list(self.last_ids_at_ts)
        for record in records:
            record_ts = ts_of(record)
            if new_ts is None or record_ts > new_ts:
                new_ts = record_ts
                ids = []
            if record_ts == new_ts:
                record_id = id_of(record)
                if record_id not in ids:
                    ids.append(record_id)

        if new_ts is None or (new_ts == self.ts and ids == self.last_ids_at_ts):
            return self
        return self.model_copy(update={"ts": new_ts, "last_ids_at_ts": ids})

    def is_duplicate(self, ts: datetime, id: str) -> bool:
        """Report whether an ID was already committed at the cursor timestamp."""
        return ts == self.ts and id in self.last_ids_at_ts


class PageTokenCursor(BaseModel):
    """A vendor-issued page token and its optional lifetime."""

    schema_version: int = 1
    kind: Literal["page_token"] = "page_token"
    token: str | None
    issued_at: datetime | None
    expires_after_s: int | None = None


class SequenceCursor(BaseModel):
    """A vendor sequence checkpoint, monotonic when the sequence is numeric."""

    schema_version: int = 1
    kind: Literal["sequence"] = "sequence"
    seq: int | str

    def advance(self, seq: int | str) -> SequenceCursor:
        """Retain a larger integer sequence or replace an opaque sequence."""
        if isinstance(self.seq, int) and isinstance(seq, int) and seq <= self.seq:
            return self
        if seq == self.seq:
            return self
        return self.model_copy(update={"seq": seq})


class SnapshotCursor(BaseModel):
    """Progress through the targets belonging to one full snapshot."""

    schema_version: int = 1
    kind: Literal["snapshot"] = "snapshot"
    snapshot_id: str
    started_at: datetime
    targets_done: list[str] = Field(default_factory=list)


class ResourceVersionCursor(BaseModel):
    """A Kubernetes resource-version checkpoint."""

    schema_version: int = 1
    kind: Literal["resource_version"] = "resource_version"
    resource_version: str | None

    def relist(self) -> ResourceVersionCursor:
        """Clear an expired resource version so the next request performs a relist."""
        return self.model_copy(update={"resource_version": None})


Cursor: TypeAlias = (
    TimeIdCursor | PageTokenCursor | SequenceCursor | SnapshotCursor | ResourceVersionCursor
)
