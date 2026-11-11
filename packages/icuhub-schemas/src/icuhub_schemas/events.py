"""CloudEvents 1.0 envelope for ICUHUB events, serialized as structured JSON."""

from datetime import datetime
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator

__all__ = ["CloudEvent", "EVENT_TYPE_PREFIX"]

EVENT_TYPE_PREFIX = "icuhub."


class CloudEvent(BaseModel):
    """A CloudEvents 1.0 event in structured JSON form.

    ``type`` must start with ``icuhub.``. ``tenantid`` and ``correlationid`` are CloudEvents
    extension attributes. Their names follow the CloudEvents naming rule (lowercase ASCII
    letters and digits, at most 20 characters); their values are consumer identifiers and
    are carried verbatim.
    """

    model_config = ConfigDict(extra="forbid")

    specversion: Literal["1.0"] = "1.0"
    id: str = Field(min_length=1)
    source: str = Field(min_length=1)
    type: str = Field(min_length=1)
    time: datetime
    datacontenttype: Literal["application/json"] = "application/json"
    subject: str | None = None
    dataschema: str | None = None
    tenantid: str | None = Field(default=None, min_length=1)
    correlationid: str | None = Field(default=None, min_length=1)
    data: Any = None

    @field_validator("type")
    @classmethod
    def _type_has_icuhub_prefix(cls, value: str) -> str:
        if not value.startswith(EVENT_TYPE_PREFIX):
            raise ValueError(f"type must start with {EVENT_TYPE_PREFIX!r}")
        return value

    def to_json(self) -> str:
        """Serialize to a CloudEvents structured JSON document; unset optional attributes are omitted."""

        return self.model_dump_json(exclude_none=True)

    @classmethod
    def from_json(cls, text: str | bytes) -> Self:
        """Parse a CloudEvents structured JSON document; raises ``pydantic.ValidationError`` on violation."""

        return cls.model_validate_json(text)
