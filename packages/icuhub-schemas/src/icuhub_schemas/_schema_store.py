"""Load vendored JSON Schemas and produce stable validation locations."""

from __future__ import annotations

import ast
import json
from collections.abc import Sequence
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from typing import Any

from jsonschema.protocols import Validator
from jsonschema.validators import validator_for

__all__ = ["SchemaIssue", "format_path", "schema_issues"]


@dataclass(frozen=True)
class SchemaIssue:
    """A JSON Schema violation and its absolute instance path."""

    path: str
    message: str


@lru_cache(maxsize=16)
def _validator(resource: str) -> Validator:
    schema_text = resources.files("icuhub_schemas").joinpath("_vendor", resource).read_text(encoding="utf-8")
    schema = json.loads(schema_text)
    validator_class = validator_for(schema)
    validator_class.check_schema(schema)
    return validator_class(schema)


def format_path(parts: Sequence[str | int]) -> str:
    """Render instance path segments as a JSON-path style string rooted at ``$``."""

    path = "$"
    for part in parts:
        if isinstance(part, int):
            path += f"[{part}]"
        elif part.isidentifier():
            path += f".{part}"
        else:
            path += f"[{part!r}]"
    return path


def _path(error: Any) -> str:
    parts: list[str | int] = list(error.absolute_path)
    if error.validator == "required":
        # jsonschema reports one error per missing name; its message is repr(name) + " is a required property".
        parts.append(ast.literal_eval(error.message.removesuffix(" is a required property")))
    return format_path(parts)


def schema_issues(document: Any, resource: str) -> list[SchemaIssue]:
    """Return all schema violations, ordered by instance path and message."""

    issues = [SchemaIssue(_path(error), error.message) for error in _validator(resource).iter_errors(document)]
    return sorted(issues, key=lambda issue: (issue.path, issue.message))
