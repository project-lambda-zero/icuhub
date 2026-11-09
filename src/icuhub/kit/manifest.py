"""Connector manifest: generated from the connector class, committed as JSON, checked for drift.

``build_manifest`` derives the manifest from the class metadata. ``render_manifest`` produces the canonical
text (sorted keys, two-space indent, trailing newline). ``check_manifest`` compares the committed file at
``manifest_path`` against the current class and returns one problem line per difference.

Entry lists (streams, operations, actions, webhooks, importers) are sorted by name so diffs stay stable. Tuple
fields (``auth``, ``scopes``, ``capabilities``, ``flows``, ``modes``) keep the author's order.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from icuhub.kit.connector import Connector, MapperSpec, StreamSpec

__all__ = ["build_manifest", "check_manifest", "main", "manifest_path", "render_manifest"]

_FORMAT_VERSION = 1
_LICENSE = "AGPL-3.0-only"
_CONNECTORS_DIR = Path(__file__).resolve().parent.parent / "connectors"
_SECRET_REF_POINTER = "#/$defs/SecretRef"


def _references_secret_ref(node: Any) -> bool:
    if isinstance(node, dict):
        if node.get("$ref") == _SECRET_REF_POINTER:
            return True
        return any(_references_secret_ref(value) for value in node.values())
    if isinstance(node, list):
        return any(_references_secret_ref(item) for item in node)
    return False


def _config_schema(cls: type[Connector]) -> dict[str, Any]:
    schema = cls.config_model.model_json_schema()
    for prop in schema.get("properties", {}).values():
        if _references_secret_ref(prop):
            prop["writeOnly"] = True
    return schema


def _cursor_kind(stream: str, spec: StreamSpec) -> str:
    field = spec.cursor.model_fields.get("kind")
    if field is None or not isinstance(field.default, str):
        raise ValueError(
            f"stream {stream!r}: cursor {spec.cursor.__name__} must declare a str default for field 'kind'"
        )
    return field.default


def _stream_entry(name: str, spec: StreamSpec, mapper: MapperSpec | None) -> dict[str, Any]:
    return {
        "name": name,
        "ocsf_class": spec.ocsf_class,
        "record_type": spec.record_type,
        "cursor": _cursor_kind(name, spec),
        "modes": list(spec.modes),
        "mapper_version": mapper.version if mapper is not None else None,
        "stability": spec.stability,
        "capability": spec.capability,
        "requires_target": spec.requires_target,
    }


def build_manifest(cls: type[Connector]) -> dict[str, Any]:
    """Return the manifest for ``cls`` as a dict of plain JSON values (lists, not tuples)."""
    streams = cls.streams()
    mappers = cls.mappers()
    record_types = sorted({spec.record_type for spec in streams.values() if spec.record_type is not None})
    return {
        "format_version": _FORMAT_VERSION,
        "kind": cls.kind,
        "version": cls.version,
        "sdk": cls.sdk,
        "owner": cls.owner,
        "support": cls.support,
        "license": _LICENSE,
        "config_schema": _config_schema(cls),
        "auth": list(cls.auth_modes),
        "scopes": [
            {"name": scope.name, "probe": scope.probe, "required_by": list(scope.required_by)}
            for scope in cls.scopes
        ],
        "capabilities": list(cls.capabilities),
        "flows": list(cls.flows),
        "streams": [
            _stream_entry(name, spec, mappers.get(name)) for name, spec in sorted(streams.items())
        ],
        "operations": [
            {
                "name": spec.name,
                "classification": spec.classification,
                "capability": spec.capability,
                "egress_class": spec.egress_class,
                "input_schema": spec.input_model.model_json_schema(),
                "output_schema": spec.output_model.model_json_schema(),
            }
            for _, spec in sorted(cls.operations().items())
        ],
        "actions": [
            {
                "name": spec.name,
                "classification": spec.classification,
                "capability": spec.capability,
                "idempotency": spec.idempotency,
                "stability": spec.stability,
                "input_schema": spec.input_model.model_json_schema(),
            }
            for _, spec in sorted(cls.actions().items())
        ],
        "webhooks": [
            {
                "name": name,
                "event_types": list(spec.event_types),
                "header_event": spec.header_event,
            }
            for name, spec in sorted(cls.webhooks().items())
        ],
        "importers": [
            {
                "name": spec.name,
                "stream": spec.stream,
                "media_types": list(spec.media_types),
                "extensions": list(spec.extensions),
            }
            for _, spec in sorted(cls.importers().items())
        ],
        "record_types": record_types,
    }


def render_manifest(cls: type[Connector]) -> str:
    """Return the canonical manifest text for ``cls``."""
    return json.dumps(build_manifest(cls), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def manifest_path(cls: type[Connector]) -> Path:
    """Return the committed manifest location for ``cls``."""
    return _CONNECTORS_DIR / cls.kind / "manifest.json"


def check_manifest(cls: type[Connector]) -> list[str]:
    """Return problems between the committed manifest and the class; an empty list means in sync."""
    path = manifest_path(cls)
    try:
        committed_text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return [f"{cls.kind}: cannot read manifest {path} ({type(exc).__name__})"]
    current_text = render_manifest(cls)
    if committed_text == current_text:
        return []
    try:
        committed = json.loads(committed_text)
    except json.JSONDecodeError as exc:
        return [f"{cls.kind}: manifest {path} is not valid JSON (line {exc.lineno})"]
    if not isinstance(committed, dict):
        return [f"{cls.kind}: manifest {path} must be a JSON object"]
    current = json.loads(current_text)
    differing = sorted(key for key in set(current) | set(committed) if current.get(key) != committed.get(key))
    if not differing:
        return [
            f"{cls.kind}: manifest {path} differs only in formatting; "
            "regenerate with `python -m icuhub manifest --write`"
        ]
    return [
        f"{cls.kind}: manifest key {key!r} in {path} differs from the class; "
        "regenerate with `python -m icuhub manifest --write`"
        for key in differing
    ]


def main(argv: list[str] | None = None) -> int:
    """Check every registered connector's committed manifest, or regenerate them with ``--write``.

    Returns 0 when all manifests are in sync (or there are no registered connectors), 1 otherwise.
    """
    parser = argparse.ArgumentParser(prog="python -m icuhub manifest", description=main.__doc__)
    parser.add_argument("--write", action="store_true", help="write the manifest files instead of checking them")
    args = parser.parse_args(argv)

    from icuhub.connectors import CONNECTORS  # noqa: PLC0415

    if args.write:
        for cls in CONNECTORS.values():
            path = manifest_path(cls)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(render_manifest(cls), encoding="utf-8")
            print(f"wrote {path}")
        return 0

    problems = [problem for cls in CONNECTORS.values() for problem in check_manifest(cls)]
    for problem in problems:
        print(problem, file=sys.stderr)
    return 1 if problems else 0
