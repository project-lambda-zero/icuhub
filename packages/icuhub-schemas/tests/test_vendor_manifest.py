"""Verify the integrity and coverage of installed schema resources."""

from __future__ import annotations

import hashlib
import json
from importlib import resources


def _json_resources(directory: object, prefix: str = "") -> set[str]:
    names: set[str] = set()
    for child in directory.iterdir():  # type: ignore[attr-defined]
        name = f"{prefix}{child.name}"
        if child.is_dir():
            names.update(_json_resources(child, f"{name}/"))
        elif child.name.endswith(".json") and child.name != "manifest.json":
            names.add(name)
    return names


def test_installed_schema_digests_match_manifest() -> None:
    package = resources.files("icuhub_schemas")
    vendor = package.joinpath("_vendor")
    manifest = json.loads(vendor.joinpath("manifest.json").read_text(encoding="utf-8"))
    entries = manifest["resources"]

    assert set(entries) == _json_resources(vendor)
    for name, entry in entries.items():
        payload = vendor.joinpath(name).read_bytes()
        assert hashlib.sha256(payload).hexdigest() == entry["sha256"], name
        assert entry["source_url"].startswith("https://")
        assert entry["version"]
