"""Prisma Cloud UVE impacted-asset gzip CSV parsing and stable row identity."""

from __future__ import annotations

import csv
import gzip
import hashlib
import io
import json
import zlib
from datetime import UTC, datetime
from typing import Any

from icuhub.connectors.prisma_cloud.mapping import parse_ms
from icuhub.kit.errors import VendorContractError

__all__ = ["parse_impacted_assets"]

_ABSENT = {"", "N/A", "[N/A]"}
_REQUIRED_COLUMNS = frozenset({"ASSET_ID", "ASSET_TYPE", "CVE_ID", "SERVICE_PROVIDER", "SEVERITY"})


def _value(row: dict[str, Any], key: str) -> str | None:
    value = row.get(key)
    if value is None:
        return None
    text = str(value).strip()
    return None if text in _ABSENT else text


def _required(row: dict[str, Any], key: str, cve_id: str) -> str:
    value = _value(row, key)
    if value is None:
        raise VendorContractError(f"Prisma UVE {cve_id} CSV row has no {key}")
    return value


def _time_ms(row: dict[str, Any], cve_id: str) -> int:
    value = _value(row, "DISCOVERED_DATE") or _value(row, "PUBLISHED_DATE")
    if value is None:
        raise VendorContractError(f"Prisma UVE {cve_id} CSV row has no discovery or publication time")
    try:
        parsed = datetime.strptime(value, "%b %d %Y").replace(tzinfo=UTC)
        return int(parsed.timestamp() * 1000)
    except ValueError:
        timestamp = parse_ms(value)
    if timestamp <= 0:
        raise VendorContractError(f"Prisma UVE {cve_id} CSV row has an invalid discovery or publication time")
    return timestamp


def _identity_text(identity: dict[str, Any]) -> str:
    return json.dumps(identity, sort_keys=True, separators=(",", ":"))


def _row_record(
    row: dict[str, Any],
    *,
    cve_id: str,
    download_sha256: str,
    row_number: int,
) -> tuple[dict[str, Any], str, str]:
    row_cve = _required(row, "CVE_ID", cve_id).upper()
    if row_cve != cve_id.upper():
        raise VendorContractError(f"Prisma UVE {cve_id} CSV contains a different CVE row")
    asset_id = _required(row, "ASSET_ID", cve_id)
    asset_type = _required(row, "ASSET_TYPE", cve_id)
    provider = _required(row, "SERVICE_PROVIDER", cve_id)
    severity = _required(row, "SEVERITY", cve_id)
    account_id = _value(row, "CLOUD_ACCOUNT_ID")
    package_name = _value(row, "PACKAGE_NAME")
    installed_versions = _value(row, "INSTALLED_VERSIONS")
    if installed_versions is not None and installed_versions.startswith("[") and installed_versions.endswith("]"):
        installed_versions = installed_versions[1:-1].strip() or None
    file_path = _value(row, "FILE_PATH") or _value(row, "PACKAGE_PATH")
    repository = _value(row, "REPOSITORY_NAME") or _value(row, "REPO_NAME")
    branch = _value(row, "BRANCH")
    identity = {
        "asset_id": asset_id,
        "asset_type": asset_type,
        "branch": branch,
        "cloud_account_id": account_id,
        "cve_id": row_cve,
        "file_path": file_path,
        "installed_versions": installed_versions,
        "package_name": package_name,
        "repository": repository,
    }
    identity_text = _identity_text(identity)
    finding_id = f"{row_cve}:{hashlib.sha256(identity_text.encode()).hexdigest()[:20]}"
    record = {
        "_asset": {
            "accountId": account_id,
            "cloudType": provider,
            "id": asset_id,
            "name": _value(row, "ASSET_NAME"),
            "provider": provider,
            "region": _value(row, "REGION"),
            "type": asset_type,
        },
        "_export": {
            "cve_id": row_cve,
            "download_sha256": download_sha256,
            "row": dict(row),
            "row_number": row_number,
        },
        "_finding": {
            "cve": row_cve,
            "description": _value(row, "VULNERABILITY_DESCRIPTION"),
            "id": finding_id,
            "link": _value(row, "CVE_LINK"),
            "packageName": package_name,
            "packagePath": file_path,
            "packageVersion": installed_versions,
            "severity": severity,
            "status": "open",
            "time": _time_ms(row, cve_id),
            "title": row_cve,
        },
        "_identity": identity,
    }
    return record, identity_text, asset_id


def parse_impacted_assets(
    data: bytes,
    *,
    cve_id: str,
    expected_assets: int,
    max_decompressed_bytes: int,
) -> list[dict[str, Any]]:
    """Decode one V3 CVE download and prove its impacted-asset cardinality.

    Every returned raw record retains the original CSV row, download digest, and a
    package/version/path-sensitive identity. Any malformed or ambiguous row fails
    the entire export rather than producing a partial complete snapshot.
    """
    if isinstance(expected_assets, bool) or not isinstance(expected_assets, int) or expected_assets < 0:
        raise VendorContractError(f"Prisma UVE {cve_id} totalImpactedAssets must be a non-negative integer")
    if not data.startswith(b"\x1f\x8b"):
        raise VendorContractError(f"Prisma UVE {cve_id} download is not gzip data")
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as compressed:
            decoded = compressed.read(max_decompressed_bytes + 1)
    except (gzip.BadGzipFile, EOFError, zlib.error) as exc:
        raise VendorContractError(f"Prisma UVE {cve_id} download has invalid gzip content") from exc
    if len(decoded) > max_decompressed_bytes:
        raise VendorContractError(f"Prisma UVE {cve_id} CSV exceeds the decompressed byte budget")
    try:
        text = decoded.decode("utf-8-sig")
        reader = csv.DictReader(io.StringIO(text, newline=""))
        fieldnames = reader.fieldnames
        if fieldnames is None or len(fieldnames) != len(set(fieldnames)):
            raise VendorContractError(f"Prisma UVE {cve_id} CSV has missing or duplicate headers")
        missing = _REQUIRED_COLUMNS.difference(fieldnames)
        if missing:
            raise VendorContractError(f"Prisma UVE {cve_id} CSV is missing required columns: {sorted(missing)}")
        records: list[dict[str, Any]] = []
        assets: set[str] = set()
        identities: set[str] = set()
        download_sha256 = hashlib.sha256(data).hexdigest()
        for row_number, row in enumerate(reader, start=2):
            if None in row:
                raise VendorContractError(f"Prisma UVE {cve_id} CSV row {row_number} has extra cells")
            record, identity_text, asset_id = _row_record(
                row,
                cve_id=cve_id,
                download_sha256=download_sha256,
                row_number=row_number,
            )
            if identity_text in identities:
                raise VendorContractError(f"Prisma UVE {cve_id} CSV repeats a row identity")
            identities.add(identity_text)
            assets.add(asset_id)
            records.append(record)
    except (UnicodeDecodeError, csv.Error) as exc:
        raise VendorContractError(f"Prisma UVE {cve_id} download is not valid UTF-8 CSV") from exc
    if len(assets) != expected_assets:
        raise VendorContractError(
            f"Prisma UVE {cve_id} impacted-asset count mismatch: expected {expected_assets}, got {len(assets)}"
        )
    return records
