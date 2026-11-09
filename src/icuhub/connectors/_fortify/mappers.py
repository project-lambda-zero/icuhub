"""Pure Fortify vendor-record to OCSF mapping shared by the Fortify connectors."""

from __future__ import annotations

from typing import Any

from icuhub.kit.errors import VendorContractError
from icuhub.kit.mapping import EnumTable, bounded_raw, epoch_ms, severity_id_from_label
from icuhub.kit.types import MapContext
from icuhub_schemas.ocsf import Cloud, FindingInfo, Metadata, Product, VulnerabilityFinding

__all__ = ["map_fod_issue"]

# Labels not listed here map to OCSF severity 0 (Unknown); no severity is invented.
_FOD_SEVERITY = EnumTable(mapping={"Critical": 5, "High": 4, "Medium": 3, "Low": 2}, default=0)
_FOD_VENDOR = "OpenText"
_FOD_PRODUCT_NAME = "Fortify on Demand"
_FOD_CLOUD_PROVIDER = "fortify_on_demand"
# OCSF activity 1 (Create): each snapshot row is an observed finding.
_ACTIVITY_CREATE = 1
_VULNERABILITY_FINDING_CLASS_UID = 2002


def _release_id(raw: dict[str, Any]) -> str:
    value = raw.get("_release_id")
    if not isinstance(value, str) or not value:
        raise VendorContractError("Fortify on Demand issue is missing the injected _release_id")
    return value


def _native_id(raw: dict[str, Any]) -> int:
    value = raw.get("id")
    if isinstance(value, bool) or not isinstance(value, int):
        raise VendorContractError("Fortify on Demand vulnerability id must be an integer")
    return value


def _optional_str(raw: dict[str, Any], key: str) -> str | None:
    value = raw.get(key)
    return value if isinstance(value, str) and value else None


def _event_time_ms(raw: dict[str, Any], ctx: MapContext) -> int:
    # Native change/creation time when the vendor supplies it; otherwise the observation time.
    native = _optional_str(raw, "lastUpdated") or _optional_str(raw, "createdDate")
    observed = epoch_ms(native) if native is not None else None
    if observed is None:
        observed = epoch_ms(ctx.received_at.isoformat())
    if observed is None:
        raise VendorContractError("Fortify on Demand observation time is unavailable")
    return observed


def map_fod_issue(raw: dict[str, Any], ctx: MapContext) -> list[VulnerabilityFinding]:
    """Map one Fortify on Demand release vulnerability to an OCSF 2002 finding.

    Identity is the release-scoped vulnerability id. Status fields are tenant-specific, so
    ``status_id`` stays unset and the native developer/auditor statuses are kept in
    ``unmapped``. ``vulnerabilities`` stays empty because no explicit CVE/CWE field is
    verified for this vendor shape.
    """
    release_id = _release_id(raw)
    native_id = _native_id(raw)
    severity_label = _optional_str(raw, "severity")
    product = Product(name=_FOD_PRODUCT_NAME, vendor_name=_FOD_VENDOR)
    unmapped = {
        key: raw[key]
        for key in ("developerStatus", "auditorStatus")
        if isinstance(raw.get(key), str) and raw[key]
    }
    finding_info = FindingInfo(
        uid=f"fortify_fod:release:{release_id}:vulnerability:{native_id}",
        title=_optional_str(raw, "category"),
        product=product,
    )
    return [
        VulnerabilityFinding(
            time=_event_time_ms(raw, ctx),
            severity_id=severity_id_from_label(severity_label, _FOD_SEVERITY),
            severity=severity_label,
            activity_id=_ACTIVITY_CREATE,
            type_uid=_VULNERABILITY_FINDING_CLASS_UID * 100 + _ACTIVITY_CREATE,
            finding_info=finding_info,
            vulnerabilities=[],
            metadata=Metadata(product=Product(name=_FOD_PRODUCT_NAME, vendor_name=_FOD_VENDOR)),
            cloud=Cloud(provider=_FOD_CLOUD_PROVIDER),
            osint=[],
            unmapped=unmapped or None,
            raw_data=bounded_raw(raw),
        )
    ]
