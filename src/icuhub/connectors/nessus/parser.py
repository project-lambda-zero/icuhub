"""Bounded parser for Nessus ``.nessus`` exports (``NessusClientData_v2``).

Structure: ``NessusClientData_v2 > Report > ReportHost > ReportItem``. Each ``ReportItem`` is one
finding and yields one ``(NessusHost, NessusItem)`` pair. Severity is preserved from the source
attribute and never recomputed from CVSS. Exceeding a size, count, or depth bound raises
``BudgetExhausted``; a wrong root, DTD or entity use, malformed XML, or a malformed record raises
``VendorContractError``. A malformed record fails the whole document; it is never dropped silently.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from dataclasses import dataclass
from xml.etree.ElementTree import Element

from icuhub.connectors.nessus.models import NessusHost, NessusItem
from icuhub.kit.errors import BudgetExhausted, VendorContractError
from icuhub.kit.xml import local, parse_xml

__all__ = ["NessusImportLimits", "file_sha256", "iter_nessus"]

ROOT = "NessusClientData_v2"
_REPORT = "Report"
_REPORT_HOST = "ReportHost"
_REPORT_ITEM = "ReportItem"
_TRUNCATION_MARKER = "TRUNCATED"
_COMPLIANCE_PREFIX = "cm:compliance-"
_MAX_SEVERITY = 4
_MAX_PORT = 65535


@dataclass(frozen=True)
class NessusImportLimits:
    """Bounds for one ``.nessus`` document.

    Defaults match ``NessusConfig``. ``max_plugin_output_chars`` truncates stored output; the
    digest always covers the full output text as it appeared in the source.
    """

    max_bytes: int = 64 * 1024 * 1024
    max_hosts: int = 10_000
    max_items: int = 200_000
    max_depth: int = 64
    max_plugin_output_chars: int = 32_768


def file_sha256(data: bytes) -> str:
    """Return the hex SHA-256 digest of the raw document, used for replay identity."""
    return hashlib.sha256(data).hexdigest()


def iter_nessus(
    data: bytes, *, limits: NessusImportLimits | None = None
) -> Iterator[tuple[NessusHost, NessusItem]]:
    """Yield one ``(host, item)`` pair per ``ReportItem`` in document order."""
    bounds = limits or NessusImportLimits()
    root = parse_xml(data, max_bytes=bounds.max_bytes)
    if local(root.tag) != ROOT:
        raise VendorContractError(f"unsupported Nessus XML root {local(root.tag)!r}; expected {ROOT!r}")
    _check_depth(root, bounds.max_depth)
    host_count = 0
    item_count = 0
    for report in _children(root, _REPORT):
        for host_element in _children(report, _REPORT_HOST):
            host_count += 1
            if host_count > bounds.max_hosts:
                raise BudgetExhausted(f"Nessus report exceeds {bounds.max_hosts} hosts")
            host = _host(host_element)
            for item_element in _children(host_element, _REPORT_ITEM):
                item_count += 1
                if item_count > bounds.max_items:
                    raise BudgetExhausted(f"Nessus report exceeds {bounds.max_items} items")
                yield host, _item(item_element, item_count - 1, bounds)


def _check_depth(root: Element, max_depth: int) -> None:
    stack: list[tuple[Element, int]] = [(root, 1)]
    while stack:
        element, depth = stack.pop()
        if depth > max_depth:
            raise BudgetExhausted(f"XML nesting exceeds {max_depth} levels")
        stack.extend((child, depth + 1) for child in element)


def _children(element: Element, name: str) -> list[Element]:
    return [child for child in element if local(child.tag) == name]


def _child_text(element: Element, name: str, *, strip: bool = True) -> str | None:
    for child in element:
        if local(child.tag) == name:
            text = child.text or ""
            return text.strip() if strip else text
    return None


def _child_texts(element: Element, name: str) -> list[str]:
    result: list[str] = []
    for child in element:
        if local(child.tag) == name:
            text = (child.text or "").strip()
            if text:
                result.append(text)
    return result


def _host(element: Element) -> NessusHost:
    name = element.get("name")
    if not name:
        raise VendorContractError("ReportHost has no name attribute")
    properties: dict[str, str] = {}
    for section in _children(element, "HostProperties"):
        for tag in _children(section, "tag"):
            key = tag.get("name")
            if key:
                properties[key] = (tag.text or "").strip()
    return NessusHost(
        key=name,
        name=name,
        uid=properties.get("host-uuid"),
        fqdn=properties.get("host-fqdn"),
        ip=properties.get("host-ip"),
        mac=properties.get("mac-address"),
        os=properties.get("operating-system"),
        started_at=properties.get("HOST_START"),
        ended_at=properties.get("HOST_END"),
        properties=properties,
    )


def _int_attr(element: Element, name: str, ordinal: int) -> int | None:
    raw = element.get(name)
    if raw is None:
        return None
    try:
        return int(raw)
    except ValueError as exc:
        raise VendorContractError(f"ReportItem {ordinal} has non-integer {name} {raw!r}") from exc


def _item(element: Element, ordinal: int, bounds: NessusImportLimits) -> NessusItem:
    plugin_id = element.get("pluginID")
    if not plugin_id:
        raise VendorContractError(f"ReportItem {ordinal} has no pluginID")
    severity = _int_attr(element, "severity", ordinal)
    if severity is not None and not 0 <= severity <= _MAX_SEVERITY:
        raise VendorContractError(f"ReportItem {ordinal} severity {severity} is outside 0..{_MAX_SEVERITY}")
    port = _int_attr(element, "port", ordinal)
    if port is not None and not 0 <= port <= _MAX_PORT:
        raise VendorContractError(f"ReportItem {ordinal} port {port} is outside 0..{_MAX_PORT}")

    full_output = _child_text(element, "plugin_output", strip=False) or ""
    digest = hashlib.sha256(full_output.encode("utf-8")).hexdigest()
    size = len(full_output)
    cap = bounds.max_plugin_output_chars
    references = (_child_text(element, "see_also") or "").split()
    compliance = {}
    for child in element:
        tag = child.tag
        if tag.startswith("{"):
            namespace, _, name = tag[1:].partition("}")
            tag = f"cm:{name}" if namespace.rstrip("/").endswith("/cm") or namespace == "cm" else name
        if tag.startswith(_COMPLIANCE_PREFIX):
            compliance[tag[len(_COMPLIANCE_PREFIX) :].replace("-", "_")] = (child.text or "").strip()
    return NessusItem(
        ordinal=ordinal,
        plugin_id=plugin_id,
        plugin_name=element.get("pluginName"),
        plugin_family=element.get("pluginFamily"),
        severity=severity,
        risk_factor=_child_text(element, "risk_factor"),
        port=port,
        protocol=element.get("protocol"),
        service=element.get("svc_name"),
        synopsis=_child_text(element, "synopsis"),
        description=_child_text(element, "description"),
        solution=_child_text(element, "solution"),
        plugin_output=full_output[:cap],
        plugin_output_sha256=digest,
        plugin_output_size=size,
        truncated=full_output.rstrip().endswith(_TRUNCATION_MARKER),
        output_bounded=size > cap,
        cves=_child_texts(element, "cve"),
        cwes=_child_texts(element, "cwe"),
        references=references,
        compliance=compliance,
        attributes=dict(element.attrib),
    )
