"""Offline Fortify importers: FPR archives and legacy or WebInspect XML reports.

Failure policy
- ``BudgetExhausted`` (retryable): archive or document bytes, member count, declared or decompressed
  member size, compression ratio, text length, snippet count, comment count, comment length, and issue
  count exceed the configured ``FortifyImportLimits``.
- ``VendorContractError``: unsafe archive member names (traversal, absolute, backslash, drive prefix),
  symbolic links, encrypted members, duplicate normalized names, missing or ambiguous ``audit.fvdl`` or
  ``audit.xml`` candidates, DTDs, entities, excessive nesting, malformed XML, unsupported or malformed
  roots, and records without their native identifiers.

An unsupported or malformed root always raises. No input yields zero records silently.

Streaming
- FPR: ``audit.fvdl`` is read in two streaming passes (auxiliary sections, then ``Vulnerabilities``).
  Processed elements are cleared as they are consumed.
- Report XML: the document is parsed whole after size and structure checks.
"""

from __future__ import annotations

import hashlib
import io
import re
import stat
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any, Literal
from xml.etree.ElementTree import Element

from defusedxml.common import DefusedXmlException
from defusedxml.ElementTree import ParseError, iterparse

from icuhub.kit.errors import BudgetExhausted, VendorContractError
from icuhub.kit.xml import local, parse_xml, safe_zip_member

__all__ = [
    "PARSER_VERSION",
    "PROFILE_REPORT_DEFINITION",
    "PROFILE_WEBINSPECT_SCAN",
    "FortifyImportLimits",
    "iter_fortify_xml",
    "iter_fpr",
]

PARSER_VERSION = "icuhub-fortify-offline/1"
PROFILE_REPORT_DEFINITION = "fortify_report_definition"
PROFILE_WEBINSPECT_SCAN = "webinspect_scan"

LocationSemantics = Literal["source_location_v2", "snippet_start_v1"]
_LOCATION_SEMANTICS: frozenset[str] = frozenset({"source_location_v2", "snippet_start_v1"})

_FVDL_NAME = "audit.fvdl"
_AUDIT_NAME = "audit.xml"
_FVDL_ROOT = "FVDL"
_REPORT_ROOT = "ReportDefinition"
_SCAN_ROOT = "Scan"
_VULNERABILITY_PATH = ("FVDL", "Vulnerabilities", "Vulnerability")
_RESULT_SECTIONS = frozenset({"Results Outline", "Issue Count by Category"})
_RULE_GROUPS = ("Accuracy", "Impact", "Probability", "altcategoryCWE")
_CWE_REFERENCE = re.compile(r"CWE ID (\d+)")
_DRIVE_PREFIX = re.compile(r"^[A-Za-z]:")
_ENCRYPTED_FLAG = 0x1


@dataclass(frozen=True)
class FortifyImportLimits:
    """Resource and structure bounds for Fortify offline imports.

    ``max_total_bytes`` bounds the archive (FPR) or the document (XML) and the sum of declared
    member sizes. ``max_ratio`` bounds declared uncompressed size over compressed size per member.
    ``max_text_chars`` bounds any single XML text node or attribute-free text value. Exceeding a
    bound raises ``BudgetExhausted``; structural violations raise ``VendorContractError``.
    The defaults are production bounds; callers with tighter requirements pass a smaller instance.
    """

    max_zip_members: int = 1_000
    max_member_bytes: int = 512 * 1024 * 1024
    max_total_bytes: int = 1024 * 1024 * 1024
    max_ratio: int = 100
    max_xml_depth: int = 64
    max_text_chars: int = 1024 * 1024
    max_comments_per_issue: int = 1_000
    max_comment_chars: int = 16 * 1024
    max_snippets: int = 100_000
    max_issues: int = 1_000_000


def iter_fpr(
    data: bytes,
    *,
    location_semantics: LocationSemantics = "source_location_v2",
    limits: FortifyImportLimits | None = None,
) -> Iterator[dict[str, Any]]:
    """Stream the issues of an FPR archive as raw records.

    ``source_location_v2`` reports the ``SourceLocation`` line. ``snippet_start_v1`` reports the
    snippet ``StartLine`` when the snippet resolves, which can precede the finding by context lines.
    Both semantics are recorded in every record as ``location_semantics``.
    """
    if location_semantics not in _LOCATION_SEMANTICS:
        raise ValueError(f"unknown FPR location semantics {location_semantics!r}")
    bounds = limits or FortifyImportLimits()
    fvdl_name, audit_name = _archive_members(data, bounds)
    artifact_sha = _sha256(data)
    fvdl = safe_zip_member(data, fvdl_name, max_uncompressed=bounds.max_member_bytes)
    audit_bytes = (
        safe_zip_member(data, audit_name, max_uncompressed=bounds.max_member_bytes) if audit_name else None
    )
    audit = _read_audit(audit_bytes, bounds)
    aux = _read_fvdl_aux(fvdl, bounds)
    file_uuid = aux.file_uuid or artifact_sha
    file_uuid_source = "fvdl_uuid" if aux.file_uuid else "artifact_sha256"
    emitted = 0
    for path, vulnerability in _walk(fvdl, bounds, root=_FVDL_ROOT):
        if path != _VULNERABILITY_PATH:
            continue
        emitted += 1
        if emitted > bounds.max_issues:
            raise BudgetExhausted(f"FPR archive exceeds the {bounds.max_issues} issue limit")
        yield _fpr_record(
            vulnerability,
            aux,
            audit,
            file_uuid=file_uuid,
            file_uuid_source=file_uuid_source,
            artifact_sha=artifact_sha,
            semantics=location_semantics,
        )
        vulnerability.clear()


def iter_fortify_xml(data: bytes, *, limits: FortifyImportLimits | None = None) -> Iterator[dict[str, Any]]:
    """Stream the issues of a legacy ``ReportDefinition`` or WebInspect ``Scan`` XML document.

    The root element selects the profile. Any other root raises ``VendorContractError``.
    """
    bounds = limits or FortifyImportLimits()
    root = parse_xml(data, max_bytes=bounds.max_total_bytes)
    _check_tree(root, bounds)
    report_sha = _sha256(data)
    name = local(root.tag)
    if name == _REPORT_ROOT:
        yield from _legacy_records(root, report_sha, bounds)
    elif name == _SCAN_ROOT:
        yield from _scan_records(root, report_sha, bounds)
    else:
        raise VendorContractError(f"unsupported Fortify XML root {name!r}")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------- streaming XML primitives


def _walk(
    data: bytes, limits: FortifyImportLimits, root: str | None
) -> Iterator[tuple[tuple[str, ...], Element]]:
    """Yield ``(path, element)`` on each end tag; ``path`` is the local-name chain from the root."""
    stack: list[str] = []
    try:
        for event, element in iterparse(
            io.BytesIO(data),
            events=("start", "end"),
            forbid_dtd=True,
            forbid_entities=True,
            forbid_external=True,
        ):
            name = local(element.tag)
            if event == "start":
                if not stack and root is not None and name != root:
                    raise VendorContractError(f"unsupported XML root {name!r}; expected {root!r}")
                stack.append(name)
                if len(stack) > limits.max_xml_depth:
                    raise VendorContractError(f"XML nesting exceeds {limits.max_xml_depth} levels")
                continue
            path = tuple(stack)
            stack.pop()
            _check_text(element, limits)
            yield path, element
    except (DefusedXmlException, ParseError) as exc:
        raise VendorContractError(f"invalid XML document: {exc}") from exc


def _check_text(element: Element, limits: FortifyImportLimits) -> None:
    for value in (element.text, element.tail):
        if value is not None and len(value) > limits.max_text_chars:
            raise BudgetExhausted(
                f"XML text of {len(value)} characters exceeds the {limits.max_text_chars} character limit"
            )


def _check_tree(root: Element, limits: FortifyImportLimits) -> None:
    stack: list[tuple[Element, int]] = [(root, 1)]
    while stack:
        element, depth = stack.pop()
        if depth > limits.max_xml_depth:
            raise VendorContractError(f"XML nesting exceeds {limits.max_xml_depth} levels")
        _check_text(element, limits)
        stack.extend((child, depth + 1) for child in element)


def _child(element: Element | None, name: str) -> Element | None:
    if element is None:
        return None
    return next((child for child in element if local(child.tag) == name), None)


def _children(element: Element, name: str) -> list[Element]:
    return [child for child in element if local(child.tag) == name]


def _descend(element: Element | None, *names: str) -> Element | None:
    current = element
    for name in names:
        current = _child(current, name)
        if current is None:
            return None
    return current


def _element_text(element: Element) -> str | None:
    return (element.text or "").strip() or None


def _raw_text(element: Element | None, name: str) -> str | None:
    child = _child(element, name)
    if child is None:
        return None
    return child.text or None


def _text(element: Element | None, name: str) -> str | None:
    value = _raw_text(element, name)
    if value is None:
        return None
    return value.strip() or None


def _int(value: str | None, field_name: str) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except ValueError as exc:
        raise VendorContractError(f"{field_name} is not an integer: {value!r}") from exc


# ---------------------------------------------------------------- FPR archive


def _unsafe_member_name(name: str) -> bool:
    return (
        not name
        or "\\" in name
        or name.startswith("/")
        or _DRIVE_PREFIX.match(name) is not None
        or any(part == ".." for part in name.split("/"))
    )


def _archive_members(data: bytes, limits: FortifyImportLimits) -> tuple[str, str | None]:
    """Validate archive metadata without extracting content; return the fvdl and optional audit names."""
    if len(data) > limits.max_total_bytes:
        raise BudgetExhausted(f"FPR archive of {len(data)} bytes exceeds the {limits.max_total_bytes} byte limit")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
    except zipfile.BadZipFile as exc:
        raise VendorContractError("FPR input is not a valid zip archive") from exc
    if len(infos) > limits.max_zip_members:
        raise BudgetExhausted(f"FPR archive has {len(infos)} members; the limit is {limits.max_zip_members}")

    seen: set[str] = set()
    total = 0
    found: dict[str, list[str]] = {_FVDL_NAME: [], _AUDIT_NAME: []}
    for info in infos:
        name = info.filename
        if _unsafe_member_name(name):
            raise VendorContractError(f"unsafe archive member name {name!r}")
        if info.flag_bits & _ENCRYPTED_FLAG:
            raise VendorContractError(f"encrypted archive member {name!r}")
        if stat.S_ISLNK(info.external_attr >> 16):
            raise VendorContractError(f"archive member {name!r} is a symbolic link")
        folded = name.casefold()
        if folded in seen:
            raise VendorContractError(f"duplicate archive member name {name!r}")
        seen.add(folded)
        if info.file_size > limits.max_member_bytes:
            raise BudgetExhausted(
                f"archive member {name!r} declares {info.file_size} bytes; the limit is {limits.max_member_bytes}"
            )
        total += info.file_size
        if total > limits.max_total_bytes:
            raise BudgetExhausted(f"archive declares more than {limits.max_total_bytes} uncompressed bytes")
        if info.file_size > info.compress_size * limits.max_ratio:
            raise BudgetExhausted(f"archive member {name!r} exceeds the {limits.max_ratio}:1 compression ratio")
        if name.endswith("/"):
            continue
        basename = folded.rsplit("/", 1)[-1]
        if basename in found:
            found[basename].append(name)

    fvdl = found[_FVDL_NAME]
    audit = found[_AUDIT_NAME]
    if not fvdl:
        raise VendorContractError("FPR archive contains no audit.fvdl")
    if len(fvdl) > 1 or len(audit) > 1:
        raise VendorContractError("FPR archive contains multiple audit.fvdl or audit.xml members")
    return fvdl[0], (audit[0] if audit else None)


@dataclass(frozen=True)
class _AuditEntry:
    suppressed: bool
    comments: list[str]


def _read_audit(data: bytes | None, limits: FortifyImportLimits) -> dict[str, _AuditEntry]:
    entries: dict[str, _AuditEntry] = {}
    if data is None:
        return entries
    for path, element in _walk(data, limits, root=None):
        if len(path) != 3 or path[1:] != ("IssueList", "Issue"):
            continue
        instance_id = element.get("instanceId")
        if instance_id:
            if instance_id in entries:
                raise VendorContractError(f"audit.xml repeats instanceId {instance_id!r}")
            entries[instance_id] = _AuditEntry(
                suppressed=element.get("suppressed", "").lower() == "true",
                comments=_comments(element, limits),
            )
        element.clear()
    return entries


def _comments(issue: Element, limits: FortifyImportLimits) -> list[str]:
    threaded = _child(issue, "ThreadedComments")
    if threaded is None:
        return []
    comments = _children(threaded, "Comment")
    if len(comments) > limits.max_comments_per_issue:
        raise BudgetExhausted(f"issue has {len(comments)} comments; the limit is {limits.max_comments_per_issue}")
    rendered: list[str] = []
    for comment in comments:
        timestamp = _text(comment, "Timestamp") or ""
        username = _text(comment, "Username") or ""
        content = _text(comment, "Content") or ""
        text = f"{timestamp} - ({username}): {content}"
        if len(text) > limits.max_comment_chars:
            raise BudgetExhausted(f"comment of {len(text)} characters exceeds the {limits.max_comment_chars} limit")
        rendered.append(text)
    return rendered


@dataclass
class _FvdlAux:
    file_uuid: str | None = None
    descriptions: dict[str, dict[str, str | None]] = field(default_factory=dict)
    snippets: dict[str, dict[str, Any]] = field(default_factory=dict)
    rules: dict[str, dict[str, str | None]] = field(default_factory=dict)


def _read_fvdl_aux(fvdl: bytes, limits: FortifyImportLimits) -> _FvdlAux:
    aux = _FvdlAux()
    for path, element in _walk(fvdl, limits, root=_FVDL_ROOT):
        if path == ("FVDL", "UUID"):
            aux.file_uuid = _element_text(element)
        elif path == ("FVDL", "Description"):
            class_id = element.get("classID")
            if class_id:
                aux.descriptions[class_id] = {
                    "abstract": _text(element, "Abstract"),
                    "explanation": _text(element, "Explanation"),
                    "recommendations": _text(element, "Recommendations"),
                    "tips": _text(element, "Tips"),
                }
            element.clear()
        elif path == ("FVDL", "Snippets", "Snippet"):
            snippet_id = element.get("id")
            if snippet_id:
                if len(aux.snippets) >= limits.max_snippets:
                    raise BudgetExhausted(f"FPR archive exceeds the {limits.max_snippets} snippet limit")
                aux.snippets[snippet_id] = {
                    "file": _text(element, "File"),
                    "start_line": _int(_text(element, "StartLine"), "StartLine"),
                    "end_line": _int(_text(element, "EndLine"), "EndLine"),
                    "text": _raw_text(element, "Text"),
                }
            element.clear()
        elif path == ("FVDL", "EngineData", "RuleInfo", "Rule"):
            rule_id = element.get("id")
            if rule_id:
                aux.rules[rule_id] = _rule_groups(element)
            element.clear()
    return aux


def _rule_groups(rule: Element) -> dict[str, str | None]:
    groups: dict[str, str | None] = {}
    meta = _child(rule, "MetaInfo")
    if meta is None:
        return groups
    for group in _children(meta, "Group"):
        name = group.get("name")
        if name in _RULE_GROUPS:
            groups[name] = _element_text(group)
    return groups


def _source_location(vulnerability: Element) -> Element | None:
    primary = _descend(vulnerability, "AnalysisInfo", "Unified", "Trace", "Primary")
    if primary is None:
        return None
    for entry in _children(primary, "Entry"):
        location = _descend(entry, "Node", "SourceLocation")
        if location is not None:
            return location
    return None


def _cwe_list(value: str | None) -> list[int]:
    if not value:
        return []
    numbers: list[int] = []
    for match in _CWE_REFERENCE.findall(value):
        number = int(match)
        if number not in numbers:
            numbers.append(number)
    return numbers


def _snippet_record(snippet: dict[str, Any] | None) -> dict[str, Any] | None:
    return snippet


def _fpr_record(
    vulnerability: Element,
    aux: _FvdlAux,
    audit: dict[str, _AuditEntry],
    *,
    file_uuid: str,
    file_uuid_source: str,
    artifact_sha: str,
    semantics: str,
) -> dict[str, Any]:
    class_info = _child(vulnerability, "ClassInfo")
    instance_info = _child(vulnerability, "InstanceInfo")
    instance_id = _text(instance_info, "InstanceID")
    if instance_id is None:
        raise VendorContractError("FPR Vulnerability has no InstanceID")
    class_id = _text(class_info, "ClassID")
    if class_id is None:
        raise VendorContractError(f"FPR issue {instance_id!r} has no ClassID")

    location = _source_location(vulnerability)
    attrs = dict(location.attrib) if location is not None else {}
    snippet_id = attrs.get("snippet") or None
    snippet = aux.snippets.get(snippet_id) if snippet_id else None
    source_line = _int(attrs.get("line"), "SourceLocation@line")
    line = source_line
    if semantics == "snippet_start_v1" and snippet is not None and snippet["start_line"] is not None:
        line = snippet["start_line"]

    description = aux.descriptions.get(class_id, {})
    rule = aux.rules.get(class_id, {})
    cwes = _cwe_list(rule.get("altcategoryCWE"))
    entry = audit.get(instance_id)
    return {
        "file_uuid": file_uuid,
        "file_uuid_source": file_uuid_source,
        "artifact_sha256": artifact_sha,
        "parser_version": PARSER_VERSION,
        "location_semantics": semantics,
        "instance_id": instance_id,
        "class_id": class_id,
        "issue_name": _text(class_info, "Type"),
        "kingdom": _text(class_info, "Kingdom"),
        "analyzer": _text(class_info, "AnalyzerName"),
        "default_severity": _text(class_info, "DefaultSeverity"),
        "instance_severity": _text(instance_info, "InstanceSeverity"),
        "confidence": _text(instance_info, "Confidence"),
        "path": attrs.get("path"),
        "line": line,
        "source_line": source_line,
        "line_end": _int(attrs.get("lineEnd"), "SourceLocation@lineEnd"),
        "col_start": _int(attrs.get("colStart"), "SourceLocation@colStart"),
        "col_end": _int(attrs.get("colEnd"), "SourceLocation@colEnd"),
        "snippet_id": snippet_id,
        "snippet": _snippet_record(snippet),
        "description": description.get("abstract"),
        "explanation": description.get("explanation"),
        "recommendation": description.get("recommendations"),
        "tips": description.get("tips"),
        "rule": {
            "accuracy": rule.get("Accuracy"),
            "impact": rule.get("Impact"),
            "probability": rule.get("Probability"),
        },
        "cwe": cwes[0] if cwes else None,
        "cwes": cwes,
        "suppressed": entry.suppressed if entry is not None else False,
        "comments": list(entry.comments) if entry is not None else [],
    }


# ---------------------------------------------------------------- report XML


def _issue_count(section: Element) -> int:
    return sum(1 for element in section.iter() if local(element.tag) == "Issue")


def _report_issues(section: Element) -> Iterator[tuple[Element, Element | None]]:
    """Yield each ``Issue`` in document order with its nearest enclosing ``GroupingSection``."""
    stack: list[tuple[Element, Element | None]] = [(child, None) for child in reversed(list(section))]
    while stack:
        element, group = stack.pop()
        name = local(element.tag)
        if name == "Issue":
            yield element, group
            continue
        if name == "GroupingSection":
            group = element
        stack.extend((child, group) for child in reversed(list(element)))


def _group_meta(group: Element | None) -> dict[str, str]:
    if group is None:
        return {}
    summary = _child(group, "MajorAttributeSummary")
    if summary is None:
        return {}
    meta: dict[str, str] = {}
    for info in _children(summary, "MetaInfo"):
        name = _text(info, "Name")
        value = _raw_text(info, "Value")
        if name and value is not None:
            meta[name] = value.strip()
    return meta


def _location(element: Element | None) -> dict[str, Any] | None:
    if element is None:
        return None
    return {
        "file_name": _text(element, "FileName"),
        "file_path": _text(element, "FilePath"),
        "line": _int(_text(element, "LineStart"), "LineStart"),
        "snippet": _raw_text(element, "Snippet"),
    }


def _legacy_records(root: Element, report_sha: str, limits: FortifyImportLimits) -> Iterator[dict[str, Any]]:
    sections = [
        section
        for section in root.iter()
        if local(section.tag) == "ReportSection" and _text(section, "Title") in _RESULT_SECTIONS
    ]
    if not sections:
        raise VendorContractError("ReportDefinition has no 'Results Outline' or 'Issue Count by Category' section")
    section = max(sections, key=_issue_count)
    seen: set[str] = set()
    for emitted, (issue, group) in enumerate(_report_issues(section), start=1):
        if emitted > limits.max_issues:
            raise BudgetExhausted(f"ReportDefinition exceeds the {limits.max_issues} issue limit")
        native = issue.get("iid")
        if not native:
            raise VendorContractError("ReportDefinition Issue has no iid")
        if native in seen:
            raise VendorContractError(f"ReportDefinition repeats iid {native!r}")
        seen.add(native)
        yield {
            "profile": PROFILE_REPORT_DEFINITION,
            "native_id": native,
            "report_sha256": report_sha,
            "parser_version": PARSER_VERSION,
            "category": _text(issue, "Category"),
            "folder": _text(issue, "Folder"),
            "kingdom": _text(issue, "Kingdom"),
            "abstract": _text(issue, "Abstract"),
            "friority": _text(issue, "Friority"),
            "primary": _location(_child(issue, "Primary")),
            "source": _location(_child(issue, "Source")),
            "group_title": group.get("groupTitle") if group is not None else None,
            "group": _group_meta(group),
        }


def _scan_records(root: Element, report_sha: str, limits: FortifyImportLimits) -> Iterator[dict[str, Any]]:
    issues = _child(root, "Issues")
    if issues is None:
        raise VendorContractError("WebInspect Scan has no Issues element")
    seen: set[str] = set()
    for emitted, issue in enumerate(_children(issues, "Issue"), start=1):
        if emitted > limits.max_issues:
            raise BudgetExhausted(f"WebInspect Scan exceeds the {limits.max_issues} issue limit")
        vulnerability_id = _text(issue, "VulnerabilityID")
        if vulnerability_id is None:
            raise VendorContractError("WebInspect Issue has no VulnerabilityID")
        url = _text(issue, "URL")
        native = f"{vulnerability_id}:{url or ''}"
        if native in seen:
            raise VendorContractError(f"WebInspect Scan repeats issue identity {native!r}")
        seen.add(native)
        yield {
            "profile": PROFILE_WEBINSPECT_SCAN,
            "native_id": native,
            "report_sha256": report_sha,
            "parser_version": PARSER_VERSION,
            "scan_version": root.get("version"),
            "vulnerability_id": vulnerability_id,
            "check_type_id": _text(issue, "CheckTypeID"),
            "engine_type": _text(issue, "EngineType"),
            "name": _text(issue, "Name"),
            "url": url,
            "scheme": _text(issue, "Scheme"),
            "host": _text(issue, "Host"),
            "port": _int(_text(issue, "Port"), "Port"),
            "severity": _int(_text(issue, "Severity"), "Severity"),
            "vulnerable_session": _raw_text(issue, "VulnerableSession"),
            "raw_response": _raw_text(issue, "RawResponse"),
        }


__all__ = [
    "PARSER_VERSION",
    "PROFILE_REPORT_DEFINITION",
    "PROFILE_WEBINSPECT_SCAN",
    "FortifyImportLimits",
    "iter_fortify_xml",
    "iter_fpr",
]
