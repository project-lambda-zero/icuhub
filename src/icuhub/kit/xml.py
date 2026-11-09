"""Hardened XML parsing and bounded ZIP member extraction."""

from __future__ import annotations

import io
import re
import stat
import zipfile
import zlib
from collections.abc import Iterator
from xml.etree.ElementTree import Element

from defusedxml.common import DefusedXmlException
from defusedxml.ElementTree import ParseError, fromstring, iterparse

from icuhub.kit.errors import BudgetExhausted, NotFound, VendorContractError

__all__ = ["iter_elements", "local", "parse_xml", "safe_zip_member"]

_DEFAULT_MAX_BYTES = 256 * 1024 * 1024
_READ_CHUNK = 64 * 1024
_DRIVE_PREFIX = re.compile(r"^[A-Za-z]:")
_S_IFMT_MASK = 0o170000


def local(tag: str) -> str:
    """Return the tag name without its ``{namespace}`` prefix."""
    return tag.rsplit("}", 1)[-1]


def _check_size(data: bytes, max_bytes: int) -> None:
    if len(data) > max_bytes:
        raise BudgetExhausted(f"XML document of {len(data)} bytes exceeds the {max_bytes} byte limit")


def parse_xml(data: bytes, *, max_bytes: int = _DEFAULT_MAX_BYTES) -> Element:
    """Parse an XML document with DTDs, entities, and external references forbidden."""
    _check_size(data, max_bytes)
    try:
        return fromstring(data, forbid_dtd=True, forbid_entities=True, forbid_external=True)
    except (DefusedXmlException, ParseError) as exc:
        raise VendorContractError(f"invalid XML document: {exc}") from exc


def iter_elements(data: bytes, tag: str, *, max_bytes: int = _DEFAULT_MAX_BYTES) -> Iterator[Element]:
    """Yield every element matching ``tag`` as its end tag is parsed.

    A Clark-notation ``{namespace}name`` matches exactly; a bare name matches on the local name.
    The size budget and the security policy are enforced before the first element is yielded.
    """
    _check_size(data, max_bytes)
    exact = tag.startswith("{")
    return _iter_matching(data, tag, exact)


def _iter_matching(data: bytes, tag: str, exact: bool) -> Iterator[Element]:
    try:
        for _, element in iterparse(
            io.BytesIO(data),
            events=("end",),
            forbid_dtd=True,
            forbid_entities=True,
            forbid_external=True,
        ):
            if (element.tag == tag) if exact else (local(element.tag) == tag):
                yield element
    except (DefusedXmlException, ParseError) as exc:
        raise VendorContractError(f"invalid XML document: {exc}") from exc


def _unsafe_member_name(name: str) -> bool:
    if not name or "\\" in name or name.startswith("/") or _DRIVE_PREFIX.match(name):
        return True
    return any(part == ".." for part in name.split("/"))


def safe_zip_member(data: bytes, name: str, *, max_uncompressed: int) -> bytes:
    """Return the bytes of one archive member under path, symlink, and size guards.

    The declared ``file_size`` is checked first, and the stream is then read in chunks with a
    running counter because a member's declared size can understate its real size.
    """
    if _unsafe_member_name(name):
        raise VendorContractError(f"unsafe zip member name requested: {name!r}")
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise VendorContractError("invalid zip archive") from exc
    with archive:
        matches = [info for info in archive.infolist() if info.filename == name]
        if not matches:
            raise NotFound(f"zip member not found: {name!r}")
        if len(matches) > 1:
            raise VendorContractError(f"zip archive contains duplicate member {name!r}")
        info = matches[0]
        if _unsafe_member_name(info.filename):
            raise VendorContractError(f"unsafe zip member name: {info.filename!r}")
        if (info.external_attr >> 16) & _S_IFMT_MASK == stat.S_IFLNK:
            raise VendorContractError(f"zip member is a symbolic link: {name!r}")
        if info.file_size > max_uncompressed:
            raise BudgetExhausted(
                f"zip member {name!r} declares {info.file_size} bytes, above the {max_uncompressed} byte limit"
            )
        out = bytearray()
        try:
            with archive.open(info) as stream:
                while chunk := stream.read(_READ_CHUNK):
                    out.extend(chunk)
                    if len(out) > max_uncompressed:
                        raise BudgetExhausted(
                            f"zip member {name!r} decompresses past the {max_uncompressed} byte limit"
                        )
        except (zipfile.BadZipFile, EOFError, NotImplementedError, RuntimeError, zlib.error) as exc:
            raise VendorContractError(f"unreadable zip member {name!r}: {type(exc).__name__}") from exc
    return bytes(out)
