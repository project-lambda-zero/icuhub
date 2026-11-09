"""SOAP envelope construction, fault-aware parsing, and XML text escaping."""

from __future__ import annotations

from typing import Literal
from xml.etree.ElementTree import Element

from icuhub.kit.errors import ConfigError, VendorContractError
from icuhub.kit.xml import local, parse_xml

__all__ = ["parse_soap", "soap_envelope", "xml_text"]

SoapVersion = Literal["1.1", "1.2"]

_ENVELOPE_NAMESPACES: dict[SoapVersion, str] = {
    "1.1": "http://schemas.xmlsoap.org/soap/envelope/",
    "1.2": "http://www.w3.org/2003/05/soap-envelope",
}
_VERSION_BY_NAMESPACE: dict[str, SoapVersion] = {namespace: version for version, namespace in _ENVELOPE_NAMESPACES.items()}
_FAULT_TEXT_LIMIT = 500


def xml_text(value: str) -> str:
    """Escape ``value`` for use as XML character data or a double- or single-quoted attribute value."""
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


def soap_envelope(body_xml: str, *, version: SoapVersion = "1.1") -> str:
    """Wrap already-serialized ``body_xml`` in a SOAP envelope. Callers escape untrusted values with ``xml_text``."""
    namespace = _ENVELOPE_NAMESPACES.get(version)
    if namespace is None:
        raise ConfigError(f"unsupported SOAP version: {version!r}")
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<soap:Envelope xmlns:soap="{namespace}"><soap:Body>{body_xml}</soap:Body></soap:Envelope>'
    )


def parse_soap(data: bytes) -> Element:
    """Return the ``Body`` element of a SOAP 1.1 or 1.2 envelope; raise ``VendorContractError`` on a Fault."""
    envelope = parse_xml(data)
    namespace = _namespace_of(envelope.tag)
    version = _VERSION_BY_NAMESPACE.get(namespace)
    if local(envelope.tag) != "Envelope" or version is None:
        raise VendorContractError("document is not a SOAP 1.1 or 1.2 envelope")
    body = _find(envelope, "Body")
    if body is None:
        raise VendorContractError("SOAP envelope has no Body element")
    fault = _find(body, "Fault")
    if fault is not None:
        raise VendorContractError(_fault_message(fault, version))
    return body


def _namespace_of(tag: str) -> str:
    if tag.startswith("{"):
        return tag[1:].split("}", 1)[0]
    return ""


def _find(parent: Element, name: str) -> Element | None:
    for child in parent:
        if local(child.tag) == name:
            return child
    return None


def _text_at(parent: Element, *names: str) -> str | None:
    current: Element | None = parent
    for name in names:
        if current is None:
            return None
        current = _find(current, name)
    if current is None:
        return None
    text = current.text.strip() if current.text else ""
    return text or None


def _fault_message(fault: Element, version: SoapVersion) -> str:
    if version == "1.1":
        code = _text_at(fault, "faultcode")
        reason = _text_at(fault, "faultstring")
    else:
        code = _text_at(fault, "Code", "Value")
        reason = _text_at(fault, "Reason", "Text")
    code_text = code or "unknown"
    reason_text = (reason or "unknown")[:_FAULT_TEXT_LIMIT]
    return f"SOAP {version} fault: code={code_text} reason={reason_text}"
