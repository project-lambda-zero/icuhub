"""Query escapers, hardened XML parsing, SOAP faults, and zip member guards."""

import io
import zipfile

import pytest

from icuhub.kit.errors import BudgetExhausted, VendorContractError
from icuhub.kit.query import jql_in, jql_string, ldap_filter_value, odata_string, rql_string
from icuhub.kit.soap import parse_soap, soap_envelope, xml_text
from icuhub.kit.xml import iter_elements, parse_xml, safe_zip_member

# --- query escapers --------------------------------------------------------


def test_jql_string_escapes_quotes_and_backslashes() -> None:
    assert jql_string('a"b') == '"a\\"b"'
    assert jql_string("c\\d") == '"c\\\\d"'


def test_jql_in_builds_a_quoted_list_and_rejects_empty_input() -> None:
    assert jql_in(["A-1", "B-2"]) == '("A-1","B-2")'
    with pytest.raises(VendorContractError, match="at least one value"):
        jql_in([])


def test_control_characters_are_rejected_in_query_values() -> None:
    with pytest.raises(VendorContractError, match="control character"):
        jql_string("a\nb")
    with pytest.raises(VendorContractError, match="control character"):
        rql_string("a\tb")
    with pytest.raises(VendorContractError, match="control character"):
        odata_string("a\x7fb")


def test_rql_string_uses_double_quotes_with_backslash_escapes() -> None:
    assert rql_string('say "hi"') == '"say \\"hi\\""'


def test_odata_string_doubles_single_quotes() -> None:
    assert odata_string("O'Brien") == "'O''Brien'"


def test_ldap_filter_value_escapes_rfc4515_specials() -> None:
    assert ldap_filter_value("a*(b)\\c") == "a\\2a\\28b\\29\\5cc"


def test_ldap_filter_value_escapes_nul_but_rejects_other_control_characters() -> None:
    assert ldap_filter_value("a\x00b") == "a\\00b"
    with pytest.raises(VendorContractError):
        ldap_filter_value("a\x01b")


# --- soap ------------------------------------------------------------------


def test_xml_text_escapes_markup_characters() -> None:
    escaped = xml_text("a<b&c")

    assert "&lt;" in escaped
    assert "&amp;" in escaped
    assert "<b" not in escaped


def test_soap_envelope_wraps_the_body() -> None:
    envelope = soap_envelope("<Ping/>")

    assert "<Ping/>" in envelope
    assert "Envelope" in envelope


def test_soap_fault_raises_vendor_contract_error() -> None:
    fault = (
        b'<?xml version="1.0"?>'
        b'<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
        b"<soap:Body><soap:Fault>"
        b"<faultcode>soap:Server</faultcode><faultstring>boom</faultstring>"
        b"</soap:Fault></soap:Body></soap:Envelope>"
    )

    with pytest.raises(VendorContractError):
        parse_soap(fault)


# --- xml -------------------------------------------------------------------


def test_parse_xml_rejects_a_document_type_declaration() -> None:
    hostile = b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e "boom">]><x>&e;</x>'

    with pytest.raises(VendorContractError, match="invalid XML document"):
        parse_xml(hostile)


def test_parse_xml_rejects_external_entities() -> None:
    hostile = (
        b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY ext SYSTEM "file:///etc/passwd">]><x>&ext;</x>'
    )

    with pytest.raises(VendorContractError):
        parse_xml(hostile)


def test_parse_xml_enforces_the_size_budget() -> None:
    with pytest.raises(BudgetExhausted):
        parse_xml(b"<x>" + b"a" * 100 + b"</x>", max_bytes=10)


def test_iter_elements_matches_bare_names_on_the_local_name() -> None:
    data = b'<root xmlns="urn:x"><Issue id="1"/><Other/><Issue id="2"/></root>'

    found = [element.get("id") for element in iter_elements(data, "Issue")]

    assert found == ["1", "2"]


def test_iter_elements_clark_notation_matches_the_exact_namespace_only() -> None:
    data = b'<root xmlns="urn:x"><Issue id="1"/></root>'

    assert [element.get("id") for element in iter_elements(data, "{urn:x}Issue")] == ["1"]
    assert list(iter_elements(data, "{urn:other}Issue")) == []


def test_iter_elements_rejects_a_document_type_declaration() -> None:
    hostile = b'<!DOCTYPE x [<!ENTITY e "boom">]><x>&e;</x>'

    with pytest.raises(VendorContractError):
        list(iter_elements(hostile, "x"))


# --- zip members -----------------------------------------------------------


def _zip_with(name: str, payload: bytes) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(name, payload)
    return buffer.getvalue()


def test_safe_zip_member_returns_the_named_member() -> None:
    archive = _zip_with("audit.fvdl", b"<FVDL/>")

    assert safe_zip_member(archive, "audit.fvdl", max_uncompressed=1024) == b"<FVDL/>"


@pytest.mark.parametrize("name", ["../escape.txt", "/abs/path.txt", "dir\\file.txt", "C:/win.txt"])
def test_safe_zip_member_rejects_traversal_and_absolute_names(name: str) -> None:
    archive = _zip_with("audit.fvdl", b"x")

    with pytest.raises(VendorContractError, match="unsafe zip member name"):
        safe_zip_member(archive, name, max_uncompressed=1024)
