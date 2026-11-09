"""Offline tests for the Nessus .nessus (NessusClientData_v2) parser: bounds, rejection, and record shape."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from icuhub.connectors.nessus.parser import NessusImportLimits, file_sha256, iter_nessus
from icuhub.kit.errors import BudgetExhausted, VendorContractError

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "nessus"


def _report(hosts: str) -> bytes:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<NessusClientData_v2><Policy/><Report name="t">'
        f"{hosts}"
        "</Report></NessusClientData_v2>\n"
    ).encode()


def _host(name: str, items: str, properties: str = "") -> str:
    return (
        f'<ReportHost name="{name}"><HostProperties>{properties}</HostProperties>'
        f"{items}</ReportHost>"
    )


def _item(plugin_id: str, severity: str = "2", extra: str = "", attrs: str = "") -> str:
    return (
        f'<ReportItem port="443" svc_name="www" protocol="tcp" severity="{severity}" '
        f'pluginID="{plugin_id}" pluginName="Plugin {plugin_id}" pluginFamily="Web Servers"{attrs}>'
        f"{extra}</ReportItem>"
    )


def _records(data: bytes, limits: NessusImportLimits | None = None) -> list:
    return list(iter_nessus(data, limits=limits))


def test_sample_scan_yields_every_host_and_item_with_all_severities() -> None:
    records = _records((FIXTURES / "sample_scan.nessus").read_bytes())

    assert len(records) >= 3
    hosts = {host.name for host, _ in records}
    assert len(hosts) >= 3
    severities = {item.severity for _, item in records}
    assert {0, 1, 2, 3, 4} <= severities


def test_severity_is_preserved_from_source_not_recomputed_from_cvss() -> None:
    data = _report(_host("h1", _item("1", severity="0", extra="<cvss_base_score>9.8</cvss_base_score>")))

    ((_, item),) = _records(data)

    assert item.severity == 0


def test_cve_and_cwe_are_extracted_and_absent_when_missing() -> None:
    data = _report(
        _host(
            "h1",
            _item("1", extra="<cve>CVE-2024-0001</cve><cwe>79</cwe>")
            + _item("2", extra=""),
        )
    )

    with_refs, without_refs = [item for _, item in _records(data)]

    assert with_refs.cves == ["CVE-2024-0001"]
    assert with_refs.cwes == ["79"]
    assert without_refs.cves == []
    assert without_refs.cwes == []


def test_port_protocol_and_service_are_captured() -> None:
    data = _report(_host("h1", _item("1")))

    ((_, item),) = _records(data)

    assert item.port == 443
    assert item.protocol == "tcp"
    assert item.service == "www"


def test_risk_factor_is_kept_as_reported() -> None:
    data = _report(_host("h1", _item("1", extra="<risk_factor>High</risk_factor>")))

    ((_, item),) = _records(data)

    assert item.risk_factor == "High"


def test_host_properties_fqdn_ip_and_os_are_mapped() -> None:
    props = (
        '<tag name="host-fqdn">web.example.test</tag>'
        '<tag name="host-ip">192.0.2.10</tag>'
        '<tag name="operating-system">Linux Kernel 5.15</tag>'
    )
    data = _report(_host("192.0.2.10", _item("1"), properties=props))

    ((host, _),) = _records(data)

    assert host.fqdn == "web.example.test"
    assert host.ip == "192.0.2.10"
    assert host.os == "Linux Kernel 5.15"


def test_plugin_output_is_bounded_and_digest_covers_full_text() -> None:
    long_output = "A" * 600
    data = _report(_host("h1", _item("1", extra=f"<plugin_output>{long_output}</plugin_output>")))
    limits = NessusImportLimits(max_plugin_output_chars=256)

    ((_, item),) = _records(data, limits)

    assert len(item.plugin_output) == 256
    assert item.output_bounded is True
    assert item.plugin_output_size == 600
    assert item.plugin_output_sha256 == hashlib.sha256(long_output.encode()).hexdigest()


def test_truncated_marker_in_plugin_output_is_detected() -> None:
    data = (FIXTURES / "truncated_scan.nessus").read_bytes()

    ((_, item),) = [r for r in _records(data) if r[1].truncated]

    assert item.truncated is True
    assert item.plugin_output.endswith("TRUNCATED")


def test_compliance_tags_populate_compliance_mapping() -> None:
    data = (FIXTURES / "compliance_scan.nessus").read_bytes()

    compliance = [item for _, item in _records(data) if item.compliance]

    assert len(compliance) >= 2
    for item in compliance:
        assert item.plugin_family == "Policy Compliance"
        assert item.compliance.get("check_name")
        assert item.compliance.get("result")


def test_file_sha256_matches_hashlib_and_is_stable() -> None:
    data = (FIXTURES / "sample_scan.nessus").read_bytes()

    assert file_sha256(data) == hashlib.sha256(data).hexdigest()
    assert file_sha256(data) == file_sha256(bytes(data))


def test_wrong_root_is_a_vendor_contract_error() -> None:
    with pytest.raises(VendorContractError):
        _records((FIXTURES / "wrong_root.xml").read_bytes())


def test_dtd_and_external_entity_are_rejected() -> None:
    with pytest.raises(VendorContractError):
        _records((FIXTURES / "xxe_scan.nessus").read_bytes())


def test_malformed_xml_is_a_vendor_contract_error() -> None:
    with pytest.raises(VendorContractError):
        _records(b"<NessusClientData_v2><Report>")


def test_item_without_plugin_id_is_a_vendor_contract_error() -> None:
    bad = _report(_host("h1", '<ReportItem port="1" severity="1"></ReportItem>'))

    with pytest.raises(VendorContractError):
        _records(bad)


def test_non_integer_severity_is_a_vendor_contract_error() -> None:
    bad = _report(_host("h1", _item("1", severity="high")))

    with pytest.raises(VendorContractError):
        _records(bad)


def test_oversize_bytes_exhaust_the_byte_budget() -> None:
    data = _report(_host("h1", _item("1")))

    with pytest.raises(BudgetExhausted):
        _records(data, NessusImportLimits(max_bytes=64))


def test_host_count_over_budget_exhausts_budget() -> None:
    data = _report(_host("h1", _item("1")) + _host("h2", _item("2")))

    with pytest.raises(BudgetExhausted):
        _records(data, NessusImportLimits(max_hosts=1))


def test_item_count_over_budget_exhausts_budget() -> None:
    data = _report(_host("h1", _item("1") + _item("2")))

    with pytest.raises(BudgetExhausted):
        _records(data, NessusImportLimits(max_items=1))


def test_depth_over_budget_exhausts_budget() -> None:
    nested = "<a>" * 40 + "x" + "</a>" * 40
    data = _report(_host("h1", _item("1", extra=nested)))

    with pytest.raises(BudgetExhausted):
        _records(data, NessusImportLimits(max_depth=8))


def test_replaying_the_same_bytes_yields_identical_records() -> None:
    data = (FIXTURES / "sample_scan.nessus").read_bytes()

    first = [(h.key, i.ordinal, i.plugin_id) for h, i in _records(data)]
    second = [(h.key, i.ordinal, i.plugin_id) for h, i in _records(data)]

    assert first == second
