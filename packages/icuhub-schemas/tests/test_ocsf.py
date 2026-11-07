"""Behaviour of the OCSF 1.9.0 models and schema validation."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from icuhub_schemas.ocsf import (
    OCSF_VERSION,
    ApiActivity,
    ApplicationSecurityPostureFinding,
    ComplianceFinding,
    DataSecurityFinding,
    DetectionFinding,
    IncidentFinding,
    Metadata,
    OcsfValidationError,
    Product,
    Vulnerability,
    VulnerabilityFinding,
    validate_ocsf,
)

COMMON: dict[str, object] = {
    "time": 1_700_000_000_000,
    "severity_id": 3,
    "metadata": {"product": {"name": "scanner", "vendor_name": "Example"}},
    "cloud": {"provider": "on-prem"},
    "osint": [],
}
FINDING_INFO: dict[str, object] = {"uid": "finding-1", "title": "Outdated package"}

CLASS_KWARGS: dict[type, dict[str, object]] = {
    VulnerabilityFinding: {
        **COMMON,
        "activity_id": 1,
        "finding_info": FINDING_INFO,
        "vulnerabilities": [{"cve": {"uid": "CVE-2024-0001"}}],
    },
    ComplianceFinding: {
        **COMMON,
        "activity_id": 1,
        "finding_info": FINDING_INFO,
        "compliance": {"status": "Failed"},
    },
    DetectionFinding: {**COMMON, "activity_id": 1, "finding_info": FINDING_INFO},
    IncidentFinding: {
        **COMMON,
        "activity_id": 1,
        "status_id": 1,
        "finding_info_list": [FINDING_INFO],
        "assignee": {"name": "alice"},
    },
    DataSecurityFinding: {**COMMON, "activity_id": 1, "finding_info": FINDING_INFO},
    ApplicationSecurityPostureFinding: {
        **COMMON,
        "activity_id": 1,
        "finding_info": FINDING_INFO,
        "application": {"name": "billing"},
    },
    ApiActivity: {
        **COMMON,
        "activity_id": 1,
        "actor": {"app_name": "svc"},
        "api": {"operation": "GetInvoice"},
        "src_endpoint": {"ip": "10.0.0.5"},
    },
}


def _vulnerability_document() -> dict[str, object]:
    return VulnerabilityFinding(**CLASS_KWARGS[VulnerabilityFinding]).to_ocsf()


@pytest.mark.parametrize("cls", list(CLASS_KWARGS))
def test_round_trip_produces_schema_valid_document(cls: type) -> None:
    model = cls(**CLASS_KWARGS[cls])

    document = model.to_ocsf()

    validate_ocsf(document)
    assert document["metadata"]["version"] == OCSF_VERSION
    assert cls.from_ocsf(document) == model


def test_type_uid_is_derived_from_class_and_activity() -> None:
    model = VulnerabilityFinding(**{**CLASS_KWARGS[VulnerabilityFinding], "activity_id": 2})

    assert model.to_ocsf()["type_uid"] == 2002 * 100 + 2


def test_consistent_supplied_type_uid_is_accepted() -> None:
    model = VulnerabilityFinding(**CLASS_KWARGS[VulnerabilityFinding], type_uid=200201)

    assert model.type_uid == 200201


def test_inconsistent_supplied_type_uid_is_rejected() -> None:
    with pytest.raises(ValidationError, match="type_uid"):
        VulnerabilityFinding(**CLASS_KWARGS[VulnerabilityFinding], type_uid=200199)


def test_unknown_class_uid_is_rejected() -> None:
    with pytest.raises(OcsfValidationError) as raised:
        validate_ocsf({"class_uid": 9999})

    assert [issue.path for issue in raised.value.issues] == ["$.class_uid"]


def test_missing_required_attribute_is_reported_with_its_path() -> None:
    document = _vulnerability_document()
    del document["cloud"]

    with pytest.raises(OcsfValidationError) as raised:
        validate_ocsf(document)

    assert "$.cloud" in [issue.path for issue in raised.value.issues]


def test_absent_fields_are_omitted_not_defaulted() -> None:
    document = _vulnerability_document()

    assert "message" not in document
    assert "resources" not in document
    assert "unmapped" not in document
    assert "raw_data" not in document


def test_unmapped_and_raw_data_are_preserved() -> None:
    model = VulnerabilityFinding(
        **CLASS_KWARGS[VulnerabilityFinding],
        unmapped={"vendor_field": {"score": 7}},
        raw_data='{"original": true}',
    )

    document = model.to_ocsf()

    assert document["unmapped"] == {"vendor_field": {"score": 7}}
    assert document["raw_data"] == '{"original": true}'
    assert VulnerabilityFinding.from_ocsf(document).unmapped == {"vendor_field": {"score": 7}}


def test_unknown_attribute_is_rejected() -> None:
    with pytest.raises(ValidationError):
        VulnerabilityFinding(**CLASS_KWARGS[VulnerabilityFinding], not_an_ocsf_attribute=1)


def test_metadata_version_is_fixed_to_pinned_release() -> None:
    with pytest.raises(ValidationError):
        Metadata(product=Product(name="scanner"), version="1.8.0")


def test_from_ocsf_rejects_schema_violation_with_path() -> None:
    document = _vulnerability_document()
    document["severity_id"] = 42

    with pytest.raises(OcsfValidationError) as raised:
        VulnerabilityFinding.from_ocsf(document)

    assert "$.severity_id" in [issue.path for issue in raised.value.issues]


def test_vulnerability_requires_exactly_one_of_cve_or_cwe() -> None:
    with pytest.raises(ValidationError):
        Vulnerability()
    with pytest.raises(ValidationError):
        Vulnerability(cve={"uid": "CVE-2024-0001"}, cwe={"uid": "CWE-79"})

    assert Vulnerability(cwe={"uid": "CWE-79"}).cwe is not None


def test_incident_requires_assignee_or_assignee_group() -> None:
    kwargs = {k: v for k, v in CLASS_KWARGS[IncidentFinding].items() if k != "assignee"}

    with pytest.raises(ValidationError):
        IncidentFinding(**kwargs)

    assert IncidentFinding(**kwargs, assignee_group={"name": "soc"}).assignee_group is not None


def test_application_posture_requires_one_of_its_root_alternatives() -> None:
    kwargs = {k: v for k, v in CLASS_KWARGS[ApplicationSecurityPostureFinding].items() if k != "application"}

    with pytest.raises(ValidationError):
        ApplicationSecurityPostureFinding(**kwargs)


def test_actor_requires_an_identity() -> None:
    with pytest.raises(ValidationError):
        ApiActivity(**{**CLASS_KWARGS[ApiActivity], "actor": {}})


def test_data_security_finding_round_trip_keeps_optional_objects() -> None:
    model = DataSecurityFinding(
        **CLASS_KWARGS[DataSecurityFinding],
        file={"name": "export.csv", "type_id": 1, "path": "/data/export.csv"},
    )

    document = model.to_ocsf()

    assert document["file"] == {"name": "export.csv", "type_id": 1, "path": "/data/export.csv"}
    assert DataSecurityFinding.from_ocsf(document) == model
