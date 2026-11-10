"""Mapper tests using synthetic fixtures that follow the documented Kubernetes and OpenShift API shapes."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from icuhub.connectors._kube.mappers import map_record
from icuhub.connectors._kube.streams import RECORD_STREAMS
from icuhub.kit.errors import VendorContractError
from icuhub.kit.types import MapContext, SourceRecord
from icuhub_schemas.ocsf import ApiActivity, ComplianceFinding

RECEIVED = datetime(2026, 11, 10, tzinfo=UTC)
CTX = MapContext(
    connection_id="conn-1",
    tenant_id="tenant-1",
    connector_kind="kubernetes",
    target=None,
    received_at=RECEIVED,
)
FIXTURES = Path(__file__).parents[2] / "fixtures"
POLICY_PARTITION = "wgpolicyk8s.io/v1alpha2/policyreports@default"
GATEKEEPER_PARTITION = "constraints.gatekeeper.sh/v1beta1/k8srequiredlabels@*"
POD_PARTITION = "core/v1/pods@default"
WORKLOAD_PARTITION = "apps/v1/deployments@payments"
RBAC_PARTITION = "rbac.authorization.k8s.io/v1/clusterroles@*"
ROUTE_PARTITION = "route.openshift.io/v1/routes@orders"
SCC_PARTITION = "security.openshift.io/v1/securitycontextconstraints@*"
COMPLIANCE_PARTITION = "compliance.openshift.io/v1alpha1/compliancecheckresults@openshift-compliance"
AUDIT_SOURCE = "kube-apiserver"
AUDIT_ID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"

MAPPED_STREAMS = frozenset(
    {
        "policy_report_changes",
        "policy_report_snapshot",
        "gatekeeper_constraint_changes",
        "gatekeeper_audit_snapshot",
        "resource_inventory_changes",
        "resource_inventory_snapshot",
        "workload_assessment_changes",
        "workload_assessment_snapshot",
        "rbac_assessment_changes",
        "rbac_assessment_snapshot",
        "audit_events",
        "openshift_inventory_changes",
        "openshift_inventory_snapshot",
        "projects_changes",
        "projects_snapshot",
        "route_assessment_changes",
        "route_assessment_snapshot",
        "scc_assessment_changes",
        "scc_assessment_snapshot",
        "compliance_result_changes",
        "compliance_result_snapshot",
        "compliance_scan_status",
    }
)


def _fixture(platform: str, name: str) -> dict[str, Any]:
    path = FIXTURES / platform / "mappers" / f"synthetic_{name}.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _record(
    record_kind: str,
    obj: dict[str, Any] | None,
    partition: str,
    *,
    event: str = "ADDED",
) -> dict[str, Any]:
    return {
        "_record_kind": record_kind,
        "_event": event,
        "_partition": partition,
        "_cluster": "prod",
        "object": obj,
    }


def _verdicts(findings: list[Any]) -> dict[str, str]:
    verdicts: dict[str, str] = {}
    for finding in findings:
        if isinstance(finding, ComplianceFinding) and finding.compliance.control and finding.compliance.status:
            verdicts[finding.compliance.control] = finding.compliance.status
    return verdicts


def _finding_uids(findings: list[Any]) -> list[str]:
    return [finding.finding_info.uid for finding in findings if isinstance(finding, ComplianceFinding)]


def _audit_record(**overrides: Any) -> dict[str, Any]:
    raw = {
        **_fixture("kubernetes", "audit_event"),
        "_record_kind": "audit_event",
        "_api_source": AUDIT_SOURCE,
        "_dedupe_key": f"{AUDIT_SOURCE}:{AUDIT_ID}:ResponseComplete",
        "_cluster": "prod",
    }
    raw.update(overrides)
    return raw


def test_every_stream_has_an_explicit_mapper_binding() -> None:
    expected = {stream for streams in RECORD_STREAMS.values() for stream in streams}
    assert MAPPED_STREAMS == expected


def test_policy_report_maps_to_one_stable_compliance_finding() -> None:
    raw = _record("policy_report", _fixture("kubernetes", "policy_report"), POLICY_PARTITION)
    (finding,) = map_record(None, "policy_report_changes", raw, CTX)
    assert isinstance(finding, ComplianceFinding)
    assert finding.class_uid == 2003
    assert finding.activity_id == 1
    assert finding.type_uid == 200301
    assert finding.time == 1_700_000_000_000
    assert finding.severity_id == 4
    assert finding.finding_info.uid == (
        "prod/11111111-1111-4111-8111-111111111111/require-labels/check-owner/"
        "22222222-2222-4222-8222-222222222222"
    )
    assert finding.compliance.status_id == 2
    assert finding.compliance.control == "check-owner"
    assert finding.resources is not None
    assert finding.resources[0].uid == "22222222-2222-4222-8222-222222222222"


@pytest.mark.parametrize(("verdict", "status_id"), [("pass", 1), ("unknown", 0), ("skip", 99)])
def test_policy_verdicts_keep_check_status_ids(verdict: str, status_id: int) -> None:
    report = _fixture("kubernetes", "policy_report")
    report["results"][0]["result"] = verdict
    raw = _record("policy_report", report, POLICY_PARTITION)
    (finding,) = map_record(None, "policy_report_snapshot", raw, CTX)
    assert isinstance(finding, ComplianceFinding)
    assert finding.compliance.status_id == status_id


def test_gatekeeper_violations_map_one_fail_finding_each() -> None:
    raw = _record("gatekeeper_constraint", _fixture("kubernetes", "gatekeeper_constraint"), GATEKEEPER_PARTITION)
    findings = map_record(None, "gatekeeper_audit_snapshot", raw, CTX)
    compliance_findings = [finding for finding in findings if isinstance(finding, ComplianceFinding)]
    assert len(compliance_findings) == 2
    assert {finding.compliance.status for finding in compliance_findings} == {"fail"}
    assert {finding.compliance.control for finding in compliance_findings} == {"namespace-must-have-team"}
    expected_time = int(datetime(2026, 11, 4, 12, 5, tzinfo=UTC).timestamp() * 1000)
    assert {finding.time for finding in compliance_findings} == {expected_time}


def test_gatekeeper_without_violations_does_not_invent_a_pass() -> None:
    constraint = _fixture("kubernetes", "gatekeeper_constraint")
    constraint["status"]["violations"] = []
    constraint["status"]["totalViolations"] = 0
    raw = _record("gatekeeper_constraint", constraint, GATEKEEPER_PARTITION)
    assert map_record(None, "gatekeeper_constraint_changes", raw, CTX) == []


def test_resource_inventory_is_a_complete_5001_source_record() -> None:
    raw = _record(
        "resource_inventory",
        _fixture("kubernetes", "resource_inventory"),
        POD_PARTITION,
        event="MODIFIED",
    )
    (record,) = map_record(None, "resource_inventory_changes", raw, CTX)
    assert isinstance(record, SourceRecord)
    assert record.record_type == "resource_inventory"
    assert record.uid == "prod/core/v1/pods/44444444-4444-4444-8444-444444444444"
    assert record.revision == "42"
    assert record.data["class_uid"] == 5001
    assert record.data["type_uid"] == 500102
    assert record.data["resources"][0]["labels"] == ["app=synthetic-api"]
    assert record.data["unmapped"] == {"cluster": "prod", "partition": POD_PARTITION, "event": "MODIFIED"}


def test_workload_emits_every_pss_rule_for_the_container() -> None:
    raw = _record("workload_assessment", _fixture("kubernetes", "workload_assessment"), WORKLOAD_PARTITION)
    findings = map_record(None, "workload_assessment_changes", raw, CTX)
    assert len(findings) == 13
    assert all(isinstance(finding, ComplianceFinding) for finding in findings)
    assert set(_verdicts(findings).values()) == {"pass"}
    assert _verdicts(findings)["workload.capabilities-drop-all"] == "pass"
    assert (
        "prod/55555555-5555-4555-8555-555555555555/workload.privileged/payments"
        in _finding_uids(findings)
    )
    repeated = map_record(None, "workload_assessment_changes", raw, CTX)
    assert _finding_uids(repeated) == _finding_uids(findings)


def test_workload_field_failures_and_unknowns_are_explicit() -> None:
    workload = _fixture("kubernetes", "workload_assessment")
    pod_spec = workload["spec"]["template"]["spec"]
    container = pod_spec["containers"][0]
    pod_spec["hostNetwork"] = True
    pod_spec["volumes"] = [{"name": "host", "hostPath": {"path": "/var/lib/synthetic"}}]
    pod_spec["securityContext"]["seccompProfile"]["type"] = "Unconfined"
    pod_spec["securityContext"]["sysctls"] = [{"name": "kernel.core_pattern", "value": "core"}]
    container["ports"][0]["hostPort"] = 8080
    container["securityContext"]["privileged"] = True
    container["securityContext"]["allowPrivilegeEscalation"] = True
    container["securityContext"]["runAsNonRoot"] = False
    container["securityContext"]["capabilities"] = {"add": ["SYS_ADMIN"], "drop": ["NET_RAW"]}
    raw = _record("workload_assessment", workload, WORKLOAD_PARTITION)
    verdicts = _verdicts(map_record(None, "workload_assessment_snapshot", raw, CTX))
    assert verdicts["workload.privileged"] == "fail"
    assert verdicts["workload.host-network"] == "fail"
    assert verdicts["workload.host-path"] == "fail"
    assert verdicts["workload.host-ports"] == "fail"
    assert verdicts["workload.capabilities-add"] == "fail"
    assert verdicts["workload.seccomp"] == "fail"
    assert verdicts["workload.sysctls"] == "fail"
    assert verdicts["workload.privilege-escalation"] == "fail"
    assert verdicts["workload.non-root"] == "fail"
    assert verdicts["workload.capabilities-drop-all"] == "fail"


def test_workload_absent_restricted_fields_are_unknown_not_silent() -> None:
    workload = _fixture("kubernetes", "workload_assessment")
    pod_spec = workload["spec"]["template"]["spec"]
    del pod_spec["securityContext"]["runAsNonRoot"]
    del pod_spec["securityContext"]["seccompProfile"]
    container_security = pod_spec["containers"][0]["securityContext"]
    del container_security["allowPrivilegeEscalation"]
    del container_security["capabilities"]["drop"]
    raw = _record("workload_assessment", workload, WORKLOAD_PARTITION)
    findings = map_record(None, "workload_assessment_changes", raw, CTX)
    assert len(findings) == 13
    verdicts = _verdicts(findings)
    assert verdicts["workload.privilege-escalation"] == "unknown"
    assert verdicts["workload.seccomp"] == "unknown"
    assert verdicts["workload.non-root"] == "unknown"
    assert verdicts["workload.capabilities-drop-all"] == "unknown"


@pytest.mark.parametrize(
    "kind",
    ["Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "ReplicationController", "Job", "CronJob"],
)
def test_workload_pod_spec_paths(kind: str) -> None:
    deployment = _fixture("kubernetes", "workload_assessment")
    pod_spec = deployment["spec"]["template"]["spec"]
    workload = {"kind": kind, "metadata": deployment["metadata"]}
    if kind == "Pod":
        workload["spec"] = pod_spec
    elif kind == "CronJob":
        workload["spec"] = {"jobTemplate": {"spec": {"template": {"spec": pod_spec}}}}
    else:
        workload["spec"] = {"template": {"spec": pod_spec}}
    raw = _record("workload_assessment", workload, WORKLOAD_PARTITION)
    findings = map_record(None, "workload_assessment_changes", raw, CTX)
    assert len(findings) == 13
    assert set(_verdicts(findings).values()) == {"pass"}


def test_rbac_role_emits_permission_rules_and_unknown_binding_rules() -> None:
    raw = _record("rbac_assessment", _fixture("kubernetes", "rbac_assessment"), RBAC_PARTITION)
    findings = map_record(None, "rbac_assessment_changes", raw, CTX)
    assert len(findings) == 13
    assert all(isinstance(finding, ComplianceFinding) for finding in findings)
    verdicts = _verdicts(findings)
    assert set(list(verdicts.values())[:11]) == {"pass"}
    assert verdicts["rbac.system-anonymous-binding"] == "unknown"
    assert verdicts["rbac.system-unauthenticated-binding"] == "unknown"


def test_rbac_wildcards_cover_each_documented_permission_risk() -> None:
    role = _fixture("kubernetes", "rbac_assessment")
    role["rules"] = [
        {"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]},
        {"apiGroups": [""], "resources": ["pods/exec", "pods/attach"], "verbs": ["create"]},
    ]
    raw = _record("rbac_assessment", role, RBAC_PARTITION)
    verdicts = _verdicts(map_record(None, "rbac_assessment_snapshot", raw, CTX))
    assert set(list(verdicts.values())[:11]) == {"fail"}


def test_rbac_binding_flags_reserved_identities_and_keeps_permissions_unknown() -> None:
    binding = _fixture("kubernetes", "rbac_binding")
    raw = _record("rbac_assessment", binding, "rbac.authorization.k8s.io/v1/clusterrolebindings@*")
    findings = map_record(None, "rbac_assessment_changes", raw, CTX)
    assert len(findings) == 13
    verdicts = _verdicts(findings)
    assert set(list(verdicts.values())[:11]) == {"unknown"}
    assert verdicts["rbac.system-anonymous-binding"] == "fail"
    assert verdicts["rbac.system-unauthenticated-binding"] == "fail"


def test_unparseable_rbac_rule_or_subject_is_unknown() -> None:
    role = _fixture("kubernetes", "rbac_assessment")
    role["rules"] = [{"verbs": "get"}]
    role_raw = _record("rbac_assessment", role, RBAC_PARTITION)
    role_verdicts = _verdicts(map_record(None, "rbac_assessment_changes", role_raw, CTX))
    assert set(list(role_verdicts.values())[:11]) == {"unknown"}

    binding = _fixture("kubernetes", "rbac_binding")
    binding["subjects"] = [{"kind": "Group"}]
    binding_raw = _record("rbac_assessment", binding, "rbac.authorization.k8s.io/v1/clusterrolebindings@*")
    binding_verdicts = _verdicts(map_record(None, "rbac_assessment_changes", binding_raw, CTX))
    assert binding_verdicts["rbac.system-anonymous-binding"] == "unknown"
    assert binding_verdicts["rbac.system-unauthenticated-binding"] == "unknown"


def test_route_assessment_fails_allow_and_never_emits_tls_material() -> None:
    raw = _record("route_assessment", _fixture("openshift", "route_assessment"), ROUTE_PARTITION)
    findings = map_record(None, "route_assessment_changes", raw, CTX)
    assert len(findings) == 2
    assert _verdicts(findings) == {"route.tls-required": "pass", "route.insecure-edge-not-allowed": "fail"}
    serialized = json.dumps([finding.model_dump(mode="json", exclude_none=True) for finding in findings])
    assert "SYNTHETIC_ROUTE_PRIVATE_KEY_VALUE" not in serialized
    assert "SYNTHETIC_ROUTE_CERTIFICATE_VALUE" not in serialized
    assert "SYNTHETIC_ROUTE_CA_CERTIFICATE_VALUE" not in serialized


def test_route_missing_tls_and_documented_insecure_default_are_distinct() -> None:
    route = _fixture("openshift", "route_assessment")
    del route["spec"]["tls"]
    raw = _record("route_assessment", route, ROUTE_PARTITION)
    verdicts = _verdicts(map_record(None, "route_assessment_snapshot", raw, CTX))
    assert verdicts == {"route.tls-required": "fail", "route.insecure-edge-not-allowed": "unknown"}

    route["spec"]["tls"] = {"termination": "reencrypt"}
    raw = _record("route_assessment", route, ROUTE_PARTITION)
    verdicts = _verdicts(map_record(None, "route_assessment_snapshot", raw, CTX))
    assert verdicts == {"route.tls-required": "pass", "route.insecure-edge-not-allowed": "pass"}


def test_scc_emits_nine_explicit_field_rules() -> None:
    raw = _record("scc_assessment", _fixture("openshift", "scc_assessment"), SCC_PARTITION)
    findings = map_record(None, "scc_assessment_snapshot", raw, CTX)
    assert len(findings) == 9
    assert set(_verdicts(findings).values()) == {"pass"}
    assert set(_verdicts(findings)) == {
        "scc.privileged-denied",
        "scc.privilege-escalation-denied",
        "scc.host-network-denied",
        "scc.host-pid-denied",
        "scc.host-ipc-denied",
        "scc.host-dir-denied",
        "scc.run-as-user-restricted",
        "scc.no-wildcard-volumes",
        "scc.no-wildcard-capabilities",
    }


def test_scc_dangerous_fields_each_fail() -> None:
    scc = _fixture("openshift", "scc_assessment")
    for field in (
        "allowPrivilegedContainer",
        "allowPrivilegeEscalation",
        "allowHostNetwork",
        "allowHostPID",
        "allowHostIPC",
        "allowHostDirVolumePlugin",
    ):
        scc[field] = True
    scc["runAsUser"]["type"] = "RunAsAny"
    scc["volumes"] = ["*"]
    scc["allowedCapabilities"] = ["*"]
    raw = _record("scc_assessment", scc, SCC_PARTITION)
    verdicts = _verdicts(map_record(None, "scc_assessment_changes", raw, CTX))
    assert len(verdicts) == 9
    assert set(verdicts.values()) == {"fail"}


def test_scc_missing_boolean_defaults_and_lists_are_not_silent() -> None:
    scc = _fixture("openshift", "scc_assessment")
    del scc["allowPrivilegedContainer"]
    del scc["volumes"]
    del scc["allowedCapabilities"]
    raw = _record("scc_assessment", scc, SCC_PARTITION)
    verdicts = _verdicts(map_record(None, "scc_assessment_changes", raw, CTX))
    assert verdicts["scc.privileged-denied"] == "pass"
    assert verdicts["scc.no-wildcard-volumes"] == "unknown"
    assert verdicts["scc.no-wildcard-capabilities"] == "unknown"


@pytest.mark.parametrize(
    ("vendor_status", "status", "status_id"),
    [
        ("PASS", "pass", 1),
        ("FAIL", "fail", 2),
        ("INFO", "informational", 99),
        ("MANUAL", "unknown", 0),
        ("NOT-APPLICABLE", "unknown", 0),
        ("NOT_APPLICABLE", "unknown", 0),
        ("INCONSISTENT", "unknown", 0),
        ("ERROR", "unknown", 0),
    ],
)
def test_compliance_result_statuses(vendor_status: str, status: str, status_id: int) -> None:
    result = _fixture("openshift", "compliance_result")
    result["status"] = vendor_status
    raw = _record("compliance_result", result, COMPLIANCE_PARTITION)
    (finding,) = map_record(None, "compliance_result_snapshot", raw, CTX)
    assert isinstance(finding, ComplianceFinding)
    assert finding.compliance.status == status
    assert finding.compliance.status_id == status_id
    assert finding.compliance.status_code == vendor_status


def test_compliance_result_has_only_typed_check_evidence() -> None:
    raw = _record("compliance_result", _fixture("openshift", "compliance_result"), COMPLIANCE_PARTITION)
    (finding,) = map_record(None, "compliance_result_changes", raw, CTX)
    assert isinstance(finding, ComplianceFinding)
    assert finding.compliance.checks is not None
    check = finding.compliance.checks[0]
    assert check.uid == "xccdf_org.ssgproject.content_rule_no_direct_root_logins"
    assert check.name == "no-direct-root-logins"
    assert check.desc == "Inspect the synthetic securetty configuration manually."
    assert check.severity == "medium"
    assert finding.compliance.category == "synthetic-worker-scan"
    assert finding.severity_id == 3
    serialized = json.dumps(finding.model_dump(mode="json", exclude_none=True))
    assert "Synthetic check description" not in serialized


def test_compliance_suite_maps_to_scan_status_source_record() -> None:
    raw = _record(
        "compliance_scan_status",
        _fixture("openshift", "compliance_scan_status"),
        "compliance.openshift.io/v1alpha1/compliancesuites@openshift-compliance",
    )
    (record,) = map_record(None, "compliance_scan_status", raw, CTX)
    assert isinstance(record, SourceRecord)
    assert record.record_type == "compliance_scan_status"
    assert record.revision == "207"
    assert record.data["kind"] == "ComplianceSuite"
    assert record.data["phase"] == "DONE"
    assert record.data["result"] == "NON-COMPLIANT"
    assert record.data["scan_names"] == ["synthetic-worker-scan"]


def test_compliance_scan_maps_to_scan_status_without_findings() -> None:
    raw = _record(
        "compliance_scan_status",
        _fixture("openshift", "compliance_scan"),
        "compliance.openshift.io/v1alpha1/compliancescans@openshift-compliance",
    )
    (record,) = map_record(None, "compliance_scan_status", raw, CTX)
    assert isinstance(record, SourceRecord)
    assert record.data["kind"] == "ComplianceScan"
    assert record.data["phase"] == "RUNNING"
    assert "scan_names" not in record.data


def test_openshift_imagestream_preserves_observed_mutable_tag_mappings() -> None:
    raw = _record(
        "openshift_inventory",
        _fixture("openshift", "openshift_inventory"),
        "image.openshift.io/v1/imagestreams@payments",
    )
    (record,) = map_record(None, "openshift_inventory_changes", raw, CTX)
    assert isinstance(record, SourceRecord)
    assert record.record_type == "openshift_inventory"
    assert len(record.data["tags"]) == 2
    assert record.data["tags"][0]["tag"] == "stable"
    assert record.data["tags"][0]["image"].startswith("sha256:")
    assert record.data["tags"][0]["created"] == "2026-11-05T10:00:00Z"
    record.data["tags"][0]["tag"] = "mutable-synthetic-tag"
    assert record.data["tags"][0]["tag"] == "mutable-synthetic-tag"


def test_openshift_image_uses_immutable_metadata_name_digest() -> None:
    raw = _record("openshift_inventory", _fixture("openshift", "image"), "image.openshift.io/v1/images@*")
    (record,) = map_record(None, "openshift_inventory_snapshot", raw, CTX)
    assert isinstance(record, SourceRecord)
    assert record.data["digest"] == record.data["name"]
    assert record.data["digest"].startswith("sha256:")


def test_project_maps_to_project_source_record() -> None:
    raw = _record("project", _fixture("openshift", "project"), "project.openshift.io/v1/projects@*")
    (record,) = map_record(None, "projects_changes", raw, CTX)
    assert isinstance(record, SourceRecord)
    assert record.record_type == "project"
    assert record.uid == "prod/Project/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa3"
    assert record.revision == "203"
    assert record.data["phase"] == "Active"


@pytest.mark.parametrize(
    ("record_kind", "stream", "partition"),
    [
        ("workload_assessment", "workload_assessment_snapshot", WORKLOAD_PARTITION),
        ("rbac_assessment", "rbac_assessment_snapshot", RBAC_PARTITION),
        ("route_assessment", "route_assessment_snapshot", ROUTE_PARTITION),
        ("scc_assessment", "scc_assessment_snapshot", SCC_PARTITION),
        ("compliance_result", "compliance_result_snapshot", COMPLIANCE_PARTITION),
    ],
)
def test_denied_assessment_partition_is_coverage_only(record_kind: str, stream: str, partition: str) -> None:
    raw = _record(record_kind, None, partition, event="COVERAGE")
    raw["_partial_coverage"] = True
    raw["_coverage"] = {"partition": partition, "reason": "forbidden", "subject": None}
    (record,) = map_record(None, stream, raw, CTX)
    assert isinstance(record, SourceRecord)
    assert record.record_type == "coverage"
    assert record.data["reason"] == "forbidden"
    assert record.data["cluster"] == "prod"


def test_stream_kind_mismatch_is_rejected() -> None:
    raw = _record("resource_inventory", _fixture("kubernetes", "resource_inventory"), POD_PARTITION)
    with pytest.raises(VendorContractError):
        map_record(None, "policy_report_changes", raw, CTX)


def test_unknown_stream_is_rejected() -> None:
    raw = _record("policy_report", _fixture("kubernetes", "policy_report"), POLICY_PARTITION)
    with pytest.raises(VendorContractError):
        map_record(None, "not_a_stream", raw, CTX)


def test_missing_cluster_is_rejected() -> None:
    raw = _record("policy_report", _fixture("kubernetes", "policy_report"), POLICY_PARTITION)
    del raw["_cluster"]
    with pytest.raises(VendorContractError):
        map_record(None, "policy_report_changes", raw, CTX)


def test_audit_event_maps_to_api_activity_with_actor_and_endpoint() -> None:
    (activity,) = map_record(None, "audit_events", _audit_record(), CTX)
    assert isinstance(activity, ApiActivity)
    assert activity.type_uid == ApiActivity.CLASS_UID * 100 + 99
    assert activity.metadata is not None
    assert activity.metadata.uid == f"{AUDIT_SOURCE}:{AUDIT_ID}:ResponseComplete"
    assert activity.actor is not None and activity.actor.user is not None
    assert activity.actor.user.name == "system:serviceaccount:automation:resource-writer"
    assert activity.src_endpoint is not None
    assert activity.src_endpoint.ip == "10.20.0.25"
    assert activity.api is not None
    assert activity.api.operation == "patch"
    assert activity.resources is not None
    assert activity.resources[0].name == "synthetic-app-02"
    expected_time = int(datetime(2026, 11, 4, 12, 10, 0, 100000, tzinfo=UTC).timestamp() * 1000)
    assert activity.time == expected_time


def test_audit_dedupe_key_must_match_source_id_and_stage() -> None:
    with pytest.raises(VendorContractError):
        map_record(None, "audit_events", _audit_record(_dedupe_key="other:x:y"), CTX)


def test_audit_without_source_ip_is_rejected() -> None:
    with pytest.raises(VendorContractError):
        map_record(None, "audit_events", _audit_record(sourceIPs=[]), CTX)


def test_audit_without_user_is_rejected() -> None:
    raw = _audit_record()
    del raw["user"]
    with pytest.raises(VendorContractError):
        map_record(None, "audit_events", raw, CTX)
