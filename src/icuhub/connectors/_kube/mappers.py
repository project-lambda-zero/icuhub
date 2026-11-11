"""Pure Kubernetes and OpenShift mappers.

PolicyReport results, Gatekeeper violations, and explicit workload, RBAC, Route, SCC, and
Compliance Operator assessments become OCSF Compliance Findings. Audit records become OCSF API
Activity. Inventory, project, scan status, and coverage records remain non-finding source records.

Every assessment rule emits pass, fail, unknown, or informational on every run. Finding identity
uses stable object identity and rule id, plus container name for workload rules. Every OCSF
document is validated against the pinned schema before it leaves the mapper.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Literal

from pydantic import BaseModel

from icuhub.connectors._kube.streams import RECORD_STREAMS
from icuhub.kit.errors import VendorContractError
from icuhub.kit.mapping import bounded_raw, epoch_ms
from icuhub.kit.types import MapContext, SourceRecord
from icuhub_schemas.ocsf import (
    Actor,
    Api,
    ApiActivity,
    Check,
    CheckStatusId,
    Cloud,
    Compliance,
    ComplianceFinding,
    FindingInfo,
    Metadata,
    NetworkEndpoint,
    Product,
    ResourceDetails,
    User,
    validate_ocsf,
)

__all__ = ["map_record"]

_PRODUCT = Product(name="Kubernetes", vendor_name="Kubernetes")
_ACTIVITY: dict[str, Literal[1, 2, 3]] = {"ADDED": 1, "MODIFIED": 2, "DELETED": 3}
_ACTIVITY_OTHER = 99
_SEVERITY: dict[str, Literal[1, 2, 3, 4, 5]] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
    "informational": 1,
}
_INVENTORY_CLASS_UID = 5001
_INVENTORY_CATEGORY_UID = 5

# https://kubernetes.io/docs/concepts/security/pod-security-standards/
# Baseline capabilities are further restricted by the cumulative Restricted policy to
# NET_BIND_SERVICE. These are the only additions accepted by the workload assessment.
_ALLOWED_ADDED_CAPABILITIES = frozenset({"NET_BIND_SERVICE"})
# https://kubernetes.io/docs/concepts/security/pod-security-standards/
# Baseline and Restricted safe sysctls listed by the PSS table.
_SAFE_SYSCTLS = frozenset(
    {
        "kernel.shm_rmid_forced",
        "net.ipv4.ip_local_port_range",
        "net.ipv4.ip_unprivileged_port_start",
        "net.ipv4.tcp_syncookies",
        "net.ipv4.ping_group_range",
        "net.ipv4.ip_local_reserved_ports",
        "net.ipv4.tcp_keepalive_time",
        "net.ipv4.tcp_fin_timeout",
        "net.ipv4.tcp_keepalive_intvl",
        "net.ipv4.tcp_keepalive_probes",
        "net.ipv4.tcp_rmem",
        "net.ipv4.tcp_wmem",
        "net.ipv4.tcp_slow_start_after_idle",
        "net.ipv4.tcp_notsent_lowat",
    }
)
# Rule ids and their assessed PSS fields follow
# https://kubernetes.io/docs/concepts/security/pod-security-standards/.
_WORKLOAD_RULE_FIELDS = (
    ("workload.privileged", "securityContext.privileged"),
    ("workload.host-process", "securityContext.windowsOptions.hostProcess"),
    ("workload.host-network", "spec.hostNetwork"),
    ("workload.host-pid", "spec.hostPID"),
    ("workload.host-ipc", "spec.hostIPC"),
    ("workload.host-path", "spec.volumes[*].hostPath"),
    ("workload.host-ports", "containers[*].ports[*].hostPort"),
    ("workload.capabilities-add", "securityContext.capabilities.add"),
    ("workload.seccomp", "securityContext.seccompProfile.type"),
    ("workload.sysctls", "spec.securityContext.sysctls[*].name"),
    ("workload.privilege-escalation", "securityContext.allowPrivilegeEscalation"),
    ("workload.non-root", "securityContext.runAsNonRoot or securityContext.runAsUser"),
    ("workload.capabilities-drop-all", "securityContext.capabilities.drop"),
)

# https://docs.redhat.com/en/documentation/openshift_container_platform/latest/html/security_and_compliance/compliance-operator
# INFO completed with informational results. MANUAL and NOT-APPLICABLE did not establish a
# verdict. INCONSISTENT and ERROR cannot be passes. Both not-applicable spellings share a state.
_COMPLIANCE_STATUSES: dict[str, Literal["pass", "fail", "unknown", "informational"]] = {
    "PASS": "pass",
    "FAIL": "fail",
    "INFO": "informational",
    "MANUAL": "unknown",
    "NOT-APPLICABLE": "unknown",
    "NOT_APPLICABLE": "unknown",
    "INCONSISTENT": "unknown",
    "ERROR": "unknown",
}


def _check_status_id(verdict: str) -> CheckStatusId:
    """Pass and fail have dedicated IDs; every other verdict is kept verbatim in ``status`` under Other."""
    if verdict == "pass":
        return 1
    if verdict == "fail":
        return 2
    if verdict == "unknown":
        return 0
    return 99


def _checked(model: BaseModel) -> BaseModel:
    """Validate against the pinned OCSF schema; a violation is a mapper bug and must surface."""
    validate_ocsf(model.model_dump(mode="json", exclude_none=True))
    return model


def _require(mapping: Mapping[str, Any], key: str, where: str) -> Any:
    value = mapping.get(key)
    if value is None or value == "":
        raise VendorContractError(f"Kubernetes {where} is missing {key!r}")
    return value


def _cluster(raw: Mapping[str, Any]) -> str:
    return _require(raw, "_cluster", "record")


def _received_ms(ctx: MapContext) -> int:
    return int(ctx.received_at.timestamp() * 1000)


def _activity_id(raw: Mapping[str, Any], where: str) -> Literal[1, 2, 3]:
    event = _require(raw, "_event", "record")
    activity_id = _ACTIVITY.get(event)
    if activity_id is None:
        raise VendorContractError(f"Kubernetes {where} event {event!r} is not supported")
    return activity_id


def _result_time_ms(result: Mapping[str, Any], ctx: MapContext) -> int:
    stamp = result.get("timestamp")
    if isinstance(stamp, Mapping) and isinstance(stamp.get("seconds"), int):
        return int(stamp["seconds"]) * 1000 + int(stamp.get("nanos", 0)) // 1_000_000
    return _received_ms(ctx)


def _resource_key(resource: Mapping[str, Any]) -> str:
    if resource.get("uid"):
        return str(resource["uid"])
    kind = resource.get("kind", "resource")
    namespace = resource.get("namespace", "")
    return f"{kind}/{namespace}/{_require(resource, 'name', 'resource')}"


def _resource_details(resource: Mapping[str, Any]) -> ResourceDetails:
    return ResourceDetails(
        uid=resource.get("uid") or None,
        name=resource.get("name") or None,
        type=resource.get("kind") or None,
        namespace=resource.get("namespace") or None,
    )


def _policy_findings(raw: Mapping[str, Any], ctx: MapContext) -> list[BaseModel]:
    """One compliance finding per PolicyReport result; the finding uid is stable across runs."""
    report = _require(raw, "object", "policy report")
    metadata = _require(report, "metadata", "policy report")
    report_uid = _require(metadata, "uid", "policy report metadata")
    cluster = _cluster(raw)
    activity_id = _activity_id(raw, "policy report")
    findings: list[BaseModel] = []
    for result in report.get("results") or []:
        policy = _require(result, "policy", "policy report result")
        rule = result.get("rule") or policy
        verdict = result.get("result") or "unknown"
        resources = [r for r in result.get("resources") or [] if isinstance(r, Mapping)]
        resource_key = _resource_key(resources[0]) if resources else "cluster"
        uid = f"{cluster}/{report_uid}/{policy}/{rule}/{resource_key}"
        findings.append(
            _checked(
                ComplianceFinding(
                    class_uid=2003,
                    category_uid=2,
                    activity_id=activity_id,
                    type_uid=2003 * 100 + activity_id,
                    time=_result_time_ms(result, ctx),
                    severity_id=_SEVERITY.get(str(result.get("severity") or "").lower(), 0),
                    severity=result.get("severity") or None,
                    metadata=Metadata(product=_PRODUCT, uid=report_uid),
                    cloud=Cloud(provider="kubernetes"),
                    osint=[],
                    message=result.get("message") or None,
                    finding_info=FindingInfo(
                        uid=uid,
                        title=f"{policy}/{rule}",
                        desc=result.get("message") or None,
                    ),
                    compliance=Compliance(
                        status=verdict,
                        status_id=_check_status_id(verdict),
                        control=rule,
                        category=result.get("category") or None,
                        standards=[policy],
                        checks=[
                            Check(
                                uid=f"{policy}/{rule}",
                                name=rule,
                                status=verdict,
                                severity=result.get("severity") or None,
                            )
                        ],
                    ),
                    resources=[_resource_details(r) for r in resources if r.get("name") or r.get("uid")] or None,
                )
            )
        )
    return findings


def _gatekeeper_findings(raw: Mapping[str, Any], ctx: MapContext) -> list[BaseModel]:
    """One fail finding per listed Gatekeeper violation, with no pass inferred from absence."""
    constraint = _require(raw, "object", "gatekeeper constraint record")
    metadata = _require(constraint, "metadata", "gatekeeper constraint")
    constraint_uid = _require(metadata, "uid", "gatekeeper constraint metadata")
    constraint_name = _require(metadata, "name", "gatekeeper constraint metadata")
    kind = _require(constraint, "kind", "gatekeeper constraint")
    cluster = _cluster(raw)
    activity_id = _activity_id(raw, "gatekeeper constraint")
    status = constraint.get("status") or {}
    audited = epoch_ms(status.get("auditTimestamp"))
    time = audited if audited is not None else _received_ms(ctx)
    findings: list[BaseModel] = []
    for violation in status.get("violations") or []:
        if not isinstance(violation, Mapping):
            raise VendorContractError("Kubernetes gatekeeper violation must be an object")
        violation_kind = _require(violation, "kind", "gatekeeper violation")
        violation_name = _require(violation, "name", "gatekeeper violation")
        namespace = violation.get("namespace") or None
        group = violation.get("group") or ""
        uid = f"{cluster}/{constraint_uid}/{group}/{violation_kind}/{namespace or ''}/{violation_name}"
        findings.append(
            _checked(
                ComplianceFinding(
                    class_uid=2003,
                    category_uid=2,
                    activity_id=activity_id,
                    type_uid=2003 * 100 + activity_id,
                    time=time,
                    severity_id=0,
                    metadata=Metadata(product=_PRODUCT, uid=constraint_uid),
                    cloud=Cloud(provider="kubernetes"),
                    osint=[],
                    message=violation.get("message") or None,
                    finding_info=FindingInfo(
                        uid=uid,
                        title=f"{kind}/{constraint_name}",
                        desc=violation.get("enforcementAction") or None,
                    ),
                    compliance=Compliance(
                        status="fail",
                        status_id=_check_status_id("fail"),
                        control=constraint_name,
                        category=None,
                        standards=[kind],
                        checks=[
                            Check(
                                uid=f"{kind}/{constraint_name}",
                                name=constraint_name,
                                status="fail",
                                severity=None,
                            )
                        ],
                    ),
                    resources=[
                        ResourceDetails(
                            uid=None,
                            name=violation_name,
                            type=violation_kind,
                            namespace=namespace,
                        )
                    ],
                )
            )
        )
    return findings


def _assessment_finding(
    raw: Mapping[str, Any],
    ctx: MapContext,
    obj: Mapping[str, Any],
    rule_id: str,
    field: str,
    verdict: str,
    standard: str,
    container: str | None = None,
) -> BaseModel:
    """Build one stable assessment finding without serializing the assessed object."""
    metadata = _require(obj, "metadata", "assessment object")
    object_uid = _require(metadata, "uid", "assessment object metadata")
    name = _require(metadata, "name", "assessment object metadata")
    namespace = metadata.get("namespace") or None
    kind = _require(obj, "kind", "assessment object")
    cluster = _cluster(raw)
    activity_id = _activity_id(raw, "assessment")
    uid = f"{cluster}/{object_uid}/{rule_id}"
    title = f"{kind}/{name}: {rule_id}"
    if container is not None:
        uid = f"{uid}/{container}"
        title = f"{kind}/{name}/{container}: {rule_id}"
    return _checked(
        ComplianceFinding(
            class_uid=2003,
            category_uid=2,
            activity_id=activity_id,
            type_uid=2003 * 100 + activity_id,
            time=_received_ms(ctx),
            severity_id=0,
            metadata=Metadata(product=_PRODUCT, uid=object_uid),
            cloud=Cloud(provider="kubernetes"),
            osint=[],
            message=field,
            finding_info=FindingInfo(uid=uid, title=title, desc=field),
            compliance=Compliance(
                status=verdict,
                status_id=_check_status_id(verdict),
                control=rule_id,
                category=container,
                standards=[standard],
                checks=[
                    Check(
                        uid=rule_id,
                        name=rule_id,
                        desc=field,
                        status=verdict,
                        status_id=_check_status_id(verdict),
                        standards=[standard],
                    )
                ],
            ),
            resources=[ResourceDetails(uid=object_uid, name=name, type=kind, namespace=namespace)],
        )
    )


def _unknown_workload_rules() -> list[tuple[str, str, str]]:
    return [(rule_id, "unknown", field) for rule_id, field in _WORKLOAD_RULE_FIELDS]


def _denied_boolean(value: Any, *, absent: str = "pass") -> str:
    if value is None:
        return absent
    if not isinstance(value, bool):
        return "unknown"
    return "fail" if value else "pass"


def _host_process_verdict(pod_sc: Mapping[str, Any], container_sc: Mapping[str, Any]) -> str:
    values: list[Any] = []
    for security_context in (pod_sc, container_sc):
        windows = security_context.get("windowsOptions")
        if windows is None:
            continue
        if not isinstance(windows, Mapping):
            return "unknown"
        values.append(windows.get("hostProcess"))
    if any(value is True for value in values):
        return "fail"
    if any(value is not None and not isinstance(value, bool) for value in values):
        return "unknown"
    return "pass"


def _host_path_verdict(pod_spec: Mapping[str, Any]) -> str:
    volumes = pod_spec.get("volumes")
    if volumes is None:
        return "pass"
    if not isinstance(volumes, list):
        return "unknown"
    for volume in volumes:
        if not isinstance(volume, Mapping):
            return "unknown"
        if volume.get("hostPath") is not None:
            return "fail"
    return "pass"


def _host_ports_verdict(container: Mapping[str, Any]) -> str:
    ports = container.get("ports")
    if ports is None:
        return "pass"
    if not isinstance(ports, list):
        return "unknown"
    for port in ports:
        if not isinstance(port, Mapping):
            return "unknown"
        host_port = port.get("hostPort")
        if host_port is None:
            continue
        if isinstance(host_port, bool) or not isinstance(host_port, int):
            return "unknown"
        if host_port == 0:
            continue
        return "fail"
    return "pass"


def _capabilities_add_verdict(capabilities: Mapping[str, Any] | None) -> str:
    if capabilities is None:
        return "pass"
    added = capabilities.get("add")
    if added is None:
        return "pass"
    if not isinstance(added, list) or any(not isinstance(item, str) for item in added):
        return "unknown"
    return "pass" if all(item in _ALLOWED_ADDED_CAPABILITIES for item in added) else "fail"


def _capabilities_drop_verdict(capabilities: Mapping[str, Any] | None, windows: bool) -> str:
    if windows:
        return "pass"
    if capabilities is None:
        return "unknown"
    dropped = capabilities.get("drop")
    if dropped is None:
        return "unknown"
    if not isinstance(dropped, list) or any(not isinstance(item, str) for item in dropped):
        return "unknown"
    return "pass" if "ALL" in dropped else "fail"


def _seccomp_verdict(pod_sc: Mapping[str, Any], container_sc: Mapping[str, Any], windows: bool) -> str:
    if windows:
        return "pass"
    profiles: list[Any] = []
    for security_context in (pod_sc, container_sc):
        profile = security_context.get("seccompProfile")
        if profile is None:
            profiles.append(None)
        elif not isinstance(profile, Mapping):
            return "unknown"
        else:
            profiles.append(profile.get("type"))
    profile_type = profiles[1] if profiles[1] is not None else profiles[0]
    if profile_type is None:
        return "unknown"
    if not isinstance(profile_type, str):
        return "unknown"
    if profile_type in {"RuntimeDefault", "Localhost"}:
        return "pass"
    if profile_type == "Unconfined":
        return "fail"
    return "unknown"


def _sysctls_verdict(pod_sc: Mapping[str, Any]) -> str:
    sysctls = pod_sc.get("sysctls")
    if sysctls is None:
        return "pass"
    if not isinstance(sysctls, list):
        return "unknown"
    for sysctl in sysctls:
        if not isinstance(sysctl, Mapping) or not isinstance(sysctl.get("name"), str):
            return "unknown"
        if sysctl["name"] not in _SAFE_SYSCTLS:
            return "fail"
    return "pass"


def _non_root_verdict(pod_sc: Mapping[str, Any], container_sc: Mapping[str, Any]) -> str:
    pod_non_root = pod_sc.get("runAsNonRoot")
    container_non_root = container_sc.get("runAsNonRoot")
    non_root = container_non_root if container_non_root is not None else pod_non_root
    pod_user = pod_sc.get("runAsUser")
    container_user = container_sc.get("runAsUser")
    run_as_user = container_user if container_user is not None else pod_user
    if non_root is not None and not isinstance(non_root, bool):
        return "unknown"
    if run_as_user is not None and (isinstance(run_as_user, bool) or not isinstance(run_as_user, int)):
        return "unknown"
    if run_as_user == 0 or non_root is False:
        return "fail"
    if non_root is True or (isinstance(run_as_user, int) and run_as_user > 0):
        return "pass"
    return "unknown"


# Every workload rule below implements the Baseline or cumulative Restricted control at
# https://kubernetes.io/docs/concepts/security/pod-security-standards/.
def _workload_rules(pod_spec: Mapping[str, Any], container: Mapping[str, Any]) -> list[tuple[str, str, str]]:
    pod_sc_value = pod_spec.get("securityContext")
    container_sc_value = container.get("securityContext")
    if pod_sc_value is not None and not isinstance(pod_sc_value, Mapping):
        return _unknown_workload_rules()
    if container_sc_value is not None and not isinstance(container_sc_value, Mapping):
        return _unknown_workload_rules()
    pod_sc = pod_sc_value or {}
    container_sc = container_sc_value or {}
    capabilities_value = container_sc.get("capabilities")
    if capabilities_value is not None and not isinstance(capabilities_value, Mapping):
        capabilities = None
        capabilities_verdict = "unknown"
    else:
        capabilities = capabilities_value
        capabilities_verdict = None
    windows = (pod_spec.get("os") or {}).get("name") == "windows" if isinstance(pod_spec.get("os"), Mapping) else False
    privilege_escalation = (
        "pass" if windows else _denied_boolean(container_sc.get("allowPrivilegeEscalation"), absent="unknown")
    )
    return [
        ("workload.privileged", _denied_boolean(container_sc.get("privileged")), "securityContext.privileged"),
        (
            "workload.host-process",
            _host_process_verdict(pod_sc, container_sc),
            "securityContext.windowsOptions.hostProcess",
        ),
        ("workload.host-network", _denied_boolean(pod_spec.get("hostNetwork")), "spec.hostNetwork"),
        ("workload.host-pid", _denied_boolean(pod_spec.get("hostPID")), "spec.hostPID"),
        ("workload.host-ipc", _denied_boolean(pod_spec.get("hostIPC")), "spec.hostIPC"),
        ("workload.host-path", _host_path_verdict(pod_spec), "spec.volumes[*].hostPath"),
        ("workload.host-ports", _host_ports_verdict(container), "containers[*].ports[*].hostPort"),
        (
            "workload.capabilities-add",
            capabilities_verdict or _capabilities_add_verdict(capabilities),
            "securityContext.capabilities.add",
        ),
        ("workload.seccomp", _seccomp_verdict(pod_sc, container_sc, windows), "securityContext.seccompProfile.type"),
        ("workload.sysctls", _sysctls_verdict(pod_sc), "spec.securityContext.sysctls[*].name"),
        (
            "workload.privilege-escalation",
            privilege_escalation,
            "securityContext.allowPrivilegeEscalation",
        ),
        (
            "workload.non-root",
            _non_root_verdict(pod_sc, container_sc),
            "securityContext.runAsNonRoot or securityContext.runAsUser",
        ),
        (
            "workload.capabilities-drop-all",
            capabilities_verdict or _capabilities_drop_verdict(capabilities, windows),
            "securityContext.capabilities.drop",
        ),
    ]


def _pod_spec(obj: Mapping[str, Any]) -> Mapping[str, Any] | None:
    kind = obj.get("kind")
    spec = obj.get("spec")
    if not isinstance(spec, Mapping):
        return None
    if kind == "Pod":
        return spec
    if kind in {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "ReplicationController", "Job"}:
        template = spec.get("template")
        if isinstance(template, Mapping) and isinstance(template.get("spec"), Mapping):
            return template["spec"]
        return None
    if kind == "CronJob":
        job_template = spec.get("jobTemplate")
        if not isinstance(job_template, Mapping) or not isinstance(job_template.get("spec"), Mapping):
            return None
        template = job_template["spec"].get("template")
        if isinstance(template, Mapping) and isinstance(template.get("spec"), Mapping):
            return template["spec"]
        return None
    raise VendorContractError(f"Kubernetes workload assessment does not support kind {kind!r}")


def _workload_containers(pod_spec: Mapping[str, Any]) -> list[tuple[str, Mapping[str, Any] | None]]:
    containers: list[tuple[str, Mapping[str, Any] | None]] = []
    for field in ("containers", "initContainers", "ephemeralContainers"):
        value = pod_spec.get(field)
        if value is None:
            continue
        if not isinstance(value, list):
            containers.append((f"<{field}>", None))
            continue
        for index, container in enumerate(value):
            if not isinstance(container, Mapping) or not isinstance(container.get("name"), str):
                containers.append((f"<{field}:{index}>", None))
            else:
                containers.append((container["name"], container))
    return containers or [("<pod>", None)]


def _workload_assessment(raw: Mapping[str, Any], ctx: MapContext) -> list[BaseModel]:
    obj = _require(raw, "object", "workload assessment record")
    pod_spec = _pod_spec(obj)
    containers = [("<pod>", None)] if pod_spec is None else _workload_containers(pod_spec)
    findings: list[BaseModel] = []
    for container_name, container in containers:
        if pod_spec is None or container is None:
            rules = _unknown_workload_rules()
        else:
            rules = _workload_rules(pod_spec, container)
        for rule_id, verdict, field in rules:
            findings.append(
                _assessment_finding(
                    raw,
                    ctx,
                    obj,
                    rule_id,
                    field,
                    verdict,
                    "Pod Security Standards Baseline and Restricted",
                    container_name,
                )
            )
    return findings


def _string_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _parsed_rbac_rules(obj: Mapping[str, Any]) -> list[Mapping[str, Any]] | None:
    rules = obj.get("rules")
    if not isinstance(rules, list):
        return None
    for rule in rules:
        if not isinstance(rule, Mapping) or not _string_list(rule.get("verbs")):
            return None
        resources = rule.get("resources")
        api_groups = rule.get("apiGroups")
        non_resource_urls = rule.get("nonResourceURLs")
        if resources is None and api_groups is None and non_resource_urls is not None:
            if not _string_list(non_resource_urls):
                return None
        elif not _string_list(resources) or not _string_list(api_groups):
            return None
    return rules


def _wildcard_verdict(rules: list[Mapping[str, Any]], field: str) -> str:
    return "fail" if any("*" in (rule.get(field) or []) for rule in rules) else "pass"


def _values_match(values: Any, expected: set[str]) -> bool:
    return isinstance(values, list) and ("*" in values or any(item in expected for item in values))


def _resource_verb_verdict(
    rules: list[Mapping[str, Any]],
    *,
    api_groups: set[str],
    resources: set[str],
    verbs: set[str],
) -> str:
    for rule in rules:
        if (
            _values_match(rule.get("apiGroups"), api_groups)
            and _values_match(rule.get("resources"), resources)
            and _values_match(rule.get("verbs"), verbs)
        ):
            return "fail"
    return "pass"


def _verb_verdict(rules: list[Mapping[str, Any]], verb: str) -> str:
    return "fail" if any(_values_match(rule.get("verbs"), {verb}) for rule in rules) else "pass"


def _parsed_subjects(obj: Mapping[str, Any]) -> list[Mapping[str, Any]] | None:
    subjects = obj.get("subjects")
    if subjects is None:
        return []
    if not isinstance(subjects, list):
        return None
    for subject in subjects:
        if (
            not isinstance(subject, Mapping)
            or not isinstance(subject.get("kind"), str)
            or not isinstance(subject.get("name"), str)
            or not subject["name"]
        ):
            return None
    return subjects


def _binding_verdict(subjects: list[Mapping[str, Any]], reserved_name: str) -> str:
    return "fail" if any(subject["name"] == reserved_name for subject in subjects) else "pass"


# Permission and reserved-subject risks are documented at
# https://kubernetes.io/docs/concepts/security/rbac-good-practices/.
# Resource and subresource verb shape, including create on pods/exec, is defined at
# https://kubernetes.io/docs/reference/access-authn-authz/rbac/.
# Anonymous requests use system:anonymous and system:unauthenticated as documented at
# https://kubernetes.io/docs/reference/access-authn-authz/authentication/#anonymous-requests.
# Binding permission checks stay unknown because a roleRef does not embed the referenced rules.
def _rbac_assessment(raw: Mapping[str, Any], ctx: MapContext) -> list[BaseModel]:
    obj = _require(raw, "object", "RBAC assessment record")
    kind = _require(obj, "kind", "RBAC assessment object")
    if kind not in {"Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding"}:
        raise VendorContractError(f"Kubernetes RBAC assessment does not support kind {kind!r}")
    is_binding = kind in {"RoleBinding", "ClusterRoleBinding"}
    rules = None if is_binding else _parsed_rbac_rules(obj)
    subjects = _parsed_subjects(obj) if is_binding else None
    permission_rules = [
        ("rbac.wildcard-verbs", "unknown" if rules is None else _wildcard_verdict(rules, "verbs"), "rules[*].verbs"),
        (
            "rbac.wildcard-resources",
            "unknown" if rules is None else _wildcard_verdict(rules, "resources"),
            "rules[*].resources",
        ),
        (
            "rbac.wildcard-api-groups",
            "unknown" if rules is None else _wildcard_verdict(rules, "apiGroups"),
            "rules[*].apiGroups",
        ),
        (
            "rbac.secrets-read",
            "unknown"
            if rules is None
            else _resource_verb_verdict(rules, api_groups={""}, resources={"secrets"}, verbs={"get", "list", "watch"}),
            "rules[*] get/list/watch on core secrets",
        ),
        ("rbac.escalate", "unknown" if rules is None else _verb_verdict(rules, "escalate"), "rules[*].verbs escalate"),
        ("rbac.bind", "unknown" if rules is None else _verb_verdict(rules, "bind"), "rules[*].verbs bind"),
        (
            "rbac.impersonate",
            "unknown" if rules is None else _verb_verdict(rules, "impersonate"),
            "rules[*].verbs impersonate",
        ),
        (
            "rbac.pods-create",
            "unknown"
            if rules is None
            else _resource_verb_verdict(rules, api_groups={""}, resources={"pods"}, verbs={"create"}),
            "rules[*] create on core pods",
        ),
        (
            "rbac.pods-exec",
            "unknown"
            if rules is None
            else _resource_verb_verdict(rules, api_groups={""}, resources={"pods/exec"}, verbs={"create"}),
            "rules[*] create on core pods/exec",
        ),
        (
            "rbac.pods-attach",
            "unknown"
            if rules is None
            else _resource_verb_verdict(rules, api_groups={""}, resources={"pods/attach"}, verbs={"create"}),
            "rules[*] create on core pods/attach",
        ),
        (
            "rbac.nodes-proxy",
            "unknown"
            if rules is None
            else _resource_verb_verdict(rules, api_groups={""}, resources={"nodes/proxy"}, verbs={"get"}),
            "rules[*] get on core nodes/proxy",
        ),
    ]
    if not is_binding:
        anonymous = "unknown"
        unauthenticated = "unknown"
    elif subjects is None:
        anonymous = "unknown"
        unauthenticated = "unknown"
    else:
        anonymous = _binding_verdict(subjects, "system:anonymous")
        unauthenticated = _binding_verdict(subjects, "system:unauthenticated")
    permission_rules.extend(
        [
            ("rbac.system-anonymous-binding", anonymous, "subjects[*].name system:anonymous"),
            (
                "rbac.system-unauthenticated-binding",
                unauthenticated,
                "subjects[*].name system:unauthenticated",
            ),
        ]
    )
    return [
        _assessment_finding(raw, ctx, obj, rule_id, field, verdict, "Kubernetes RBAC good practices")
        for rule_id, verdict, field in permission_rules
    ]


# Route TLS fields and insecure edge behavior are defined at
# https://docs.openshift.com/container-platform/latest/networking/routes/route-configuration.html
# and https://docs.okd.io/latest/rest_api/network_apis/route-route-openshift-io-v1.html.
# The assessed object is never serialized, so tls.key, tls.certificate, and tls.caCertificate
# values cannot enter finding evidence.
def _route_assessment(raw: Mapping[str, Any], ctx: MapContext) -> list[BaseModel]:
    obj = _require(raw, "object", "Route assessment record")
    if obj.get("kind") != "Route":
        raise VendorContractError("OpenShift route_assessment object must be a Route")
    spec = obj.get("spec")
    tls = spec.get("tls") if isinstance(spec, Mapping) else None
    termination = tls.get("termination") if isinstance(tls, Mapping) else None
    tls_verdict = "pass" if termination in {"edge", "reencrypt", "passthrough"} else "fail"
    if termination not in {"edge", "reencrypt", "passthrough"} or not isinstance(tls, Mapping):
        insecure_verdict = "unknown"
    else:
        policy = tls.get("insecureEdgeTerminationPolicy")
        if policy is None:
            policy = "None"
        if policy == "Allow":
            insecure_verdict = "fail"
        elif policy in {"None", "Redirect"}:
            insecure_verdict = "pass"
        else:
            insecure_verdict = "unknown"
    return [
        _assessment_finding(
            raw,
            ctx,
            obj,
            "route.tls-required",
            "spec.tls.termination",
            tls_verdict,
            "OpenShift Route",
        ),
        _assessment_finding(
            raw,
            ctx,
            obj,
            "route.insecure-edge-not-allowed",
            "spec.tls.insecureEdgeTerminationPolicy",
            insecure_verdict,
            "OpenShift Route",
        ),
    ]


def _scc_strategy_verdict(scc: Mapping[str, Any]) -> str:
    strategy = scc.get("runAsUser")
    if not isinstance(strategy, Mapping):
        return "unknown"
    strategy_type = strategy.get("type")
    if strategy_type == "RunAsAny":
        return "fail"
    if strategy_type in {"MustRunAs", "MustRunAsRange", "MustRunAsNonRoot"}:
        return "pass"
    return "unknown"


def _scc_list_verdict(scc: Mapping[str, Any], field: str) -> str:
    values = scc.get(field)
    if values is None:
        return "unknown"
    if not _string_list(values):
        return "unknown"
    return "fail" if "*" in values else "pass"


# SCC boolean defaults, RunAsUser strategies, volume wildcard, and capability controls are
# documented at https://docs.openshift.com/container-platform/latest/authentication/managing-security-context-constraints.html.
def _scc_assessment(raw: Mapping[str, Any], ctx: MapContext) -> list[BaseModel]:
    obj = _require(raw, "object", "SCC assessment record")
    if obj.get("kind") != "SecurityContextConstraints":
        raise VendorContractError("OpenShift scc_assessment object must be SecurityContextConstraints")
    rules = [
        ("scc.privileged-denied", _denied_boolean(obj.get("allowPrivilegedContainer")), "allowPrivilegedContainer"),
        (
            "scc.privilege-escalation-denied",
            _denied_boolean(obj.get("allowPrivilegeEscalation")),
            "allowPrivilegeEscalation",
        ),
        ("scc.host-network-denied", _denied_boolean(obj.get("allowHostNetwork")), "allowHostNetwork"),
        ("scc.host-pid-denied", _denied_boolean(obj.get("allowHostPID")), "allowHostPID"),
        ("scc.host-ipc-denied", _denied_boolean(obj.get("allowHostIPC")), "allowHostIPC"),
        (
            "scc.host-dir-denied",
            _denied_boolean(obj.get("allowHostDirVolumePlugin")),
            "allowHostDirVolumePlugin",
        ),
        ("scc.run-as-user-restricted", _scc_strategy_verdict(obj), "runAsUser.type"),
        ("scc.no-wildcard-volumes", _scc_list_verdict(obj, "volumes"), "volumes[*]"),
        (
            "scc.no-wildcard-capabilities",
            _scc_list_verdict(obj, "allowedCapabilities"),
            "allowedCapabilities[*]",
        ),
    ]
    return [
        _assessment_finding(raw, ctx, obj, rule_id, field, verdict, "OpenShift SecurityContextConstraints")
        for rule_id, verdict, field in rules
    ]


def _compliance_result(raw: Mapping[str, Any], ctx: MapContext) -> list[BaseModel]:
    """Map exactly one CCR, retaining only documented typed check evidence."""
    obj = _require(raw, "object", "ComplianceCheckResult record")
    if obj.get("kind") != "ComplianceCheckResult":
        raise VendorContractError("OpenShift compliance_result object must be a ComplianceCheckResult")
    metadata = _require(obj, "metadata", "ComplianceCheckResult")
    object_uid = _require(metadata, "uid", "ComplianceCheckResult metadata")
    name = _require(metadata, "name", "ComplianceCheckResult metadata")
    namespace = metadata.get("namespace") or None
    annotations = metadata.get("annotations") if isinstance(metadata.get("annotations"), Mapping) else {}
    labels = metadata.get("labels") if isinstance(metadata.get("labels"), Mapping) else {}
    check_id = obj.get("id") if isinstance(obj.get("id"), str) and obj.get("id") else name
    rule_name = annotations.get("compliance.openshift.io/rule") or check_id
    scan_name = labels.get("compliance.openshift.io/scan-name") or None
    severity = obj.get("severity") if isinstance(obj.get("severity"), str) else None
    instructions = obj.get("instructions") if isinstance(obj.get("instructions"), str) else None
    vendor_status = obj.get("status") if isinstance(obj.get("status"), str) else "UNKNOWN"
    verdict = _COMPLIANCE_STATUSES.get(vendor_status, "unknown")
    activity_id = _activity_id(raw, "ComplianceCheckResult")
    finding = ComplianceFinding(
        class_uid=2003,
        category_uid=2,
        activity_id=activity_id,
        type_uid=2003 * 100 + activity_id,
        time=_received_ms(ctx),
        severity_id=_SEVERITY.get((severity or "").lower(), 0),
        severity=severity,
        metadata=Metadata(product=_PRODUCT, uid=object_uid),
        cloud=Cloud(provider="kubernetes"),
        osint=[],
        finding_info=FindingInfo(
            uid=f"{_cluster(raw)}/{object_uid}/compliance-result",
            title=rule_name,
            desc=None,
        ),
        compliance=Compliance(
            status=verdict,
            status_id=_check_status_id(verdict),
            status_code=vendor_status,
            control=rule_name,
            category=scan_name,
            standards=["OpenShift Compliance Operator"],
            checks=[
                Check(
                    uid=check_id,
                    name=rule_name,
                    desc=instructions,
                    severity=severity,
                    status=verdict,
                    status_id=_check_status_id(verdict),
                    standards=["OpenShift Compliance Operator"],
                )
            ],
        ),
        resources=[
            ResourceDetails(
                uid=object_uid,
                name=name,
                type="ComplianceCheckResult",
                namespace=namespace,
            )
        ],
    )
    return [_checked(finding)]


def _coverage(raw: Mapping[str, Any], ctx: MapContext) -> SourceRecord:
    partition = _require(raw, "_partition", "coverage record")
    cluster = _cluster(raw)
    coverage = raw.get("_coverage") or {}
    subject = coverage.get("subject") or None
    uid = f"{cluster}/{partition}/coverage" + (f"/{subject}" if subject else "")
    return SourceRecord(
        record_type="coverage",
        uid=uid,
        data={
            "cluster": cluster,
            "partition": partition,
            "reason": coverage.get("reason") or "unknown",
            "subject": subject,
            "observed_at": ctx.received_at.isoformat(),
        },
    )


def _inventory(raw: Mapping[str, Any], ctx: MapContext) -> SourceRecord:
    """Inventory has no OCSF class in the vendored schema; the record carries a complete 5001-shaped document."""
    obj = _require(raw, "object", "inventory record")
    metadata = _require(obj, "metadata", "inventory object")
    object_uid = _require(metadata, "uid", "inventory object metadata")
    partition = _require(raw, "_partition", "inventory record")
    cluster = _cluster(raw)
    event = _require(raw, "_event", "record")
    activity_id = _ACTIVITY.get(event)
    if activity_id is None:
        raise VendorContractError(f"Kubernetes inventory event {event!r} is not supported")
    resource_type = partition.split("@", 1)[0].rsplit("/", 1)[-1]
    name = metadata.get("name") or object_uid
    namespace = metadata.get("namespace") or None
    document: dict[str, Any] = {
        "class_uid": _INVENTORY_CLASS_UID,
        "category_uid": _INVENTORY_CATEGORY_UID,
        "activity_id": activity_id,
        "type_uid": _INVENTORY_CLASS_UID * 100 + activity_id,
        "time": _received_ms(ctx),
        "metadata": {
            "version": "1.9.0",
            "product": {"name": _PRODUCT.name, "vendor_name": _PRODUCT.vendor_name},
            "uid": object_uid,
        },
        "cloud": {"provider": "kubernetes"},
        "resources": [
            {
                "uid": object_uid,
                "name": name,
                "type": resource_type,
                "namespace": namespace,
                "labels": [f"{k}={v}" for k, v in (metadata.get("labels") or {}).items()],
            }
        ],
        "unmapped": {"cluster": cluster, "partition": partition, "event": event},
    }
    revision = metadata.get("resourceVersion")
    return SourceRecord(
        record_type="resource_inventory",
        uid=f"{cluster}/{partition.split('@', 1)[0]}/{object_uid}",
        revision=str(revision) if revision is not None else None,
        data=document,
    )


def _object_identity(obj: Mapping[str, Any], where: str) -> tuple[str, dict[str, Any], str]:
    metadata = _require(obj, "metadata", where)
    object_uid = _require(metadata, "uid", f"{where} metadata")
    name = _require(metadata, "name", f"{where} metadata")
    kind = _require(obj, "kind", where)
    data = {
        "kind": kind,
        "name": name,
        "namespace": metadata.get("namespace") or None,
        "uid": object_uid,
        "resourceVersion": metadata.get("resourceVersion") or None,
    }
    return object_uid, data, kind


def _image_stream_tags(obj: Mapping[str, Any]) -> list[dict[str, Any]]:
    status = obj.get("status")
    tags = status.get("tags") if isinstance(status, Mapping) else None
    if tags is None:
        return []
    if not isinstance(tags, list):
        raise VendorContractError("OpenShift ImageStream status.tags must be a list")
    observed: list[dict[str, Any]] = []
    for tag in tags:
        if (
            not isinstance(tag, Mapping)
            or not isinstance(tag.get("tag"), str)
            or not isinstance(tag.get("items"), list)
        ):
            raise VendorContractError("OpenShift ImageStream tag entries must contain tag and items")
        for item in tag["items"]:
            if not isinstance(item, Mapping):
                raise VendorContractError("OpenShift ImageStream tag event must be an object")
            observed.append({"tag": tag["tag"], "image": item.get("image"), "created": item.get("created")})
    return observed


def _openshift_inventory(raw: Mapping[str, Any]) -> SourceRecord:
    obj = _require(raw, "object", "OpenShift inventory record")
    object_uid, data, kind = _object_identity(obj, "OpenShift inventory object")
    if kind == "ImageStream":
        data["tags"] = _image_stream_tags(obj)
    elif kind == "Image":
        data["digest"] = data["name"]
    return SourceRecord(
        record_type="openshift_inventory",
        uid=f"{_cluster(raw)}/{kind}/{object_uid}",
        revision=data["resourceVersion"],
        data=data,
    )


def _project(raw: Mapping[str, Any]) -> SourceRecord:
    obj = _require(raw, "object", "Project record")
    if obj.get("kind") != "Project":
        raise VendorContractError("OpenShift project record object must be a Project")
    object_uid, data, kind = _object_identity(obj, "Project object")
    status = obj.get("status")
    data["phase"] = status.get("phase") if isinstance(status, Mapping) else None
    return SourceRecord(
        record_type="project",
        uid=f"{_cluster(raw)}/{kind}/{object_uid}",
        revision=data["resourceVersion"],
        data=data,
    )


def _compliance_scan_status(raw: Mapping[str, Any]) -> SourceRecord:
    obj = _require(raw, "object", "compliance scan status record")
    kind = _require(obj, "kind", "compliance scan status object")
    if kind not in {"ComplianceScan", "ComplianceSuite"}:
        raise VendorContractError("OpenShift compliance_scan_status object must be a ComplianceScan or ComplianceSuite")
    object_uid, data, _ = _object_identity(obj, "compliance scan status object")
    status = obj.get("status")
    status = status if isinstance(status, Mapping) else {}
    data["phase"] = status.get("phase") or status.get("Phase")
    data["result"] = status.get("result") or status.get("Result")
    if kind == "ComplianceSuite":
        scan_statuses = status.get("scanStatuses")
        if scan_statuses is not None:
            if not isinstance(scan_statuses, list) or any(
                not isinstance(item, Mapping) or not isinstance(item.get("name"), str) for item in scan_statuses
            ):
                raise VendorContractError("OpenShift ComplianceSuite status.scanStatuses must contain named scans")
            data["scan_names"] = [item["name"] for item in scan_statuses]
        else:
            spec = obj.get("spec")
            scans = spec.get("scans") if isinstance(spec, Mapping) else None
            if scans is None:
                data["scan_names"] = []
            elif not isinstance(scans, list) or any(
                not isinstance(item, Mapping) or not isinstance(item.get("name"), str) for item in scans
            ):
                raise VendorContractError("OpenShift ComplianceSuite spec.scans must contain named scans")
            else:
                data["scan_names"] = [item["name"] for item in scans]
    return SourceRecord(
        record_type="compliance_scan_status",
        uid=f"{_cluster(raw)}/{kind}/{object_uid}",
        revision=data["resourceVersion"],
        data=data,
    )


def _audit_event(raw: Mapping[str, Any]) -> list[BaseModel]:
    """One OCSF API Activity per audit event, keyed by API source, auditID, and stage."""
    source = _require(raw, "_api_source", "audit record")
    audit_id = _require(raw, "auditID", "audit record")
    stage = _require(raw, "stage", "audit record")
    dedupe = _require(raw, "_dedupe_key", "audit record")
    if dedupe != f"{source}:{audit_id}:{stage}":
        raise VendorContractError("Kubernetes audit _dedupe_key does not match its API source, auditID, and stage")
    verb = _require(raw, "verb", "audit record")
    received = epoch_ms(_require(raw, "requestReceivedTimestamp", "audit record"))
    if received is None:
        raise VendorContractError("Kubernetes audit requestReceivedTimestamp must be a timestamp")
    user = _require(raw, "user", "audit record")
    username = _require(user, "username", "audit user")
    source_ips = raw.get("sourceIPs")
    if not isinstance(source_ips, list) or not source_ips or not isinstance(source_ips[0], str):
        raise VendorContractError("Kubernetes audit record has no source IP")
    object_ref = raw.get("objectRef")
    resources: list[ResourceDetails] | None = None
    if isinstance(object_ref, Mapping) and (object_ref.get("name") or object_ref.get("uid")):
        resources = [
            ResourceDetails(
                uid=object_ref.get("uid") or None,
                name=object_ref.get("name") or None,
                type=object_ref.get("resource") or None,
                namespace=object_ref.get("namespace") or None,
            )
        ]
    return [
        _checked(
            ApiActivity(
                type_uid=ApiActivity.CLASS_UID * 100 + _ACTIVITY_OTHER,
                activity_id=_ACTIVITY_OTHER,
                severity_id=0,
                time=received,
                metadata=Metadata(product=_PRODUCT, uid=dedupe),
                cloud=Cloud(provider="kubernetes"),
                osint=[],
                actor=Actor(user=User(name=username, uid=user.get("uid") or None)),
                api=Api(operation=verb),
                src_endpoint=NetworkEndpoint(ip=source_ips[0]),
                resources=resources,
                raw_data=bounded_raw(dict(raw)),
            )
        )
    ]


def map_record(
    _connector,
    stream_name: str,
    raw: dict[str, Any],
    ctx: MapContext,
) -> list[BaseModel]:
    """Dispatch on the record kind the stream emitted, never on the vendor object's shape."""
    record_kind = _require(raw, "_record_kind", "record")
    streams = RECORD_STREAMS.get(record_kind)
    if streams is None:
        raise VendorContractError(f"unsupported Kubernetes record kind {record_kind!r}")
    if stream_name not in streams:
        raise VendorContractError(f"record kind {record_kind!r} does not belong to stream {stream_name!r}")
    if raw.get("_partial_coverage"):
        return [_coverage(raw, ctx)]
    if record_kind == "policy_report":
        return _policy_findings(raw, ctx)
    if record_kind == "gatekeeper_constraint":
        return _gatekeeper_findings(raw, ctx)
    if record_kind == "resource_inventory":
        return [_inventory(raw, ctx)]
    if record_kind == "workload_assessment":
        return _workload_assessment(raw, ctx)
    if record_kind == "rbac_assessment":
        return _rbac_assessment(raw, ctx)
    if record_kind == "openshift_inventory":
        return [_openshift_inventory(raw)]
    if record_kind == "project":
        return [_project(raw)]
    if record_kind == "route_assessment":
        return _route_assessment(raw, ctx)
    if record_kind == "scc_assessment":
        return _scc_assessment(raw, ctx)
    if record_kind == "compliance_result":
        return _compliance_result(raw, ctx)
    if record_kind == "compliance_scan_status":
        return [_compliance_scan_status(raw)]
    return _audit_event(raw)
