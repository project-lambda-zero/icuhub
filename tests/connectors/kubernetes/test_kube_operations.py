"""RouteTransport coverage for every Kubernetes and OpenShift read operation."""

from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Literal

import pytest

from icuhub.connectors._kube.operations import KUBERNETES_OPERATIONS, OPENSHIFT_OPERATIONS
from icuhub.connectors.kubernetes import Kubernetes
from icuhub.connectors.openshift import OpenShift
from icuhub.kit.connector import Connector
from icuhub.kit.testing import RouteTransport, make_connector

BASE = {
    "base_url": "https://api.example.test",
    "cluster_name": "prod",
    "bearer_token": {"ref": "cluster-token"},
}
SECRETS = {"cluster-token": b"token"}
Routes = dict[tuple[str, str], Any]


@dataclass(frozen=True)
class _Resource:
    group: str
    version: str
    name: str
    kind: str


@dataclass(frozen=True)
class _Case:
    edition: type[Connector]
    name: str
    args: dict[str, Any]
    resources: tuple[_Resource, ...] = ()
    responses: Routes = field(default_factory=dict)
    config: dict[str, Any] = field(default_factory=dict)
    denied: Literal["discovery", "version", "sar", "arf"] = "discovery"


PODS = _Resource("", "v1", "pods", "Pod")
POLICY_REPORTS = _Resource("wgpolicyk8s.io", "v1alpha2", "policyreports", "PolicyReport")
GATEKEEPER = _Resource("constraints.gatekeeper.sh", "v1beta1", "k8srequiredlabels", "K8sRequiredLabels")
CLUSTER_VERSIONS = _Resource("config.openshift.io", "v1", "clusterversions", "ClusterVersion")
PROJECTS = _Resource("project.openshift.io", "v1", "projects", "Project")
ROUTES = _Resource("route.openshift.io", "v1", "routes", "Route")
SCCS = _Resource("security.openshift.io", "v1", "securitycontextconstraints", "SecurityContextConstraints")
BUILDCONFIGS = _Resource("build.openshift.io", "v1", "buildconfigs", "BuildConfig")
BUILDS = _Resource("build.openshift.io", "v1", "builds", "Build")
IMAGESTREAMS = _Resource("image.openshift.io", "v1", "imagestreams", "ImageStream")
IMAGESTREAMTAGS = _Resource("image.openshift.io", "v1", "imagestreamtags", "ImageStreamTag")
IMAGES = _Resource("image.openshift.io", "v1", "images", "Image")
COMPLIANCE_RESULTS = _Resource("compliance.openshift.io", "v1alpha1", "compliancecheckresults", "ComplianceCheckResult")
COMPLIANCE_SCANS = _Resource("compliance.openshift.io", "v1alpha1", "compliancescans", "ComplianceScan")
COMPLIANCE_SUITES = _Resource("compliance.openshift.io", "v1alpha1", "compliancesuites", "ComplianceSuite")
USERS = _Resource("user.openshift.io", "v1", "users", "User")
GROUPS = _Resource("user.openshift.io", "v1", "groups", "Group")


def _ok(body: Any, status: int = 200) -> dict[str, Any]:
    return {"status": status, "json": body}


def _forbidden() -> dict[str, Any]:
    return _ok({"message": "forbidden"}, status=403)


def _object(resource: _Resource, name: str = "sample", **fields: Any) -> dict[str, Any]:
    api_version = resource.version if not resource.group else f"{resource.group}/{resource.version}"
    return {
        "apiVersion": api_version,
        "kind": resource.kind,
        "metadata": {"uid": f"uid-{name}", "name": name, "resourceVersion": "7"},
        **fields,
    }


def _list(resource: _Resource, **fields: Any) -> dict[str, Any]:
    return {"metadata": {"resourceVersion": "10"}, "items": [_object(resource, **fields)]}


def _discovery_routes(*resources: _Resource) -> Routes:
    core_versions = sorted({resource.version for resource in resources if not resource.group})
    grouped: dict[str, set[str]] = {}
    for resource in resources:
        if resource.group:
            grouped.setdefault(resource.group, set()).add(resource.version)
    routes: Routes = {
        ("GET", "/api"): _ok({"versions": core_versions}),
        ("GET", "/apis"): _ok(
            {
                "groups": [
                    {
                        "name": group,
                        "versions": [{"version": version} for version in sorted(versions)],
                    }
                    for group, versions in sorted(grouped.items())
                ]
            }
        ),
    }
    for version in core_versions:
        entries = [resource for resource in resources if not resource.group and resource.version == version]
        routes[("GET", f"/api/{version}")] = _ok(
            {
                "resources": [
                    {"name": resource.name, "kind": resource.kind, "namespaced": True, "verbs": ["get", "list"]}
                    for resource in entries
                ]
            }
        )
    for group, versions in grouped.items():
        for version in sorted(versions):
            entries = [
                resource
                for resource in resources
                if resource.group == group and resource.version == version
            ]
            routes[("GET", f"/apis/{group}/{version}")] = _ok(
                {
                    "resources": [
                        {
                            "name": resource.name,
                            "kind": resource.kind,
                            "namespaced": True,
                            "verbs": ["get", "list", "watch"],
                        }
                        for resource in entries
                    ]
                }
            )
    return routes


def _case(
    edition: type[Connector],
    name: str,
    args: dict[str, Any],
    resource: _Resource | None,
    path: str | None,
    body: dict[str, Any] | None,
    **overrides: Any,
) -> _Case:
    resources = () if resource is None else (resource,)
    responses = {} if path is None or body is None else {("GET", path): _ok(body)}
    return _Case(edition, name, args, resources=resources, responses=responses, **overrides)


OBJECT_CASES = [
    _case(
        Kubernetes,
        "get_resource",
        {"version": "v1", "resource": "pods", "kind": "Pod", "namespace": "default", "name": "web"},
        PODS,
        "/api/v1/namespaces/default/pods/web",
        _object(PODS, "web"),
    ),
    _case(
        Kubernetes,
        "get_policy_report",
        {
            "group": "wgpolicyk8s.io",
            "version": "v1alpha2",
            "resource": "policyreports",
            "namespace": "default",
            "name": "baseline",
        },
        POLICY_REPORTS,
        "/apis/wgpolicyk8s.io/v1alpha2/namespaces/default/policyreports/baseline",
        _object(POLICY_REPORTS, "baseline"),
    ),
    _case(
        Kubernetes,
        "get_gatekeeper_constraint",
        {"kind": "K8sRequiredLabels", "name": "require-owner"},
        GATEKEEPER,
        "/apis/constraints.gatekeeper.sh/v1beta1/k8srequiredlabels/require-owner",
        _object(GATEKEEPER, "require-owner"),
    ),
    _case(
        OpenShift,
        "get_cluster_version",
        {},
        CLUSTER_VERSIONS,
        "/apis/config.openshift.io/v1/clusterversions/version",
        _object(CLUSTER_VERSIONS, "version"),
    ),
    _case(
        OpenShift,
        "get_project",
        {"name": "default"},
        PROJECTS,
        "/apis/project.openshift.io/v1/projects/default",
        _object(PROJECTS, "default"),
    ),
    _case(
        OpenShift,
        "get_route",
        {"name": "web", "namespace": "default"},
        ROUTES,
        "/apis/route.openshift.io/v1/namespaces/default/routes/web",
        _object(ROUTES, "web", spec={"host": "web.example.test"}, status={"ingress": []}),
    ),
    _case(
        OpenShift,
        "get_scc",
        {"name": "restricted"},
        SCCS,
        "/apis/security.openshift.io/v1/securitycontextconstraints/restricted",
        _object(SCCS, "restricted"),
    ),
    _case(
        OpenShift,
        "get_buildconfig",
        {"name": "web", "namespace": "default"},
        BUILDCONFIGS,
        "/apis/build.openshift.io/v1/namespaces/default/buildconfigs/web",
        _object(BUILDCONFIGS, "web"),
    ),
    _case(
        OpenShift,
        "get_build",
        {"name": "web-1", "namespace": "default"},
        BUILDS,
        "/apis/build.openshift.io/v1/namespaces/default/builds/web-1",
        _object(BUILDS, "web-1"),
    ),
    _case(
        OpenShift,
        "get_imagestream",
        {"name": "web", "namespace": "default"},
        IMAGESTREAMS,
        "/apis/image.openshift.io/v1/namespaces/default/imagestreams/web",
        _object(IMAGESTREAMS, "web"),
    ),
    _case(
        OpenShift,
        "get_imagestream_tag",
        {"imagestream": "web", "tag": "latest", "namespace": "default"},
        IMAGESTREAMTAGS,
        "/apis/image.openshift.io/v1/namespaces/default/imagestreamtags/web:latest",
        _object(IMAGESTREAMTAGS, "web:latest"),
    ),
]

LIST_CASES = [
    _case(
        Kubernetes,
        "list_resources",
        {"version": "v1", "resource": "pods", "kind": "Pod", "namespace": "default"},
        PODS,
        "/api/v1/namespaces/default/pods",
        _list(PODS),
    ),
    _case(OpenShift, "list_projects", {}, PROJECTS, "/apis/project.openshift.io/v1/projects", _list(PROJECTS)),
    _case(
        OpenShift,
        "list_routes",
        {"namespace": "default"},
        ROUTES,
        "/apis/route.openshift.io/v1/namespaces/default/routes",
        _list(ROUTES, spec={"host": "web.example.test"}, status={"ingress": []}),
    ),
    _case(OpenShift, "list_sccs", {}, SCCS, "/apis/security.openshift.io/v1/securitycontextconstraints", _list(SCCS)),
    _case(OpenShift, "list_images", {}, IMAGES, "/apis/image.openshift.io/v1/images", _list(IMAGES)),
    _case(
        OpenShift,
        "list_imagestreams",
        {"namespace": "default"},
        IMAGESTREAMS,
        "/apis/image.openshift.io/v1/namespaces/default/imagestreams",
        _list(IMAGESTREAMS),
    ),
    _case(
        OpenShift,
        "list_compliance_scans",
        {"namespace": "default"},
        COMPLIANCE_SCANS,
        "/apis/compliance.openshift.io/v1alpha1/namespaces/default/compliancescans",
        _list(COMPLIANCE_SCANS, status={"phase": "DONE"}),
    ),
]

WATCH_PATH = "/api/v1/namespaces/default/pods"
WATCH_EVENT = json.dumps({"type": "ADDED", "object": _object(PODS, "web")}).encode("utf-8")
SAR_PATH = "/apis/authorization.k8s.io/v1/subjectaccessreviews"
ARF_PATH = "/apis/compliance.openshift.io/v1alpha1/namespaces/default/arf/report"

SPECIAL_CASES = [
    _Case(Kubernetes, "list_api_resources", {}, resources=(PODS,)),
    _Case(
        Kubernetes,
        "get_openapi_schema",
        {},
        responses={("GET", "/openapi/v3"): _ok({"paths": {}})},
    ),
    _Case(
        Kubernetes,
        "get_server_version",
        {},
        responses={("GET", "/version"): _ok({"gitVersion": "v1.30.2"})},
        denied="version",
    ),
    _Case(
        Kubernetes,
        "get_subject_access_review",
        {"user": "reader", "verb": "get", "version": "v1", "resource": "pods"},
        responses={("POST", SAR_PATH): _ok({"status": {"allowed": True, "denied": False}})},
        config={"subject_access_review_enabled": True},
        denied="sar",
    ),
    _Case(
        Kubernetes,
        "watch_resource",
        {"version": "v1", "resource": "pods", "kind": "Pod", "namespace": "default"},
        resources=(PODS,),
        responses={("GET", WATCH_PATH): {"status": 200, "content": WATCH_EVENT}},
    ),
    _Case(
        OpenShift,
        "list_compliance_results",
        {"namespace": "default"},
        resources=(COMPLIANCE_RESULTS, COMPLIANCE_SCANS, COMPLIANCE_SUITES),
        responses={
            (
                "GET",
                "/apis/compliance.openshift.io/v1alpha1/namespaces/default/compliancecheckresults",
            ): _ok(_list(COMPLIANCE_RESULTS, status="PASS")),
            (
                "GET",
                "/apis/compliance.openshift.io/v1alpha1/namespaces/default/compliancescans",
            ): _ok(_list(COMPLIANCE_SCANS, status={"phase": "DONE"})),
            (
                "GET",
                "/apis/compliance.openshift.io/v1alpha1/namespaces/default/compliancesuites",
            ): _ok(_list(COMPLIANCE_SUITES, status={"phase": "DONE"})),
        },
    ),
    _Case(
        OpenShift,
        "list_users_groups",
        {},
        resources=(USERS, GROUPS),
        responses={
            ("GET", "/apis/user.openshift.io/v1/users"): _ok(_list(USERS)),
            ("GET", "/apis/user.openshift.io/v1/groups"): _ok(_list(GROUPS)),
        },
        config={"include_users_groups": True},
    ),
    _Case(
        OpenShift,
        "get_raw_arf",
        {"path": ARF_PATH},
        responses={
            ("GET", ARF_PATH): {
                "status": 200,
                "content": b"<arf>evidence</arf>",
                "headers": {"content-type": "application/xml"},
            }
        },
        config={"raw_arf_enabled": True},
        denied="arf",
    ),
]

CASES = [*OBJECT_CASES, *LIST_CASES, *SPECIAL_CASES]


def test_operation_case_matrix_covers_every_declared_operation() -> None:
    declared = {operation.__name__ for operation in (*KUBERNETES_OPERATIONS, *OPENSHIFT_OPERATIONS)}
    assert len(CASES) == len(declared)
    assert {case.name for case in CASES} == declared


def _routes(case: _Case) -> Routes:
    return {**_discovery_routes(*case.resources), **case.responses}


def _denied_routes(case: _Case) -> Routes:
    if case.denied == "discovery":
        return {("GET", "/api"): _forbidden()}
    if case.denied == "version":
        return {("GET", "/version"): _forbidden()}
    if case.denied == "sar":
        return {("POST", SAR_PATH): _forbidden()}
    return {("GET", ARF_PATH): _forbidden()}


def _connector(case: _Case, routes: Routes, **config: Any) -> tuple[Connector, RouteTransport]:
    transport = RouteTransport(routes)
    connector = make_connector(case.edition, {**BASE, **case.config, **config}, transport, SECRETS)
    return connector, transport


def _invoke(connector: Connector, name: str, args: dict[str, Any]) -> Any:
    spec = connector.operations()[name]
    parsed = spec.input_model.model_validate(args)
    return asyncio.run(spec.fn(connector, parsed))


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.name)
def test_read_operation_happy_path(case: _Case) -> None:
    connector, transport = _connector(case, _routes(case))
    result = _invoke(connector, case.name, case.args)
    assert result.coverage == "evaluated"
    assert result.complete is True
    assert transport.requests


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.name)
def test_read_operation_denied_is_not_evaluated(case: _Case) -> None:
    connector, _ = _connector(case, _denied_routes(case))
    result = _invoke(connector, case.name, case.args)
    assert result.coverage == "not_evaluated"
    assert result.complete is False
    assert result.coverage_reason


def test_subject_access_review_is_disabled_by_default() -> None:
    configured = next(case for case in CASES if case.name == "get_subject_access_review")
    case = _Case(configured.edition, configured.name, configured.args)
    connector, transport = _connector(case, {})
    result = _invoke(connector, case.name, case.args)
    assert result.coverage == "not_evaluated"
    assert result.complete is False
    assert "disabled" in (result.coverage_reason or "")
    assert transport.requests == []


def test_raw_arf_is_disabled_by_default() -> None:
    configured = next(case for case in CASES if case.name == "get_raw_arf")
    case = _Case(configured.edition, configured.name, configured.args)
    connector, transport = _connector(case, {})
    result = _invoke(connector, case.name, case.args)
    assert result.coverage == "not_evaluated"
    assert result.complete is False
    assert "disabled" in (result.coverage_reason or "")
    assert transport.requests == []


def test_raw_arf_is_size_capped_and_hashed_after_truncation() -> None:
    case = next(case for case in CASES if case.name == "get_raw_arf")
    content = b"x" * 1030
    routes = {("GET", ARF_PATH): {"status": 200, "content": content}}
    connector, _ = _connector(case, routes, max_evidence_bytes=1024)
    result = _invoke(connector, case.name, case.args)
    assert result.coverage == "degraded"
    assert result.complete is False
    assert result.content == content[:1024]
    assert result.size_bytes == 1024
    assert result.vendor_size_bytes == len(content)
    assert result.sha256 == hashlib.sha256(content[:1024]).hexdigest()


def test_list_users_groups_is_disabled_by_default() -> None:
    configured = next(case for case in CASES if case.name == "list_users_groups")
    case = _Case(configured.edition, configured.name, configured.args)
    connector, transport = _connector(case, {})
    result = _invoke(connector, case.name, case.args)
    assert result.coverage == "not_evaluated"
    assert result.complete is False
    assert result.users_coverage == "not_evaluated"
    assert result.groups_coverage == "not_evaluated"
    assert transport.requests == []


def test_compliance_scans_missing_discovery_gate_is_not_evaluated() -> None:
    case = next(case for case in CASES if case.name == "list_compliance_scans")
    connector, transport = _connector(case, _discovery_routes())
    result = _invoke(connector, case.name, case.args)
    assert result.coverage == "not_evaluated"
    assert result.complete is False
    assert result.done is False
    paths = [(request.method, request.url.path) for request in transport.requests]
    assert paths.count(("GET", "/api")) == 2
    assert paths.count(("GET", "/apis")) == 2
    assert all(path in {"/api", "/apis"} for _, path in paths)


def test_watch_410_refreshes_discovery_once_and_requires_relist_after_retry() -> None:
    case = next(case for case in CASES if case.name == "watch_resource")
    responses = iter(
        [
            {"status": 410, "json": {"message": "expired"}},
            {"status": 200, "content": WATCH_EVENT},
        ]
    )

    def watch_response(_request: Any) -> dict[str, Any]:
        return next(responses)

    routes = _routes(case)
    routes[("GET", WATCH_PATH)] = watch_response
    connector, transport = _connector(case, routes)
    result = _invoke(connector, case.name, case.args)
    assert result.coverage == "not_evaluated"
    assert result.complete is False
    assert result.relisted is True
    paths = [(request.method, request.url.path) for request in transport.requests]
    assert paths.count(("GET", "/api")) == 2
    assert paths.count(("GET", "/apis")) == 2
    assert paths.count(("GET", "/api/v1")) == 2
    assert paths.count(("GET", WATCH_PATH)) == 2


def test_kubernetes_operation_tuple_matches_the_declared_surface() -> None:
    assert tuple(operation.__name__ for operation in KUBERNETES_OPERATIONS) == (
        "get_resource",
        "list_resources",
        "get_policy_report",
        "list_api_resources",
        "get_openapi_schema",
        "get_gatekeeper_constraint",
        "get_server_version",
        "get_subject_access_review",
        "watch_resource",
    )


def test_openshift_operation_tuple_matches_the_declared_surface() -> None:
    assert tuple(operation.__name__ for operation in OPENSHIFT_OPERATIONS) == (
        "get_resource",
        "list_resources",
        "list_api_resources",
        "get_openapi_schema",
        "get_server_version",
        "get_cluster_version",
        "list_projects",
        "get_project",
        "get_route",
        "list_routes",
        "get_scc",
        "list_sccs",
        "get_buildconfig",
        "get_build",
        "get_imagestream",
        "get_imagestream_tag",
        "list_images",
        "list_imagestreams",
        "get_policy_report",
        "list_compliance_results",
        "list_compliance_scans",
        "watch_resource",
        "list_users_groups",
        "get_raw_arf",
    )
