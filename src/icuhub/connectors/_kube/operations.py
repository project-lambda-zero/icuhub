"""Typed, bounded Kubernetes and OpenShift read operations.

Discovery is cached per connector. A served-path 404, an expired list or watch,
or a kind/version mismatch refreshes discovery once and retries the read once.
A repeated failure is explicit non-evaluated coverage, never an empty success.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Literal, TypeVar
from urllib.parse import quote, urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

from icuhub.connectors._kube.base import CLUSTER_CAPABILITY, KubeBase
from icuhub.connectors._kube.client import KubeApiClient, ResourceSpec
from icuhub.connectors._kube.models import (
    _SENSITIVE_RESOURCES,
    EmptyArgs,
    GetResourceArgs,
    InputModel,
    ListResourcesArgs,
    PolicyReportArgs,
    RawArfArgs,
    SubjectAccessReviewArgs,
    WatchResourceArgs,
)
from icuhub.kit.connector import operation
from icuhub.kit.errors import BudgetExhausted, ConfigError, NotFound, PermissionDenied, VendorContractError
from icuhub.kit.http import HttpResult

__all__ = [
    "ApiResourcesOutput",
    "BoundedListArgs",
    "ClusterNameArgs",
    "ComplianceCheckResultOutput",
    "ComplianceResultStatus",
    "ComplianceResultsOutput",
    "ComplianceScansOutput",
    "GatekeeperConstraintArgs",
    "ImageListOutput",
    "ImageStreamListOutput",
    "ImageStreamTagArgs",
    "ImageStreamTagOutput",
    "KUBERNETES_OPERATIONS",
    "NamespacedListArgs",
    "NamespacedNameArgs",
    "OPENSHIFT_OPERATIONS",
    "OpenApiSchemaArgs",
    "OpenApiSchemaOutput",
    "OperationOutput",
    "ProjectListOutput",
    "RawArfOutput",
    "ResourceListOutput",
    "ResourceObjectOutput",
    "RouteListOutput",
    "RouteOutput",
    "RouteRecord",
    "ServerVersionOutput",
    "SubjectAccessReviewOutput",
    "UsersGroupsOutput",
    "WatchResourceOutput",
    "get_build",
    "get_buildconfig",
    "get_cluster_version",
    "get_gatekeeper_constraint",
    "get_imagestream",
    "get_imagestream_tag",
    "get_openapi_schema",
    "get_policy_report",
    "get_project",
    "get_resource",
    "get_route",
    "get_raw_arf",
    "get_scc",
    "get_server_version",
    "get_subject_access_review",
    "list_api_resources",
    "list_compliance_results",
    "list_compliance_scans",
    "list_images",
    "list_imagestreams",
    "list_projects",
    "list_resources",
    "list_routes",
    "list_sccs",
    "list_users_groups",
    "watch_resource",
]

CoverageState = Literal["evaluated", "degraded", "not_evaluated"]
_FINDING_CAPABILITY = "FindingSource"
_OK = 200
_GONE = 410
_REDACTED = "[redacted]"
_MAX_DISCOVERY_ATTEMPTS = 2


class OperationOutput(BaseModel):
    """Strict base that makes incomplete or denied reads explicit."""

    model_config = ConfigDict(extra="forbid")

    coverage: CoverageState = "evaluated"
    coverage_reason: str | None = None
    complete: bool = True


class ResourceObjectOutput(OperationOutput):
    data: dict[str, Any] | None = None


class ResourceListOutput(OperationOutput):
    items: list[dict[str, Any]] = Field(default_factory=list)
    resource_version: str | None = None
    continue_token: str | None = None


class ApiResourcesOutput(OperationOutput):
    core: dict[str, Any] = Field(default_factory=dict)
    groups: dict[str, Any] = Field(default_factory=dict)
    resources: list[dict[str, Any]] = Field(default_factory=list)
    refreshed: bool = False


class OpenApiSchemaArgs(InputModel):
    """An optional path key from the OpenAPI v3 index."""

    subpath: str | None = None

    @field_validator("subpath")
    @classmethod
    def safe_subpath(cls, value: str | None) -> str | None:
        if value is None:
            return None
        parts = urlsplit(value)
        if not value or parts.scheme or parts.netloc or ".." in value.split("/"):
            raise ValueError("OpenAPI subpath must be an index-relative path without parent traversal")
        return value


class OpenApiSchemaOutput(OperationOutput):
    data: dict[str, Any] | None = None
    path: str | None = None


class ServerVersionOutput(OperationOutput):
    data: dict[str, Any] = Field(default_factory=dict)


class WatchResourceOutput(OperationOutput):
    events: list[dict[str, Any]] = Field(default_factory=list)
    objects: list[dict[str, Any]] = Field(default_factory=list)
    resource_version: str | None = None
    relisted: bool = False


class SubjectAccessReviewOutput(OperationOutput):
    allowed: bool | None = None
    denied: bool | None = None
    reason: str | None = None
    evaluation_error: str | None = None


class BoundedListArgs(InputModel):
    limit: int | None = Field(default=None, ge=1, le=500)
    continue_token: str | None = None


class NamespacedListArgs(BoundedListArgs):
    namespace: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    label_selector: str | None = None
    field_selector: str | None = None


class NamespacedNameArgs(InputModel):
    name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    namespace: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class ClusterNameArgs(InputModel):
    name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class GatekeeperConstraintArgs(InputModel):
    kind: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    namespace: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class ImageStreamTagArgs(InputModel):
    imagestream: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    tag: str = Field(min_length=1, max_length=256, pattern=r"^[^/\\]+$")
    namespace: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class RouteRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    data: dict[str, Any]
    spec: dict[str, Any]
    ingress_status: list[dict[str, Any]]


class RouteOutput(ResourceObjectOutput):
    spec: dict[str, Any] = Field(default_factory=dict)
    ingress_status: list[dict[str, Any]] = Field(default_factory=list)


class RouteListOutput(ResourceListOutput):
    routes: list[RouteRecord] = Field(default_factory=list)


class ProjectListOutput(ResourceListOutput):
    visibility: Literal["identity_filtered"] = "identity_filtered"


class ImageStreamTagOutput(ResourceObjectOutput):
    imagestream: str = ""
    tag: str = ""
    mutable_mapping: Literal[True] = True
    identity_semantics: Literal["observed_mutable_tag"] = "observed_mutable_tag"


class ImageStreamListOutput(ResourceListOutput):
    tag_identity_semantics: Literal["observed_mutable_tag"] = "observed_mutable_tag"


class ImageListOutput(ResourceListOutput):
    identity_semantics: Literal["immutable_digest"] = "immutable_digest"


class ComplianceResultStatus(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"
    MANUAL = "MANUAL"
    INFO = "INFO"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    INCONSISTENT = "INCONSISTENT"
    UNKNOWN = "UNKNOWN"


class ComplianceCheckResultOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    data: dict[str, Any]
    raw_status: str
    status: ComplianceResultStatus


class ComplianceResultsOutput(ResourceListOutput):
    results: list[ComplianceCheckResultOutput] = Field(default_factory=list)
    scans_done: bool = False
    suites_done: bool = False
    closure_eligible: bool = False


class ComplianceScansOutput(ResourceListOutput):
    done: bool = False


class UsersGroupsOutput(OperationOutput):
    users: list[dict[str, Any]] = Field(default_factory=list)
    groups: list[dict[str, Any]] = Field(default_factory=list)
    users_coverage: CoverageState = "not_evaluated"
    groups_coverage: CoverageState = "not_evaluated"


class RawArfOutput(OperationOutput):
    content: bytes = b""
    sha256: str = ""
    size_bytes: int = 0
    vendor_size_bytes: int = 0
    media_type: str = "application/xml"
    evidence_only: Literal[True] = True


@dataclass(frozen=True, slots=True)
class _Discovery:
    core: dict[str, Any]
    groups: dict[str, Any]
    resources: tuple[dict[str, Any], ...]
    specs: dict[tuple[str, str, str], ResourceSpec]


class _SchemaDriftError(Exception):
    pass


class _ExpiredReadError(Exception):
    pass


_OutputT = TypeVar("_OutputT", bound=OperationOutput)


def _not_evaluated(model: type[_OutputT], reason: str) -> _OutputT:
    return model(coverage="not_evaluated", coverage_reason=reason, complete=False)


def _json_object(response: HttpResult, where: str) -> dict[str, Any]:
    body = response.json()
    if not isinstance(body, dict):
        raise VendorContractError(f"{where} returned a non-object body")
    return body


def _segment(value: str) -> str:
    return quote(value, safe="")


def _reject_sensitive(resource: str) -> None:
    if resource in _SENSITIVE_RESOURCES:
        raise ConfigError(f"{resource} reads are disabled because secret and OAuth token objects are excluded")


def _reject_sensitive_path(path: str) -> None:
    if set(path.split("/")) & _SENSITIVE_RESOURCES:
        raise ConfigError("secret and OAuth token object reads are disabled")


def _contains_pem(value: str) -> bool:
    return "-----BEGIN " in value and "-----" in value


def _public_value(value: Any, key: str = "") -> Any:
    normalized = key.replace("_", "").replace("-", "").lower()
    sensitive_keys = {
        "authorization",
        "apikey",
        "clientsecret",
        "credential",
        "credentials",
        "dockerconfigjson",
        "password",
        "privatekey",
        "secret",
        "token",
    }
    if normalized in sensitive_keys or normalized.endswith("password") or normalized.endswith("privatekey"):
        return _REDACTED
    if isinstance(value, str):
        return _REDACTED if _contains_pem(value) else value
    if isinstance(value, Mapping):
        return {str(item_key): _public_value(item, str(item_key)) for item_key, item in value.items()}
    if isinstance(value, list):
        return [_public_value(item) for item in value]
    if isinstance(value, tuple):
        return [_public_value(item) for item in value]
    return value


def _public_object(obj: dict[str, Any]) -> dict[str, Any]:
    public = _public_value(obj)
    if not isinstance(public, dict):
        raise VendorContractError("Kubernetes object could not be redacted")
    return public


def _expected_api_version(spec: ResourceSpec) -> str:
    return spec.version if not spec.group else f"{spec.group}/{spec.version}"


def _validate_object(obj: dict[str, Any], spec: ResourceSpec) -> None:
    kind = obj.get("kind")
    api_version = obj.get("apiVersion")
    if kind is not None and kind != spec.kind:
        raise _SchemaDriftError(f"expected kind {spec.kind}, observed {kind}")
    if api_version is not None and api_version != _expected_api_version(spec):
        raise _SchemaDriftError(f"expected apiVersion {_expected_api_version(spec)}, observed {api_version}")


def _spec(
    discovery: _Discovery,
    group: str,
    version: str,
    resource: str,
    kind: str | None,
) -> ResourceSpec:
    _reject_sensitive(resource)
    found = discovery.specs.get((group, version, resource))
    if found is None:
        raise NotFound(f"resource {group or 'core'}/{version}/{resource} is not served")
    if kind is not None and found.kind != kind:
        raise _SchemaDriftError(f"cached kind {found.kind} differs from requested kind {kind}")
    return found


async def _read_discovery(connector: KubeBase) -> _Discovery:
    discovered = await connector.api.discover()
    core = discovered.core
    groups = discovered.groups
    requests: list[tuple[str, str, str]] = []
    versions = core.get("versions") or []
    if not isinstance(versions, list) or not all(isinstance(version, str) for version in versions):
        raise VendorContractError("Kubernetes core discovery versions must be strings")
    requests.extend(("", version, f"/api/{_segment(version)}") for version in versions)
    group_items = groups.get("groups") or []
    if not isinstance(group_items, list):
        raise VendorContractError("Kubernetes named-group discovery must be a list")
    for group in group_items:
        if not isinstance(group, dict) or not isinstance(group.get("name"), str):
            raise VendorContractError("Kubernetes named-group discovery entry is invalid")
        group_versions = group.get("versions") or []
        if not isinstance(group_versions, list):
            raise VendorContractError("Kubernetes named-group versions must be a list")
        for version in group_versions:
            if not isinstance(version, dict) or not isinstance(version.get("version"), str):
                raise VendorContractError("Kubernetes named-group version entry is invalid")
            version_name = version["version"]
            requests.append(
                (
                    group["name"],
                    version_name,
                    f"/apis/{_segment(group['name'])}/{_segment(version_name)}",
                )
            )
    resources: list[dict[str, Any]] = []
    specs: dict[tuple[str, str, str], ResourceSpec] = {}
    for group, version, path in requests:
        response = await connector.http.request("GET", path, expected=(_OK,))
        body = _json_object(response, path)
        entries = body.get("resources") or []
        if not isinstance(entries, list):
            raise VendorContractError(f"{path} resources must be a list")
        for entry in entries:
            if not isinstance(entry, dict):
                raise VendorContractError(f"{path} contains a non-object resource")
            resource = entry.get("name")
            kind = entry.get("kind")
            if not isinstance(resource, str) or not isinstance(kind, str) or "/" in resource:
                continue
            spec = ResourceSpec(
                key=f"{group or 'core'}/{version}/{resource}",
                group=group,
                version=version,
                resource=resource,
                kind=kind,
            )
            specs[(group, version, resource)] = spec
            resources.append(
                {
                    "group": group,
                    "version": version,
                    "resource": resource,
                    "kind": kind,
                    "namespaced": bool(entry.get("namespaced", False)),
                    "verbs": list(entry.get("verbs") or []),
                    "path": path,
                }
            )
    resources.sort(key=lambda item: (item["group"], item["version"], item["resource"]))
    return _Discovery(core=core, groups=groups, resources=tuple(resources), specs=specs)


async def _get_discovery(connector: KubeBase, *, refresh: bool = False) -> _Discovery:
    cached = getattr(connector, "_operation_discovery", None)
    if isinstance(cached, _Discovery) and not refresh:
        return cached
    discovered = await _read_discovery(connector)
    connector._operation_discovery = discovered
    return discovered


async def _with_discovery_refresh(
    connector: KubeBase,
    run: Callable[[_Discovery, int], Awaitable[_OutputT]],
    unavailable: Callable[[str], _OutputT],
) -> _OutputT:
    """Refresh discovery once after a stale served path, expired read, or schema drift."""
    try:
        discovery = await _get_discovery(connector)
    except PermissionDenied:
        return unavailable("discovery forbidden for this identity")
    except NotFound:
        try:
            discovery = await _get_discovery(connector, refresh=True)
        except (NotFound, PermissionDenied) as exc:
            return unavailable(f"discovery retry failed: {type(exc).__name__}")
    for attempt in range(_MAX_DISCOVERY_ATTEMPTS):
        try:
            return await run(discovery, attempt)
        except PermissionDenied:
            return unavailable("resource read forbidden for this identity")
        except (NotFound, _ExpiredReadError, _SchemaDriftError) as exc:
            if attempt == _MAX_DISCOVERY_ATTEMPTS - 1:
                return unavailable(f"read remains unavailable after discovery refresh: {type(exc).__name__}")
            try:
                discovery = await _get_discovery(connector, refresh=True)
            except PermissionDenied:
                return unavailable("discovery refresh forbidden for this identity")
            except NotFound:
                return unavailable("discovery refresh found an unserved path")
    return unavailable("discovery attempts exhausted")


def _list_metadata(body: dict[str, Any]) -> tuple[str | None, str | None]:
    metadata = body.get("metadata") or {}
    if not isinstance(metadata, dict):
        raise VendorContractError("Kubernetes list metadata must be an object")
    resource_version = metadata.get("resourceVersion")
    continue_token = metadata.get("continue") or None
    if resource_version is not None and not isinstance(resource_version, str):
        raise VendorContractError("Kubernetes list resourceVersion must be a string")
    if continue_token is not None and not isinstance(continue_token, str):
        raise VendorContractError("Kubernetes list continuation token must be a string")
    return resource_version, continue_token


async def _list_partition(
    connector: KubeBase,
    spec: ResourceSpec,
    *,
    namespace: str | None,
    limit: int | None = None,
    continue_token: str | None = None,
    label_selector: str | None = None,
    field_selector: str | None = None,
) -> ResourceListOutput:
    advanced = any(value is not None for value in (limit, continue_token, label_selector, field_selector))
    if advanced:
        params: dict[str, Any] = {"limit": min(limit or connector.config.page_size, connector.config.page_size)}
        if continue_token is not None:
            params["continue"] = continue_token
        if label_selector is not None:
            params["labelSelector"] = label_selector
        if field_selector is not None:
            params["fieldSelector"] = field_selector
        path = spec.path(namespace=namespace)
        response = await connector.http.request("GET", path, params=params, expected=(_OK, _GONE))
        if response.status == _GONE:
            raise _ExpiredReadError("list continuation expired")
        body = _json_object(response, path)
        raw_items = body.get("items") or []
        if not isinstance(raw_items, list) or not all(isinstance(item, dict) for item in raw_items):
            raise VendorContractError(f"{path} items must be objects")
        resource_version, next_token = _list_metadata(body)
        for item in raw_items:
            _validate_object(item, spec)
        return ResourceListOutput(
            items=[_public_object(item) for item in raw_items],
            resource_version=resource_version,
            continue_token=next_token,
            complete=next_token is None,
            coverage="evaluated" if next_token is None else "degraded",
            coverage_reason=None if next_token is None else "more pages remain; continue with continue_token",
        )
    try:
        listed = await connector.api.list_all(spec, namespace=namespace)
    except VendorContractError as exc:
        if "continuation expired" in str(exc):
            raise _ExpiredReadError("list continuation expired") from exc
        raise
    for item in listed.items:
        _validate_object(item, spec)
    configured_cap = connector.config.page_size * connector.config.max_pages
    items = listed.items[:configured_cap]
    truncated = len(items) != len(listed.items)
    return ResourceListOutput(
        items=[_public_object(item) for item in items],
        resource_version=listed.resource_version,
        continue_token=listed.continue_token,
        complete=listed.complete and not truncated,
        coverage="degraded" if truncated else "evaluated",
        coverage_reason="configured item cap reached" if truncated else None,
    )


async def _read_object(
    connector: KubeBase,
    group: str,
    version: str,
    resource: str,
    kind: str | None,
    name: str,
    namespace: str | None,
) -> ResourceObjectOutput:
    async def run(discovery: _Discovery, attempt: int) -> ResourceObjectOutput:
        del attempt
        spec = _spec(discovery, group, version, resource, kind)
        result = await connector.api.get(spec, name=name, namespace=namespace)
        _validate_object(result.data, spec)
        return ResourceObjectOutput(data=_public_object(result.data))

    return await _with_discovery_refresh(
        connector,
        run,
        lambda reason: _not_evaluated(ResourceObjectOutput, reason),
    )


async def _read_list(
    connector: KubeBase,
    spec_to_resolve: tuple[str, str, str, str | None],
    *,
    namespace: str | None,
    limit: int | None = None,
    continue_token: str | None = None,
    label_selector: str | None = None,
    field_selector: str | None = None,
) -> ResourceListOutput:
    async def run(discovery: _Discovery, attempt: int) -> ResourceListOutput:
        del attempt
        spec = _spec(discovery, *spec_to_resolve)
        return await _list_partition(
            connector,
            spec,
            namespace=namespace,
            limit=limit,
            continue_token=continue_token,
            label_selector=label_selector,
            field_selector=field_selector,
        )

    return await _with_discovery_refresh(
        connector,
        run,
        lambda reason: _not_evaluated(ResourceListOutput, reason),
    )


def _fixed_spec(group: str, version: str, resource: str, kind: str) -> tuple[str, str, str, str]:
    return group, version, resource, kind


async def _get_fixed(
    connector: KubeBase,
    spec: tuple[str, str, str, str],
    name: str,
    namespace: str | None = None,
) -> ResourceObjectOutput:
    return await _read_object(connector, *spec, name, namespace)


async def _list_fixed(
    connector: KubeBase,
    spec: tuple[str, str, str, str],
    args: BoundedListArgs,
    namespace: str | None = None,
) -> ResourceListOutput:
    selectors = args if isinstance(args, NamespacedListArgs) else None
    return await _read_list(
        connector,
        spec,
        namespace=namespace,
        limit=args.limit,
        continue_token=args.continue_token,
        label_selector=selectors.label_selector if selectors else None,
        field_selector=selectors.field_selector if selectors else None,
    )


@operation(
    "get_resource",
    input_model=GetResourceArgs,
    output_model=ResourceObjectOutput,
    classification="read",
    capability=CLUSTER_CAPABILITY,
    egress_class="vendor_tenant",
)
async def get_resource(connector: KubeBase, args: GetResourceArgs) -> ResourceObjectOutput:
    return await _read_object(
        connector,
        args.group,
        args.version,
        args.resource,
        args.kind,
        args.name,
        args.namespace,
    )


@operation(
    "list_resources",
    input_model=ListResourcesArgs,
    output_model=ResourceListOutput,
    classification="read",
    capability=CLUSTER_CAPABILITY,
    egress_class="vendor_tenant",
)
async def list_resources(connector: KubeBase, args: ListResourcesArgs) -> ResourceListOutput:
    return await _read_list(
        connector,
        (args.group, args.version, args.resource, args.kind),
        namespace=args.namespace,
        limit=args.limit,
        continue_token=args.continue_token,
        label_selector=args.label_selector,
        field_selector=args.field_selector,
    )


@operation(
    "get_policy_report",
    input_model=PolicyReportArgs,
    output_model=ResourceObjectOutput,
    classification="read",
    capability=_FINDING_CAPABILITY,
    egress_class="vendor_tenant",
)
async def get_policy_report(connector: KubeBase, args: PolicyReportArgs) -> ResourceObjectOutput:
    kind = "ClusterPolicyReport" if args.resource == "clusterpolicyreports" else "PolicyReport"
    return await _read_object(
        connector,
        args.group,
        args.version,
        args.resource,
        kind,
        args.name,
        args.namespace,
    )


@operation(
    "list_api_resources",
    input_model=EmptyArgs,
    output_model=ApiResourcesOutput,
    classification="read",
    capability=CLUSTER_CAPABILITY,
    egress_class="vendor_tenant",
)
async def list_api_resources(connector: KubeBase, args: EmptyArgs) -> ApiResourcesOutput:
    del args

    async def run(discovery: _Discovery, attempt: int) -> ApiResourcesOutput:
        return ApiResourcesOutput(
            core=discovery.core,
            groups=discovery.groups,
            resources=list(discovery.resources),
            refreshed=attempt > 0,
        )

    return await _with_discovery_refresh(
        connector,
        run,
        lambda reason: _not_evaluated(ApiResourcesOutput, reason),
    )


@operation(
    "get_openapi_schema",
    input_model=OpenApiSchemaArgs,
    output_model=OpenApiSchemaOutput,
    classification="read",
    capability=CLUSTER_CAPABILITY,
    egress_class="vendor_tenant",
)
async def get_openapi_schema(connector: KubeBase, args: OpenApiSchemaArgs) -> OpenApiSchemaOutput:
    async def run(discovery: _Discovery, attempt: int) -> OpenApiSchemaOutput:
        del discovery, attempt
        index_response = await connector.http.request("GET", "/openapi/v3", expected=(_OK,))
        index = _json_object(index_response, "/openapi/v3")
        if args.subpath is None:
            return OpenApiSchemaOutput(data=index, path="/openapi/v3")
        paths = index.get("paths") or {}
        if not isinstance(paths, dict) or not isinstance(paths.get(args.subpath), dict):
            raise NotFound(f"OpenAPI path {args.subpath!r} is not served")
        relative = paths[args.subpath].get("serverRelativeURL")
        if not isinstance(relative, str):
            raise VendorContractError("OpenAPI path has no serverRelativeURL")
        parsed = urlsplit(relative)
        if parsed.scheme or parsed.netloc or not parsed.path.startswith("/openapi/v3/"):
            raise VendorContractError("OpenAPI serverRelativeURL must stay below /openapi/v3")
        response = await connector.http.request("GET", relative, expected=(_OK,))
        return OpenApiSchemaOutput(data=_json_object(response, relative), path=relative)

    return await _with_discovery_refresh(
        connector,
        run,
        lambda reason: _not_evaluated(OpenApiSchemaOutput, reason),
    )


@operation(
    "get_gatekeeper_constraint",
    input_model=GatekeeperConstraintArgs,
    output_model=ResourceObjectOutput,
    classification="read",
    capability=_FINDING_CAPABILITY,
    egress_class="vendor_tenant",
)
async def get_gatekeeper_constraint(connector: KubeBase, args: GatekeeperConstraintArgs) -> ResourceObjectOutput:
    return await _read_object(
        connector,
        "constraints.gatekeeper.sh",
        "v1beta1",
        args.kind.lower(),
        args.kind,
        args.name,
        args.namespace,
    )


@operation(
    "get_server_version",
    input_model=EmptyArgs,
    output_model=ServerVersionOutput,
    classification="read",
    capability=CLUSTER_CAPABILITY,
    egress_class="vendor_tenant",
)
async def get_server_version(connector: KubeBase, args: EmptyArgs) -> ServerVersionOutput:
    del args
    try:
        result = await connector.api.server_version()
    except PermissionDenied:
        return _not_evaluated(ServerVersionOutput, "server version read forbidden for this identity")
    return ServerVersionOutput(data=result.data)


@operation(
    "get_subject_access_review",
    input_model=SubjectAccessReviewArgs,
    output_model=SubjectAccessReviewOutput,
    classification="read",
    capability=_FINDING_CAPABILITY,
    egress_class="vendor_tenant",
)
async def get_subject_access_review(connector: KubeBase, args: SubjectAccessReviewArgs) -> SubjectAccessReviewOutput:
    if not connector.config.subject_access_review_enabled:
        return _not_evaluated(
            SubjectAccessReviewOutput,
            "SubjectAccessReview is disabled; set subject_access_review_enabled=True to authorize it",
        )
    _reject_sensitive(args.resource)
    attributes: dict[str, Any] = {
        "group": args.group,
        "version": args.version,
        "resource": args.resource,
        "verb": args.verb,
    }
    if args.namespace is not None:
        attributes["namespace"] = args.namespace
    if args.name is not None:
        attributes["name"] = args.name
    body = {
        "apiVersion": "authorization.k8s.io/v1",
        "kind": "SubjectAccessReview",
        "spec": {"user": args.user, "groups": list(args.groups), "resourceAttributes": attributes},
    }
    try:
        response = await connector.http.request(
            "POST",
            "/apis/authorization.k8s.io/v1/subjectaccessreviews",
            json=body,
            idempotency="safe_read",
            expected=(200, 201),
        )
    except (PermissionDenied, NotFound) as exc:
        return _not_evaluated(SubjectAccessReviewOutput, f"access review unavailable: {type(exc).__name__}")
    review = _json_object(response, "SubjectAccessReview")
    status = review.get("status") or {}
    if not isinstance(status, dict):
        raise VendorContractError("SubjectAccessReview status must be an object")
    allowed = status.get("allowed")
    denied = status.get("denied")
    reason = status.get("reason") if isinstance(status.get("reason"), str) else None
    evaluation_error = status.get("evaluationError") if isinstance(status.get("evaluationError"), str) else None
    if not isinstance(allowed, bool):
        allowed = None
    if not isinstance(denied, bool):
        denied = None
    evaluated = allowed is True and denied is not True and evaluation_error is None
    return SubjectAccessReviewOutput(
        allowed=allowed,
        denied=denied,
        reason=reason,
        evaluation_error=evaluation_error,
        coverage="evaluated" if evaluated else "not_evaluated",
        coverage_reason=None if evaluated else reason or evaluation_error or "access was denied or could not be determined",
        complete=evaluated,
    )


async def _filtered_watch(
    connector: KubeBase,
    spec: ResourceSpec,
    args: WatchResourceArgs,
    *,
    timeout_s: int,
    max_events: int,
) -> WatchResourceOutput:
    path = spec.path(namespace=args.namespace)
    params: dict[str, Any] = {
        "watch": "true",
        "resourceVersion": args.resource_version or "0",
        "timeoutSeconds": timeout_s,
        "allowWatchBookmarks": "true",
    }
    if args.label_selector is not None:
        params["labelSelector"] = args.label_selector
    if args.field_selector is not None:
        params["fieldSelector"] = args.field_selector
    response = await connector.http.request("GET", path, params=params, expected=(_OK, _GONE))
    if response.status == _GONE:
        raise _ExpiredReadError("watch resourceVersion expired")
    events: list[dict[str, Any]] = []
    objects: list[dict[str, Any]] = []
    last_version = args.resource_version or "0"
    for line in response.content.splitlines():
        if not line.strip():
            continue
        if len(events) >= max_events:
            raise BudgetExhausted(f"watch event limit of {max_events} exceeded for {path}")
        try:
            event = json.loads(line)
        except ValueError as exc:
            raise VendorContractError(f"{path} returned an invalid watch event") from exc
        if not isinstance(event, dict) or not isinstance(event.get("object"), dict):
            raise VendorContractError(f"{path} watch event must contain an object")
        event_type = event.get("type")
        obj = event["object"]
        if event_type == "ERROR":
            if obj.get("code") == _GONE:
                raise _ExpiredReadError("watch resourceVersion expired")
            raise VendorContractError(f"{path} watch returned an ERROR event")
        if event_type not in {"ADDED", "MODIFIED", "DELETED", "BOOKMARK"}:
            raise VendorContractError(f"{path} watch returned an unknown event type")
        _validate_object(obj, spec)
        metadata = obj.get("metadata") or {}
        version = metadata.get("resourceVersion") if isinstance(metadata, dict) else None
        if not isinstance(version, str) or not version:
            raise VendorContractError(f"{path} watch event has no resourceVersion")
        last_version = version
        public_event = _public_object(event)
        events.append(public_event)
        if event_type != "BOOKMARK":
            objects.append(_public_object(obj))
    return WatchResourceOutput(events=events, objects=objects, resource_version=last_version)


@operation(
    "watch_resource",
    input_model=WatchResourceArgs,
    output_model=WatchResourceOutput,
    classification="read",
    capability=CLUSTER_CAPABILITY,
    egress_class="vendor_tenant",
)
async def watch_resource(connector: KubeBase, args: WatchResourceArgs) -> WatchResourceOutput:
    timeout_s = min(args.timeout_s or connector.config.watch_timeout_s, connector.config.watch_timeout_s)
    max_events = min(args.max_events or connector.config.max_watch_events, connector.config.max_watch_events)

    async def run(discovery: _Discovery, attempt: int) -> WatchResourceOutput:
        spec = _spec(discovery, args.group, args.version, args.resource, args.kind)
        if args.label_selector is None and args.field_selector is None:
            client = connector.api
            if max_events != connector.config.max_watch_events:
                client = KubeApiClient(
                    connector.http,
                    page_size=connector.config.page_size,
                    max_pages=connector.config.max_pages,
                    max_watch_events=max_events,
                )
            window = await client.watch(
                spec,
                resource_version=args.resource_version or "0",
                timeout_s=timeout_s,
                namespace=args.namespace,
            )
            if window.relisted:
                raise _ExpiredReadError("watch resourceVersion expired")
            for obj in window.objects:
                _validate_object(obj, spec)
            result = WatchResourceOutput(
                events=[_public_object(event) for event in window.events],
                objects=[_public_object(obj) for obj in window.objects],
                resource_version=window.resource_version,
            )
        else:
            result = await _filtered_watch(connector, spec, args, timeout_s=timeout_s, max_events=max_events)
        if attempt:
            return WatchResourceOutput(
                coverage="not_evaluated",
                coverage_reason="resourceVersion expired during the first watch; relist before resuming",
                complete=False,
                relisted=True,
            )
        return result

    def unavailable(reason: str) -> WatchResourceOutput:
        return WatchResourceOutput(
            coverage="not_evaluated",
            coverage_reason=reason,
            complete=False,
            relisted="ExpiredRead" in reason,
        )

    return await _with_discovery_refresh(connector, run, unavailable)


_CLUSTER_VERSION = _fixed_spec("config.openshift.io", "v1", "clusterversions", "ClusterVersion")
_PROJECT = _fixed_spec("project.openshift.io", "v1", "projects", "Project")
_ROUTE = _fixed_spec("route.openshift.io", "v1", "routes", "Route")
_SCC = _fixed_spec("security.openshift.io", "v1", "securitycontextconstraints", "SecurityContextConstraints")
_BUILDCONFIG = _fixed_spec("build.openshift.io", "v1", "buildconfigs", "BuildConfig")
_BUILD = _fixed_spec("build.openshift.io", "v1", "builds", "Build")
_IMAGESTREAM = _fixed_spec("image.openshift.io", "v1", "imagestreams", "ImageStream")
_IMAGESTREAMTAG = _fixed_spec("image.openshift.io", "v1", "imagestreamtags", "ImageStreamTag")
_IMAGE = _fixed_spec("image.openshift.io", "v1", "images", "Image")
_COMPLIANCE_RESULT = _fixed_spec("compliance.openshift.io", "v1alpha1", "compliancecheckresults", "ComplianceCheckResult")
_COMPLIANCE_SCAN = _fixed_spec("compliance.openshift.io", "v1alpha1", "compliancescans", "ComplianceScan")
_COMPLIANCE_SUITE = _fixed_spec("compliance.openshift.io", "v1alpha1", "compliancesuites", "ComplianceSuite")
_USER = _fixed_spec("user.openshift.io", "v1", "users", "User")
_GROUP = _fixed_spec("user.openshift.io", "v1", "groups", "Group")


def _route_record(data: dict[str, Any]) -> RouteRecord:
    spec = data.get("spec") or {}
    status = data.get("status") or {}
    ingress = (status.get("ingress") or []) if isinstance(status, dict) else []
    if not isinstance(spec, dict) or not isinstance(ingress, list) or not all(isinstance(item, dict) for item in ingress):
        raise VendorContractError("Route spec and status.ingress have invalid shapes")
    return RouteRecord(data=data, spec=spec, ingress_status=ingress)


@operation(
    "get_cluster_version",
    input_model=EmptyArgs,
    output_model=ResourceObjectOutput,
    classification="read",
    capability=CLUSTER_CAPABILITY,
    egress_class="vendor_tenant",
)
async def get_cluster_version(connector: KubeBase, args: EmptyArgs) -> ResourceObjectOutput:
    del args
    return await _get_fixed(connector, _CLUSTER_VERSION, "version")


@operation(
    "list_projects",
    input_model=BoundedListArgs,
    output_model=ProjectListOutput,
    classification="read",
    capability=CLUSTER_CAPABILITY,
    egress_class="vendor_tenant",
)
async def list_projects(connector: KubeBase, args: BoundedListArgs) -> ProjectListOutput:
    result = await _list_fixed(connector, _PROJECT, args)
    return ProjectListOutput(**result.model_dump())


@operation(
    "get_project",
    input_model=ClusterNameArgs,
    output_model=ResourceObjectOutput,
    classification="read",
    capability=CLUSTER_CAPABILITY,
    egress_class="vendor_tenant",
)
async def get_project(connector: KubeBase, args: ClusterNameArgs) -> ResourceObjectOutput:
    return await _get_fixed(connector, _PROJECT, args.name)


@operation(
    "get_route",
    input_model=NamespacedNameArgs,
    output_model=RouteOutput,
    classification="read",
    capability=_FINDING_CAPABILITY,
    egress_class="vendor_tenant",
)
async def get_route(connector: KubeBase, args: NamespacedNameArgs) -> RouteOutput:
    result = await _get_fixed(connector, _ROUTE, args.name, args.namespace)
    if result.data is None:
        return RouteOutput(**result.model_dump())
    route = _route_record(result.data)
    return RouteOutput(**result.model_dump(), spec=route.spec, ingress_status=route.ingress_status)


@operation(
    "list_routes",
    input_model=NamespacedListArgs,
    output_model=RouteListOutput,
    classification="read",
    capability=_FINDING_CAPABILITY,
    egress_class="vendor_tenant",
)
async def list_routes(connector: KubeBase, args: NamespacedListArgs) -> RouteListOutput:
    result = await _list_fixed(connector, _ROUTE, args, args.namespace)
    return RouteListOutput(**result.model_dump(), routes=[_route_record(item) for item in result.items])


@operation(
    "get_scc",
    input_model=ClusterNameArgs,
    output_model=ResourceObjectOutput,
    classification="read",
    capability=_FINDING_CAPABILITY,
    egress_class="vendor_tenant",
)
async def get_scc(connector: KubeBase, args: ClusterNameArgs) -> ResourceObjectOutput:
    return await _get_fixed(connector, _SCC, args.name)


@operation(
    "list_sccs",
    input_model=BoundedListArgs,
    output_model=ResourceListOutput,
    classification="read",
    capability=_FINDING_CAPABILITY,
    egress_class="vendor_tenant",
)
async def list_sccs(connector: KubeBase, args: BoundedListArgs) -> ResourceListOutput:
    return await _list_fixed(connector, _SCC, args)


@operation(
    "get_buildconfig",
    input_model=NamespacedNameArgs,
    output_model=ResourceObjectOutput,
    classification="read",
    capability=CLUSTER_CAPABILITY,
    egress_class="vendor_tenant",
)
async def get_buildconfig(connector: KubeBase, args: NamespacedNameArgs) -> ResourceObjectOutput:
    return await _get_fixed(connector, _BUILDCONFIG, args.name, args.namespace)


@operation(
    "get_build",
    input_model=NamespacedNameArgs,
    output_model=ResourceObjectOutput,
    classification="read",
    capability=CLUSTER_CAPABILITY,
    egress_class="vendor_tenant",
)
async def get_build(connector: KubeBase, args: NamespacedNameArgs) -> ResourceObjectOutput:
    return await _get_fixed(connector, _BUILD, args.name, args.namespace)


@operation(
    "get_imagestream",
    input_model=NamespacedNameArgs,
    output_model=ResourceObjectOutput,
    classification="read",
    capability=CLUSTER_CAPABILITY,
    egress_class="vendor_tenant",
)
async def get_imagestream(connector: KubeBase, args: NamespacedNameArgs) -> ResourceObjectOutput:
    return await _get_fixed(connector, _IMAGESTREAM, args.name, args.namespace)


@operation(
    "get_imagestream_tag",
    input_model=ImageStreamTagArgs,
    output_model=ImageStreamTagOutput,
    classification="read",
    capability=CLUSTER_CAPABILITY,
    egress_class="vendor_tenant",
)
async def get_imagestream_tag(connector: KubeBase, args: ImageStreamTagArgs) -> ImageStreamTagOutput:
    result = await _get_fixed(connector, _IMAGESTREAMTAG, f"{args.imagestream}:{args.tag}", args.namespace)
    return ImageStreamTagOutput(**result.model_dump(), imagestream=args.imagestream, tag=args.tag)


@operation(
    "list_images",
    input_model=BoundedListArgs,
    output_model=ImageListOutput,
    classification="read",
    capability=CLUSTER_CAPABILITY,
    egress_class="vendor_tenant",
)
async def list_images(connector: KubeBase, args: BoundedListArgs) -> ImageListOutput:
    result = await _list_fixed(connector, _IMAGE, args)
    return ImageListOutput(**result.model_dump())


@operation(
    "list_imagestreams",
    input_model=NamespacedListArgs,
    output_model=ImageStreamListOutput,
    classification="read",
    capability=CLUSTER_CAPABILITY,
    egress_class="vendor_tenant",
)
async def list_imagestreams(connector: KubeBase, args: NamespacedListArgs) -> ImageStreamListOutput:
    result = await _list_fixed(connector, _IMAGESTREAM, args, args.namespace)
    return ImageStreamListOutput(**result.model_dump())


def _phase_done(items: list[dict[str, Any]]) -> bool:
    if not items:
        return False
    phases: list[str] = []
    for item in items:
        status = item.get("status") or {}
        phase = status.get("phase") if isinstance(status, dict) else None
        if not isinstance(phase, str):
            return False
        phases.append(phase)
    return all(phase == "DONE" for phase in phases)


def _compliance_result(item: dict[str, Any]) -> ComplianceCheckResultOutput:
    raw_status = item.get("status")
    if not isinstance(raw_status, str):
        raise VendorContractError("ComplianceCheckResult status must be a string")
    try:
        status = ComplianceResultStatus(raw_status)
    except ValueError:
        status = ComplianceResultStatus.NOT_APPLICABLE if raw_status == "NOT-APPLICABLE" else ComplianceResultStatus.UNKNOWN
    return ComplianceCheckResultOutput(data=item, raw_status=raw_status, status=status)


@operation(
    "list_compliance_results",
    input_model=NamespacedListArgs,
    output_model=ComplianceResultsOutput,
    classification="read",
    capability=_FINDING_CAPABILITY,
    egress_class="vendor_tenant",
)
async def list_compliance_results(connector: KubeBase, args: NamespacedListArgs) -> ComplianceResultsOutput:
    result = await _list_fixed(connector, _COMPLIANCE_RESULT, args, args.namespace)
    if result.coverage == "not_evaluated":
        return ComplianceResultsOutput(**result.model_dump())
    scans = await _list_fixed(connector, _COMPLIANCE_SCAN, BoundedListArgs(), args.namespace)
    suites = await _list_fixed(connector, _COMPLIANCE_SUITE, BoundedListArgs(), args.namespace)
    scans_done = scans.coverage == "evaluated" and scans.complete and _phase_done(scans.items)
    suites_done = suites.coverage == "evaluated" and suites.complete and _phase_done(suites.items)
    aggregators_complete = scans_done or suites_done
    related_coverage = {scans.coverage, suites.coverage}
    complete = result.complete and aggregators_complete and "not_evaluated" not in related_coverage
    coverage: CoverageState = result.coverage
    reason = result.coverage_reason
    if "not_evaluated" in related_coverage:
        coverage = "not_evaluated"
        reason = "compliance scan or suite state could not be evaluated"
    elif not aggregators_complete:
        coverage = "degraded"
        reason = "closure requires an observed ComplianceScan or ComplianceSuite in DONE phase"
    return ComplianceResultsOutput(
        **result.model_dump(exclude={"coverage", "coverage_reason", "complete"}),
        results=[_compliance_result(item) for item in result.items],
        scans_done=scans_done,
        suites_done=suites_done,
        closure_eligible=complete and coverage == "evaluated",
        coverage=coverage,
        coverage_reason=reason,
        complete=complete,
    )


@operation(
    "list_compliance_scans",
    input_model=NamespacedListArgs,
    output_model=ComplianceScansOutput,
    classification="read",
    capability=_FINDING_CAPABILITY,
    egress_class="vendor_tenant",
)
async def list_compliance_scans(connector: KubeBase, args: NamespacedListArgs) -> ComplianceScansOutput:
    result = await _list_fixed(connector, _COMPLIANCE_SCAN, args, args.namespace)
    done = result.coverage == "evaluated" and result.complete and _phase_done(result.items)
    return ComplianceScansOutput(**result.model_dump(), done=done)


@operation(
    "list_users_groups",
    input_model=BoundedListArgs,
    output_model=UsersGroupsOutput,
    classification="read",
    capability=CLUSTER_CAPABILITY,
    egress_class="vendor_tenant",
)
async def list_users_groups(connector: KubeBase, args: BoundedListArgs) -> UsersGroupsOutput:
    if not connector.config.include_users_groups:
        return _not_evaluated(UsersGroupsOutput, "User and Group reads are disabled by include_users_groups=False")
    users = await _list_fixed(connector, _USER, args)
    groups = await _list_fixed(connector, _GROUP, args)
    evaluated = users.coverage == groups.coverage == "evaluated"
    return UsersGroupsOutput(
        users=users.items,
        groups=groups.items,
        users_coverage=users.coverage,
        groups_coverage=groups.coverage,
        coverage="evaluated" if evaluated else "not_evaluated",
        coverage_reason=None if evaluated else "one or both User and Group reads were not evaluated",
        complete=evaluated and users.complete and groups.complete,
    )


@operation(
    "get_raw_arf",
    input_model=RawArfArgs,
    output_model=RawArfOutput,
    classification="read",
    capability=_FINDING_CAPABILITY,
    egress_class="vendor_tenant",
)
async def get_raw_arf(connector: KubeBase, args: RawArfArgs) -> RawArfOutput:
    if not connector.config.raw_arf_enabled:
        return _not_evaluated(RawArfOutput, "raw ARF evidence is disabled; set raw_arf_enabled=True to authorize it")
    _reject_sensitive_path(args.path)
    try:
        response = await connector.http.request("GET", args.path, expected=(_OK,))
    except (PermissionDenied, NotFound) as exc:
        return _not_evaluated(RawArfOutput, f"ARF evidence unavailable: {type(exc).__name__}")
    limit = connector.config.max_evidence_bytes
    content = response.content[:limit]
    if _contains_pem(content.decode("utf-8", errors="ignore")):
        return _not_evaluated(RawArfOutput, "ARF evidence contains PEM material and is not returned")
    complete = len(response.content) <= limit
    return RawArfOutput(
        content=content,
        sha256=hashlib.sha256(content).hexdigest(),
        size_bytes=len(content),
        vendor_size_bytes=len(response.content),
        media_type=response.headers.get("content-type", "application/xml"),
        coverage="evaluated" if complete else "degraded",
        coverage_reason=None if complete else "ARF evidence exceeded max_evidence_bytes and was truncated",
        complete=complete,
    )


KUBERNETES_OPERATIONS = (
    get_resource,
    list_resources,
    get_policy_report,
    list_api_resources,
    get_openapi_schema,
    get_gatekeeper_constraint,
    get_server_version,
    get_subject_access_review,
    watch_resource,
)

OPENSHIFT_OPERATIONS = (
    get_resource,
    list_resources,
    list_api_resources,
    get_openapi_schema,
    get_server_version,
    get_cluster_version,
    list_projects,
    get_project,
    get_route,
    list_routes,
    get_scc,
    list_sccs,
    get_buildconfig,
    get_build,
    get_imagestream,
    get_imagestream_tag,
    list_images,
    list_imagestreams,
    get_policy_report,
    list_compliance_results,
    list_compliance_scans,
    watch_resource,
    list_users_groups,
    get_raw_arf,
)
