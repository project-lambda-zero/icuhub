"""Kubernetes and OpenShift configuration, cursor, operation, and action contracts."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from icuhub.kit.cursors import PageTokenCursor, SequenceCursor, SnapshotCursor
from icuhub.kit.types import ConnectorConfig, SecretRef

__all__ = [
    "ApiDiscoveryResult",
    "AnnotateResourceArgs",
    "AuditCursor",
    "AuditFilePosition",
    "AuditFileSource",
    "DeletePodArgs",
    "EmptyArgs",
    "EvidenceResult",
    "GetResourceArgs",
    "InstantiateBuildConfigArgs",
    "ItemsResult",
    "KubeConfig",
    "KubePartitionCursor",
    "KubeSnapshotCursor",
    "ListResourcesArgs",
    "ManagedAuditSource",
    "OwnerEvidenceArgs",
    "OwnerEvidenceResult",
    "PolicyReportArgs",
    "RawArfArgs",
    "ResourceListResult",
    "ResourceLogsArgs",
    "ResourceObjectResult",
    "ResourceSelection",
    "ScaleWorkloadArgs",
    "ServerVersionResult",
    "SubjectAccessReviewArgs",
    "UpdateRouteTlsArgs",
    "UpdateSccArgs",
    "WatchResourceArgs",
    "WatchResult",
]

_NAME = r"^[A-Za-z0-9][A-Za-z0-9._-]*$"
_RESOURCE = r"^[a-z0-9][a-z0-9.-]*$"
_PLAN_HASH = r"^[0-9a-f]{64}$"
_SENSITIVE_RESOURCES = frozenset({"secrets", "oauthaccesstokens", "oauthauthorizetokens"})


class InputModel(BaseModel):
    """Strict base for operation and action inputs."""

    model_config = ConfigDict(extra="forbid")


class EmptyArgs(InputModel):
    """An operation with no arguments."""


class ResourceSelection(InputModel):
    """One explicitly selected served resource partition."""

    group: str = Field(default="", pattern=r"^[A-Za-z0-9.-]*$")
    version: str = Field(pattern=_NAME)
    resource: str = Field(pattern=_RESOURCE)
    kind: str = Field(pattern=_NAME)
    namespace: str | None = Field(default=None, pattern=_NAME)

    @model_validator(mode="after")
    def exclude_sensitive_resources(self) -> ResourceSelection:
        if self.resource in _SENSITIVE_RESOURCES:
            raise ValueError(f"{self.resource} reads are not supported by this connector")
        return self


class AuditFileSource(InputModel):
    """One local audit JSONL source with its authoritative API source and node identity."""

    path: str = Field(min_length=1)
    api_source: str = Field(default="kube-apiserver", pattern=_NAME)
    node: str = Field(min_length=1, pattern=_NAME)


class ManagedAuditSource(InputModel):
    """A local replay envelope for one managed audit transport adapter."""

    transport: Literal["cloudwatch", "event_hub", "pubsub"]
    path: str = Field(min_length=1)
    api_source: str = Field(default="kube-apiserver", pattern=_NAME)
    node: str = Field(default="managed", pattern=_NAME)


class KubeConfig(ConnectorConfig):
    """Native Kubernetes API connection with least-privilege defaults.

    Secret and OAuth token objects are rejected in resource selections. Write and
    destructive permissions are separate from target read credentials.
    """

    base_url: str = ""
    bearer_token: SecretRef | None = None
    bearer_file: str | None = None
    kubeconfig: SecretRef | None = None
    kubeconfig_context: str | None = None
    in_cluster: bool = False
    cluster_name: str = Field(default="cluster", pattern=_NAME)
    namespaces: tuple[str, ...] = ()
    inventory_resources: tuple[ResourceSelection, ...] = Field(
        default_factory=lambda: (
            ResourceSelection(version="v1", resource="pods", kind="Pod"),
            ResourceSelection(version="v1", resource="services", kind="Service"),
            ResourceSelection(version="v1", resource="namespaces", kind="Namespace"),
            ResourceSelection(version="v1", resource="nodes", kind="Node"),
            ResourceSelection(group="apps", version="v1", resource="deployments", kind="Deployment"),
            ResourceSelection(group="apps", version="v1", resource="statefulsets", kind="StatefulSet"),
            ResourceSelection(group="apps", version="v1", resource="daemonsets", kind="DaemonSet"),
        )
    )
    workload_resources: tuple[ResourceSelection, ...] = Field(
        default_factory=lambda: (
            ResourceSelection(version="v1", resource="pods", kind="Pod"),
            ResourceSelection(group="apps", version="v1", resource="deployments", kind="Deployment"),
            ResourceSelection(group="apps", version="v1", resource="statefulsets", kind="StatefulSet"),
            ResourceSelection(group="apps", version="v1", resource="daemonsets", kind="DaemonSet"),
        )
    )
    rbac_resources: tuple[ResourceSelection, ...] = Field(
        default_factory=lambda: (
            ResourceSelection(group="rbac.authorization.k8s.io", version="v1", resource="roles", kind="Role"),
            ResourceSelection(group="rbac.authorization.k8s.io", version="v1", resource="clusterroles", kind="ClusterRole"),
            ResourceSelection(group="rbac.authorization.k8s.io", version="v1", resource="rolebindings", kind="RoleBinding"),
            ResourceSelection(group="rbac.authorization.k8s.io", version="v1", resource="clusterrolebindings", kind="ClusterRoleBinding"),
        )
    )
    policy_reports_enabled: bool = True
    gatekeeper_enabled: bool = True
    page_size: int = Field(default=100, ge=1, le=500)
    max_pages: int = Field(default=1000, ge=1, le=10000)
    watch_timeout_s: int = Field(default=5, ge=1, le=60)
    max_watch_events: int = Field(default=1000, ge=1, le=10000)
    max_log_bytes: int = Field(default=256 * 1024, ge=1024, le=16 * 1024 * 1024)
    max_evidence_bytes: int = Field(default=256 * 1024, ge=1024, le=16 * 1024 * 1024)
    max_owner_depth: int = Field(default=8, ge=1, le=32)
    max_owner_objects: int = Field(default=64, ge=1, le=256)
    max_audit_bytes_per_batch: int = Field(default=1024 * 1024, ge=4096, le=64 * 1024 * 1024)
    max_audit_identities: int = Field(default=4096, ge=128, le=100000)
    audit_files: tuple[AuditFileSource, ...] = ()
    managed_audit_files: tuple[ManagedAuditSource, ...] = ()
    audit_api_source: str = Field(default="kube-apiserver", pattern=_NAME)
    audit_webhook_auth: Literal["bearer", "mtls"] = "bearer"
    include_users_groups: bool = False
    subject_access_review_enabled: bool = False
    raw_arf_enabled: bool = False
    write_enabled: bool = False
    destructive_enabled: bool = False

    @model_validator(mode="after")
    def validate_authentication(self) -> KubeConfig:
        token_sources = sum(
            value is not None for value in (self.bearer_token, self.bearer_file, self.kubeconfig)
        )
        if self.in_cluster:
            if token_sources or self.client_cert is not None:
                raise ValueError("in_cluster cannot be combined with another authentication source")
            if not self.base_url:
                self.base_url = "https://kubernetes.default.svc"
        elif token_sources > 1:
            raise ValueError("configure only one bearer token, token path, or kubeconfig")
        elif token_sources == 0 and self.client_cert is None:
            raise ValueError("bearer token, token path, kubeconfig, in-cluster, or client certificate is required")
        if not self.base_url:
            raise ValueError("base_url is required")
        if (self.client_cert is None) != (self.client_key is None):
            raise ValueError("client_cert and client_key must be configured together")
        if self.watch_timeout_s >= self.timeout_s:
            raise ValueError("timeout_s must be greater than watch_timeout_s")
        return self


class KubePartitionCursor(PageTokenCursor):
    """Independent opaque resourceVersion and audit-safe state per resource partition."""

    token: str | None = None
    issued_at: datetime | None = None
    partitions: dict[str, str] = Field(default_factory=dict)

    def resource_version(self, partition: str) -> str | None:
        return self.partitions.get(partition)

    def advance(self, partition: str, resource_version: str) -> KubePartitionCursor:
        if self.partitions.get(partition) == resource_version:
            return self
        versions = dict(self.partitions)
        versions[partition] = resource_version
        return self.model_copy(update={"partitions": versions})

    def relist(self, partition: str) -> KubePartitionCursor:
        """Forget only the expired partition so no stale cache can close absence."""
        if partition not in self.partitions:
            return self
        versions = dict(self.partitions)
        del versions[partition]
        return self.model_copy(update={"partitions": versions, "token": None})


class KubeSnapshotCursor(SnapshotCursor):
    """Full-list progress with a transient continue token for one resource partition."""

    partition: str | None = None
    continue_token: str | None = None
    resource_version: str | None = None

    def complete_partition(self, partition: str) -> KubeSnapshotCursor:
        done = self.targets_done if partition in self.targets_done else [*self.targets_done, partition]
        return self.model_copy(
            update={"targets_done": done, "partition": None, "continue_token": None, "resource_version": None}
        )


class AuditFilePosition(BaseModel):
    """Durable byte offset plus prefix fingerprint for one rotated audit file identity."""

    offset: int = Field(default=0, ge=0)
    fingerprint: str = ""


class AuditCursor(SequenceCursor):
    """Audit offsets, managed sequences, and bounded cross-transport identity dedupe."""

    seq: int | str = 0
    files: dict[str, AuditFilePosition] = Field(default_factory=dict)
    managed_positions: dict[str, str] = Field(default_factory=dict)
    identities: list[str] = Field(default_factory=list)
    max_identities: int = Field(default=4096, ge=128, le=100000)

    def advance_file(
        self, api_source: str, node: str, file: str, offset: int, fingerprint: str = ""
    ) -> AuditCursor:
        key = f"{api_source}/{node}/{file}"
        position = AuditFilePosition(offset=offset, fingerprint=fingerprint)
        if self.files.get(key) == position:
            return self
        files = dict(self.files)
        files[key] = position
        return self.model_copy(update={"files": files})

    def advance_managed(self, transport: str, source: str, position: str) -> AuditCursor:
        key = f"{transport}/{source}"
        if self.managed_positions.get(key) == position:
            return self
        positions = dict(self.managed_positions)
        positions[key] = position
        return self.model_copy(update={"managed_positions": positions})

    def observe(self, identity: str) -> tuple[AuditCursor, bool]:
        """Return an advanced cursor and whether this identity was already committed."""
        if identity in self.identities:
            return self, True
        identities = [*self.identities, identity]
        if len(identities) > self.max_identities:
            identities = identities[-self.max_identities :]
        return self.model_copy(update={"identities": identities}), False


class GetResourceArgs(InputModel):
    group: str = Field(default="", pattern=r"^[A-Za-z0-9.-]*$")
    version: str = Field(pattern=_NAME)
    resource: str = Field(pattern=_RESOURCE)
    name: str = Field(pattern=_NAME)
    namespace: str | None = Field(default=None, pattern=_NAME)
    kind: str | None = Field(default=None, pattern=_NAME)


class ListResourcesArgs(InputModel):
    group: str = Field(default="", pattern=r"^[A-Za-z0-9.-]*$")
    version: str = Field(pattern=_NAME)
    resource: str = Field(pattern=_RESOURCE)
    namespace: str | None = Field(default=None, pattern=_NAME)
    kind: str | None = Field(default=None, pattern=_NAME)
    limit: int | None = Field(default=None, ge=1, le=500)
    continue_token: str | None = None
    label_selector: str | None = None
    field_selector: str | None = None


class WatchResourceArgs(InputModel):
    group: str = Field(default="", pattern=r"^[A-Za-z0-9.-]*$")
    version: str = Field(pattern=_NAME)
    resource: str = Field(pattern=_RESOURCE)
    namespace: str | None = Field(default=None, pattern=_NAME)
    kind: str | None = Field(default=None, pattern=_NAME)
    label_selector: str | None = None
    field_selector: str | None = None
    resource_version: str | None = None
    timeout_s: int | None = Field(default=None, ge=1, le=60)
    max_events: int | None = Field(default=None, ge=1, le=10000)


class PolicyReportArgs(InputModel):
    group: Literal["wgpolicyk8s.io", "openreports.io"]
    version: str = Field(pattern=_NAME)
    resource: Literal["policyreports", "clusterpolicyreports"]
    name: str = Field(pattern=_NAME)
    namespace: str | None = Field(default=None, pattern=_NAME)

    @model_validator(mode="after")
    def validate_scope(self) -> PolicyReportArgs:
        if self.resource == "policyreports" and self.namespace is None:
            raise ValueError("namespace is required for a namespaced PolicyReport")
        if self.resource == "clusterpolicyreports" and self.namespace is not None:
            raise ValueError("namespace is not valid for a ClusterPolicyReport")
        return self


class SubjectAccessReviewArgs(InputModel):
    user: str = Field(min_length=1)
    groups: tuple[str, ...] = ()
    verb: Literal["get", "list", "watch", "create", "patch", "update", "delete"]
    group: str = Field(default="", pattern=r"^[A-Za-z0-9.-]*$")
    version: str = Field(pattern=_NAME)
    resource: str = Field(pattern=_RESOURCE)
    name: str | None = Field(default=None, pattern=_NAME)
    namespace: str | None = Field(default=None, pattern=_NAME)


class ResourceLogsArgs(InputModel):
    namespace: str = Field(pattern=_NAME)
    name: str = Field(pattern=_NAME)
    container: str | None = Field(default=None, pattern=_NAME)
    tail_lines: int | None = Field(default=None, ge=0, le=10000)
    previous: bool = False
    since_seconds: int | None = Field(default=None, ge=1)
    timestamps: bool = False


class OwnerEvidenceArgs(GetResourceArgs):
    max_depth: int | None = Field(default=None, ge=1, le=32)


class RawArfArgs(InputModel):
    """A configured API-relative Compliance Operator ARF evidence path."""

    path: str = Field(min_length=1)

    @model_validator(mode="after")
    def safe_relative_path(self) -> RawArfArgs:
        if not self.path.startswith("/") or self.path.startswith("//") or ".." in self.path.split("/"):
            raise ValueError("ARF path must be an API-relative absolute path without parent traversal")
        return self


class _ApprovedAction(InputModel):
    approved_plan_hash: str = Field(pattern=_PLAN_HASH)


class _ResourceActionArgs(InputModel):
    group: str = Field(default="", pattern=r"^[A-Za-z0-9.-]*$")
    version: str = Field(pattern=_NAME)
    resource: str = Field(pattern=_RESOURCE)
    name: str = Field(pattern=_NAME)
    namespace: str | None = Field(default=None, pattern=_NAME)
    expected_uid: str | None = Field(default=None, min_length=1)
    expected_resource_version: str = Field(min_length=1)


class AnnotateResourceArgs(_ResourceActionArgs):
    """Exact metadata annotation and label changes."""

    annotations: dict[str, str | None] = Field(default_factory=dict)
    labels: dict[str, str | None] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_changes(self) -> AnnotateResourceArgs:
        if not self.annotations and not self.labels:
            raise ValueError("at least one annotation or label change is required")
        for key in (*self.annotations, *self.labels):
            if not key or len(key) > 253:
                raise ValueError("annotation and label keys must be non-empty and at most 253 characters")
        return self


class ScaleWorkloadArgs(_ResourceActionArgs, _ApprovedAction):
    """ResourceVersion-conditional scale-subresource change."""

    replicas: int = Field(ge=0)
    current_replicas: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_change(self) -> ScaleWorkloadArgs:
        if self.replicas == self.current_replicas:
            raise ValueError("desired replicas must differ from current replicas")
        return self


class DeletePodArgs(_ApprovedAction):
    namespace: str = Field(pattern=_NAME)
    name: str = Field(pattern=_NAME)
    expected_uid: str = Field(min_length=1)
    expected_resource_version: str = Field(min_length=1)
    grace_period_seconds: int | None = Field(default=None, ge=0)


class UpdateRouteTlsArgs(_ApprovedAction):
    namespace: str = Field(pattern=_NAME)
    name: str = Field(pattern=_NAME)
    expected_uid: str = Field(min_length=1)
    expected_resource_version: str = Field(min_length=1)
    termination: Literal["edge", "passthrough", "reencrypt"]
    insecure_edge_termination_policy: Literal["None", "Allow", "Redirect"] | None = None
    certificate_ref: SecretRef | None = None
    private_key_ref: SecretRef | None = None
    ca_certificate_ref: SecretRef | None = None
    destination_ca_certificate_ref: SecretRef | None = None


class InstantiateBuildConfigArgs(_ApprovedAction):
    namespace: str = Field(pattern=_NAME)
    name: str = Field(pattern=_NAME)
    expected_uid: str = Field(min_length=1)
    expected_resource_version: str = Field(min_length=1)


class UpdateSccArgs(_ApprovedAction):
    name: str = Field(pattern=_NAME)
    expected_uid: str = Field(min_length=1)
    expected_resource_version: str = Field(min_length=1)
    changes: dict[str, Any] = Field(min_length=1)

    @model_validator(mode="after")
    def declared_security_fields(self) -> UpdateSccArgs:
        allowed = {
            "allowPrivilegeEscalation", "allowHostNetwork", "allowHostPID", "allowHostIPC",
            "allowPrivilegedContainer", "readOnlyRootFilesystem", "runAsUser", "seLinuxContext",
            "supplementalGroups", "fsGroup", "volumes", "allowedCapabilities",
            "defaultAddCapabilities", "requiredDropCapabilities", "forbiddenSysctls", "allowedUnsafeSysctls",
        }
        unknown = sorted(set(self.changes) - allowed)
        if unknown:
            raise ValueError(f"undeclared SCC fields: {', '.join(unknown)}")
        return self


class ResourceObjectResult(BaseModel):
    data: dict[str, Any]


class ResourceListResult(BaseModel):
    items: list[dict[str, Any]]
    resource_version: str | None
    continue_token: str | None
    complete: bool


class ItemsResult(BaseModel):
    items: list[dict[str, Any]]
    resource_version: str | None = None
    continue_token: str | None = None
    complete: bool
    coverage: dict[str, str] = Field(default_factory=dict)


class WatchResult(BaseModel):
    events: list[dict[str, Any]]
    resource_version: str | None
    relisted: bool
    objects: list[dict[str, Any]] = Field(default_factory=list)


class ApiDiscoveryResult(BaseModel):
    core: dict[str, Any]
    groups: dict[str, Any]
    openapi: dict[str, Any] | None = None
    resources: dict[str, Any] = Field(default_factory=dict)


class ServerVersionResult(BaseModel):
    data: dict[str, Any]


class EvidenceResult(BaseModel):
    content: str
    sha256: str
    size_bytes: int
    media_type: str
    complete: bool = True


class OwnerEvidenceResult(BaseModel):
    items: list[dict[str, Any]]
    complete: bool
