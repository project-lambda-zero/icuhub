"""Shared Kubernetes and OpenShift connector configuration and typed API contracts."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from icuhub.kit.cursors import PageTokenCursor, SequenceCursor, SnapshotCursor
from icuhub.kit.types import ConnectorConfig, SecretRef

__all__ = [
    "ApiDiscoveryResult",
    "AnnotateResourceArgs",
    "AuditCursor",
    "AuditFileSource",
    "DeletePodArgs",
    "GetResourceArgs",
    "InstantiateBuildConfigArgs",
    "KubeConfig",
    "KubePartitionCursor",
    "KubeSnapshotCursor",
    "ListResourcesArgs",
    "PolicyReportArgs",
    "ResourceListResult",
    "ResourceObjectResult",
    "RouteTlsArgs",
    "ScaleWorkloadArgs",
    "ServerVersionResult",
    "SubjectAccessReviewArgs",
    "UpdateSccArgs",
    "WatchResourceArgs",
    "WatchResult",
]

_NAME = r"^[A-Za-z0-9][A-Za-z0-9._-]*$"
_RESOURCE = r"^[a-z0-9][a-z0-9.-]*$"
_MAP_KEY = r"^[A-Za-z0-9](?:[A-Za-z0-9._/-]*[A-Za-z0-9])?$"


class InputModel(BaseModel):
    """Strict base for operation and action inputs."""

    model_config = ConfigDict(extra="forbid")


class AuditFileSource(InputModel):
    """One local audit JSONL source with its authoritative API source and node identity."""

    path: str = Field(min_length=1)
    api_source: str = Field(default="kube-apiserver", pattern=_NAME)
    node: str = Field(min_length=1, pattern=_NAME)


class KubeConfig(ConnectorConfig):
    """Kubernetes API connection.

    Least privilege starts with discovery and version reads plus get/list/watch on only the
    enabled resources. Secrets and OAuth token objects are never listed. Action permissions
    must be granted independently. Audit sources require separate local file or receiver access.
    """

    bearer_token: SecretRef | None = None
    page_size: int = Field(default=100, ge=1, le=500)
    max_pages: int = Field(default=1000, ge=1, le=10000)
    watch_timeout_s: int = Field(default=5, ge=1, le=60)
    max_watch_events: int = Field(default=1000, ge=1, le=10000)
    max_audit_bytes_per_batch: int = Field(default=1024 * 1024, ge=4096, le=64 * 1024 * 1024)
    audit_files: tuple[AuditFileSource, ...] = ()
    audit_api_source: str = Field(default="kube-apiserver", pattern=_NAME)
    include_users_groups: bool = False
    destructive_enabled: bool = False

    @model_validator(mode="after")
    def validate_authentication(self) -> KubeConfig:
        if self.bearer_token is None and self.client_cert is None:
            raise ValueError("bearer_token or a client certificate pair is required")
        if (self.client_cert is None) != (self.client_key is None):
            raise ValueError("client_cert and client_key must be configured together")
        if self.watch_timeout_s >= self.timeout_s:
            raise ValueError("timeout_s must be greater than watch_timeout_s")
        return self


class KubePartitionCursor(PageTokenCursor):
    """Page-token cursor carrying an independent opaque resourceVersion per resource partition."""

    token: str | None = None
    issued_at: Any = None
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
        """Mark one resource partition complete; the input cursor is unchanged."""
        done = self.targets_done if partition in self.targets_done else [*self.targets_done, partition]
        return self.model_copy(update={"targets_done": done, "partition": None, "continue_token": None})


class AuditFilePosition(BaseModel):
    """Durable byte offset for one rotated audit file identity."""

    offset: int = Field(default=0, ge=0)


class AuditCursor(SequenceCursor):
    """Durable byte offsets keyed by ``api_source/node/file`` for audit JSONL sources."""

    seq: int | str = 0
    files: dict[str, AuditFilePosition] = Field(default_factory=dict)

    def advance_file(self, api_source: str, node: str, file: str, offset: int) -> AuditCursor:
        """Return a copy with one source/node/file offset advanced."""
        key = f"{api_source}/{node}/{file}"
        current = self.files.get(key)
        if current is not None and current.offset == offset:
            return self
        files = dict(self.files)
        files[key] = AuditFilePosition(offset=offset)
        return self.model_copy(update={"files": files})


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
    resource_version: str | None = None
    timeout_s: int | None = Field(default=None, ge=1, le=60)
    max_events: int | None = Field(default=None, ge=1, le=10000)
    label_selector: str | None = None
    field_selector: str | None = None


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


class _ResourceActionArgs(InputModel):
    group: str = Field(default="", pattern=r"^[A-Za-z0-9.-]*$")
    version: str = Field(pattern=_NAME)
    resource: str = Field(pattern=_RESOURCE)
    name: str = Field(pattern=_NAME)
    namespace: str | None = Field(default=None, pattern=_NAME)
    expected_uid: str | None = Field(default=None, min_length=1)
    expected_resource_version: str = Field(min_length=1)


class AnnotateResourceArgs(_ResourceActionArgs):
    """Exact metadata annotation and label changes for Kubernetes or a Route."""

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


class ScaleWorkloadArgs(_ResourceActionArgs):
    """ResourceVersion-conditional scale-subresource change."""

    replicas: int = Field(ge=0)
    current_replicas: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_change(self) -> ScaleWorkloadArgs:
        if self.replicas == self.current_replicas:
            raise ValueError("desired replicas must differ from current replicas")
        return self


class DeletePodArgs(InputModel):
    namespace: str = Field(pattern=_NAME)
    name: str = Field(pattern=_NAME)
    expected_uid: str = Field(min_length=1)
    expected_resource_version: str = Field(min_length=1)
    grace_period_seconds: int | None = Field(default=None, ge=0)


class RouteTlsArgs(InputModel):
    """Redacted Route TLS inputs; certificate material is resolved only during apply."""

    namespace: str = Field(pattern=_NAME)
    name: str = Field(pattern=_NAME)
    expected_uid: str = Field(min_length=1)
    expected_resource_version: str = Field(min_length=1)
    termination: Literal["edge", "reencrypt", "passthrough"]
    certificate: SecretRef | None = None
    private_key: SecretRef | None = None
    ca_certificate: SecretRef | None = None
    destination_ca_certificate: SecretRef | None = None
    insecure_edge_termination_policy: Literal["Allow", "InsecureEdgeTerminationPolicy", "Redirect", "None"] | None = None

    @model_validator(mode="after")
    def validate_material(self) -> RouteTlsArgs:
        if self.termination == "passthrough":
            if any((self.certificate, self.private_key, self.ca_certificate, self.destination_ca_certificate)):
                raise ValueError("passthrough Routes do not accept certificate material")
            return self
        if self.certificate is None or self.private_key is None:
            raise ValueError("edge and reencrypt Routes require certificate and private_key references")
        if self.termination == "reencrypt" and self.destination_ca_certificate is None:
            raise ValueError("reencrypt Routes require destination_ca_certificate")
        return self


class InstantiateBuildConfigArgs(InputModel):
    namespace: str = Field(pattern=_NAME)
    name: str = Field(pattern=_NAME)
    expected_uid: str = Field(min_length=1)
    expected_resource_version: str = Field(min_length=1)
    request_id: str | None = Field(default=None, min_length=1)


class UpdateSccArgs(InputModel):
    name: str = Field(pattern=_NAME)
    expected_uid: str = Field(min_length=1)
    expected_resource_version: str = Field(min_length=1)
    patch: dict[str, Any]

    @model_validator(mode="after")
    def validate_patch(self) -> UpdateSccArgs:
        if not self.patch:
            raise ValueError("an exact SCC field diff is required")
        if "metadata" in self.patch or "status" in self.patch:
            raise ValueError("SCC updates must patch security fields, not metadata or status")
        return self


class ResourceObjectResult(BaseModel):
    data: dict[str, Any]


class ResourceListResult(BaseModel):
    items: list[dict[str, Any]]
    resource_version: str | None
    continue_token: str | None
    complete: bool


class WatchResult(BaseModel):
    events: list[dict[str, Any]]
    resource_version: str | None
    relisted: bool
    objects: list[dict[str, Any]] = Field(default_factory=list)


class ApiDiscoveryResult(BaseModel):
    core: dict[str, Any]
    groups: dict[str, Any]
    openapi: dict[str, Any] | None = None


class ServerVersionResult(BaseModel):
    data: dict[str, Any]
