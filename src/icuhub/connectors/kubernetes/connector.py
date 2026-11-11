"""Kubernetes API server connector: Gatekeeper, policy reports, inventory, audit, and workload actions."""

from typing import ClassVar, Literal

from icuhub.connectors._kube.connector import (
    KUBERNETES_STREAM_SPECS,
    KubeConnectorBase,
    declare_mapper,
    declare_stream,
)
from icuhub.connectors._kube.operations import KUBERNETES_OPERATIONS
from icuhub.connectors.kubernetes.models import KubernetesConfig
from icuhub.kit.types import Scope

__all__ = ["Kubernetes"]


class Kubernetes(KubeConnectorBase):
    """Kubernetes API server connector edition.

    Edition-only streams are bound in the class body so the kit never exposes them on the OpenShift edition.
    """

    kind: ClassVar[str] = "kubernetes"
    display_name: ClassVar[str] = "Kubernetes"
    version: ClassVar[str] = "0.1.0"
    edition: ClassVar[Literal["kubernetes"]] = "kubernetes"
    target_kind: ClassVar[str] = "kubernetes_cluster"
    config_model: ClassVar[type[KubernetesConfig]] = KubernetesConfig
    # The kit has no client-certificate strategy; mTLS is a transport setting on KubeConfig, not an auth mode.
    auth_modes: ClassVar[tuple[str, ...]] = ("BearerToken",)
    flows: ClassVar[tuple[str, ...]] = ("F-112",)
    scopes: ClassVar[tuple[Scope, ...]] = (
        Scope(
            name="cluster_discovery",
            probe="GET /api and GET /apis",
            required_by=("ClusterOps", "FindingSource", "TelemetrySource"),
        ),
        Scope(name="server_version", probe="GET /version", required_by=("ClusterOps",)),
    )

    for _name, _options in KUBERNETES_STREAM_SPECS.items():
        locals()[f"stream_{_name}"] = declare_stream(_name, _options)
        locals()[f"map_{_name}"] = declare_mapper(_name)
    del _name, _options

    for _operation in KUBERNETES_OPERATIONS:
        locals()[_operation.__name__] = _operation
    del _operation
