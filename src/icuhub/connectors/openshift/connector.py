"""OpenShift API server connector: Route/SCC assessment, Route and BuildConfig actions, and SCC updates."""

from typing import ClassVar, Literal

from icuhub.connectors._kube import actions
from icuhub.connectors._kube.connector import (
    OPENSHIFT_STREAM_SPECS,
    KubeConnectorBase,
    declare_mapper,
    declare_stream,
)
from icuhub.connectors._kube.operations import OPENSHIFT_OPERATIONS
from icuhub.connectors.openshift.models import OpenShiftConfig
from icuhub.kit.types import Scope

__all__ = ["OpenShift"]


class OpenShift(KubeConnectorBase):
    """OpenShift API server connector edition.

    Edition-only streams and actions are bound in the class body so the kit never exposes them on the Kubernetes edition.
    """

    kind: ClassVar[str] = "openshift"
    display_name: ClassVar[str] = "OpenShift"
    version: ClassVar[str] = "0.1.0"
    edition: ClassVar[Literal["openshift"]] = "openshift"
    target_kind: ClassVar[str] = "openshift_cluster"
    config_model: ClassVar[type[OpenShiftConfig]] = OpenShiftConfig
    # The kit has no client-certificate strategy; mTLS is a transport setting on KubeConfig, not an auth mode.
    auth_modes: ClassVar[tuple[str, ...]] = ("BearerToken",)
    flows: ClassVar[tuple[str, ...]] = ("F-113",)
    scopes: ClassVar[tuple[Scope, ...]] = (
        Scope(
            name="cluster_discovery",
            probe="GET /api and GET /apis",
            required_by=("ClusterOps", "FindingSource", "TelemetrySource"),
        ),
        Scope(name="server_version", probe="GET /version", required_by=("ClusterOps",)),
    )

    for _name, _options in OPENSHIFT_STREAM_SPECS.items():
        locals()[f"stream_{_name}"] = declare_stream(_name, _options)
        locals()[f"map_{_name}"] = declare_mapper(_name)
    del _name, _options

    for _operation in OPENSHIFT_OPERATIONS:
        locals()[_operation.__name__] = _operation
    del _operation

    update_route_tls = actions.update_route_tls
    apply_update_route_tls = actions.apply_update_route_tls
    reconcile_update_route_tls = actions.reconcile_update_route_tls
    instantiate_buildconfig = actions.instantiate_buildconfig
    apply_instantiate_buildconfig = actions.apply_instantiate_buildconfig
    reconcile_instantiate_buildconfig = actions.reconcile_instantiate_buildconfig
    update_scc = actions.update_scc
    apply_update_scc = actions.apply_update_scc
    reconcile_update_scc = actions.reconcile_update_scc
