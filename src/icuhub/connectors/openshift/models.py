"""OpenShift edition configuration."""

from icuhub.connectors._kube.models import KubeConfig

__all__ = ["OpenShiftConfig"]


class OpenShiftConfig(KubeConfig):
    """Connection settings for an OpenShift API server."""
