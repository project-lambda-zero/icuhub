"""Kubernetes edition configuration."""

from icuhub.connectors._kube.models import KubeConfig

__all__ = ["KubernetesConfig"]


class KubernetesConfig(KubeConfig):
    """Connection settings for a vanilla Kubernetes API server."""
