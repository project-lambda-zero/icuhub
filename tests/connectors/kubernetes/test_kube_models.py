"""Shared Kubernetes model and cursor contracts."""

from __future__ import annotations

from datetime import UTC, datetime
from importlib import import_module

import pytest
from pydantic import ValidationError


def test_every_public_model_is_defined() -> None:
    module = import_module("icuhub.connectors._kube.models")
    assert all(hasattr(module, name) for name in module.__all__)


def test_config_requires_an_authentication_method() -> None:
    models = import_module("icuhub.connectors._kube.models")
    with pytest.raises(ValidationError):
        models.KubeConfig(base_url="https://api.example.test")
    config = models.KubeConfig(
        base_url="https://api.example.test",
        bearer_token={"ref": "cluster-token"},
    )
    assert config.page_size == 100
    assert config.destructive_enabled is False


def test_partition_cursor_preserves_opaque_resource_versions() -> None:
    models = import_module("icuhub.connectors._kube.models")
    cursor = models.KubePartitionCursor(partitions={"pods": "000100"})
    assert cursor.kind == "page_token"
    assert cursor.partitions["pods"] == "000100"
    assert cursor.advance("pods", "000099").partitions["pods"] == "000099"


def test_snapshot_cursor_tracks_partition_completion() -> None:
    models = import_module("icuhub.connectors._kube.models")
    started = datetime(2026, 11, 10, tzinfo=UTC)
    cursor = models.KubeSnapshotCursor(snapshot_id="rv-1", started_at=started)
    done = cursor.complete_partition("pods")
    assert done.targets_done == ["pods"]
    assert cursor.targets_done == []


def test_audit_cursor_is_per_source_and_node() -> None:
    models = import_module("icuhub.connectors._kube.models")
    cursor = models.AuditCursor()
    advanced = cursor.advance_file("kube-apiserver", "node-a", "audit.log", 1024)
    assert advanced.files["kube-apiserver/node-a/audit.log"].offset == 1024
    assert advanced.kind == "sequence"
