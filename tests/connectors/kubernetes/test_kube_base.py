"""Shared Kubernetes connector base: credential sources, mTLS-only auth, health, discovery, webhook token, and action identity."""

from __future__ import annotations

import asyncio
import json
import string
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from icuhub.connectors._kube.base import (
    _MAX_KUBECONFIG_BYTES,
    KubeBase,
    _kubeconfig_token,
    _parse_kubeconfig,
    _TransportAuth,
)
from icuhub.connectors.kubernetes import Kubernetes
from icuhub.kit.errors import ConfigError, WebhookRejected
from icuhub.kit.testing import RouteTransport, make_connector
from icuhub.kit.types import TargetRecord, WebhookDelivery
from icuhub.kit.webhook import SharedToken

RECEIVED = datetime(2026, 11, 4, 12, 0, tzinfo=UTC)
VERSION = ("GET", "/version")
OK_VERSION: dict[tuple[str, str], Any] = {VERSION: {"status": 200, "json": {"gitVersion": "v1.30.2"}}}
BASE = {"base_url": "https://api.example.test", "cluster_name": "prod"}


def _connect(
    config: dict[str, Any],
    routes: dict[tuple[str, str], Any] | None = None,
    secrets: dict[str, bytes] | None = None,
) -> tuple[KubeBase, RouteTransport]:
    transport = RouteTransport(routes if routes is not None else OK_VERSION)
    connector = make_connector(Kubernetes, {**BASE, **config}, transport, secrets or {})
    assert isinstance(connector, KubeBase)
    return connector, transport


def _kubeconfig(*, current: str | None, contexts: dict[str, str], users: dict[str, dict[str, Any]]) -> bytes:
    document: dict[str, Any] = {
        "contexts": [{"name": name, "context": {"user": user}} for name, user in contexts.items()],
        "users": [{"name": name, "user": user} for name, user in users.items()],
    }
    if current is not None:
        document["current-context"] = current
    return json.dumps(document).encode("utf-8")


def test_bearer_secret_is_sent_as_authorization_header() -> None:
    connector, transport = _connect({"bearer_token": {"ref": "cluster-token"}}, secrets={"cluster-token": b"s3cr3t\n"})
    report = asyncio.run(connector.check())
    assert report.status == "healthy"
    assert transport.requests[0].headers["authorization"] == "Bearer s3cr3t"


def test_bearer_file_is_read_and_trimmed(tmp_path: Path) -> None:
    token_path = tmp_path / "token"
    token_path.write_bytes(b"  file-token\n")
    connector, transport = _connect({"bearer_file": str(token_path)})
    asyncio.run(connector.check())
    assert transport.requests[0].headers["authorization"] == "Bearer file-token"


def test_empty_token_path_is_rejected(tmp_path: Path) -> None:
    token_path = tmp_path / "token"
    token_path.write_bytes(b"  \n")
    with pytest.raises(ConfigError, match="empty"):
        _connect({"bearer_file": str(token_path)})


def test_unreadable_token_path_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="cannot read"):
        _connect({"bearer_file": str(tmp_path / "missing")})


def test_kubeconfig_uses_the_named_context_user() -> None:
    raw = _kubeconfig(
        current="prod",
        contexts={"prod": "prod-user", "dev": "dev-user"},
        users={"prod-user": {"token": "prod-token"}, "dev-user": {"token": "dev-token"}},
    )
    connector, transport = _connect(
        {"kubeconfig": {"ref": "kubeconfig"}, "kubeconfig_context": "dev"},
        secrets={"kubeconfig": raw},
    )
    asyncio.run(connector.check())
    assert transport.requests[0].headers["authorization"] == "Bearer dev-token"


def test_kubeconfig_defaults_to_current_context() -> None:
    raw = _kubeconfig(
        current="prod",
        contexts={"prod": "prod-user", "dev": "dev-user"},
        users={"prod-user": {"token": "prod-token"}, "dev-user": {"token": "dev-token"}},
    )
    connector, transport = _connect({"kubeconfig": {"ref": "kubeconfig"}}, secrets={"kubeconfig": raw})
    asyncio.run(connector.check())
    assert transport.requests[0].headers["authorization"] == "Bearer prod-token"


def test_yaml_kubeconfig_with_bearer_token_is_accepted() -> None:
    raw = b"""current-context: prod
contexts:
  - name: prod
    context:
      user: prod-user
users:
  - name: prod-user
    user:
      token: yaml-token
"""
    document = _parse_kubeconfig(raw)
    assert document["current-context"] == "prod"
    assert _kubeconfig_token(raw, None) == "yaml-token"


def test_equivalent_json_kubeconfig_is_accepted() -> None:
    yaml_raw = b"""current-context: prod
contexts:
  - name: prod
    context: {user: prod-user}
users:
  - name: prod-user
    user: {token: shared-token}
"""
    json_raw = json.dumps(_parse_kubeconfig(yaml_raw)).encode("utf-8")
    assert _parse_kubeconfig(json_raw) == _parse_kubeconfig(yaml_raw)
    assert _kubeconfig_token(json_raw, "prod") == "shared-token"


def test_kubeconfig_duplicate_mapping_key_is_rejected() -> None:
    with pytest.raises(ConfigError, match="duplicate key 'current-context'"):
        _parse_kubeconfig(b"current-context: prod\ncurrent-context: dev\n")


def test_kubeconfig_non_mapping_document_is_rejected() -> None:
    with pytest.raises(ConfigError, match="single mapping document"):
        _parse_kubeconfig(b"- contexts\n- users\n")


def test_kubeconfig_python_object_tag_is_rejected() -> None:
    raw = b"!!python/object/apply:os.system ['echo unsafe']\n"
    with pytest.raises(ConfigError, match="valid single YAML or JSON document"):
        _parse_kubeconfig(raw)


def test_oversize_kubeconfig_is_rejected_before_parsing() -> None:
    with pytest.raises(ConfigError, match="exceeds"):
        _parse_kubeconfig(b" " * (_MAX_KUBECONFIG_BYTES + 1))


def test_kubeconfig_context_that_is_not_defined_is_rejected() -> None:
    raw = _kubeconfig(current="prod", contexts={"prod": "prod-user"}, users={"prod-user": {"token": "t"}})
    with pytest.raises(ConfigError, match="context 'missing' not found"):
        _kubeconfig_token(raw, "missing")


def test_kubeconfig_without_selected_context_is_rejected() -> None:
    raw = _kubeconfig(current=None, contexts={"prod": "prod-user"}, users={"prod-user": {"token": "t"}})
    with pytest.raises(ConfigError, match="selects no context"):
        _kubeconfig_token(raw, None)


def test_kubeconfig_user_without_bearer_token_is_rejected() -> None:
    raw = _kubeconfig(
        current="prod",
        contexts={"prod": "prod-user"},
        users={"prod-user": {"client-certificate-data": "Zm9v"}},
    )
    with pytest.raises(ConfigError, match="no bearer token"):
        _connect({"kubeconfig": {"ref": "kubeconfig"}}, secrets={"kubeconfig": raw})


@pytest.fixture
def stub_client_certificate(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("icuhub.kit.http._load_client_chain", lambda *_args: None)


def test_mtls_only_sends_no_authorization_header(stub_client_certificate: None) -> None:
    connector, transport = _connect(
        {"client_cert": {"ref": "cert"}, "client_key": {"ref": "key"}},
        secrets={"cert": b"cert-pem", "key": b"key-pem"},
    )
    report = asyncio.run(connector.check())
    assert report.status == "healthy"
    assert "authorization" not in transport.requests[0].headers


def test_build_auth_returns_transport_auth_that_emits_no_header(stub_client_certificate: None) -> None:
    connector, _ = _connect(
        {"client_cert": {"ref": "cert"}, "client_key": {"ref": "key"}},
        secrets={"cert": b"cert-pem", "key": b"key-pem"},
    )
    auth = asyncio.run(connector.build_auth())
    assert isinstance(auth, _TransportAuth)
    headers = {"x-existing": "preserved"}
    asyncio.run(auth.apply(headers, "GET", "https://api.example.test/version"))
    assert headers == {"x-existing": "preserved"}


def test_mtls_audit_webhook_has_no_header_verifier(stub_client_certificate: None) -> None:
    connector, _ = _connect(
        {"client_cert": {"ref": "cert"}, "client_key": {"ref": "key"}, "audit_webhook_auth": "mtls"},
        secrets={"cert": b"cert-pem", "key": b"key-pem"},
    )
    assert connector.webhook_verifier(b"unused") is None


def test_bearer_audit_webhook_checks_the_shared_token() -> None:
    connector, _ = _connect({"bearer_token": {"ref": "cluster-token"}}, secrets={"cluster-token": b"t"})
    verifier = connector.webhook_verifier(b"hook-secret")
    assert isinstance(verifier, SharedToken)
    good = WebhookDelivery(headers={"authorization": "Bearer hook-secret"}, body=b"{}", received_at=RECEIVED)
    assert verifier.verify(good, now=RECEIVED).delivery_id is None
    bad = WebhookDelivery(headers={"authorization": "Bearer wrong"}, body=b"{}", received_at=RECEIVED)
    with pytest.raises(WebhookRejected):
        verifier.verify(bad, now=RECEIVED)


def test_empty_audit_webhook_secret_is_rejected() -> None:
    connector, _ = _connect({"bearer_token": {"ref": "cluster-token"}}, secrets={"cluster-token": b"t"})
    with pytest.raises(ConfigError):
        connector.webhook_verifier(b"")


def test_action_identity_is_deterministic_sha256_and_hides_raw_key_text() -> None:
    connector, _ = _connect({"bearer_token": {"ref": "cluster-token"}}, secrets={"cluster-token": b"t"})
    key = {"namespace": "orders", "name": "checkout-sensitive-name", "resourceVersion": "7"}
    reordered = {"resourceVersion": "7", "name": "checkout-sensitive-name", "namespace": "orders"}
    identity = connector.action_identity("scale_workload", key)
    assert identity == connector.action_identity("scale_workload", reordered)
    assert len(identity) == 64
    assert identity == identity.lower()
    assert set(identity) <= set(string.hexdigits)
    assert "checkout-sensitive-name" not in identity
    assert "orders" not in identity


def test_action_identity_differs_by_tenant_cluster_action_and_natural_key() -> None:
    connector, _ = _connect({"bearer_token": {"ref": "cluster-token"}}, secrets={"cluster-token": b"t"})
    key = {"namespace": "orders", "name": "checkout", "resourceVersion": "7"}
    baseline = connector.action_identity("scale_workload", key)

    other_cluster, _ = _connect(
        {"cluster_name": "staging", "bearer_token": {"ref": "cluster-token"}}, secrets={"cluster-token": b"t"}
    )
    other_tenant, _ = _connect({"bearer_token": {"ref": "cluster-token"}}, secrets={"cluster-token": b"t"})
    other_tenant.ctx.tenant_id = "other-tenant"

    identities = {
        baseline,
        other_cluster.action_identity("scale_workload", key),
        other_tenant.action_identity("scale_workload", key),
        connector.action_identity("delete_pod", key),
        connector.action_identity("scale_workload", {**key, "resourceVersion": "8"}),
    }
    assert len(identities) == 5


def test_health_unauthorized_marks_cluster_failing() -> None:
    connector, _ = _connect(
        {"bearer_token": {"ref": "cluster-token"}},
        routes={VERSION: {"status": 401, "json": {"message": "unauthorized"}}},
        secrets={"cluster-token": b"t"},
    )
    report = asyncio.run(connector.check())
    assert report.status == "failing"
    assert report.capabilities["ClusterOps"].status == "failing"
    assert report.capabilities["ClusterOps"].reason == "AuthFailed"


def test_health_forbidden_marks_cluster_degraded() -> None:
    connector, _ = _connect(
        {"bearer_token": {"ref": "cluster-token"}},
        routes={VERSION: {"status": 403, "json": {"message": "forbidden"}}},
        secrets={"cluster-token": b"t"},
    )
    report = asyncio.run(connector.check())
    assert report.status == "degraded"
    assert report.capabilities["ClusterOps"].status == "degraded"
    assert report.capabilities["ClusterOps"].reason == "PermissionDenied"


def test_health_healthy_reports_version_and_leaves_other_capabilities_unprobed() -> None:
    connector, _ = _connect({"bearer_token": {"ref": "cluster-token"}}, secrets={"cluster-token": b"t"})
    report = asyncio.run(connector.check())
    assert report.status == "healthy"
    assert report.vendor_version == "v1.30.2"
    assert report.capabilities["ClusterOps"].status == "healthy"
    for name in ("FindingSource", "TelemetrySource"):
        assert report.capabilities[name].status == "not_evaluated"


def test_discover_yields_one_cluster_target() -> None:
    connector, _ = _connect({"bearer_token": {"ref": "cluster-token"}}, secrets={"cluster-token": b"t"})

    async def collect() -> list[TargetRecord]:
        return [target async for target in connector.discover()]

    targets = asyncio.run(collect())
    assert len(targets) == 1
    assert targets[0].source_uid == "prod"
    assert targets[0].kind == Kubernetes.target_kind
