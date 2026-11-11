"""Static invariants for the OpenShift runtime profile (docs/OPENSHIFT_RUNTIME.md).

These tests read the manifests and Dockerfile from disk. They do not contact a cluster.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from icuhub.settings import Settings

ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "deploy" / "openshift"
RUNTIME_SA = "icuhub-runtime"
WORKLOAD_KINDS = {"Deployment", "Job"}
DEFAULT_MODE_0440 = 288
DASHES = re.compile("[\u2013\u2014]")


def _manifest_paths() -> list[Path]:
    return sorted(p for p in DEPLOY.rglob("*.yaml") if "optional" not in p.parts and p.name != "kustomization.yaml")


def _docs(path: Path) -> list[dict[str, Any]]:
    return [doc for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")) if doc is not None]


def _all_docs() -> list[tuple[str, dict[str, Any]]]:
    return [(p.name, doc) for p in _manifest_paths() for doc in _docs(p)]


def _pod_spec(doc: dict[str, Any]) -> dict[str, Any]:
    return doc["spec"]["template"]["spec"]


def _workloads() -> list[dict[str, Any]]:
    return [doc for _, doc in _all_docs() if doc["kind"] in WORKLOAD_KINDS]


def _component(doc: dict[str, Any]) -> str:
    return doc["metadata"]["labels"]["app.kubernetes.io/component"]


def _by_name(name: str) -> dict[str, Any]:
    matches = [doc for _, doc in _all_docs() if doc["metadata"]["name"] == name and doc["kind"] in WORKLOAD_KINDS]
    assert len(matches) == 1, name
    return matches[0]


def _mounts(doc: dict[str, Any]) -> dict[str, str]:
    container = _pod_spec(doc)["containers"][0]
    return {m["name"]: m["mountPath"] for m in container.get("volumeMounts", [])}


def _secret_volumes(doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {v["name"]: v["secret"] for v in _pod_spec(doc).get("volumes", []) if "secret" in v}


def test_manifests_parse_and_declare_kind_and_name() -> None:
    paths = _manifest_paths()
    assert paths, "no manifests found under deploy/openshift"
    for path in paths:
        for doc in _docs(path):
            assert doc.get("apiVersion"), path.name
            assert doc.get("kind"), path.name
            assert doc.get("metadata", {}).get("name"), path.name


def test_no_cluster_scoped_rbac_or_scc_and_empty_role() -> None:
    kinds = {doc["kind"] for _, doc in _all_docs()}
    assert "ClusterRole" not in kinds
    assert "ClusterRoleBinding" not in kinds
    assert "SecurityContextConstraints" not in kinds
    roles = [doc for _, doc in _all_docs() if doc["kind"] == "Role"]
    assert [r["rules"] for r in roles] == [[]]


def test_secrets_are_not_defined_in_repository() -> None:
    assert "Secret" not in {doc["kind"] for _, doc in _all_docs()}


def test_service_account_disables_token_automount() -> None:
    sa = next(doc for _, doc in _all_docs() if doc["kind"] == "ServiceAccount")
    assert sa["metadata"]["name"] == RUNTIME_SA
    assert sa["automountServiceAccountToken"] is False


def test_every_workload_uses_runtime_sa_and_hardened_context() -> None:
    workloads = _workloads()
    assert workloads
    for doc in workloads:
        pod = _pod_spec(doc)
        name = doc["metadata"]["name"]
        assert pod["serviceAccountName"] == RUNTIME_SA, name
        assert pod["automountServiceAccountToken"] is False, name
        assert pod["securityContext"]["runAsNonRoot"] is True, name
        assert pod["securityContext"]["seccompProfile"]["type"] == "RuntimeDefault", name
        for container in pod["containers"]:
            ctx = container["securityContext"]
            assert ctx["allowPrivilegeEscalation"] is False, name
            assert ctx["readOnlyRootFilesystem"] is True, name
            assert ctx["capabilities"]["drop"] == ["ALL"], name
            assert ctx["seccompProfile"]["type"] == "RuntimeDefault", name
            assert "limits" in container["resources"], name


def test_secret_volumes_use_group_read_mode() -> None:
    for doc in _workloads():
        for secret in _secret_volumes(doc).values():
            assert secret["defaultMode"] == DEFAULT_MODE_0440, doc["metadata"]["name"]


def test_evidence_keys_mounted_only_by_api() -> None:
    for doc in _workloads():
        name = doc["metadata"]["name"]
        mounts = _mounts(doc)
        if _component(doc) == "api":
            assert mounts["evidence-keys"] == "/var/run/icuhub/evidence", name
            assert "evidence-keys" in _secret_volumes(doc), name
        else:
            assert "evidence-keys" not in mounts, name
            assert "evidence-keys" not in _secret_volumes(doc), name


def test_openbao_token_mounted_by_runtime_but_not_migration() -> None:
    for doc in _workloads():
        name = doc["metadata"]["name"]
        if _component(doc) == "migrate":
            assert "openbao-token" not in _mounts(doc), name
            assert "openbao-token" not in _secret_volumes(doc), name
        else:
            assert _mounts(doc)["openbao-token"] == "/var/run/icuhub/runtime", name
            assert _secret_volumes(doc)["openbao-token"]["secretName"] == "icuhub-openbao", name


def test_migration_job_is_one_shot_with_exact_argv() -> None:
    job = _by_name("icuhub-migrate")
    assert job["kind"] == "Job"
    assert job["spec"]["backoffLimit"] == 2
    assert job["spec"]["activeDeadlineSeconds"] == 900
    pod = _pod_spec(job)
    assert pod["restartPolicy"] == "Never"
    container = pod["containers"][0]
    assert container["command"] == ["python", "-m", "icuhub", "migrate"]
    db_ref = next(e for e in container["env"] if e["name"] == "ICUHUB_DATABASE_URL")
    assert db_ref["valueFrom"]["secretKeyRef"]["name"] == "icuhub-migrate-db"


def test_api_and_worker_use_runtime_database_secret() -> None:
    for name in ("icuhub-api", "icuhub-worker"):
        container = _pod_spec(_by_name(name))["containers"][0]
        db_ref = next(e for e in container["env"] if e["name"] == "ICUHUB_DATABASE_URL")
        assert db_ref["valueFrom"]["secretKeyRef"] == {"name": "icuhub-runtime-db", "key": "database-url"}, name


def test_api_command_binds_port_and_probes_health_endpoints() -> None:
    api = _by_name("icuhub-api")
    container = _pod_spec(api)["containers"][0]
    assert container["command"] == ["python", "-m", "icuhub", "api", "--host", "0.0.0.0", "--port", "8080"]
    assert container["livenessProbe"]["httpGet"]["path"] == "/healthz"
    assert container["readinessProbe"]["httpGet"]["path"] == "/readyz"
    assert container["startupProbe"]["httpGet"]["path"] == "/healthz"
    assert api["spec"]["replicas"] >= 2


def test_worker_has_no_ports_or_service() -> None:
    worker = _by_name("icuhub-worker")
    container = _pod_spec(worker)["containers"][0]
    assert "ports" not in container
    services = [doc for _, doc in _all_docs() if doc["kind"] == "Service"]
    for svc in services:
        assert svc["spec"]["selector"]["app.kubernetes.io/component"] != "worker"


def test_outbox_relay_runs_inside_long_running_worker() -> None:
    worker = _by_name("icuhub-worker")
    assert worker["kind"] == "Deployment"
    container = _pod_spec(worker)["containers"][0]
    assert container["command"] == ["python", "-m", "icuhub", "worker", "--relay"]


def test_no_relay_cronjob_exists() -> None:
    assert "CronJob" not in {doc["kind"] for _, doc in _all_docs()}


def test_kafka_is_tls_only_with_sasl_and_secret_refs() -> None:
    configmap = next(doc for _, doc in _all_docs() if doc["kind"] == "ConfigMap")
    data = configmap["data"]
    assert data["ICUHUB_KAFKA_SECURITY"] in {"ssl", "sasl_ssl"}
    assert data["ICUHUB_KAFKA_SECURITY"] != "plaintext"
    assert data["ICUHUB_KAFKA_SASL_USERNAME_REF"].startswith("file:/")
    assert data["ICUHUB_KAFKA_SASL_PASSWORD_REF"].startswith("file:/")
    assert data["ICUHUB_KAFKA_CA_FILE"]


def test_kafka_secret_volumes_mounted_only_by_worker() -> None:
    for doc in _workloads():
        name = doc["metadata"]["name"]
        secrets = _secret_volumes(doc)
        if name == "icuhub-worker":
            assert secrets["kafka-ca"]["secretName"] == "icuhub-kafka-ca", name
            assert secrets["kafka-sasl"]["secretName"] == "icuhub-kafka-sasl", name
        else:
            assert "kafka-ca" not in secrets, name
            assert "kafka-sasl" not in secrets, name


def test_route_is_edge_tls_with_redirect_and_targets_api_service() -> None:
    route = next(doc for _, doc in _all_docs() if doc["kind"] == "Route")
    assert route["spec"]["tls"]["termination"] == "edge"
    assert route["spec"]["tls"]["insecureEdgeTerminationPolicy"] == "Redirect"
    assert route["spec"]["to"]["name"] == "icuhub-api"


def test_pdb_protects_api_with_minimum_one() -> None:
    pdb = next(doc for _, doc in _all_docs() if doc["kind"] == "PodDisruptionBudget")
    assert pdb["spec"]["minAvailable"] == 1
    assert pdb["spec"]["selector"]["matchLabels"]["app.kubernetes.io/component"] == "api"


def test_network_policy_default_deny_and_no_worker_ingress() -> None:
    policies = [doc for _, doc in _all_docs() if doc["kind"] == "NetworkPolicy"]
    default = next(p for p in policies if p["metadata"]["name"] == "default-deny-all")
    assert default["spec"]["podSelector"] == {}
    assert set(default["spec"]["policyTypes"]) == {"Ingress", "Egress"}
    for policy in policies:
        selector = policy["spec"].get("podSelector", {})
        is_worker = selector.get("matchLabels", {}).get("app.kubernetes.io/component") == "worker"
        if is_worker:
            assert "ingress" not in policy["spec"], policy["metadata"]["name"]


def test_no_open_cidr_in_any_policy_including_optional() -> None:
    for path in DEPLOY.rglob("*.yaml"):
        for doc in _docs(path):
            if doc.get("kind") != "NetworkPolicy":
                continue
            for direction, peers_key in (("ingress", "from"), ("egress", "to")):
                for rule in doc["spec"].get(direction, []):
                    for peer in rule.get(peers_key, []):
                        block = peer.get("ipBlock", {})
                        assert block.get("cidr") not in {"0.0.0.0/0", "::/0"}, path.name
                        assert not {"0.0.0.0/0", "::/0"}.intersection(block.get("except", [])), path.name


def test_optional_oidc_egress_is_api_only_single_host_https() -> None:
    policy = _docs(DEPLOY / "optional" / "oidc-egress.yaml")[0]
    assert policy["kind"] == "NetworkPolicy"
    assert policy["spec"]["podSelector"] == {"matchLabels": {"app.kubernetes.io/component": "api"}}
    assert policy["spec"]["policyTypes"] == ["Egress"]
    assert "ingress" not in policy["spec"]
    (rule,) = policy["spec"]["egress"]
    assert rule["to"] == [{"ipBlock": {"cidr": "192.0.2.10/32"}}]
    assert rule["ports"] == [{"protocol": "TCP", "port": 443}]


def test_kustomization_lists_only_existing_manifests_and_excludes_optional() -> None:
    kustomization = _docs(DEPLOY / "kustomization.yaml")[0]
    assert kustomization["apiVersion"] == "kustomize.config.k8s.io/v1beta1"
    resources = kustomization["resources"]
    assert not any("optional" in r for r in resources)
    for resource in resources:
        assert (DEPLOY / resource).is_file(), resource
    listed = set(resources)
    on_disk = {p.name for p in _manifest_paths() if p.parent == DEPLOY and p.name != "kustomization.yaml"}
    assert on_disk <= listed, on_disk - listed


def test_kustomization_image_digest_is_sha256_placeholder_format() -> None:
    kustomization = _docs(DEPLOY / "kustomization.yaml")[0]
    image = kustomization["images"][0]
    assert image["name"] == "icuhub"
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", image["digest"])


def test_configmap_keys_map_to_real_settings_fields() -> None:
    configmap = next(doc for _, doc in _all_docs() if doc["kind"] == "ConfigMap")
    for key in configmap["data"]:
        assert key.startswith("ICUHUB_"), key
        field = key.removeprefix("ICUHUB_").lower()
        assert field in Settings.model_fields, key


def test_dockerfile_runs_as_non_root_uid_and_dockerignore_is_default_deny() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    user_lines = [line for line in dockerfile.splitlines() if line.startswith("USER ")]
    assert user_lines == ["USER 10001:0"]
    dockerignore = [
        line.strip()
        for line in (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    assert dockerignore[0] == "**"


def test_new_artifacts_contain_no_em_or_en_dashes() -> None:
    targets = [ROOT / "Dockerfile", ROOT / ".dockerignore", ROOT / "docs" / "OPENSHIFT_RUNTIME.md", *_manifest_paths()]
    targets.extend((DEPLOY / "optional").glob("*.yaml"))
    for path in targets:
        assert not DASHES.search(path.read_text(encoding="utf-8")), path.name
