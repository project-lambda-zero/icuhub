# OpenShift runtime profile

This document describes the minimal production runtime profile for ICUHUB on OpenShift. The manifests live in `deploy/openshift/` and are applied with Kustomize. The container image is built from the repository `Dockerfile`.

## Components

| Workload | Kind | Command | Notes |
|---|---|---|---|
| `icuhub-api` | Deployment | `python -m icuhub api --host 0.0.0.0 --port 8080` | HTTP on the `http` port (8080), behind the `icuhub-api` Service and edge-TLS Route. Has `/healthz` probes. Mounts the evidence signing keys. |
| `icuhub-worker` | Deployment | `python -m icuhub worker --relay` | Leased Postgres workers and the outbox relay in one long-running process. No ports, no Service, no probes. Mounts the Kafka CA bundle. |
| `icuhub-migrate` | Job | `python -m icuhub migrate` | One-shot Alembic migration (revision 0004). Uses the migrate owner role. |

The relay is not a CronJob. The worker publishes outbox batches to Kafka from its long-running loop. The profile contains no CronJob.

Shared resources:

- `ServiceAccount icuhub-runtime` with `automountServiceAccountToken: false` and an empty Role. The runtime identity has no Kubernetes API privileges, no SCC grant, and no Route or target-cluster Secret access.
- `icuhub-config` ConfigMap: non-secret settings. Each key maps to a field of `icuhub.settings.Settings`.
- `PodDisruptionBudget icuhub-api` with `minAvailable: 1`.
- NetworkPolicies: `default-deny-all`, plus `allow-api-ingress-from-router`, `allow-dns-egress`, `allow-postgres-egress`, `allow-openbao-egress`, `allow-kafka-egress` (worker only), and `allow-smtp-egress`.
- `optional/vendor-egress.yaml` is not in the kustomization. Apply it only when the deployment needs vendor egress.
- `optional/oidc-egress.yaml` is not in the kustomization. Replace its documentation-reserved `/32` address with the environment's OIDC issuer address, then apply it before enabling OIDC. It permits only TCP 443 from the API to that single address.

All pods run as non-root under the restricted Pod Security profile, with `readOnlyRootFilesystem`, all capabilities dropped, and `RuntimeDefault` seccomp.

## Kafka: TLS and SASL are required

Kafka publishing runs only in the worker. The profile sets `ICUHUB_KAFKA_SECURITY=sasl_ssl`. Plaintext is not a supported profile. The only other accepted value is `ssl`, which keeps TLS without SASL and requires the same CA setup. Do not set `plaintext` for any environment that runs this profile.

Settings used by the worker:

| Setting | Source in this profile |
|---|---|
| `ICUHUB_KAFKA_BOOTSTRAP` | ConfigMap, placeholder broker address |
| `ICUHUB_KAFKA_SECURITY` | ConfigMap, `sasl_ssl` |
| `ICUHUB_KAFKA_CA_FILE` | ConfigMap, `/var/run/icuhub/kafka/ca.pem` |
| `ICUHUB_KAFKA_SASL_MECHANISM` | ConfigMap, `SCRAM-SHA-512` |
| `ICUHUB_KAFKA_SASL_USERNAME_REF` | ConfigMap, `file:/var/run/icuhub/kafka-sasl/username` |
| `ICUHUB_KAFKA_SASL_PASSWORD_REF` | ConfigMap, `file:/var/run/icuhub/kafka-sasl/password` |

The worker accepts only two SecretRef forms: `env:NAME` or `file:/absolute/path`. Any other form is rejected before the broker starts. This profile uses `file:` because the credentials come from mounted Secret files. The SASL username and password are never stored as literal values in the ConfigMap. The CA bundle is mounted read-only from the `icuhub-kafka-ca` Secret, key `ca.pem`, at `/var/run/icuhub/kafka/`. The SASL credentials are mounted read-only from the `icuhub-kafka-sasl` Secret, keys `username` and `password`, at `/var/run/icuhub/kafka-sasl/`. Both Secrets are mounted by the worker only.

NetworkPolicy `allow-kafka-egress` selects `app.kubernetes.io/component: worker` and allows TCP 9092 to the broker namespace. The API has no Kafka egress.

## Target-cluster access

Connector credentials for target clusters are separate from the runtime identity. The runtime ServiceAccount has no RBAC and disables token automount, so the Kubernetes connector cannot use the in-cluster service account token. `in_cluster` reads `/var/run/secrets/kubernetes.io/serviceaccount/token`, which is absent in this profile. Configure target-cluster access with one of:

- `bearer_token` as a SecretRef, or `bearer_file` if the file is provisioned by an operator-controlled mount, or
- `kubeconfig` as a SecretRef, with `kubeconfig_context` if needed.

Do not grant the runtime ServiceAccount any Role, RoleBinding, SCC, Route, or Secret permission for target clusters.

## Database roles

Two database URLs are used, from two Secrets:

- `icuhub-runtime-db`, key `database-url`: the least-privilege runtime role. Mounted as `ICUHUB_DATABASE_URL` in the API and worker.
- `icuhub-migrate-db`, key `database-url`: the owner role. Mounted only in the migrate Job. Migrations create the `SECURITY DEFINER` functions and need owner privileges.

The migrate Job does not mount the OpenBao token and does not mount evidence keys. The Job runs with `automountServiceAccountToken: false`.

## Secrets expected in the namespace

The repository defines no Secret objects. The operator creates these before apply:

| Secret | Keys | Mounted by | Mode |
|---|---|---|---|
| `icuhub-runtime-db` | `database-url` | API, worker (env) | env |
| `icuhub-migrate-db` | `database-url` | migrate Job (env) | env |
| `icuhub-openbao` | `openbao-token` | API, worker at `/var/run/icuhub/runtime` | 0440 |
| `icuhub-evidence-keys` | `signing-key.pem`, `verification-key.pem` | API only at `/var/run/icuhub/evidence` | 0440 |
| `icuhub-kafka-ca` | `ca.pem` | worker only at `/var/run/icuhub/kafka` | 0440 |
| `icuhub-kafka-sasl` | `username`, `password` | worker only at `/var/run/icuhub/kafka-sasl` | 0440 |

Secret volumes use `defaultMode: 288` (0440), which is group-read for the `fsGroup` assigned by the restricted SCC. Only the file KEK provider checks file modes.

## Placeholders to replace

These values in the repository are placeholders and must be replaced before any apply:

- Namespace `icuhub` (`namespace.yaml`, `kustomization.yaml`). Replace it consistently if the environment uses another namespace.
- Image `registry.example.com/icuhub/icuhub` and the digest `sha256:000...000` in `kustomization.yaml`. Set the digest of the image built from this repository.
- Hostnames: `icuhub.apps.example.com` (`ICUHUB_PUBLIC_BASE_URL`, Route), `sso.example.com` (OIDC), `openbao.openbao.svc.cluster.local`, `kafka.kafka.svc.cluster.local:9092`, `smtp.smtp.svc.cluster.local`.
- OIDC issuer address `192.0.2.10/32` in `optional/oidc-egress.yaml`. The placeholder is documentation-reserved and intentionally unusable; replace it before applying that optional policy.
- The `icuhub-kafka-sasl` and `icuhub-kafka-ca` Secret contents, which the operator supplies from the Kafka cluster.

## Apply procedure

1. Build the image: `docker build -t icuhub:<tag> .`, push it, and put its digest in `kustomization.yaml`.
2. Create the namespace-scoped Secrets listed above.
3. Validate: `oc apply --dry-run=server -k deploy/openshift`.
4. If OIDC is enabled, replace the OIDC egress placeholder and apply `deploy/openshift/optional/oidc-egress.yaml`. Apply `vendor-egress.yaml` only for targets that require it.
5. Run the migration: delete any prior `icuhub-migrate` Job, apply, and wait for completion.
6. Apply the profile: `oc apply -k deploy/openshift`.
7. Confirm the API `/healthz` probes pass and the worker logs show the relay running with the Kafka settings accepted.

## Live-only checks

The static tests in `tests/test_openshift_runtime.py` cannot verify these. Check them against a real cluster:

- The worker connects to Kafka over TLS with SASL and publishes an outbox batch.
- Kafka SASL `file:` references resolve through the worker system-secret resolver, and the runtime database URL comes from the mounted `icuhub-runtime-db` Secret. Neither value uses the tenant credential broker.
- The OpenBao token and KEK operations succeed from the API and worker.
- The migration Job completes and the database reaches revision 0004.
- NetworkPolicies allow the required paths and deny the others. With the environment-specific OIDC policy applied, the API can fetch the issuer JWKS document.
- The restricted SCC admits the pods with the `fsGroup` used for 0440 Secret files.
