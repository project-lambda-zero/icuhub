# ICUHUB

ICUHUB is a standalone integration hub for enterprise security, engineering, and IT tools.
Each vendor integration is built once, and every internal platform uses it through one
governed, audited path. The first consumer is AILA; others include the posture management
console and other enterprise hubs.

**Status: MVP offline implementation complete; live acceptance pending.** Decisions D1-D22 are closed (`docs/adr/`).
The shared schema package [`packages/icuhub-schemas`](packages/icuhub-schemas) (OCSF 1.9.0, SARIF 2.1.0,
CloudEvents envelope, finding fingerprint), durable core runtime, REST/MCP surfaces, all required connector
editions, and F1-F7 flows are implemented with offline fixtures and PostgreSQL integration tests. The OpenShift
runtime profile is included. Live vendor and cluster acceptance is opt-in; remaining target-system uncertainties
are tracked in [`docs/IMPLEMENTATION_GAPS.md`](docs/IMPLEMENTATION_GAPS.md).

## What it does

| Part | Responsibility |
|---|---|
| Connectors | One class per vendor (GitHub, GitLab, Bitbucket, Jira, ServiceNow, F5, Fortify, Nessus, CrowdStrike, Splunk, Sentinel, Prisma Cloud, Wiz, Kubernetes/OpenShift, Google Threat Intelligence, ...) |
| Connection store + credential broker | Tenant-scoped connections; credentials injected server-side, never exposed to consumers |
| Policy + approvals | Every operation classified `read` / `write` / `destructive`; write actions require approval unless three switches are on |
| Audit | Every external call recorded with caller, tenant, correlation ID; hash-chained; exportable as OCSF |
| Evidence export | `GET /v1/cases/{case_id}/evidence-export` returns an Ed25519-signed, tenant-isolated bundle with offline digest, audit-chain, and evidence-reference verification |
| Normalization | OCSF for events and findings, SARIF 2.1.0 for code findings |

## Entry points

| Entry point | Used by |
|---|---|
| REST API (`/v1`) | Platform backends |
| MCP endpoint (`/mcp`) | AI agents |
| Event stream (`icuhub.*` topics) | Subscribers |
| Webhook ingress (`/hooks/{connection_id}`) | Vendors |

## Documents

| Document | Content |
|---|---|
| [`docs/BRD.md`](docs/BRD.md) | Business requirements |
| [`docs/MVP.md`](docs/MVP.md) | MVP scope, per-kind done gates, and delivery phases M1..M7 |
| [`docs/HLD.md`](docs/HLD.md) | High-level design |
| [`docs/COMMATRIX.md`](docs/COMMATRIX.md) | Communication matrix (network flows) |
| [`docs/INTEGRATION_INVENTORY.md`](docs/INTEGRATION_INVENTORY.md) | Integrations in existing consumers and their ICUHUB disposition |
| [`docs/OPTIONS.md`](docs/OPTIONS.md) | Technology options per concern and decision outcomes |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | Delivery phases P0-P10 |
| [`docs/PRIOR_ART.md`](docs/PRIOR_ART.md) | How comparable projects implement integrations, and the lessons ICUHUB takes |
| [`docs/CONNECTOR_FRAMEWORK.md`](docs/CONNECTOR_FRAMEWORK.md) | Connector contract, sync engine, mapping, actions, testing kit |
| [`docs/VENDOR_CONNECTORS.md`](docs/VENDOR_CONNECTORS.md) | Per-vendor API facts and connector specs |
| [`docs/COVERAGE_GAPS.md`](docs/COVERAGE_GAPS.md) | Vendor spec gaps against open-source integration platforms |
| [`docs/CONNECTOR_GUIDE.md`](docs/CONNECTOR_GUIDE.md) | How to add a connector |
| [`docs/adr/`](docs/adr/) | Architecture decision records |

## Development

```bash
python -m pip install -e ".[dev]" -e packages/icuhub-schemas
python -m ruff check .
python -m compileall -q src packages tools
python -m pytest -q --import-mode=importlib packages/icuhub-schemas/tests tests
python tools/license_check.py
```

Evidence export uses an Ed25519 PKCS8 private key and its SubjectPublicKeyInfo public key:
`ICUHUB_EVIDENCE_SIGNING_KEY_FILE` and `ICUHUB_EVIDENCE_VERIFICATION_KEY_FILE`. The private key is
never included in an export. Verify a bundle without database access:

```bash
python -m icuhub.core.evidence_export verify bundle.json --public-key evidence-verification.pem
```

AI coding agents: start with [`AGENTS.md`](AGENTS.md).

## License

AGPL-3.0. See [`LICENSE`](LICENSE).
