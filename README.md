# ICUHUB

ICUHUB is a standalone integration hub for enterprise security, engineering, and IT tools.
Each vendor integration is built once, and every internal platform uses it through one
governed, audited path. The first consumer is AILA; others include the posture management
console and other enterprise hubs.

**Status: Phase 0 (design).** There is no runtime code yet. See `docs/HLD.md` section 18
for the roadmap.

## What it does

| Part | Responsibility |
|---|---|
| Connectors | One class per vendor (GitHub, GitLab, Bitbucket, Jira, ServiceNow, F5, Fortify, Nessus, CrowdStrike, Splunk, Sentinel, Prisma Cloud, Wiz, Kubernetes/OpenShift, Google Threat Intelligence, ...) |
| Connection store + credential broker | Tenant-scoped connections; credentials injected server-side, never exposed to consumers |
| Policy + approvals | Every operation classified `read` / `write` / `destructive`; write actions require approval unless three switches are on |
| Audit | Every external call recorded with caller, tenant, correlation ID; hash-chained; exportable as OCSF |
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
| [`docs/HLD.md`](docs/HLD.md) | High-level design |
| [`docs/COMMATRIX.md`](docs/COMMATRIX.md) | Communication matrix (network flows) |
| [`docs/CONNECTOR_GUIDE.md`](docs/CONNECTOR_GUIDE.md) | How to add a connector |
| [`docs/adr/`](docs/adr/) | Architecture decision records |

## Development

```bash
python -m pip install -e ".[dev]"
python -m ruff check .
python -m compileall -q src
python -m pytest -q
```

AI coding agents: start with [`AGENTS.md`](AGENTS.md).

## License

AGPL-3.0. See [`LICENSE`](LICENSE).
