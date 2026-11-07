# ICUHUB -- Technology Options

| Field | Value |
|---|---|
| Document | Options and recommendations per design concern |
| Status | v0.1 (research cutoff 2026-11-06) |
| Feeds | `BRD.md` section 18 (open decisions), `docs/adr/` |

Versions, licenses, and release dates below come from public project pages and release
notes at the research cutoff. Each one is re-checked when the code that uses it is
written ("verify at adoption").

Outcome of the operator decisions (BRD section 18):

| Decision | Section | Outcome | ADR |
|---|---|---|---|
| D1 language | -- | Python 3.11+ | 0004 |
| D2 event backbone | 7 | Postgres outbox feeding Apache Kafka (the recommendation was NATS JetStream) | 0005 |
| D3 secrets | 8 | Envelope encryption in Postgres, OpenBao Transit KEK | 0006 |
| D4 deployment | -- | One ICUHUB per install | 0007 |
| D5, D6 OCSF | 5, 16 | OCSF 1.9.0, own models | 0008 |
| D7 envelope | 7 | CloudEvents 1.0 | 0009 |
| D8 wave 1 | 4 | GitHub, GitLab, Jira, F5, GTI, SMTP notifier | 0010 |
| D9 host execution | 15 | Stays in consumers (the recommendation was ICUHUB) | 0011 |
| D10 vuln-intel feeds | -- | ICUHUB mirror, wave 2 | 0012 |
| D11 policy | 9 | Typed rules in Postgres | 0013 |
| D12 durable execution | 10 | Own Postgres state machine and job queue | 0014 |
| D13 ticket routing | -- | In ICUHUB, prioritization in consumers | 0015 |
| D14 HTTP toolkit | 2 | httpx2, tenacity, aiolimiter, Authlib, asyncpg | 0016 |
| D15 manifest authoring | 1 | Generated from code, committed, CI diff | 0017 |
| D16 connector runtime | 1 | In-process only, first-party connectors (the recommendation added a later subprocess tier for third-party code) | 0018 |
| D17 declarative mapping | 17 | JMESPath (the recommendation was own helpers) | 0019 |

Evaluation criteria applied to every concern:

| Criterion | Meaning |
|---|---|
| Fit | Matches ICUHUB's shape: synchronous governed operations plus durable actions, multi-tenant, policy and audit in ICUHUB |
| License | OSI-approved and compatible with AGPL-3.0 distribution (NFR-15); source-available licenses are excluded from the runtime |
| Air-gap | Runs from mirrored artifacts with no runtime internet dependency (NFR-10) |
| Operations | Number of extra services to run, back up, and upgrade on OpenShift |
| Reuse | Approach worth copying even when the product is rejected |

---

## 1. Connector framework

| Option | License | Fit | Air-gap | Verdict |
|---|---|---|---|---|
| Airbyte declarative manifests (YAML components) with Python escape hatches | CDK MIT; platform ELv2 | ELT replication model (streams, records, state), not governed actions | Possible via private registries; platform too heavy for a library role | Copy the manifest/component split; do not embed |
| Singer / Meltano SDK taps | Apache-2.0 / MIT | Stream replication protocol; no auth, rate-limit, or action semantics in the spec | Good | Copy typed REST stream helpers and bookmark checkpoints |
| Tracecat actions, StackStorm packs, n8n nodes | AGPL-3.0 / Apache-2.0 / Sustainable Use (fair-code) | Workflow products; action + secrets composition is relevant | Mixed; each needs its own stack | Copy Tracecat's action/secrets composition and pinned registry model |
| Nango provider registry and credential broker | ELv2; several features Enterprise-only | Provider metadata separated from auth is the right model | Conditional | Copy provider/auth separation; do not depend on it |
| Steampipe plugins, Synqly, Merge (normalized query or unified API) | AGPL-3.0 / proprietary / proprietary | Wrong runtime shape or hides vendor depth (NG4) | Steampipe yes, Synqly offline licensing, Merge no | Copy Steampipe's scoped limiters only |
| In-process Python registries: PR-Agent `GitProvider`, DefectDojo parsers | MIT / BSD-3-Clause | Closest fit: small protocol, plain registry, fixture-tested parsers | Excellent | Adopt the approach (FR-CNR-01, FR-ING-04) |

**Recommendation:** ICUHUB's own hybrid. Ordinary HTTP vendors are described by a
versioned, JSON-Schema-validated manifest (endpoints, auth strategy, pagination, rate
limits, field extraction); vendors with unusual behaviour are small Python classes
implementing the capability protocols. Both run inside the same execution envelope
(policy, credentials, audit). Manifests are an optimisation added in P2 only if the
first wave shows enough repetition; the Python protocol path is the baseline.

Sources: docs.airbyte.com (declarative component schema), hub.meltano.com/singer/spec,
docs.tracecat.com (custom actions), nango.dev/docs, steampipe.io/docs,
github.com/The-PR-Agent/pr-agent (`git_providers`), DefectDojo parser documentation.

## 2. HTTP toolkit (decision D14)

| Option | Components (version at cutoff) | License | Shared rate limit | Verdict |
|---|---|---|---|---|
| A | httpx2 2.16.0 (maintained continuation of HTTPX), tenacity 9.2.1, aiolimiter 1.3.0, Authlib 1.9.5, asyncpg 0.32.0, stdlib `hmac`/`ssl` | BSD-3 / Apache-2.0 / MIT / BSD-3 / Apache-2.0 | PostgreSQL token bucket keyed by (tenant, connection, vendor account, quota) | Recommended |
| B | httpx 0.28.1 (classic, last release 2024-12), httpx-retries 0.6.0, aiolimiter, redis-py 8.1.0 | BSD-3 / MIT / MIT / MIT | Redis token bucket (Lua) | Acceptable if Redis is mandated anyway |
| C | aiohttp 3.14.5, stamina 26.1.0 or tenacity, Redis bucket | Apache-2.0 + MIT / MIT | Redis | Works; extra dependencies and no gain over A |
| D | requests 2.34.2 + urllib3 Retry | Apache-2.0 / MIT | -- | Synchronous maintenance jobs only |

**Recommendation:** option A. One async client layer around `httpx2.AsyncClient`;
Authlib for OAuth 2.0 flows; a small internal pagination iterator; per-pod `aiolimiter`
pacing plus the authoritative PostgreSQL bucket so limits hold across replicas (HLD
5.5). SOAP (FR-CNR-08) uses the same transport with an XML codec; the SOAP library is a
separate choice made in P8 when Maximo is built.

Sources: pypi.org/project/httpx2, github.com/pydantic/httpx2, pypi.org/project/tenacity,
pypi.org/project/aiolimiter, pypi.org/project/Authlib, pypi.org/project/asyncpg.

## 3. MCP endpoint and gateway

| Option | License | Role | Air-gap | Verdict |
|---|---|---|---|---|
| Official MCP Python SDK 2.3.0, specification revision 2026-07-28 | MIT | Server library for ICUHUB's `/mcp` and client library for MCP-backed connectors | Excellent | Recommended baseline |
| IBM ContextForge 1.1.0 | Apache-2.0 | Federation gateway with virtual servers and team-scoped tool RBAC | High (mirrored images, Helm) | Optional, only if an install needs a separate federation gateway |
| agentgateway 1.7.0 / Envoy-based Agent Router | Apache-2.0 | Proxy with token exchange and CEL policy | High | Alternative where an Envoy estate exists |
| Microsoft MCP Gateway 1.0.0 | MIT | Gateway, Azure/Entra-centric | Medium-low | Not recommended |
| Docker MCP Gateway | MIT (governance features commercial) | Workstation-oriented | Low | Not recommended |
| Lasso MCP Gateway, Kong AI Gateway | MIT (beta) / commercial | Guardrail proxy / enterprise gateway | Partial / licensed | Not recommended |

**Recommendation:** ICUHUB implements `/mcp` itself with the official SDK and stays the
authority for policy, approvals, credentials, and audit. No gateway sits in the default
path. MCP-backed connectors negotiate the protocol revision per vendor (some vendor
servers still speak 2025-06-18 or 2025-11-25). Where a caller identity must reach the
vendor, use OAuth 2.0 token exchange (RFC 8693) with a distinct audience, never raw
`Authorization` passthrough. MCP tool annotations (`readOnlyHint`, `destructiveHint`)
are inputs to classification, never a substitute for it (FR-MCPG-02).

Sources: modelcontextprotocol.io/specification/latest and the 2026-07-28 changelog,
github.com/IBM/mcp-context-forge (v1.1.0), github.com/agentgateway/agentgateway,
github.com/microsoft/mcp-gateway, github.com/docker/mcp-gateway.

## 4. Vendor-official MCP servers (MCP-backed connectors)

| Server | Version at cutoff | License | Air-gap | Wave |
|---|---|---|---|---|
| GitHub MCP Server (local, against GitHub Enterprise Server) | 2.1.0 | MIT | Strong | 1 (read-only bundle) |
| GitLab native `/api/v4/mcp` (Self-Managed 19.5+) | product feature | GitLab license | Strong | 1 (read-only bundle) |
| `containers/kubernetes-mcp-server` (community, not Kubernetes-project official) | 0.1.2 | Apache-2.0 | Strong | 2 (`read_only`, least-privilege RBAC) |
| Jenkins MCP Server plugin | 0.225.x | MIT | Strong | 2 (Streamable HTTP only, restricted account) |
| Splunk MCP Server app | 2.1.0 | Splunk terms | Good on Splunk Enterprise | 2 (controlled beta) |
| google/mcp-security (SecOps, SOAR, GTI, SCC) | per component | Apache-2.0 (services proprietary) | Poor (needs SaaS) | Egress-enabled installs only |
| CrowdStrike falcon-mcp | 0.20.2, maintenance mode | MIT | Poor (needs Falcon SaaS) | Egress-enabled installs only |
| Atlassian remote MCP, Wiz MCP, Microsoft Sentinel MCP, ServiceNow MCP console | hosted | proprietary | Unsuitable disconnected | Egress-enabled installs only |

**Recommendation:** native connectors stay the primary path for wave 1 (GitHub, GitLab,
Jira, F5, GTI) because ICUHUB needs write operations, fixtures, and stable schemas.
Vendor MCP servers are added as MCP-backed connections for read-only breadth, pinned
and mirrored. In strictly disconnected profiles, hosted-only servers are omitted rather
than replaced with community servers.

Sources: github.com/github/github-mcp-server, GitLab MCP documentation,
github.com/containers/kubernetes-mcp-server, plugins.jenkins.io (MCP Server),
Splunkbase (MCP Server app), github.com/google/mcp-security,
github.com/CrowdStrike/falcon-mcp.

## 5. Normalization (decisions D5, D6)

| Option | License | Coverage | Verdict |
|---|---|---|---|
| OCSF 1.9.0 (2026-08-03) canonical JSON, ICUHUB-owned Pydantic models, validation against the official JSON schema export with `jsonschema` | Apache-2.0 (schema, compiler) / MIT (`jsonschema`) | Full: any class the export contains | Recommended (D5 = 1.9.0, D6 = own models) |
| Prowler `py-ocsf-models` 0.10.0 | Apache-2.0 | Partial class coverage, follows its own release cadence | Optional reference; not the system of record |
| SARIF 2.1.0 (OASIS) with `sarif-om` 1.0.4 | MIT | Code findings exchange | Boundary codec (FR-NRM-06); a hand-written codec over the OASIS schema is equally viable |
| CycloneDX 1.7 (ECMA-424) with `cyclonedx-python-lib` 11.x | Apache-2.0 | SBOM and VEX | Boundary codec for `SbomSink` (P8) |
| SPDX 3.0 / 2.3 with `spdx-tools` 0.8.5 | Apache-2.0 | SBOM | Only when a consumer requires SPDX |
| STIX 2.1 with OASIS `stix2` 3.x | BSD-3-Clause | Threat-intel bundles | Boundary codec for `ThreatIntel` imports (P10) |

**Recommendation:** OCSF 1.9.0 is the only canonical representation. Class map:
2002 vulnerability, 2003 compliance, 2004 detection, 2005 incident, 2006 data security,
2007 application security posture, 2008 IAM analysis, 6003 API activity (audit export).
`metadata.version = "1.9.0"`; `type_uid = class_uid * 100 + activity_id`; native
payload kept in `raw_data`; unrepresentable fields in `unmapped`. The schema bundle is
generated at build time and vendored with a digest, so runtime validation needs no
network. SARIF, CycloneDX, and STIX are boundary adapters, kept out of canonical
storage; when an export is lossy the OCSF record remains the source.

Sources: github.com/ocsf/ocsf-schema (release 1.9.0), schema.ocsf.io/1.9.0,
pypi.org/project/ocsf-schema-compiler, github.com/prowler-cloud/py-ocsf-models,
docs.oasis-open.org/sarif/sarif/v2.1.0, cyclonedx.org/specification/overview,
docs.oasis-open.org/cti/stix/v2.1.

## 6. Webhook ingress

| Option | License | Verdict |
|---|---|---|
| ICUHUB-native ingress with per-vendor verifiers and a PostgreSQL inbox | -- | Recommended |
| Standard Webhooks specification + `standardwebhooks` 1.1.0 verifier | Apache-2.0 / MIT | Use for compliant senders (GitLab 19.x signed webhooks) |
| Svix (managed Ingest; OSS dispatch server) | MIT library / commercial Ingest | Ingest is managed SaaS; not usable on-prem for ingress |
| Hookdeck Event Gateway | proprietary SaaS | Not usable disconnected |
| Hookdeck Outpost | Apache-2.0 | Outbound delivery only; not ingress |
| Convoy | ELv2 | Excluded by NFR-15 |

**Recommendation:** ICUHUB-native ingress. Random endpoint ID (at least 128 bits) per
webhook connection; tenant derived from the connection, never from the payload; raw
body verified before parsing; constant-time comparison; current and previous secret
during rotation; per-vendor dedupe key (GitHub `X-GitHub-Delivery`, GitLab `webhook-id`
or `Idempotency-Key`, Bitbucket `X-Request-UUID`, Jira admin webhooks `sha256(body)`
because no delivery ID is documented); `UNIQUE(connection_id, dedupe_key)` with
insert-or-ignore and outbox insert in the same transaction; 202 for new, 200 for
duplicate. Dedupe records are kept for the retention period, not a short cache, because
several vendor schemes do not sign timestamps. Processing is effectively-once; external
effects carry their own idempotency keys.

Sources: github.com/standard-webhooks/standard-webhooks, docs.github.com (validating
webhook deliveries), GitLab webhook documentation, Atlassian Jira webhook
documentation, Bitbucket Cloud webhook documentation, svix.com/ingest,
hookdeck.com/docs, github.com/frain-dev/convoy.

## 7. Event backbone (decisions D2, D7)

| Option | License | Air-gap and operations | Verdict |
|---|---|---|---|
| PostgreSQL transactional outbox feeding NATS JetStream | PostgreSQL License / Apache-2.0 | One server for development (R=1), three for production (R=3); no cloud dependency; released CloudEvents NATS binding | Recommended |
| PostgreSQL outbox + `LISTEN/NOTIFY` only | PostgreSQL License | Smallest footprint; consumers poll ICUHUB; NOTIFY is only a wake-up hint | Development and small installs; same interface |
| Apache Kafka (KRaft) | Apache-2.0 | Separate controllers and brokers; heavy for a hub | Where an enterprise already runs Kafka |
| RabbitMQ streams | MPL-2.0 | Well documented for OpenShift | Acceptable alternative |
| Redpanda | BSL 1.1 (community) | -- | Excluded by NFR-15 |
| Redis Streams | RSALv2 / SSPLv1 / AGPLv3 (Redis 8) | Weaker durability for a canonical log | Not recommended |

**Recommendation:** the outbox row is the canonical record, written in the business
transaction as a structured CloudEvents 1.0 JSON document (D7) with a stable,
tenant-qualified `source` and `id`. A relay claims rows, publishes with a
deterministic message ID derived from `(source, id)`, and marks the row published only
after the broker acknowledges. One `EventPublisher` interface; JetStream as the first
backbone, Kafka as a later adapter only if an install requires it. Consumers dedupe by
`(source, id)` in their own inbox; broker dedupe windows are not permanent dedupe.

Sources: docs.nats.io/concepts/jetstream, postgresql.org/docs (LISTEN, NOTIFY),
kafka.apache.org (KRaft), rabbitmq.com/docs/streams, docs.redpanda.com (licenses),
redis.io (streams), cloudevents.io (spec 1.0.2).

## 8. Secret backend and credential broker (decision D3)

| Option | License | Role | Verdict |
|---|---|---|---|
| Application AES-256-GCM envelope encryption in PostgreSQL (pyca/cryptography) | Apache-2.0 or BSD-3-Clause | Data key per value, tenant/object/field/version as associated data, wrapped by a key-encryption key (KEK) | Mandatory layer for any credential ICUHUB stores |
| OpenBao (Transit, KV, Database engines) | MPL-2.0 | KEK provider (Transit), dynamic database credentials, per-tenant namespaces | Recommended production KEK provider and optional credential source |
| HashiCorp Vault | BSL 1.1 (1.15+); namespaces Enterprise-only | Same role as OpenBao | Adapter for enterprises that already run it; not bundled (NFR-15) |
| CyberArk Conjur OSS | LGPL-3.0 | Secrets server | Adapter only on request |
| External Secrets Operator | Apache-2.0 | Delivers secrets into Kubernetes | Deployment delivery of bootstrap secrets, not the broker |
| SOPS (age) | MPL-2.0 | Encrypted files | Bootstrap only |

**Recommendation:** one `CredentialBroker` with a `KeyProvider` interface. Stored
credentials are always envelope-encrypted in PostgreSQL; the KEK comes from OpenBao
Transit in production, from a read-only file KEK in development, and from Vault or an
HSM where the enterprise already has one. Providers never fall back silently to one
another; a provider outage fails closed. Where OpenBao can issue dynamic credentials
(databases), connections may reference them instead of stored values.

Sources: github.com/openbao/openbao, openbao.org/docs (secrets/transit,
secrets/databases, namespaces), cryptography.io (AEAD), NIST SP 800-38D,
developer.hashicorp.com/vault (license, transit), github.com/cyberark/conjur,
external-secrets.io, getsops.io.

## 9. Policy engine (decision D11)

| Option | License | Model | Air-gap | Notes |
|---|---|---|---|---|
| Typed rules stored in PostgreSQL, evaluated in-process | -- | Closed rule model (match on tenant, caller, connection, operation, classification, egress class, argument predicates from a fixed operator set) | Excellent | Smallest to deploy; rule editing from the admin API is direct; correctness rests on ICUHUB's evaluator and decision-table tests |
| Open Policy Agent (Rego), sidecar or service | Apache-2.0 | General predicates, signed bundles, `opa test` | Strong | CNCF graduated; adds a sidecar and a bundle pipeline; rule editing from the admin UI needs Rego generation |
| Cedar via `cedarpy` | Apache-2.0 | Typed schema, in-process | Excellent | The Python binding is not officially supported; skip-on-error semantics need a defensive wrapper |
| Cerbos PDP | Apache-2.0 (hub commercial) | YAML + CEL | Strong | Pre-1.0 |
| OpenFGA | Apache-2.0 | Relationship tuples + CEL | Strong | Best when relationship traversal dominates; ICUHUB's rules are attribute-based |
| Casbin / PyCasbin | Apache-2.0 | RBAC/ABAC models | Excellent | Weak explanations |

**Recommendation:** typed rules in PostgreSQL (HLD 16.6 shape), evaluated in-process
behind a `PolicyEvaluator` interface that returns `allow`, `deny`, `require_approval`,
or `preview` with stable reason codes, the matched rule IDs, and the policy version
digest. The research pass ranked OPA first for predicate richness; the typed model is
preferred here because ICUHUB's predicates are a closed set, rules are edited per tenant
through the admin API, and it avoids a sidecar and a bundle pipeline. OPA stays the
documented extension if custom predicates become a requirement (new ADR). Every engine
choice fails closed on error or timeout.

Sources: openpolicyagent.org/docs (integration, policy testing), docs.cedarpolicy.com,
docs.cerbos.dev, openfga.dev/docs, casbin.apache.org/docs.

## 10. Durable execution for actions and approvals (decision D12)

| Option | License | Operations | Notes |
|---|---|---|---|
| ICUHUB PostgreSQL state machine (HLD 6.3) with a PostgreSQL job queue (`FOR UPDATE SKIP LOCKED`) | PostgreSQL License | No extra service | Expiry by sweeper, retries by job rows; correctness rests on ICUHUB's transitions and tests |
| Temporal Server + Python SDK | MIT | Separate cluster (frontend, history, matching, worker services, its own database) | Strongest durable timers, signals, and retry boundaries; heaviest to run on-prem |
| DBOS Transact (Python library on PostgreSQL) | MIT (Conductor proprietary) | Library only | Simplest PostgreSQL-only engine; failover model to prove |
| Hatchet | MIT | Separate service + PostgreSQL | Younger |
| Restate | BSL 1.1 | -- | Excluded by NFR-15 |
| Prefect | Apache-2.0 | Separate server | Data pipelines, not business transactions |
| Celery / ARQ + state machine | BSD-3 / MIT | Redis or RabbitMQ broker | ARQ is maintenance-only |

Engine-independent requirements (apply to every option): an execution ledger with a
unique `(tenant, idempotency_key)`; states including `awaiting_approval`, `executing`,
`uncertain`, `succeeded`, `failed`, `expired`; policy re-evaluated immediately before
execution; vendor request IDs persisted; ledger change and outbox row committed
together; an `uncertain` outcome is reconciled through a vendor lookup before any retry;
a non-idempotent destructive call is never retried blindly.

**Recommendation:** ICUHUB's own PostgreSQL state machine and job queue. ICUHUB actions
are short: one approval pause and one vendor call, not long multi-step workflows, so a
separate workflow cluster costs more to operate than it saves. The research pass ranked
Temporal first; it remains the upgrade path (new ADR) if multi-step remediation
workflows enter scope. DBOS is the fallback if the in-house queue proves insufficient.

Sources: docs.temporal.io (timers, message passing), docs.dbos.dev, docs.hatchet.run,
docs.restate.dev (license), docs.prefect.io, docs.celeryq.dev, github.com/python-arq/arq.

## 11. Tamper-evident audit

| Option | License | Verdict |
|---|---|---|
| PostgreSQL append-only per-tenant SHA-256 hash chain with signed checkpoints anchored outside PostgreSQL | PostgreSQL License | Recommended |
| Tessera (tlog-tiles Merkle log) | Apache-2.0 | Upgrade path when independent inclusion and consistency proofs are required |
| Trillian, Sigstore Rekor v1 | Apache-2.0 | Maintenance mode; not for new deployments |
| immudb | BSL 1.1 | Excluded by NFR-15 |

**Recommendation:** in the business transaction, append `tenant_id`, `event_id`,
per-tenant sequence, UTC time, caller, action, resource, outcome, correlation ID,
canonical payload digest, previous hash, and entry hash; unique `(tenant_id, sequence)`;
the chain head is locked per append; the runtime role has no `UPDATE`, `DELETE`, or
`TRUNCATE`. Chain heads are signed periodically with a key outside PostgreSQL and
exported to an independently administered store, because a hash chain alone does not
stop a privileged rewrite. SIEM export (FR-AUD-03) is a derived path: OCSF 1.9.0 API
Activity (`class_uid` 6003) over syslog TLS (RFC 5425) or Splunk HEC, with durable
cursors; SIEM acknowledgement is not integrity evidence.

Sources: postgresql.org/docs (pgcrypto, triggers), github.com/transparency-dev/tessera,
c2sp.org/tlog-tiles, github.com/codenotary/immudb (license), docs.sigstore.dev,
schema.ocsf.io/1.9.0/classes/api_activity.

## 12. Caller authentication, token exchange, tenancy

| Option | License | Verdict |
|---|---|---|
| Any OIDC provider; ICUHUB is a resource server validating short-lived, audience-bound access tokens | -- | Required baseline |
| Keycloak (confidential clients, Standard Token Exchange V2) | Apache-2.0 | Reference IdP for disconnected installs and development |
| Microsoft Entra ID (client credentials, on-behalf-of) | proprietary | Supported where the enterprise uses it; on-behalf-of is not generic RFC 8693 |
| authentik | MIT core | Alternative IdP; delegation support is new |
| Ory Hydra | Apache-2.0 | Headless alternative; token exchange unverified |
| SPIFFE/SPIRE | Apache-2.0 | Optional workload mTLS; agent manifests may not pass restricted SCC |

**Recommendation:** ICUHUB stays IdP-agnostic. Services authenticate with client
credentials; admins with authorization code + PKCE; ID tokens are never API authority.
Where a caller identity must be carried to a vendor or upstream MCP server, use
RFC 8693 token exchange with one target audience, downscoped, lifetime capped by the
subject token, and `sub`, `act`, `azp`, scope, audience, tenant, and exchange ID kept in
audit. `/mcp` follows MCP authorization: protected-resource metadata (RFC 9728),
`resource` indicators (RFC 8707), audience validation on every request, `401` with
`WWW-Authenticate`, no query-string tokens. Every tenant table has row-level security
with `USING` and `WITH CHECK` policies that fail closed when the tenant context is
unset (NFR-04).

Sources: keycloak.org/securing-apps/token-exchange, learn.microsoft.com (client
credentials, on-behalf-of), docs.goauthentik.io, github.com/ory/hydra, spiffe.io/docs,
RFC 8693, RFC 9728, RFC 8707, modelcontextprotocol.io (authorization).

## 13. Client SDK generation

| Option | License | Verdict |
|---|---|---|
| `openapi-python-client` 0.29.1 (includes a fix for code generation from malicious specifications) | MIT | Recommended for Python |
| Hey API `openapi-ts` | MIT | Recommended if a TypeScript consumer appears |
| OpenAPI Generator 7.26.0 | Apache-2.0 | Fallback with broad language coverage |
| Microsoft Kiota | MIT | TypeScript generator still preview |
| Speakeasy, Fern | ELv2 / commercial | Excluded by NFR-15 |

**Recommendation:** generate at build time from the reviewed, versioned OpenAPI
document; stable unique `operationId`s; golden-output no-diff check in CI; token
providers, CA bundles, correlation IDs, idempotency keys, and retries live in a
hand-written wrapper, never in generated files.

Sources: github.com/openapi-generators/openapi-python-client (release v0.29.1),
github.com/hey-api/hey-api, github.com/OpenAPITools/openapi-generator,
github.com/microsoft/kiota, github.com/speakeasy-api/speakeasy (license),
github.com/fern-api/fern.

## 14. Egress control and enterprise PKI

| Layer | Option | License | Verdict |
|---|---|---|---|
| Application | Destination allowlist per connection + fresh TLS context per connection from its versioned CA bundle; explicit proxies; redirects re-authorized | -- | Mandatory (FR-CNR-09, BR-26) |
| Network | Default-deny Kubernetes NetworkPolicy + OpenShift OVN-Kubernetes EgressFirewall | Apache-2.0 | Recommended default |
| Network | Squid forward proxy in CONNECT/splice mode | GPL-2.0-or-later (separate process) | When a central proxy is mandated (COMMATRIX F-034) |
| Network | Istio egress gateway, Cilium egress gateway | Apache-2.0 | Only where the platform team already runs them |

**Recommendation:** application policy binds tenant, operation, credential, destination,
and CA bundle; network policy contains anything the application misses. No TLS
interception of connections that need tenant-specific upstream trust. Containers run
under restricted-v2 SCC: non-root, arbitrary UID, no host networking, no added
capabilities. Legacy `EgressNetworkPolicy` manifests are not used on OVN clusters.

Sources: openshift-docs (egress firewall, SCC), docs.cilium.io (egress gateway),
istio.io (egress gateway), squid-cache.org (ACL), python-httpx.org (SSL, proxies).

## 15. SSH and SFTP library

Not needed: ADR-0011 (D9) keeps remote host execution in the consumers.

## 16. Phase 1 dependency set (decisions D5, D6)

| Package | Role | License | Runtime or build |
|---|---|---|---|
| `pydantic` 2.x | OCSF, SARIF, CloudEvents models | MIT | Runtime |
| `jsonschema` 4.x | Validation against the vendored OCSF and SARIF JSON schemas | MIT | Runtime |
| OCSF 1.9.0 JSON schema export (vendored files with digest) | Validation input | Apache-2.0 | Data file |
| SARIF 2.1.0 JSON schema (OASIS, errata 01) | Validation input | OASIS copyright notice; redistribution terms to verify at adoption | Data file |

`py-ocsf-models`, `sarif-om`, and `cyclonedx-python-lib` are not needed for Phase 1: the
package owns its models and validates them against the official schemas.

## 17. Declarative mapping expressions (decision D17)

| Option | License | Fit | Air-gap | Verdict |
|---|---|---|---|---|
| Own helpers (dotted paths, enum tables, timestamps) | -- | Smallest surface; no filters or projections | Excellent | Recommended; not chosen |
| JMESPath (`jmespath` 1.1.0) | MIT | Standard, specified grammar with a compliance suite; filters and projections over nested JSON; pure Python | Excellent | Chosen (ADR-0019) |
| jq (Python bindings) | MIT (jq), bindings vary | Most expressive, Turing-complete; native extension | Needs native wheels per platform | Rejected: mappings become programs |

Guard rails from the survey (`PRIOR_ART.md` PA-20): expressions compile at module load,
built-in functions only, extraction only, typed validation in the OCSF models, and every
expression change bumps the mapper version and its golden fixtures
(`CONNECTOR_FRAMEWORK.md` section 6.1). Version re-checked at adoption (P2).

Sources: jmespath.org (specification), pypi.org/project/jmespath (1.1.0, MIT,
Python >= 3.9), jqlang.org.
