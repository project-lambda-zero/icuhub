# ICUHUB -- Business Requirements Document (BRD)

| Field | Value |
|---|---|
| Document | ICUHUB Business Requirements |
| Prototype name | ICUHUB (working name, no branding work planned) |
| Status | Draft v0.1 |
| Date | 2026-11-05 |
| Companion documents | `HLD.md` (high-level design), `COMMATRIX.md` (communication matrix) |

---

## 1. Purpose

ICUHUB is a standalone integration service. It connects every enterprise security,
engineering, and IT tool (SCM, CI/CD, scanners, SIEM, SOAR, EDR, WAF, DLP, CSPM/CNAPP,
Kubernetes/OpenShift, ticketing, threat intelligence) once, and exposes those
connections to every internal platform through one governed, audited path.

ICUHUB exists so integrations are written once instead of being rebuilt inside each
product. It is deliberately "just an integration hub": connectors, credentials,
policy, audit, normalization. It holds no AI reasoning and no product UI beyond
administration.

## 2. Background

- The AI security platform (AILA) needs to reach external tools from its agents and
  workflows: open fix pull requests, pull scanner findings, query SIEM, block on WAF,
  file tickets.
- The enterprise installation also contains a posture management console and other
  hubs beyond the AI platform. Each of them needs the same integrations.
- Without a shared hub, every platform re-implements the same connectors, stores
  vendor credentials separately, and audits external actions separately (or not at
  all). The result is scattered, unaudited scripts.
- The industry evidence for the pattern: DefectDojo (330+ parsers), AiSOC (91
  connectors), Tracecat (100+ integrations), and entire businesses (Nango, Synqly,
  Merge) exist because every product team rebuilds integrations.
- Decision recorded: ICUHUB is a separate repository and service (option C), not a
  package inside AILA, and not bound to the AILA brand or codebase.

## 3. Problem statement

| # | Problem | Consequence today |
|---|---|---|
| P1 | Each platform builds its own connectors | Duplicated effort, drift between implementations, N x M maintenance |
| P2 | Vendor credentials live in each platform | Wide secret sprawl, failed security reviews, no central rotation |
| P3 | External side effects (WAF block, host isolation, PR creation) are not governed in one place | No single approval policy, no single answer to "who did what to which system" |
| P4 | Every tool speaks its own data format | Each consumer writes its own parsers; findings cannot be correlated across tools |
| P5 | AI agents calling vendors directly | Prompt injection or hallucination can reach production systems without a policy gate |
| P6 | No standard export of findings/audit | Customer SIEM/GRC cannot ingest platform output without custom mapping |

## 4. Goals

| ID | Goal |
|---|---|
| G1 | One implementation per vendor integration, reused by every consumer platform |
| G2 | Zero vendor credentials held by consumers; credentials injected server-side |
| G3 | Every external call passes one policy decision point and lands in one audit trail |
| G4 | All data leaving ICUHUB is normalized: OCSF for events and findings, SARIF 2.1.0 for code findings |
| G5 | AI agents get vendor tools through MCP with the same policy and audit as any other caller |
| G6 | Adding a vendor is: one connector class, one registry entry; it appears on every entry point for every consumer |
| G7 | Deployable on-prem and air-gapped in enterprise Kubernetes/OpenShift |

## 5. Non-goals

| ID | Non-goal | Reason |
|---|---|---|
| NG1 | AI reasoning, agents, prompt handling | Belongs to AILA and other AI consumers |
| NG2 | Being a SIEM, SOAR, data lake, or long-term telemetry store | ICUHUB moves and normalizes data; it does not replace those systems |
| NG3 | Product branding, domains, trademarks, marketing site | It is an internal integration service |
| NG4 | A "unified API" that hides vendor-specific capability | Agents need vendor depth (F5 iRules, Fortify issue metadata); vendor-specific operations stay available |
| NG5 | Running exploitation, sandboxes, or fix loops | Belongs to AILA (VR module + platform sandbox) |
| NG6 | End-user UI for analysts | Consumers own their UIs; ICUHUB ships an admin surface only |
| NG7 | High-volume telemetry through the request/response API | Telemetry flows connector -> event stream -> consumers |

## 6. Stakeholders and personas

| Persona | Needs from ICUHUB |
|---|---|
| Platform engineer (AILA, posture console, other hubs) | A stable REST API, MCP endpoint, event stream, and client SDK; no vendor code in their product |
| AI agent (via AILA) | Discoverable tools per connection, typed schemas, clear `pending_approval` / `denied` results |
| Integration engineer | A small connector contract, an HTTP toolkit (auth, pagination, rate limits, retries), fixtures to prove mappings |
| Security administrator | Register connections, manage credentials, define policy, approve actions, review audit |
| Approver (SOC lead, change manager) | An approvals queue with the full proposed action, evidence, and expiry |
| Auditor / compliance | Tamper-evident audit of every external call, exportable to the customer SIEM in OCSF |
| Customer security review | Central credential custody, least privilege, egress control, data classification |

## 7. Scope

### 7.1 In scope

1. Connector framework (contract, registry, HTTP toolkit, fixtures, proof gate).
2. Connection store (tenant, vendor kind, endpoint, credential reference, settings).
3. Credential broker (storage via secret backend, injection, refresh, rotation).
4. Policy engine (operation classification, allow/deny, approval requirements, three switches, egress rules).
5. Approval workflow (durable, expiring, auditable).
6. Audit log of every external call and every policy decision.
7. Four entry points: REST API, MCP endpoint, event stream, webhook ingress.
8. Ingestion modes: scheduled pull with cursors, webhook push, streaming collectors, report-file parsers.
9. Normalization: shared OCSF/SARIF schema package used by ICUHUB and by consumers.
10. Admin surface: connections, policy, approvals, audit viewer, connector health.
11. Deployment artifacts: container images, Helm chart, OpenShift-compatible manifests.

### 7.2 Out of scope

Everything in section 5, plus: per-consumer business logic, long-term retention of
telemetry beyond the stream retention window, billing.

## 8. Business requirements

| ID | Requirement | Priority |
|---|---|---|
| BR-01 | Any internal platform can use any configured integration without writing vendor code | Must |
| BR-02 | Consumers never receive vendor credentials | Must |
| BR-03 | Every external read, write, and destructive action is policy-checked and audited with caller, tenant, and correlation ID | Must |
| BR-04 | Write and destructive actions support human approval before execution | Must |
| BR-05 | Findings and events are delivered in OCSF; code findings additionally in SARIF 2.1.0 | Must |
| BR-06 | AI agents reach integrations through MCP only, under the same policy | Must |
| BR-07 | Multi-tenant isolation: a tenant's connections, data, and audit are invisible to other tenants | Must |
| BR-08 | Runs on-prem, air-gapped, on Kubernetes and OpenShift | Must |
| BR-09 | Adding a new vendor does not require changes in any consumer | Must |
| BR-10 | Data egress to third parties (for example threat intel lookups) is classified and controllable per connection | Must |
| BR-11 | Audit is exportable to the customer SIEM | Should |
| BR-12 | Vendor-official MCP servers can be governed through ICUHUB instead of being wired into each consumer | Should |
| BR-13 | Connector mappings are proven with replayed vendor-shaped fixtures before being marked live | Must |
| BR-14 | Unmeasured or unknown values are reported as "not measured", never as zero | Must |

## 9. Functional requirements

### 9.1 Connections and credentials

| ID | Requirement |
|---|---|
| FR-CON-01 | Admin can create, update, disable, and delete a connection: tenant, connector kind, display name, slug, base URL, credential reference, settings, egress class, enabled flag |
| FR-CON-02 | Supported auth schemes: API key, basic, bearer token, OAuth 2.0 client credentials, OAuth 2.0 authorization code with refresh, OAuth 1.0a (Jira Server legacy), JWT/service account (GCP, GitHub App), mTLS client certificate, HMAC request signing |
| FR-CON-03 | Credentials are stored in the secret backend; the database stores only a reference |
| FR-CON-04 | Tokens are refreshed automatically before expiry; refresh failures mark the connection `degraded` and emit an event |
| FR-CON-05 | Credential rotation without downtime (new version written, connections switch atomically) |
| FR-CON-06 | Connection health check on demand and on schedule; result exposed via API and events |
| FR-CON-07 | A connection can be scoped to a subset of operations (for example read-only F5) |

### 9.2 Connector framework

| ID | Requirement |
|---|---|
| FR-CNR-01 | A connector is one class implementing one or more capability protocols, registered in one plain dictionary (PR-Agent `GitProvider` pattern, MIT, attributed) |
| FR-CNR-02 | Capability protocols are small and separate; a connector implements only what the vendor supports; no `NotImplementedError` stubs |
| FR-CNR-03 | Vendor-specific operations are exposed in addition to capability operations (`f5.create_irule`, not only `Enforcer.block`) |
| FR-CNR-04 | Every operation declares: name, input schema, output schema, classification (`read` / `write` / `destructive`), egress class, idempotency behaviour |
| FR-CNR-05 | Shared HTTP toolkit: retries with backoff, rate-limit handling (429 / `Retry-After`), pagination helpers, timeouts, TLS settings, proxy support, request signing |
| FR-CNR-06 | Three connector types: native (Python class calling the vendor API), MCP-backed (an upstream vendor MCP server governed by ICUHUB), file parser (uploaded report to findings) |
| FR-CNR-07 | Each connector ships vendor-shaped fixtures; a mapping is "live" only after a fixture replayed through the real connector produces the expected OCSF output; a proof gate reverts the connector and asserts the output disappears |

### 9.3 Policy and approvals

| ID | Requirement |
|---|---|
| FR-POL-01 | Every call is evaluated against policy: caller identity, tenant, connection, operation, classification, arguments, egress class |
| FR-POL-02 | Decisions: `allow`, `deny`, `require_approval`, `preview` |
| FR-POL-03 | Three switches must all be on for a write/destructive action to execute automatically: deployment switch, tenant switch, policy rule switch. All default off. Anything less runs as `preview` and returns the plan |
| FR-POL-04 | Approval is a durable pause: survives restarts, expires after a configured TTL with a recorded `expired` outcome, never hangs |
| FR-POL-05 | Approvals carry: proposed operation, arguments, caller, correlation ID, evidence links supplied by the caller, expiry |
| FR-POL-06 | Approvers are resolved from IdP groups; self-approval by the requesting service is impossible |
| FR-POL-07 | Egress classes: `internal`, `vendor_tenant` (customer's own SaaS tenant), `third_party_shared` (data may join a shared dataset, for example public threat-intel lookups). Policy can deny or require approval per class |
| FR-POL-08 | Replay/simulation mode: calls flagged `mode=replay` can never execute writes; the action layer is the mutation boundary |

### 9.4 Entry points

| ID | Requirement |
|---|---|
| FR-API-01 | REST API (OpenAPI 3.1) for connections, operations, findings, actions, approvals, audit, health |
| FR-API-02 | MCP endpoint (Streamable HTTP) listing tools per caller and tenant, filtered by policy |
| FR-API-03 | Event stream with documented topics and a stable envelope; at-least-once delivery; consumers dedupe by event ID |
| FR-API-04 | Webhook ingress per connection: signature verification, timestamp/replay protection, dedupe by vendor delivery ID, normalization, publish to stream |
| FR-API-05 | Every request carries caller identity (service token or mTLS), tenant, and correlation ID; missing tenant is rejected |
| FR-API-06 | Write operations accept an `Idempotency-Key`; repeated keys return the original result |
| FR-API-07 | Generated Python client SDK from the OpenAPI spec |

### 9.5 Ingestion

| ID | Requirement |
|---|---|
| FR-ING-01 | Scheduled pull with a resumable cursor per connection and stream, and a bounded per-poll budget (backpressure instead of flooding) |
| FR-ING-02 | Push via webhooks (SCM, CI, ticketing, some scanners) |
| FR-ING-03 | Streaming collectors: AWS S3 + SQS notifications, GCP Pub/Sub, Azure Event Hubs, syslog/CEF listener |
| FR-ING-04 | Report-file parsers (Fortify FPR, Nessus XML, Burp, SARIF, CycloneDX, and others) modelled on the DefectDojo parser approach |
| FR-ING-05 | Deduplication by stable fingerprint per finding |

### 9.6 Normalization

| ID | Requirement |
|---|---|
| FR-NRM-01 | Shared schema package (`icuhub-schemas`) with OCSF models (pinned OCSF version) and SARIF 2.1.0 codecs, usable by consumers |
| FR-NRM-02 | Findings map to OCSF Findings classes: Vulnerability Finding (2002), Compliance Finding (2003), Detection Finding (2004), Incident Finding (2005), Data Security Finding (2006) |
| FR-NRM-03 | Activity projection on every event: actor, action, resource, location, outcome; `actor.kind` read from the vendor's documented field, never inferred |
| FR-NRM-04 | Original vendor payload is retained alongside the normalized record (bounded size, reference for oversized) |
| FR-NRM-05 | Fields with no vendor source are left null and flagged unmapped, never defaulted |
| FR-NRM-06 | Code-located findings export as SARIF 2.1.0 (for GitHub code scanning and similar surfaces) |

### 9.7 Audit

| ID | Requirement |
|---|---|
| FR-AUD-01 | One audit record per external call and per policy decision: time, caller, tenant, connection, operation, classification, decision, approval ID, argument digest, result status, latency, correlation ID |
| FR-AUD-02 | Audit records are hash-chained per tenant (tamper-evident) |
| FR-AUD-03 | Audit export to customer SIEM as OCSF (API Activity / Account Change / Web Resources Activity classes as applicable) over syslog TLS, Splunk HEC, or the event stream |
| FR-AUD-04 | Secrets and raw credential material never appear in audit or logs; arguments are digested, with an allowlist of fields kept in clear |

### 9.8 Administration

| ID | Requirement |
|---|---|
| FR-ADM-01 | Admin UI and API: connections, credentials (write-only), policy rules, approvals queue, audit search, connector health, fixture proof status |
| FR-ADM-02 | SSO via OIDC/SAML through the enterprise IdP; RBAC roles: `icuhub_admin`, `icuhub_approver`, `icuhub_auditor`, `icuhub_viewer` |

## 10. Non-functional requirements

| ID | Category | Requirement |
|---|---|---|
| NFR-01 | Security | TLS 1.2+ everywhere; mTLS or OIDC client credentials between services; secrets only in the secret backend |
| NFR-02 | Security | Containers run non-root with arbitrary UID (OpenShift restricted SCC), read-only root filesystem |
| NFR-03 | Security | Default-deny egress; outbound traffic only to registered connection endpoints (through egress proxy where required) |
| NFR-04 | Tenancy | Tenant ID on every row; Postgres row-level security; tenant derived from the caller token, not from an unauthenticated header |
| NFR-05 | Availability | API stateless and horizontally scalable; workers scale independently; no single in-memory state |
| NFR-06 | Durability | Approvals, cursors, webhook deliveries, and outbox events survive restarts |
| NFR-07 | Performance | Proxy overhead for a synchronous operation (excluding vendor latency) p95 under 50 ms [target, not measured] |
| NFR-08 | Performance | Telemetry never flows through the REST API; stream throughput sized per deployment [not measured] |
| NFR-09 | Observability | OpenTelemetry traces and metrics; correlation ID propagated to every span and audit record |
| NFR-10 | Operability | Air-gapped install: all images and charts mirrorable; no runtime internet dependency except configured vendor endpoints |
| NFR-11 | Compatibility | API versioned (`/v1`); breaking changes only with a new major path; event schema versioned |
| NFR-12 | Honesty | Metrics and health report "not measured" or "unknown" instead of zero when no data exists |

## 11. Integration catalog and waves

Wave order is a proposal; the first wave is driven by the first consumers (AILA VR
exploit-and-fix loop, posture console).

| Category | Vendors / systems | Connector type | Wave |
|---|---|---|---|
| SCM | GitHub, GitLab, Bitbucket Cloud, Bitbucket Server, Azure DevOps, Gitea | Native (PR-Agent provider pattern + write side); GitLab MCP optional | 1 |
| CI/CD | GitLab CI, Jenkins, GitHub Actions, Azure Pipelines | Native; Jenkins MCP plugin optional | 2 |
| Ticketing / ITSM | Jira, ServiceNow | Native | 1 |
| SAST / SCA / DAST | Fortify (SSC), Mend, Invicti, Snyk, SonarQube, Checkmarx | Native + file parsers | 2 |
| Vulnerability scanners | Nessus / Tenable, Qualys, Rapid7 | Native + file parsers | 2 |
| WAF / ADC | F5 BIG-IP (iControl REST), F5 Distributed Cloud, Cloudflare, Imperva | Native | 1 (F5) |
| EDR / XDR | CrowdStrike Falcon, Microsoft Defender, SentinelOne | Native or MCP-backed | 2 |
| SIEM | Splunk, Microsoft Sentinel, Google SecOps, Elastic, QRadar | Native or MCP-backed | 2 |
| SOAR | Google SecOps SOAR, Cortex XSOAR, Splunk SOAR | Native or MCP-backed | 3 |
| CSPM / CNAPP | Prisma Cloud, Wiz, Google SCC, AWS Security Hub | Native or MCP-backed | 2 |
| DLP | Microsoft Purview, Symantec DLP, Forcepoint | Native | 3 |
| Container platforms | Kubernetes, OpenShift | MCP-backed (`containers/kubernetes-mcp-server`) or native | 2 |
| Threat intelligence | Google Threat Intelligence (VirusTotal), MISP, OpenCTI | MCP-backed (`google/mcp-security`) or native | 1 (GTI) |
| Cloud log collectors | AWS S3+SQS, GCP Pub/Sub, Azure Event Hubs, syslog/CEF | Streaming collectors | 3 |
| Identity | Okta, Entra ID | Native | 3 |

## 12. Approaches adopted from prior art (copied as approaches, not as code)

| Source | Approach | Where it lands |
|---|---|---|
| PR-Agent (MIT) | `GitProvider` ABC plus plain dict registry; provider implementations for GitHub, GitLab, Bitbucket, Azure DevOps, Gitea, Gerrit | SCM capability; ported with attribution, decoupled from `pr_agent` settings; write side added (branch, commit, open change request, checks, SARIF upload) |
| DefectDojo | Parsers (file in, findings out) separate from connectors (API sync); fingerprint dedup | Ingestion modes, file parsers |
| Nango | Connection ID in, credential injected server-side, token refresh | Credential broker |
| MCP gateway pattern | Central tool discovery, auth, policy, audit for agent tool calls | MCP entry point |
| AiSOC | Earned-executable mappings with replayed fixtures and prove gate; activity projection; preview-before-act with three switches; durable expiring approvals; write adapter as mutation boundary; cursors with bounded poll budget; "not measured" instead of zero | Connector framework, normalization, policy, ingestion |
| GTI Agentic | Data-egress warnings (queries can join a shared dataset) | Egress classes |
| OCSF / SARIF | Vendor-neutral schemas | Shared schema package |

## 13. Constraints

- Separate repository and service; must not import or depend on AILA code.
- Python for the service and connector SDK [proposed; decision D1].
- Postgres for state; secret backend for credentials.
- Runs on Kubernetes and OpenShift (restricted SCC).
- Any third-party dependency adoption (event bus, secret backend, OCSF model library) is decided explicitly before use.

## 14. Assumptions

- Consumers can obtain service identities from the enterprise IdP (OIDC client credentials) or a mesh CA (mTLS).
- Customers provide service accounts with least-privilege scopes in each vendor.
- Vendor API endpoints are reachable from the ICUHUB egress path.

## 15. Dependencies

| Dependency | Purpose | Status |
|---|---|---|
| Enterprise IdP (OIDC/SAML) | Admin SSO, service tokens, approver groups | Required |
| Postgres 15+ | State, audit, outbox | Required |
| Secret backend (Vault, External Secrets, or KMS envelope encryption) | Credentials | Decision D3 |
| Event backbone (Kafka, Redpanda, or NATS JetStream) | Event stream | Decision D2 |
| Container platform (Kubernetes / OpenShift) | Runtime | Required |

## 16. Risks

| ID | Risk | Mitigation |
|---|---|---|
| R1 | Second distributed system adds operational cost (service auth, versioning, two release trains) | Versioned API and events, generated SDK, contract tests in CI of each consumer |
| R2 | Canonical model churn early on | Pin OCSF version; keep raw payload; schema package versioned independently |
| R3 | God-service growth (hub absorbs business logic) | Non-goals enforced in review; ICUHUB contains no product logic |
| R4 | Lowest-common-denominator abstraction | Vendor-specific operations always exposed alongside capability operations |
| R5 | Hub becomes the telemetry bottleneck | Telemetry goes through the stream, never the API |
| R6 | Vendor API drift breaks connectors silently | Scheduled health checks, fixture replays in CI, `degraded` state and events |
| R7 | Agent-triggered destructive actions | Classification, three switches, approvals, replay mode boundary |
| R8 | Credential compromise blast radius | Secret backend, per-connection least privilege, rotation, mTLS, egress allowlist |
| R9 | Single point of failure for all products | HA deployment, stateless API, durable outbox, consumers degrade gracefully when hub is unavailable |

## 17. Success metrics

| Metric | Target |
|---|---|
| Vendor integrations implemented once and used by 2+ consumers | All wave-1 connectors |
| Consumer code paths that call vendors directly | 0 (enforced by consumer-side audit check) |
| External calls with complete audit records | 100% |
| Write/destructive actions executed without a policy decision | 0 |
| Time to add a new read-only connector with fixtures | Tracked; not measured yet |
| Connector mappings live without a passing fixture proof | 0 |

## 18. Open decisions

| ID | Decision | Options | Recommendation |
|---|---|---|---|
| D1 | Service language | Python, Go | Python (shares schema package with consumers, PR-Agent/DefectDojo approaches are Python) |
| D2 | Event backbone | Kafka, Redpanda, NATS JetStream | Undecided; must be asked before adoption |
| D3 | Secret backend | HashiCorp Vault, External Secrets Operator + cloud KMS, envelope encryption in Postgres | Undecided |
| D4 | Deployment model | One ICUHUB per enterprise install shared by all consoles; multi-tenant hosted | One per install |
| D5 | OCSF version pin | Latest stable at implementation time | Pin at Phase 1 |
| D6 | OCSF model library | Own models, or evaluate Prowler `py-ocsf-models` | Evaluate first, ask before adopting |
| D7 | Event envelope | CloudEvents 1.0 with OCSF payload, or custom envelope | CloudEvents 1.0 |
| D8 | First-wave connectors | Section 11 wave 1 | GitHub, GitLab, Jira, F5, GTI |

## 19. Glossary

| Term | Meaning |
|---|---|
| Connector | Code that knows how to talk to one vendor product |
| Connection | A configured instance of a connector for a tenant (endpoint + credentials + settings) |
| Capability | A small protocol a connector may implement (SourceControl, FindingSource, Enforcer, ...) |
| Operation | One callable function on a connection, with schema and classification |
| Classification | `read`, `write`, or `destructive` |
| Egress class | How far data leaves the customer boundary when the operation runs |
| Consumer | Any platform calling ICUHUB (AILA, posture console, other hubs) |
| Correlation ID | Consumer-side identifier (for example an AILA investigation ID) carried through audit and events |
| OCSF | Open Cybersecurity Schema Framework |
| SARIF | Static Analysis Results Interchange Format 2.1.0 |
| MCP | Model Context Protocol |
| Proof gate | Fixture replay that must produce the expected output, and must stop producing it when the connector is reverted |
