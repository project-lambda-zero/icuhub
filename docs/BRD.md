# ICUHUB -- Business Requirements Document (BRD)

| Field | Value |
|---|---|
| Document | ICUHUB Business Requirements |
| Prototype name | ICUHUB (working name, no branding work planned) |
| Status | Draft v0.3 |
| Date | 2026-11-07 |
| Companion documents | `HLD.md` (high-level design), `COMMATRIX.md` (communication matrix), `INTEGRATION_INVENTORY.md` (integrations in existing consumers), `OPTIONS.md` (technology options), `ROADMAP.md` (delivery phases) |

v0.2 appends requirements derived from `INTEGRATION_INVENTORY.md` (inventory rows are
cited as `INV-nn`). Existing IDs are unchanged.

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
| NG8 | Gateway for LLM, embedding, reranker, or speech APIs (INV-84..86) | Model traffic belongs to the enterprise AI gateway; ICUHUB contains no AI code (NG1) |
| NG9 | Mirror for software, tool, model, or symbol downloads (INV-03, INV-72, INV-85) | Supply-chain artifacts belong to the enterprise artifact repository, which already handles signing, scanning, and retention |
| NG10 | Conversational channels of assistant products (Teams bots, chat apps) (INV-64) | Those are product surfaces, not tool integrations. One-way notifications are in scope (FR-NTF-*) |
| NG11 | Hosting the consumers' local analysis engines and lab tooling (INV-31, INV-32, INV-82, INV-83) | They operate on local files and devices next to the consumer; they have no vendor credential or tenant boundary for ICUHUB to govern |
| NG12 | End-user login for consumer platforms (INV-50) | Each consumer federates with the enterprise IdP directly; ICUHUB authenticates its own callers only (HLD section 10) |
| NG13 | Remote command execution and file transfer on managed hosts over SSH/SFTP (INV-40..48) | Decided in ADR-0011 (D9): consumers keep their SSH stacks; host results can enter ICUHUB as result files (FR-ING-06) |

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
| BR-15 | Withdrawn by ADR-0011 (D9): remote host execution stays in consumers (NG13). ID reserved | -- |
| BR-16 | Finding-to-ticket flows are shared: routing to one or more tracker instances, fingerprint deduplication, and status synchronization are implemented once (INV-10..14) (ADR-0015) | Must |
| BR-17 | Outbound notifications (approvals, run results, reports) use one governed notifier path (INV-60, INV-61, COMMATRIX F-035) | Must |
| BR-18 | Each existing consumer can move its vendor integrations to ICUHUB without losing a capability it has today (migration parity, `INTEGRATION_INVENTORY.md` section 4) | Must |
| BR-19 | Segregation of duties: the identity that requests an action, the identity that approves it, and the identity that administers the connection or policy it uses are separable, and the separation is enforceable per tenant | Must |
| BR-20 | Destructive actions can be bound to an external change record (ITSM change or ticket reference) as an approval precondition | Should |
| BR-21 | Data protection: every stored payload has a data class and a retention period; expired data is purged without breaking the audit chain | Must |
| BR-22 | Business continuity: documented recovery point and recovery time objectives, tested restore, and consumer behaviour when ICUHUB is unavailable (NFR-13) | Must |
| BR-23 | Service ownership: published service levels, an owner per connector, and a support path for connector breakage caused by vendor changes (NFR-14) | Should |
| BR-24 | Licensing: every runtime dependency and bundled artifact has a license compatible with distributing ICUHUB under AGPL-3.0 on-prem (NFR-15) | Must |
| BR-25 | Arbitrary outbound HTTP requested by consumers or agents (generic fetch) is governed: destination allowlists, egress class, size limits, and audit (INV-80) | Must |
| BR-26 | Corporate PKI is supported everywhere: per-connection and per-install CA bundles and client certificates; TLS verification cannot be switched off | Must |
| BR-27 | Public vulnerability intelligence (CVE, EPSS, KEV, OSV, distribution advisories) is available to every consumer from one cached, mirrorable source, including in air-gapped installs (INV-02, INV-70) (ADR-0012) | Should |

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
| FR-CON-08 | Webhook secrets rotate with an overlap window in which the current and previous secrets verify (`CONNECTOR_FRAMEWORK.md`, PA-33) |
| FR-CON-09 | Each connection's required vendor scopes are declared in the manifest and probed by `check` (`CONNECTOR_FRAMEWORK.md`, PA-32) |

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
| FR-CNR-08 | The toolkit supports SOAP/XML services (WSDL-described operations, XML request and response codecs, SOAP faults mapped to typed errors) alongside JSON/REST (INV-12) |
| FR-CNR-09 | Transport safety is not configurable away: TLS verification always on (custom CA bundles instead, BR-26); connectors never spawn shell commands carrying credentials or untrusted values; every outbound request goes through the toolkit client |
| FR-CNR-10 | Query languages are built from structured inputs: LDAP filters escaped (RFC 4515), SOAP/SQL-like WHERE clauses parameterized or escaped per vendor rules, JQL values quoted; operation inputs never accept raw query fragments unless the operation is classified for it and audited |
| FR-CNR-11 | Vendor-specific field mappings (custom field IDs, priority tables, severity-to-priority maps) are data on the connection or route, never code, and never forked per customer (INV-11, INV-12) |
| FR-CNR-12 | Each connector has a manifest generated from its code and committed; CI fails on drift; the host refuses unsupported `format_version` or `sdk` ranges (`CONNECTOR_FRAMEWORK.md`, PA-01, PA-02) |
| FR-CNR-13 | Connector lifecycle members: `check`, `discover`, streams, mappers, read operations, plan/apply actions, webhook parsers (section 3.2) (`CONNECTOR_FRAMEWORK.md`, PA-09) |
| FR-CNR-14 | Connector errors use the typed taxonomy (section 3.4); retry and health decisions read the error class only (`CONNECTOR_FRAMEWORK.md`, PA-27) |
| FR-CNR-15 | Manifest declares owner, support tier, and stability per stream, operation, and action; tier and stability rules in section 9 apply (`CONNECTOR_FRAMEWORK.md`, PA-05) |
| FR-CNR-16 | Every connector passes the conformance suite and HTTP contract tests; `core` connectors also pass live acceptance before release (`CONNECTOR_FRAMEWORK.md`, PA-37, PA-38) |
| FR-CNR-17 | Write and destructive actions provide `plan` and `apply`; approvals bind to the plan hash; `apply` re-checks preconditions (`CONNECTOR_FRAMEWORK.md`, PA-26) |
| FR-CNR-18 | Connectors are first-party code in this repository, registered in `CONNECTORS`; ICUHUB loads no connector package from outside the repository (ADR-0018) (`CONNECTOR_FRAMEWORK.md`, PA-07) |
| FR-CNR-19 | Manifest schema changes are classified additive or breaking by a diff tool; breaking changes require a connector major version and a migration (`CONNECTOR_FRAMEWORK.md`, PA-03, PA-04) |

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
| FR-POL-09 | Actions have the states `stale_plan`, `no_op`, `accepted_async`, and `outcome_unknown`; `outcome_unknown` is resolved by reconciliation, never by blind retry (`CONNECTOR_FRAMEWORK.md`, PA-27) |

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
| FR-ING-06 | Tabular and line-oriented result files (CSV, XLSX, JSON, JSONL, plain lines) are ingested through declared mapping profiles (column to field, severity map, fingerprint fields), not ad-hoc parsers; this includes result files that consumers collect from hosts themselves (INV-30, INV-90, INV-91, NG13) |
| FR-ING-07 | Stream checkpoints are typed, versioned, and advanced only in the transaction that writes records and outbox events; resets are audited (`CONNECTOR_FRAMEWORK.md`, PA-12, PA-13) |
| FR-ING-08 | Time-based cursors use tie-breaker IDs and a bounded overlap window (`CONNECTOR_FRAMEWORK.md`, PA-14) |
| FR-ING-09 | Findings are resolved by absence only in a complete `full` run, behind a removal circuit breaker; incomplete or permission-denied targets resolve nothing (`CONNECTOR_FRAMEWORK.md`, PA-15) |
| FR-ING-10 | Targets are discovered per connection with include, exclude, pause, and missing-since aging (`CONNECTOR_FRAMEWORK.md`, PA-10) |
| FR-ING-11 | Parser and mapper failures are quarantined with replay; exhausted jobs go to a visible dead-letter state; no silent disable (`CONNECTOR_FRAMEWORK.md`, PA-18) |
| FR-ING-12 | Sync jobs run under leases with budgets and per-tenant, per-connection, per-kind concurrency caps (`CONNECTOR_FRAMEWORK.md`, PA-17) |
| FR-ING-13 | Rate limits are shared across replicas per connection and per credential and honour `Retry-After` (`CONNECTOR_FRAMEWORK.md`, PA-35) |

### 9.6 Normalization

| ID | Requirement |
|---|---|
| FR-NRM-01 | Shared schema package (`icuhub-schemas`) with OCSF models (pinned OCSF version) and SARIF 2.1.0 codecs, usable by consumers |
| FR-NRM-02 | Findings map to OCSF Findings classes: Vulnerability Finding (2002), Compliance Finding (2003), Detection Finding (2004), Incident Finding (2005), Data Security Finding (2006) |
| FR-NRM-03 | Activity projection on every event: actor, action, resource, location, outcome; `actor.kind` read from the vendor's documented field, never inferred |
| FR-NRM-04 | Original vendor payload is retained alongside the normalized record (bounded size, reference for oversized) |
| FR-NRM-05 | Fields with no vendor source are left null and flagged unmapped, never defaulted |
| FR-NRM-06 | Code-located findings export as SARIF 2.1.0 (for GitHub code scanning and similar surfaces) |
| FR-NRM-07 | Parsing and mapping are separate; each finding records parser and mapper versions; stored raw batches can be re-mapped without a vendor call within retention (`CONNECTOR_FRAMEWORK.md`, PA-19, PA-21) |
| FR-NRM-08 | Source record ID, fingerprint, and delivery ID are distinct; the fingerprint carries an algorithm version and excludes mutable fields (`CONNECTOR_FRAMEWORK.md`, PA-23) |
| FR-NRM-09 | Resources carry canonical asset references (`AssetRef`) in OCSF `resources[].uid`; ICUHUB links findings by asset and does not merge findings across sources (`CONNECTOR_FRAMEWORK.md`, PA-25, PA-40) |

### 9.7 Audit

| ID | Requirement |
|---|---|
| FR-AUD-01 | One audit record per external call and per policy decision: time, caller, tenant, connection, operation, classification, decision, approval ID, argument digest, result status, latency, correlation ID |
| FR-AUD-02 | Audit records are hash-chained per tenant (tamper-evident) |
| FR-AUD-03 | Audit export to customer SIEM as OCSF (API Activity / Account Change / Web Resources Activity classes as applicable) over syslog TLS, Splunk HEC, or the event stream |
| FR-AUD-04 | Secrets and raw credential material never appear in audit or logs; arguments are digested, with an allowlist of fields kept in clear |
| FR-AUD-05 | Retention purge of payloads and audit bodies keeps the hash chain verifiable: purged records leave their digest and chain link, and the purge itself is an audited event (BR-21) |

### 9.8 Administration

| ID | Requirement |
|---|---|
| FR-ADM-01 | Admin UI and API: connections, credentials (write-only), policy rules, approvals queue, audit search, connector health, fixture proof status |
| FR-ADM-02 | SSO via OIDC/SAML through the enterprise IdP; RBAC roles: `icuhub_admin`, `icuhub_approver`, `icuhub_auditor`, `icuhub_viewer` |
| FR-ADM-03 | Segregation-of-duties constraints per tenant: an approver cannot approve an action whose policy rule or connection they changed within a configured window; an admin cannot approve; constraint violations are denials with a recorded reason (BR-19) |
| FR-ADM-04 | Change-record binding: a policy rule can require an external change reference on approval; the reference is validated through a `Tracker` connection (exists, open, approved state) before execution (BR-20) |

### 9.9 Remote host execution (withdrawn)

FR-RX-01..10 are withdrawn by ADR-0011 (D9): remote host execution stays in consumers
(NG13). The IDs stay reserved and are not reused.

### 9.10 Ticket lifecycle (`Tracker`) (ADR-0015)

| ID | Requirement |
|---|---|
| FR-TKT-01 | `Tracker` covers create, get, search, comment, update fields, assign, transition (including close and reopen), link, and attachment; close and reopen are classified `destructive` when the vendor workflow makes them irreversible for the tenant |
| FR-TKT-02 | Ticket creation from a finding is keyed by the finding fingerprint and route: a repeat request updates or comments on the linked ticket instead of opening a duplicate (INV-10) |
| FR-TKT-03 | Routes: a tenant defines routing profiles (connection, project or queue, issue type, labels, assignee rule, one ticket per finding or one summary ticket per batch); one request can fan out to several routes and several instances of the same vendor |
| FR-TKT-04 | Title and body templates per route, rendered in the vendor's format (Atlassian Document Format, wiki markup, HTML, plain text) from the normalized finding |
| FR-TKT-05 | Field mapping per connection: custom field discovery from the vendor, mapping of normalized fields to vendor fields, severity-to-priority tables (INV-11, INV-12) |
| FR-TKT-06 | Status synchronization: ticket state changes (webhook or poll) are normalized and published, and the link between finding and ticket is updated; consumers decide what a state change means for their own records |
| FR-TKT-07 | Partial failure in a fan-out is reported per route; a failed route never blocks or silently skips another (INV-10) |
| FR-TKT-08 | Business prioritization (which findings deserve a ticket, SLA deadlines) stays in the consumer; ICUHUB executes the routing it is given |
| FR-TKT-09 | Outbound ticket writes record the remote revision they produced; matching inbound events are treated as echoes (`CONNECTOR_FRAMEWORK.md`, PA-29) |

### 9.11 Notifications (`Notifier`)

| ID | Requirement |
|---|---|
| FR-NTF-01 | Channels: SMTP (STARTTLS or implicit TLS, optional auth) and chat incoming webhooks (Teams, Slack, Google Chat); further channels are connectors |
| FR-NTF-02 | Messages are rendered from templates owned by the tenant; recipients are resolved from addresses, groups (FR-DIR-*), or approver roles, never hard-coded in code |
| FR-NTF-03 | Approval notifications are emitted for `icuhub.approval.requested`, expiry warnings, and outcomes (COMMATRIX F-035) |
| FR-NTF-04 | Message bodies are classified like any payload (BR-21) and are not written to logs |

### 9.12 Directory lookups (`Directory`)

| ID | Requirement |
|---|---|
| FR-DIR-01 | Read-only lookups of users, groups, group membership, and manager chains over LDAPS and Microsoft Graph |
| FR-DIR-02 | Used by ICUHUB for approver resolution and notification recipients, and exposed to consumers for ticket assignment and ownership questions |
| FR-DIR-03 | Filters are built under FR-CNR-10; the service account is bound read-only |
| FR-DIR-04 | Results are cached with a bounded TTL and invalidated on connection change |

### 9.13 Governed fetch

| ID | Requirement |
|---|---|
| FR-FET-01 | A `web.fetch` operation performs one HTTP(S) request for a consumer or agent and returns a bounded, typed response (status, headers allowlist, body reference) |
| FR-FET-02 | Destinations are checked on every hop (including redirects and DNS resolution) against tenant allowlists and denylists; private, loopback, link-local, and metadata ranges are denied unless a rule allows them explicitly |
| FR-FET-03 | Each destination has an egress class (FR-POL-07); `third_party_shared` destinations follow the same policy as threat-intel lookups |
| FR-FET-04 | Methods other than GET and HEAD are classified `write` |
| FR-FET-05 | Size, time, and redirect limits are enforced and recorded in audit |

### 9.14 MCP server governance

| ID | Requirement |
|---|---|
| FR-MCPG-01 | An operator registers an upstream MCP server as an MCP-backed connection (FR-CNR-06): transport (Streamable HTTP; stdio only from an admin-approved, pinned image or command), credential reference, and the protocol revision it negotiates |
| FR-MCPG-02 | Upstream tools are imported into the operation catalog with an operator-assigned classification; an unclassified tool is not callable |
| FR-MCPG-03 | Calls to upstream tools pass ICUHUB policy, approval, credential injection, and audit exactly like native operations (BR-12) |
| FR-MCPG-04 | A change in the upstream tool list or tool schema marks the connection `degraded` until an operator reviews the diff |
| FR-MCPG-05 | Tool descriptions from upstream servers are treated as untrusted text: length-bounded and shown to approvers as vendor-supplied |

### 9.15 Vulnerability intelligence feeds (ADR-0012)

| ID | Requirement |
|---|---|
| FR-FEED-01 | Feed connectors for NVD CVE API 2.0, FIRST EPSS, CISA KEV, OSV, GitHub advisories, and distribution security trackers, pulled on schedule with cursors (FR-ING-01) |
| FR-FEED-02 | Records are stored in a local mirror and served by query (CVE, package and ecosystem, product), so consumers stop calling the public sources directly |
| FR-FEED-03 | The mirror can be seeded and refreshed from offline bundles for air-gapped installs |
| FR-FEED-04 | Each record carries its source, fetch time, and upstream modification time; stale data is reported as stale, not current |
| FR-FEED-05 | Provider rate limits and API keys are held by ICUHUB; consumers never need a feed API key |

### 9.16 Consumer migration

| ID | Requirement |
|---|---|
| FR-MIG-01 | Every in-scope row of `INTEGRATION_INVENTORY.md` section 4 maps to an ICUHUB connection kind and operation set before the owning consumer migrates |
| FR-MIG-02 | Each migrated operation has a parity fixture: a recorded request and response from the consumer's current behaviour replayed through the ICUHUB connector |
| FR-MIG-03 | Consumers migrate per integration behind their own feature flag; the direct path is removed in the consumer release after the ICUHUB path is verified (no dual-write shims) |
| FR-MIG-04 | Credential import from a consumer's store into the ICUHUB secret backend is a one-time, audited admin operation; the consumer's copy is deleted afterwards |
| FR-MIG-05 | The consumer-side boundary audit (no direct vendor calls) is enabled for each integration once it migrates (success metric in section 17) |

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
| NFR-13 | Continuity | Recovery point objective 15 minutes and recovery time objective 4 hours for state, audit, and pending approvals [proposed targets, not measured]; restore is exercised before each release that changes the schema; consumers queue or fail visibly while ICUHUB is unavailable, never fall back to direct vendor calls |
| NFR-14 | Service levels | API availability 99.5% monthly per install [proposed target, not measured]; connector health and vendor-side outages are reported separately from ICUHUB availability; each connector lists an owner |
| NFR-15 | Licensing | Runtime dependencies and bundled artifacts are OSI-approved and AGPL-3.0-compatible; source-available licenses (ELv2, BSL, SSPL) are excluded from the runtime; licenses are recorded in `OPTIONS.md` at adoption |
| NFR-16 | Data retention | Defaults per data class: raw vendor payloads 30 days, normalized records 180 days, audit 400 days, all tenant-configurable within deployment limits [proposed defaults] |
| NFR-17 | -- | Withdrawn by ADR-0011 (D9); ID reserved |
| NFR-18 | Observability | Per-stream and per-action metrics and health (`CONNECTOR_FRAMEWORK.md` section 11) are exported for every connector (PA-36) |

## 11. Integration catalog and waves

Wave order is a proposal; the first wave is driven by the first consumers (AILA VR
exploit-and-fix loop, posture console) and, since v0.2, by migration parity for the
existing consumers (BR-18). Waves map to roadmap phases: wave 1 = `ROADMAP.md` P5,
wave 2 = P7 to P9, wave 3 = P10.

| Category | Vendors / systems | Connector type | Wave |
|---|---|---|---|
| SCM | GitHub, GitLab (1); Bitbucket Cloud, Bitbucket Server, Azure DevOps, Gitea (3) | Native (PR-Agent provider pattern + write side); GitLab MCP optional | 1 / 3 |
| CI/CD | GitLab CI, Jenkins, GitHub Actions, Azure Pipelines; inbound CI callbacks (INV-06) | Native; Jenkins MCP plugin optional | 2 |
| Ticketing | Jira Cloud and Data Center, several instances per tenant (INV-10, INV-11) | Native | 1 |
| ITSM | ServiceNow, Micro Focus Service Manager, IBM Maximo (SOAP) (INV-12..14) | Native | 2 |
| GRC | RSA Archer (INV-15) | Native | 3 |
| SAST / SCA / DAST | Fortify (SSC) + FPR parser, Mend, OWASP Dependency-Track (2); Invicti, Snyk, SonarQube, Checkmarx (3) | Native + file parsers | 2 / 3 |
| Vulnerability scanners | Tenable Security Center, Nessus Manager + `.nessus` parser (2); Qualys, Rapid7 (3) | Native + file parsers | 2 / 3 |
| Notifications | SMTP (1); Teams, Slack, Google Chat incoming webhooks (2) | Native (`Notifier`) | 1 / 2 |
| Directory | LDAPS, Microsoft Graph users and groups (INV-51, INV-52) | Native (`Directory`) | 2 |
| Generic egress | Governed `web.fetch` (INV-80) | Native | 2 |
| Operator MCP servers | Any upstream MCP server registered by an operator (INV-81) | MCP-backed | 2 |
| Vulnerability intelligence | NVD, EPSS, KEV, OSV, GitHub advisories, distribution trackers (INV-70) (ADR-0012) | Native feed connectors + mirror | 2 |
| Collaboration | Microsoft Graph meetings, transcripts, change notifications (INV-62, INV-63) | Native | 3 |
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

The full survey of comparable security, DevOps, and platform-engineering projects, with
sources and the lesson IDs PA-01..PA-41, is `PRIOR_ART.md`; `CONNECTOR_FRAMEWORK.md`
applies it. The table below lists the approaches adopted before that survey.

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
- Python 3.11+ for the service, connector kit, and schema package (ADR-0004).
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
| OpenBao (Transit key-encryption keys) | Wraps the data keys of envelope-encrypted credentials | Required in production (ADR-0006) |
| Apache Kafka (KRaft), fed by the Postgres outbox | Event stream | Required (ADR-0005) |
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
| R10 | Withdrawn with ADR-0011 (no host execution in ICUHUB); ID reserved | -- |
| R11 | Migration parity gaps keep direct vendor paths alive in consumers | Parity fixtures per migrated operation (FR-MIG-02), consumer-side boundary audit (FR-MIG-05), migration tracked per inventory row |
| R12 | Upstream MCP servers and vendor APIs change faster than connectors | Tool-list diff review (FR-MCPG-04), pinned protocol revisions, scheduled fixture replays (R6) |
| R13 | Shared ticket routing grows into product logic | FR-TKT-08: prioritization stays in consumers; routing profiles are data, reviewed against NG items |

## 17. Success metrics

| Metric | Target |
|---|---|
| Vendor integrations implemented once and used by 2+ consumers | All wave-1 connectors |
| Consumer code paths that call vendors directly | 0 (enforced by consumer-side audit check) |
| External calls with complete audit records | 100% |
| Write/destructive actions executed without a policy decision | 0 |
| Time to add a new read-only connector with fixtures | Tracked; not measured yet |
| Connector mappings live without a passing fixture proof | 0 |
| In-scope inventory rows migrated to ICUHUB per consumer | Tracked per row in `INTEGRATION_INVENTORY.md`; not measured yet |
| Duplicate tickets opened for the same finding and route | 0 |

## 18. Decisions

All decisions D1-D17 are closed. New open decisions are appended as D18 onward with
options and a recommendation, and stay open until an ADR closes them.

| ID | Decision | Options considered | Outcome | ADR |
|---|---|---|---|---|
| D1 | Service language | Python, Go | Python 3.11+ | [0004](adr/0004-service-language-python.md) |
| D2 | Event backbone | Kafka, Redpanda, NATS JetStream, RabbitMQ streams, PostgreSQL outbox only (`OPTIONS.md` section 7) | PostgreSQL transactional outbox feeding Apache Kafka (KRaft) | [0005](adr/0005-event-backbone-postgres-outbox-kafka.md) |
| D3 | Secret backend | HashiCorp Vault, OpenBao, Conjur, External Secrets Operator, envelope encryption in Postgres (`OPTIONS.md` section 8) | AES-256-GCM envelope encryption in Postgres; KEK from OpenBao Transit in production, file KEK in development | [0006](adr/0006-credentials-envelope-encryption-openbao-kek.md) |
| D4 | Deployment model | One ICUHUB per enterprise install; multi-tenant hosted | One per install | [0007](adr/0007-deployment-one-hub-per-install.md) |
| D5 | OCSF version pin | Latest stable at implementation time | OCSF 1.9.0 | [0008](adr/0008-ocsf-1-9-0-own-models.md) |
| D6 | OCSF model library | Own models, Prowler `py-ocsf-models` (`OPTIONS.md` sections 5, 16) | Own Pydantic v2 models validated against the vendored official schema with `jsonschema` | [0008](adr/0008-ocsf-1-9-0-own-models.md) |
| D7 | Event envelope | CloudEvents 1.0, custom envelope | CloudEvents 1.0 structured JSON | [0009](adr/0009-cloudevents-envelope.md) |
| D8 | First-wave connectors | Section 11 wave 1 | GitHub, GitLab, Jira, F5, GTI, SMTP notifier | [0010](adr/0010-wave-1-connectors.md) |
| D9 | Ownership of remote host execution (SSH/SFTP) | ICUHUB `HostAccess` capability; consumers keep their SSH stacks | Consumers keep SSH; BR-15, FR-RX-*, NFR-17 withdrawn | [0011](adr/0011-host-execution-stays-in-consumers.md) |
| D10 | Ownership of public vulnerability-intelligence feeds | ICUHUB feed connectors + mirror; feeds stay in the consumer | ICUHUB mirror in wave 2; consumer clients removed after parity | [0012](adr/0012-vulnerability-intelligence-mirror.md) |
| D11 | Policy engine | Typed rules, OPA/Rego, Cedar, Cerbos, OpenFGA, Casbin (`OPTIONS.md` section 9) | Typed rules in Postgres, evaluated in-process | [0013](adr/0013-policy-typed-rules.md) |
| D12 | Durable execution for actions and approvals | Own Postgres state machine + queue, Temporal, DBOS, Hatchet, Restate, Prefect (`OPTIONS.md` section 10) | Own Postgres state machine and `SKIP LOCKED` job queue | [0014](adr/0014-durable-execution-postgres.md) |
| D13 | Ownership of finding-to-ticket routing, dedupe, and status sync | ICUHUB generic routing; consumers keep ticket logic | ICUHUB generic routing; prioritization stays in consumers | [0015](adr/0015-ticket-routing-in-icuhub.md) |
| D14 | HTTP toolkit dependency set | httpx2, classic httpx, aiohttp, requests stacks (`OPTIONS.md` section 2) | httpx2, tenacity, aiolimiter, Authlib, asyncpg | [0016](adr/0016-http-toolkit-stack.md) |
| D15 | Connector manifest authoring | Generated from code and committed; handwritten YAML; class attributes only (`CONNECTOR_FRAMEWORK.md` section 15) | Generated from code, committed, CI diff | [0017](adr/0017-connector-manifest-generated.md) |
| D16 | Where connector code runs | First-party in-process plus later subprocess tier; container per connector; in-process only | In-process only; first-party connectors in this repository; no third-party loading | [0018](adr/0018-connectors-first-party-in-process.md) |
| D17 | Declarative mapping | Own helpers; JMESPath; jq (`OPTIONS.md` section 17) | JMESPath for extraction, kit helpers for enums and timestamps, Python for the rest | [0019](adr/0019-jmespath-mapping-expressions.md) |

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
