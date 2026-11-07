# ICUHUB -- Integration Inventory

| Field | Value |
|---|---|
| Document | Inventory of external integrations in existing consumer platforms |
| Status | v0.1 |
| Date | 2026-11-06 |
| Method | Read-only code scans of each consumer repository; one row per external system, grounded in code locations |
| Companion documents | `BRD.md` v0.2 (BR-16..27, NG8..13, FR-CNR-08..11, FR-TKT, FR-NTF, FR-DIR, FR-FET, FR-MCPG, FR-FEED, FR-MIG, NFR-13..16; decisions D1..D14 closed in ADR-0004..0016), `OPTIONS.md`, `ROADMAP.md` |

---

## 1. Purpose

ICUHUB replaces the vendor code that every platform writes for itself. Before designing
connectors, this document records what the existing platforms already integrate with,
how they do it today, and what that means for ICUHUB: which capability covers it, which
connector type, which delivery wave, or why it stays outside ICUHUB.

Code locations, internal host names, and private project names are kept in a private
working file outside this repository (AGENTS.md 5.7). This document uses consumer
aliases.

## 2. Consumers scanned

| Alias | Platform | Stack | External systems found |
|---|---|---|---|
| AILA | AI security platform (VR, malware, forensics, vulnerability modules) | Python, FastAPI, ARQ, Postgres | 39 (platform 21, vulnerability + forensics 17, VR + malware 8; overlaps merged below) |
| C-SCAN | Scan-orchestration platform: SSH playbooks against hosts, multi-instance Jira ticketing | Python, FastAPI, ARQ, Postgres | 7 |
| C-APPSEC | AppSec middleware (legacy PHP app, Python rewrite in design) fronting SAST, SCA, vulnerability management, ITSM, and GRC tools | PHP / MySQL (legacy), Python (target) | 22 |
| C-ASSIST | Enterprise assistant platform (chat, meeting pipeline, usage panel) on a third-party agent framework | Python | 13 in scope |
| ENG-AUDIT | `audit-mcp` -- source-code audit MCP server | Python | 7 |
| ENG-RE | `reverser-belt-mcp` -- binary analysis MCP server | Python | 8 |
| ENG-ANDROID | `android-mcp` -- Android analysis MCP server | Python | 13 |

Not scanned in this pass:

| Item | Reason | Follow-up |
|---|---|---|
| One media-processing project | Scanned; no security, engineering, or IT tool integrations in ICUHUB scope (LLM APIs, local video tooling only) | None |

## 3. Headline findings

1. **Remote host execution over SSH is the most common integration and it is not in
   the original catalog.** AILA (managed systems, vulnerability inventory, forensics
   analyzers, VR/malware workstations, sandbox provisioning) and C-SCAN (playbooks,
   scanner CLI runs) all run commands and move files over SSH with their own credential
   storage and their own host-key handling. Several of these runs change host state
   (software installs, script execution, model-chosen shell commands). ADR-0011 (D9)
   keeps host execution in the consumers (BRD NG13); section 6 lists the SSH hardening
   items they keep, and host results can enter ICUHUB as result files (FR-ING-06).
2. **Ticketing is the most common vendor write.** Jira appears in C-SCAN (multi-instance,
   create-only, no dedupe) and C-APPSEC (create, transition, reopen, custom fields,
   comments, JQL search); C-APPSEC also writes to an ITSM over SOAP (IBM Maximo) and to
   Micro Focus Service Manager and ServiceNow. Every consumer re-implements
   "finding -> ticket" with its own templates and none deduplicate reliably. This becomes
   the ticket lifecycle requirements (FR-TKT-*).
3. **Multiple instances of the same vendor are normal**, not an edge case: several Jira
   instances per tenant (C-SCAN), numbered connections per vendor (C-APPSEC). The
   connection model (one row per configured instance) already supports this; fan-out
   and per-route defaults are added (FR-TKT-03).
4. **AppSec tool coverage is concentrated in C-APPSEC**: Fortify SSC, Mend (two API
   generations), OWASP Dependency-Track, Tenable Security Center, Nessus Manager, RSA
   Archer, Maximo, Service Manager. Many of its operations are destructive (delete
   project versions, suppress issues, approve artifacts, delete scanner agent groups,
   accept-risk rules, close ITSM tickets) and none are behind an approval gate today.
5. **Public advisory feeds** (NVD, OSV, EPSS, CISA KEV, GitHub advisories, Arch and Alpine
   trackers) are used only by AILA today. A shared, cached feed service matters for
   air-gapped installs and for other consumers that prioritize findings. ADR-0012 (D10)
   makes ICUHUB the mirror (FR-FEED-*, wave 2).
6. **Outbound notifications are scattered**: SMTP in AILA (scheduled reports) and
   C-APPSEC (HTML mail built in controllers), Teams incoming webhooks and Microsoft Graph
   chat posts in C-ASSIST. ICUHUB needs a `Notifier` capability anyway for approval
   notifications (COMMATRIX F-035).
7. **Agent-reachable generic egress exists**: AILA's `http_fetch` agent tool performs
   arbitrary HTTP(S) requests, and its MCP client paths do not apply the SSRF policy.
   A governed fetch operation (allowlist, egress class, audit) belongs in ICUHUB
   (FR-FET-*).
8. **Operator-registered MCP servers** in AILA's catalog (HTTP, Streamable HTTP, and
   stdio with an admin-supplied command line) are the case BR-12 describes: vendor MCP
   servers should be governed by ICUHUB instead of being wired into each consumer.
9. **The in-house analysis engines (ENG-*) are not vendor integrations.** They wrap local
   CLIs and in-process libraries over files on a shared filesystem. They stay with the
   consumers. Their own surfaces have no authentication, which is a consumer hardening
   item, not an ICUHUB feature.
10. **Security gaps repeat across consumers** (section 6): TLS verification disabled,
    credentials in source or on command lines, host-key auto-accept, sentinel error
    returns, no idempotency, unescaped query construction. Each maps to an ICUHUB rule
    that prevents it by construction.

## 4. Consolidated catalog

Columns: **Used by** lists consumer aliases. **Direction** follows the classification
guide (`CONNECTOR_GUIDE.md` section 2): read, write, destructive, or mixed.
**Disposition** is the ICUHUB outcome: capability + connector type + wave (waves in
`ROADMAP.md`), or `consumer` (stays in the consumer) or `out` (out of ICUHUB scope) with
the reason.

### 4.1 Source control and CI/CD

| ID | System | Used by | Direction | Today | Disposition |
|---|---|---|---|---|---|
| INV-01 | Git hosting: clone / fetch of target repositories (GitHub, GitLab, any git URL over HTTPS or SSH) | AILA (VR, malware via ENG-AUDIT `clone_repo`; SSH `git clone` on workstations), ENG-AUDIT | read | git CLI; host credentials or none; caller-supplied URL, no allowlist | `SourceControl` vendor operation returning an archive reference or a clone URL with a short-lived, repository-scoped token; repository allowlist per connection; native; wave 1 (with GitHub, GitLab) |
| INV-02 | GitHub REST (security advisories endpoint) | AILA (vulnerability) | read | httpx; optional token; client-side rate limiter | Part of the `VulnIntel` feed set (FR-FEED-*, ADR-0012); wave 2 |
| INV-03 | GitHub release and source downloads (decompiler archive, sandbox runtimes, forensics tool installers) | AILA (sandbox, forensics), ENG-RE | read | direct HTTPS downloads, sha256 pinning in one case only | `out`: software supply belongs to the enterprise artifact repository (NG9) |
| INV-04 | Bitbucket (Cloud / Server) | C-APPSEC (configuration only, no client) | none | config table | `SourceControl`; native; wave 3 unless a consumer needs it earlier |
| INV-05 | Internal Gitea (release channel for a desktop client) | C-ASSIST | read | HTTPS | `SourceControl` (Gitea); wave 3 |
| INV-06 | Jenkins (CI callbacks into the consumer; build links) | C-APPSEC | write (inbound) | inbound POST with one shared static token | Webhook ingress (`/hooks`) + `BuildSystem`; wave 2 |

### 4.2 Ticketing, ITSM, and GRC

| ID | System | Used by | Direction | Today | Disposition |
|---|---|---|---|---|---|
| INV-10 | Jira Cloud (REST v3, ADF bodies) -- several instances per tenant | C-SCAN | write | Basic (email + API token) per instance; per-route project, issue type, labels, templates; no retries, no dedupe (re-runs open duplicates) | `Tracker`; native; wave 1; FR-TKT-01..08 |
| INV-11 | Jira Cloud / Data Center (REST v2): search (JQL), create, transition, reopen, comment, custom fields, assignee | C-APPSEC | mixed | Basic or bearer PAT; hard-coded custom-field IDs; per-customer code forks | `Tracker` + vendor-specific operations (transitions, field discovery); wave 1 |
| INV-12 | IBM Maximo (SOAP, vulnerability work object): query, create, update status, close | C-APPSEC | mixed | SOAP over WSDL with API-key header; WHERE clause built by string concatenation | `Tracker` (ITSM); native with SOAP support in the toolkit (FR-CNR-08); wave 2 |
| INV-13 | Micro Focus Service Manager (REST): create, reopen, close, details | C-APPSEC | mixed (close = destructive) | Basic | `Tracker` (ITSM); native; wave 2 |
| INV-14 | ServiceNow (comment on ticket) | C-APPSEC | write | Basic | `Tracker` (ITSM); native; wave 2 |
| INV-15 | RSA Archer GRC (scan-request records, paged read) | C-APPSEC | read | session login, cookie token | New capability `RiskRegister` (GRC); native; wave 3 |

### 4.3 Application security testing and vulnerability management

| ID | System | Used by | Direction | Today | Disposition |
|---|---|---|---|---|---|
| INV-20 | Fortify Software Security Center: projects and versions (create, commit, attributes, delete), issues and statistics, custom tags, suppress, artifact approve, FPR upload | C-APPSEC | mixed (delete, suppress, approve, commit = destructive) | token from Basic login cached in the web session; TLS verification disabled on upload; token on the command line | `FindingSource` + vendor-specific operations; native + FPR file parser; wave 2 |
| INV-21 | Fortify scan-result callback (CI posts results, consumer returns pass/fail gate) | C-APPSEC | write (inbound) | one shared token, timing-unsafe compare; thresholds hard-coded; blocking sleep in the handler | Webhook ingress + event; gate decision stays in the consumer |
| INV-22 | Mend SCA (legacy v1 and v2 API): projects, alerts, hierarchy, state, delete project | C-APPSEC | mixed (delete = destructive) | user key + org token; v2 login -> bearer | `FindingSource` + vendor-specific operations; native; wave 2 |
| INV-23 | Mend project-creation callback | C-APPSEC | write (inbound) | shared token | Webhook ingress |
| INV-24 | OWASP Dependency-Track: create project, set properties, issue lookups | C-APPSEC | write | API key, partly via shell `curl` (key on the command line) | New capability `SbomSink` + `FindingSource`; native; wave 2 |
| INV-25 | Tenable Security Center: scanners, feeds, plugins, queries, analysis, start remediation scan, delete rollover scans, create policy, accept-risk rules | C-APPSEC | mixed (scan start = write; delete, policy, accept-risk = destructive) | token login, header token; sentinel error returns | `FindingSource` + vendor-specific operations; native; wave 2 |
| INV-26 | Nessus Manager: agents, agent groups (add, remove), profiles, update channels | C-APPSEC | mixed (group membership changes = destructive) | API access + secret key headers | `FindingSource` + vendor-specific operations; native; wave 2 |
| INV-27 | Nessus offline audit files | C-APPSEC | read | local file import | File parser; wave 2 |
| INV-28 | Qualys | C-APPSEC (tables only, no client) | none | -- | `FindingSource`; wave 3 |
| INV-29 | Prisma Cloud Compute (Twistlock) images | C-APPSEC (helper, caller unverified) | read | token helper | `FindingSource`; wave 2 (with Prisma Cloud) |
| INV-30 | Host-side scanner CLI, run on target hosts over SSH; CSV result pulled back | C-SCAN | mixed | shell command over SSH, file transfer back | CLI run stays in the consumer over its own SSH (NG13); the CSV result is ingested through a mapping profile (FR-ING-06); wave 2 |
| INV-31 | SAST CLIs (semgrep, bandit, trivy, bearer, gosec, phpstan) producing SARIF | ENG-AUDIT | read | local subprocess | `consumer` (local tools). Their SARIF output reaches SCM through `CodeScanningSink` |
| INV-32 | MobSF REST service | ENG-ANDROID | mixed | API key header to an operator-run instance | `consumer` (lab analysis service next to the engine) |

### 4.4 Remote host access

All rows stay in the consumers (NG13, ADR-0011). They are kept here because they carry
consumer hardening items (section 6).

| ID | System | Used by | Direction | Today | Disposition |
|---|---|---|---|---|---|
| INV-40 | Managed Linux hosts: inventory, heartbeat, discovery, agent `ssh_command` tool | AILA (platform) | mixed | paramiko; password or key from the consumer's secret store; unknown host keys rejected; no command filtering on the agent tool | `consumer` (NG13); hardening item: command approval on the agent tool |
| INV-41 | Vulnerability-module host inventory (package manager queries, version checks) | AILA (vulnerability) | read | SSH, read-only commands | `consumer` (NG13) |
| INV-42 | Forensics analyzer hosts: read-only tool runs (memory, disk, network, malware tooling) | AILA (forensics) | read | SSH | `consumer` (NG13) |
| INV-43 | Forensics analyzer hosts: script upload and execution, tool installation, model-chosen shell commands gated by string blocklists | AILA (forensics) | destructive | SSH + SFTP | `consumer` (NG13); hardening item: approval for model-chosen commands instead of string blocklists |
| INV-44 | Evidence transfer (analyzer -> platform host) | AILA (forensics) | read | SFTP | `consumer` (NG13) |
| INV-45 | Analysis workstations: target staging, fuzz campaign control | AILA (VR, malware) | destructive | SSH + SFTP | `consumer` (NG13) |
| INV-46 | Sandbox host provisioning (micro-VM and jail runtime installs) | AILA (sandbox) | destructive | SSH, downloads from GitHub | `consumer` (NG13); downloads via artifact repository (NG9) |
| INV-47 | Production target hosts: operator-authored playbook scripts, output copies | C-SCAN | destructive | SSH; **unknown host keys auto-accepted when no known_hosts file is set**; no run lock, no idempotency | `consumer` (NG13); hardening item: pin host keys, add a run lock and idempotency |
| INV-48 | Public IP-echo services queried from managed hosts | AILA (discovery) | read | HTTPS from the host | `consumer` (NG13) |

### 4.5 Identity and directory

| ID | System | Used by | Direction | Today | Disposition |
|---|---|---|---|---|---|
| INV-50 | OIDC identity providers (Microsoft Entra ID, Google, generic issuers) for user login | AILA, C-SCAN, C-ASSIST | read | authorization-code flow per consumer | `out` (NG12): user login stays between each consumer and the IdP; ICUHUB uses the same IdP for its own callers (HLD 10) |
| INV-51 | LDAP / Active Directory: user lookup, bind for login | C-APPSEC | read | LDAP with unescaped filters (injection surface) | Login: `out` (move to OIDC). Directory lookups (users, groups, managers for ticket assignment and approver resolution): new capability `Directory`; native (LDAPS, Graph); wave 2 |
| INV-52 | Corporate directory over LDAPS | C-ASSIST | read | LDAPS bind | `Directory`; wave 2 |

### 4.6 Notifications and collaboration

| ID | System | Used by | Direction | Today | Disposition |
|---|---|---|---|---|---|
| INV-60 | SMTP mail relay: scheduled reports, flow summaries, failure mails | AILA, C-APPSEC | write | SMTP; in C-APPSEC TLS verification disabled, hard-coded recipients, full bodies logged | `Notifier` (email); native; wave 1 (needed for approvals) |
| INV-61 | Microsoft Teams incoming webhook (channel post) | C-ASSIST | write | connector URL (secret) | `Notifier` (chat); native; wave 2 |
| INV-62 | Microsoft Graph: online meetings, transcripts, recordings, change-notification subscriptions, chat and channel posts | C-ASSIST | mixed | OAuth client credentials | `Collaboration` connector (Graph) + webhook ingress with validation handshake; wave 3 |
| INV-63 | Microsoft Graph change notifications (inbound) | C-ASSIST | read (inbound) | shared `clientState`, optional source CIDR allowlist | Webhook ingress adapter (FR-API-04) |
| INV-64 | Microsoft Teams Bot Framework, Google Chat, and other messaging channels of the agent framework | C-ASSIST | mixed | per channel | `out` (NG10): conversational channels of an assistant product, not tool integrations |

### 4.7 Threat intelligence and public data feeds

| ID | System | Used by | Direction | Today | Disposition |
|---|---|---|---|---|---|
| INV-70 | OSV, NVD CVE API 2.0, FIRST EPSS, CISA KEV, GitHub advisories, Arch Linux security tracker, Alpine secdb | AILA (vulnerability, VR, CLI health probes) | read | httpx per provider; per-provider rate limits and retries; NVD key optional | `VulnIntel` feed connectors with a shared mirror (FR-FEED-*, ADR-0012); AILA keeps its clients until parity; wave 2 |
| INV-71 | HaveIBeenPwned Pwned Passwords range API | AILA (password policy) | read | k-anonymity prefix query | `ThreatIntel`; egress `third_party_shared`; wave 3 |
| INV-72 | Volatility symbol packs (vendor CDN) | AILA (forensics, executed on the analyzer) | read | HTTPS from the analyzer | `out`: artifact repository (NG9) |

### 4.8 Generic egress, MCP, and AI

| ID | System | Used by | Direction | Today | Disposition |
|---|---|---|---|---|---|
| INV-80 | `http_fetch` agent tool: arbitrary HTTP(S) request from an agent turn | AILA | mixed | SSRF policy per hop on this path, not on MCP client paths | Governed `web.fetch` operation (FR-FET-*); native; wave 2 |
| INV-81 | Operator-registered MCP servers (HTTP, Streamable HTTP, stdio with admin-supplied command) | AILA | mixed | catalog rows; stdio command line only checked against a transport allowlist | MCP-backed connectors governed by ICUHUB (BR-12, FR-MCPG-*); wave 2 |
| INV-82 | In-house MCP engines: `audit-mcp`, `reverser-belt-mcp`, `android-mcp`, and REA (stdio, Ghidra provider) | AILA | mixed | loopback HTTP or stdio children, no authentication | `consumer` (NG11): analysis engines over local files. Hardening item: authenticate the HTTP surfaces |
| INV-83 | Local and device tooling behind the engines: decompilers, solvers, scanner CLIs, headless browsers, adb, Frida, drozer, objection, apktool, jadx | ENG-* | read to destructive (device instrumentation) | local subprocess / device transport | `consumer` (lab tooling) |
| INV-84 | LLM gateways (OpenAI-compatible endpoints, hosted model APIs, local model servers) | AILA, C-ASSIST, media project | write | bearer API keys | `out` (NG8): routed through the enterprise AI gateway, not ICUHUB |
| INV-85 | Embedding and reranker APIs, model weight downloads (Hugging Face Hub) | AILA, ENG-AUDIT | read / write | HTTPS | `out` (NG8 for APIs, NG9 for downloads) |
| INV-86 | Text-to-speech and other AI services | C-ASSIST | write | bearer token | `out` (NG8) |

### 4.9 Files, observability, and internal surfaces

| ID | System | Used by | Direction | Today | Disposition |
|---|---|---|---|---|---|
| INV-90 | Spreadsheet import/export (XLSX reader/writer, CSV issue metrics, spreadsheet-driven accept-risk rules) | C-APPSEC | mixed | local files | Import: file parsers with mapping profiles (FR-ING-06); wave 3. Export: `consumer` UX |
| INV-91 | Remote output parsing (CSV, JSON, JSONL, lines) and findings CSV export | C-SCAN | read | local parsing of transferred files | File parsers (FR-ING-06); export stays in the consumer |
| INV-92 | Scanner SARIF and native JSON results | ENG-AUDIT | read | local | SARIF parser (FR-ING-04) when results enter ICUHUB |
| INV-93 | OpenTelemetry OTLP export, Prometheus scrape endpoints | AILA, C-SCAN | write / read | operator-configured | `out`: observability infrastructure (each service exports its own) |
| INV-94 | Inbound consumer endpoints that fan out to several vendors in one request (scan start + ticket + mail, without transaction or compensation) | C-APPSEC | mixed | session auth, admin role | Replaced by consumer -> ICUHUB operations; each vendor call becomes its own audited action (FR-POL-*) |
| INV-95 | Fuzz reporter sidecar (inbound crash reports) | AILA | write (inbound) | HTTP | `consumer` (internal component) |

## 5. Disposition summary

| Disposition | Count | Rows |
|---|---|---|
| ICUHUB native or MCP-backed connector | 29 | INV-01, 02, 04-06, 10-15, 20, 22, 24-29, 51, 52, 60-63, 70, 71, 80, 81 |
| ICUHUB ingress (webhook adapters) | 4 | INV-06 (inbound part), 21, 23, 63 |
| ICUHUB file parser | 5 | INV-27, 30 (CSV), 90 (import), 91, 92 |
| Stays in the consumer | 15 | INV-31, 32, 40-48, 82, 83, 94 (replaced, not migrated), 95 |
| Out of ICUHUB scope | 8 | INV-03, 50, 64, 72, 84, 85, 86, 93 |

Counts overlap where a row has an outbound and an inbound part.

## 6. Cross-cutting gaps observed in consumers

Each gap on a path that moves to ICUHUB is prevented there by a rule or requirement, so
the consumer loses the gap without fixing it locally. Gaps on paths that stay in the
consumers are marked as consumer hardening items.

| Gap | Seen in | ICUHUB rule that prevents it |
|---|---|---|
| TLS verification disabled (HTTP client, curl `-k`, mail) | C-APPSEC | NFR-01; per-connection CA bundles (HLD 5.5); no `verify=false` switch (FR-CNR-09) |
| Credentials in source code, in configuration files, or on process command lines | C-APPSEC | BR-02, FR-CON-03; connectors never shell out with credentials (FR-CNR-09) |
| Symmetric encryption key hard-coded in source | C-APPSEC | Secret backend (D3); keys never in code |
| SSH host keys auto-accepted when no known_hosts file is configured | C-SCAN | Consumer hardening item (NG13): pin host keys, reject unknown keys |
| Model-chosen shell commands gated only by string blocklists; no command filtering on an agent SSH tool | AILA | Consumer hardening item (NG13): approval for free-form commands, typed command templates |
| Sentinel return values (`-1`, error arrays) and swallowed exceptions | C-APPSEC | AGENTS.md 5.5.2; typed errors (RFC 9457) from every operation |
| No idempotency: re-runs duplicate tickets and repeat remote scripts | C-SCAN, C-APPSEC | FR-API-06; FR-TKT-02 fingerprint-linked ticket creation |
| Destructive vendor operations with no approval gate (delete, suppress, accept-risk, agent-group changes, ITSM close) | C-APPSEC | FR-POL-03/04; destructive classification per operation |
| Query strings built by concatenation (LDAP filters, SOAP WHERE clauses, SQL) | C-APPSEC | FR-CNR-10: structured inputs only; connectors escape or bind parameters |
| Single shared static token for inbound callbacks, compared with loose equality | C-APPSEC | FR-API-04: per-connection secrets, constant-time compare, replay window |
| One request fans out to several vendors without transaction or compensation | C-APPSEC | Each vendor call is its own action with its own state and audit (HLD 6.3) |
| No outbound rate limiting except one adapter; no shared limiter across processes | AILA | HLD 5.5 per-connection token bucket shared across replicas |
| SSRF policy not applied on every outbound path; arbitrary agent-driven HTTP | AILA | NFR-03 default-deny egress; FR-FET-* governed fetch |
| External-call audit split across several tables, not hash-chained in two consumers | AILA, C-SCAN | FR-AUD-01/02 one hash-chained audit per tenant |
| Hard-coded vendor field IDs, recipients, and per-customer code forks | C-APPSEC | FR-TKT-05 data-driven field mapping per connection; tenant settings, not code |
| Blocking sleeps in request handlers | C-APPSEC | HLD 6.2: long operations are asynchronous actions |
| In-house MCP servers accept unauthenticated calls if bound beyond loopback | ENG-* | Consumer hardening item (not an ICUHUB feature); ICUHUB's own `/mcp` always requires a token (FR-API-05) |

## 7. Patterns worth keeping

| Pattern | Seen in | Where it lands |
|---|---|---|
| One connection record per configured instance, keyed by vendor kind, many instances per tenant | C-APPSEC, C-SCAN | `connection` table (HLD 4) |
| Per-route defaults on top of a connection (project key, issue type, labels, title/body templates, one-issue-per-row vs summary) | C-SCAN | Tracker routes (FR-TKT-03, FR-TKT-04) |
| Severity-to-priority mapping tables between tools (scanner severity -> ITSM priority) | C-APPSEC | Data-driven mapping profiles per connection (FR-TKT-05) |
| Accept-risk round trip (spreadsheet -> scanner rule) as a controlled change | C-APPSEC | Destructive operation behind approval (FR-POL-04) |
| Dry-run of a playbook that builds the plan without touching hosts | C-SCAN | `preview` decision (FR-POL-02) |
| Retry-After handling, batch splitting on 414, per-provider minimum intervals | AILA | HTTP toolkit (HLD 5.5) |
| Request-keyed idempotency cache for retried calls | AILA | `Idempotency-Key` (FR-API-06) |

## 8. Keeping this inventory current

1. Re-scan a consumer when it adds an external call; add rows with new `INV-` IDs
   (never renumber).
2. When a consumer migrates a row to ICUHUB, record the ICUHUB connection kind and the
   consumer release in the private working file, and mark the row `migrated` here.
3. The consumer-side boundary audit (RFC-296 section 5.5 in AILA) is the enforcement
   check that migrated rows stay migrated.
