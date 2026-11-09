# Vendor connectors: per-vendor facts and ICUHUB connector specs

| Field | Value |
|---|---|
| Document | VENDOR_CONNECTORS.md |
| Status | v0.1 |
| Date | 2026-11-07 |
| Inputs | Vendor API documentation, OpenAPI specifications, and vendor and open-source repositories (research 2026-11-07); `CONNECTOR_FRAMEWORK.md`; `BRD.md` section 11; `adr/0010-wave-1-connectors.md`; `HLD.md` section 5.1 |
| Feeds | ROADMAP P5, P7, P8, P10 |

This document defines, for 21 products, the vendor facts that shape an ICUHUB connector and the connector specification for each connector kind. It covers 23 kind IDs: GitHub, GitLab, Bitbucket, Jira, Confluence, and Invicti each split into separate kinds for edition-specific contracts, and Prisma Cloud and Qualys each carry two profiles under one kind.

Section numbers such as "5.3" refer to `CONNECTOR_FRAMEWORK.md`. Waves follow `BRD.md` section 11. Every kind listed here is `core` tier: maintainer-owned, with live acceptance against a vendor sandbox or test tenant before release (`CONNECTOR_FRAMEWORK.md` section 9); a kind without sandbox access cannot release as `core`, which is tracked in section 9 of this document. Facts in sections 3 to 8 and 10 cite primary sources; `[UNVERIFIED]` marks claims the research did not confirm.

## 1. Summary

| Kind | Product / edition | Capabilities | Streams (OCSF class) | Actions | Push | Auth | Wave | Tier |
|---|---|---|---|---|---|---|---|---|
| `github` | GitHub.com and GitHub Enterprise Cloud | Code scanning, Dependabot, and secret scanning alerts; branch protection; pull requests and reviews; enterprise audit | code_scanning_alerts (2002), dependabot_alerts (2002), secret_scanning_alerts (2004), branch_protection (2003), pull_requests, reviews, review_comments (TicketRecord, CommentRecord), audit_events (6003), audit_stream_files (6003) | upload_code_scanning_sarif, update_code_scanning_alert, create_pr_comment, create_review, create_pull_request, merge_pull_request | Webhook, `X-Hub-Signature-256` | GitHub App installation token or PAT | 1 | core |
| `github_enterprise_server` | GitHub Enterprise Server (self-hosted) | As `github`, plus GHES host and feature probes; self-signed or private CA TLS needs explicit trust configuration | As `github` | As `github` | Webhook, `X-Hub-Signature-256` | GitHub App installation token or PAT on the configured GHES host; IP allowlist and SAML credential authorization may apply | 1 | core |
| `gitlab` | GitLab.com | Vulnerability findings, merge requests, Ultimate audit event streaming | vulnerabilities (2002), merge_requests (TicketRecord), audit_events (6003), audit_stream_objects (6003) | create_merge_request, approve_merge_request, change_vulnerability_state, merge_merge_request, create_vulnerability_export | Webhook, Standard Webhooks headers | Access token or OAuth application | 1 | core |
| `gitlab_self_managed` | GitLab Self-Managed and Dedicated | As `gitlab`, plus per-host tier and feature probes and a configurable CA bundle for private certificates | vulnerabilities (2002), merge_requests (TicketRecord), audit_events (6003); batched audit objects are GitLab.com only | As `gitlab` | Webhook, Standard Webhooks headers | Access token or OAuth application on the instance host | 1 | core |
| `bitbucket_cloud` | Bitbucket Cloud | Pull requests, Code Insights reports, branch restrictions | pull_requests (TicketRecord), pr_comments and pr_activity (CommentRecord), code_insights_reports (2002, vulnerability insights only), branch_restrictions (2003) | create_pull_request, approve_or_unapprove, merge_pull_request (destructive) | Webhook; signature scheme `[UNVERIFIED]` | OAuth 2.0 or scoped API token | 3 | core |
| `bitbucket_data_center` | Bitbucket Data Center (self-hosted) | Pull requests, Code Insights reports, node-local audit log files | pull_requests (TicketRecord), code_insights_reports (2002, vulnerability insights only), audit_log_files (6003), repositories and projects (ProjectRecord) | create_pull_request, approve_or_unapprove, put_code_insights_report, merge_pull_request (destructive), change_branch_permission_or_restriction (destructive) | Webhook, `X-Hub-Signature: sha256=<hex>` | HTTP access token or basic auth | 3 | core |
| `jira_cloud` | Jira Cloud | Issue, project, and comment sync; optional audit records; ticket writes; Rovo MCP for interactive use only | issues (TicketRecord), projects (ProjectRecord), comments (CommentRecord), audit_records (6003) | create_issue, update_issue_fields, add_comment, transition_issue, link_issue, add_remote_link, delete_issue (destructive, disabled by default) | Webhook with HMAC SHA256 `[UNVERIFIED]` for Cloud, plus poll reconciliation | OAuth 2.0 3LO, scoped service account, or email plus API token via gateway | 1 | core |
| `jira_dc` | Jira Data Center | Issue, project, and comment sync; optional audit records; ticket writes; signed webhooks; version-gated native REST | issues (TicketRecord), projects (ProjectRecord), comments (CommentRecord), audit_records (6003, source ID `[UNVERIFIED]`) | create_issue, update_issue_fields, add_comment, transition_issue, link_issue, add_attachment, delete issue, comment, or attachment (destructive, disabled by default) | Signed webhooks, `X-Hub-Signature: sha256=<hex>`, plus poll reconciliation | Personal access token (Bearer) | 1 | core |
| `confluence_cloud` | Confluence Cloud | Space and page sync, comment sync, optional audit records, report page publishing, Rovo MCP for interactive use only | spaces (SpaceRecord), pages (DocumentRecord), comments (CommentRecord), audit_records (6003, source ID `[UNVERIFIED]`) | create_report_page, update_report_page, add_comment, add_label, upload_attachment, delete_page, purge_trash, change_restrictions, delete_space (destructive, disabled by default) | No base verifier; optional Connect JWT or Forge bridge | OAuth 2.0 3LO, or API token Basic via gateway | 2 | core |
| `confluence_dc` | Confluence Data Center | Space and page sync, comment sync, report page publishing, signed admin webhooks, version-gated REST; no Rovo MCP | spaces (SpaceRecord), pages (DocumentRecord), comments (CommentRecord), audit_records (6003, source ID `[UNVERIFIED]`) | create_report_page, update_report_page, add comment, label, or property, upload_attachment, move, delete, purge, change restrictions (destructive, disabled by default) | Signed admin webhooks plus poll reconciliation | Personal access token (Bearer) | 3 | core |
| `kubernetes` | Kubernetes (upstream and managed distributions) | Inventory; Kyverno and OpenReports policy reports; Gatekeeper constraint evidence; API audit events; guarded writes | policy_report_changes and policy_report_snapshot (2003); gatekeeper_constraint_changes and gatekeeper_audit_snapshot (2003); resource_inventory_changes and resource_inventory_snapshot (non-finding); audit_events (6003) | annotate_or_label_resource (write), scale_workload (write), delete_pod (destructive) | `kubernetes_audit` webhook, bearer or mTLS; no HMAC | ServiceAccount token, kubeconfig, in-cluster, OIDC, or client certificate; least-privilege get, list, watch | 2 | core |
| `openshift` | OpenShift Container Platform and reachable managed offerings | Route and SCC assessment; policy reports; Build and ImageStream inventory; API audit events; guarded writes | route_scc_assessment_changes and route_scc_assessment_snapshot (2003); policy_report_changes and policy_report_snapshot (2003); inventory (non-finding); audit_events (6003) | annotate_route (write), update_route_tls (write), instantiate_buildconfig (write), update_scc (destructive) | `openshift_audit` webhook, bearer or mTLS; no HMAC | ServiceAccount token or OAuth access token; no browser SAML automation | 2 | core |
| `prisma_cloud` (profiles `cspm`, `compute`) | Prisma Cloud CSPM and Compute (CWPP) | CSPM alert polling, detail reads, posture, alert state writes; Compute image, host, and registry vulnerability scans, compliance, runtime incidents | cspm_config_alerts (2003), cspm_vulnerability_alerts (2002), cspm_detection_alerts (2004), cspm_compliance_posture (non-finding metrics), compute_image_vulnerabilities (2002), compute_host_vulnerabilities (2002), compute_compliance (2003), compute_runtime_incidents (2004) | dismiss_alert, snooze_alert, reopen_alert, remediate_alert, start_registry_scan, create_or_update_collection, delete_collection | None for cspm; Compute alert profile disabled until a provider contract is selected | cspm: access key ID and secret exchanged at `POST /login` for a 10-minute JWT; compute: `POST /api/v<VERSION>/authenticate` | 2 | core |
| `fortify_ssc` | Fortify Software Security Center (self-managed) | Issue sync, artifact and activity records, triage writes, FPR upload, webhook receiver | issues (2002); activity (6003, audit); artifacts (non-finding evidence) | audit_issue, set_issue_suppression, assign_issue, add_issue_comment, upload_fpr, create_webhook, purge_artifact, purge_project_version | Webhook, HMAC SHA256 over raw body plus `Date`, `X-SSC-Signature` | `FortifyToken` header or Basic; AutomationToken for longer automation; SSO does not remove the REST token requirement | 2 | core |
| `fortify_fod` | Fortify on Demand (multi-tenant SaaS) | Release issue sync, scan history, data exports, bulk audit, scan start and import, reports | issues (2002); scans (non-finding evidence); data_exports (non-finding export job) | bulk_audit_issues, start_scan, cancel_scan, import_scan, create_report, delete_release_application_report | None; polling only until a verifier is evidenced | OAuth2 client credentials (API client credentials preferred for automation), or password grant with PAT; Bearer; `api-tenant` scope | 2 | core |
| `invicti_enterprise` | Invicti Enterprise (on-demand and on-premises REST API 1.0) | Native HTTP sync of issues, scans, and scan results; issue-export webhooks; report download | issues (2002), scans (non-finding), scan_results (2002) | scan start, issue update, delete_scan (destructive), manage_website_or_agent | Configurable outbound issue-export webhook; no HMAC asserted | HTTP Basic (User ID and API token) | 3 | core |
| `invicti_standard` | Invicti Standard (desktop JSON report and Send To Actions) | JSON report parsing; generic authenticated webhook receiver | report_issues (2002), webhook_issues (2002) | none in pack | Outbound Send To Actions webhook; static header or Basic auth | Operator-supplied Basic or custom header; local file access for reports | 3 | core |
| `mend_sca` | Mend SCA (formerly WhiteSource); Platform API 3.0 and SCA API 2.0 | Polling sync of findings, libraries, projects, activity, alerts, legal violations; SBOM import; async reports | security_findings (2002), security_alerts (2002), legal_violations (2003), legal_alerts (2003), libraries (non-finding), activity (non-finding) | apply_policy, import_sbom, create_project, update_project_metadata, delete_resource (destructive) | None; no webhook endpoints in either OpenAPI document | Email, user key, and org token or UUID exchanged for JWT Bearer; explicit `api_version` 3.0 or 2.0; SSO does not replace user-key or JWT auth | 2 | core |
| `qualys_enterprise` (profiles `vmdr`, `was`) | Qualys Enterprise (VMDR, WAS, KnowledgeBase, CSAM) | VM host detections, KnowledgeBase, WAS findings, asset inventory; profiles enabled independently | vmdr.host_detections (2002 and 2004), was.findings (2002 and 2004), vmdr.knowledgebase (non-finding), vmdr.assets (non-finding) | was.ignore_finding (write), was.reactivate_finding (write) | None | HTTP Basic over TLS; CSAM JWT via `POST /auth`; SAML or SSO-only accounts need a confirmed non-interactive path `[INFERENCE]` | 3 | core |
| `tenable_vm` | Tenable Vulnerability Management (cloud) | Asynchronous vulnerability and asset exports, read-only | vulnerability_export (2002), asset_export (non-finding) | none | None; polling only | `X-ApiKeys` header with access and secret keys | 2 | core |
| `tenable_sc` | Tenable Security Center (on-premises) | Cumulative and patched vulnerability analysis; alert and notification read | analysis_cumulative (2002), analysis_patched (2002, inferred), notifications (event) | none | None; polling only | `x-apikey` header; token and session mechanics `[UNVERIFIED]` | 2 | core |
| `nessus` | Nessus (file and live export) | `.nessus` file parser primary; license-gated live scan export secondary | scan_runs (non-finding), export_findings (2002 and 2004) | none | None | `X-ApiKeys` for Manager and cloud; standalone key header `[UNVERIFIED]` | 2 | core |
| `archer` | Archer GRC (on-premises and SaaS; Integrated Risk Management) | Vulnerability scan results, assessment findings, risks, exception and remediation workflow records, application and device inventory, attachments as evidence; plan/apply writes | vulnerability_scan_results (2002), assessment_findings (2003), risks, exception_requests, remediation_plans, applications_devices, vulnerability_library (non-finding), attachments (non-finding evidence), history, data_feed_runs | create_finding_or_exception, update_finding_or_exception, upload_attachment, execute_data_feed (write); delete_content (destructive, disabled by default) | None; polling and scheduled reconciliation | Session login (REST) or domain session (SOAP); dedicated identity; PAT not assumed `[UNVERIFIED]` | 1 | core |

## 2. Cross-vendor patterns

| Pattern | Vendors | Kit feature |
|---|---|---|
| Time-windowed reads with overlap and ID dedupe instead of durable cursors | GitHub, GitLab, Bitbucket Cloud, Bitbucket DC, Jira Cloud, Jira DC, Confluence Cloud, Confluence DC, Fortify on Demand, Prisma Cloud, Invicti, Mend, Qualys WAS, Tenable VM, Tenable SC | 5.3 `time_id` cursor; overlap window on every incremental read |
| Absence closes records only from complete full snapshots; partial, scoped, capped, or permission-limited views never close | Every kind with a finding stream | 5.4 deletion and closure |
| Offset or page-token pagination over mutable lists; GitHub code scanning has no `updated_since` filter, so use `sort=updated&direction=asc` with a client-side high-water mark | GitHub, Invicti Enterprise, Mend SCA, Tenable SC, Kubernetes | 5.3 `page_token` cursor; `snapshot` for full runs |
| Asynchronous export jobs: submit, poll, download chunks; chunk order is not guaranteed and chunks expire | GitLab, Tenable VM, Qualys, Nessus, Fortify SSC, Fortify on Demand, Prisma Cloud | 5.3 `snapshot` cursor; 7.1 plan and apply for submissions |
| XML or file-based sources | Qualys (XML and VMRS), Nessus (`.nessus`), Invicti Standard (JSON report), Fortify (FPR) | 5.3 `sequence` cursor; 10 testing kit with fixtures per format version |
| HMAC webhook schemes differ per vendor; header names and signed inputs are per kind and never shared | GitHub (`X-Hub-Signature-256`), Bitbucket DC and Jira DC (`X-Hub-Signature: sha256=<hex>`), GitLab (Standard Webhooks headers), Fortify SSC (`X-SSC-Signature`) | 8 credentials and webhook verifiers |
| Webhooks are hints: verify, then reconcile through authoritative REST reads. Kinds with no vendor-signed push contract poll only | All webhook vendors; polling only for Invicti Enterprise, Invicti Standard, Mend SCA, Prisma Cloud CSPM, Fortify on Demand, Qualys, Tenable VM, Tenable SC, Nessus | 8 webhook verifier `none` with reason; 5.2 push and pull |
| Delivery and event identity dedupe; deliveries are at least once | GitHub (`X-GitHub-Delivery`), Kubernetes and OpenShift audit (`auditID` plus stage plus API source) | 5.3 `sequence` cursor; 8 replay protection |
| Self-signed or private CA chains and on-prem TLS: CA bundles, never skip-verify; no automated browser SAML login | GitHub Enterprise Server, Jira DC, Confluence DC, Kubernetes, OpenShift, Prisma Cloud Compute, Invicti Enterprise, Qualys, Tenable SC, Nessus | HTTP kit: CA bundle, proxy, and mTLS (framework section 8 credentials; section 12 for MCP-facing paths) |
| Endpoint-specific and per-node rate limits; `429` with `Retry-After`; Data Center limits are per node | Jira Cloud (per-issue writes 20 per 2 s and 100 per 30 s), Jira DC (`X-RateLimit-*` headers), Bitbucket DC (per-node token bucket), Invicti Enterprise (200 per minute; 10 per minute on summary endpoints), Prisma Cloud (V2 alert 2 per second), Kubernetes (API Priority and Fairness) | 5.5 scheduling, fairness, and limits |
| Non-finding records stay non-finding: tickets, pages, spaces, projects, inventory, configuration; 2002, 2003, and 2004 only for scanner or policy evidence; audit records go to 6003 | Jira, Confluence, GitHub PRs and reviews, Kubernetes and OpenShift inventory | 6.1 mapping rules |
| Writes use plan and apply with idempotency keys, a current-state precondition (version, `resourceVersion`, status), and read-back; destructive actions disabled by default | Jira, Confluence, Kubernetes, OpenShift, Prisma Cloud, Qualys WAS | 7.1 plan and apply |
| Native HTTP is authoritative for sync; MCP is interactive only | GitHub, GitLab, Jira Cloud, Confluence Cloud, Kubernetes, OpenShift, Fortify SSC | 12 MCP gateway rules |
| Scoped or narrowed credentials return partial results without error | Qualys, Tenable VM, Jira DC PAT | 5.4 closure; treat as `not_evaluated` for affected scope |

## 3. Source control management

### GitHub

GitHub connector coverage includes GitHub.com, GitHub Enterprise Cloud, and GitHub Enterprise Server (GHES), with repository security, development, policy, and audit inputs. This subsection defines `github` for GitHub.com and Enterprise Cloud, and `github_enterprise_server` for GHES so hosts, feature probes, fixtures, and version support remain separate. Native HTTP is authoritative for synchronization; the official MCP server is optional for interactive operations only.

#### Facts

| Topic | Fact |
|---|---|
| Editions and API versions and sunsets | REST is date-versioned with `X-GitHub-Api-Version`; documented versions are `2026-03-10` and `2022-11-28`, with the latter supported until 2028-03-10. Retirement returns `410 Gone` and is announced by `Deprecation` and `Sunset`. GHES edition note: endpoint and event coverage varies by GHES release and Advanced Security licensing. https://docs.github.com/en/rest/about-the-rest-api/api-versions |
| Authentication and scopes | Prefer GitHub App installation tokens; fine-grained and classic PATs, OAuth user tokens, and App user tokens are also supported. SAML authorization, IP allowlists, and installation policy can reject otherwise valid credentials. Enterprise audit REST requires an enterprise-owner credential and administration scope [UNVERIFIED: page not read in this pass]. https://docs.github.com/en/rest/authentication/keeping-your-api-credentials-secure |
| Base URLs | Cloud REST `https://api.github.com`, GraphQL `https://api.github.com/graphql`, asset namespace `https://github.com/{owner}/{repo}`. GHES REST `https://{ghes-host}/api/v3`, GraphQL `https://{ghes-host}/api/graphql`. Data-resident tenant host format `{tenant}.ghe.com` is [UNVERIFIED: host format not read in this pass]. |
| Rate limits and pagination | Cloud primary limits vary by credential from 60/hour unauthenticated to 5,000 or 15,000/hour; installation scaling and caps are [UNVERIFIED: paraphrase not confirmed on the rate-limit page]. Honor rate headers, `retry-after`, and secondary limits. Use `Link`, `page`, `per_page=100`, and code-scanning `before`/`after` URLs verbatim. GHES may disable primary limiting. https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api |
| Incremental support | Security lists lack a general modified-since filter; page code scanning by ascending update time and maintain an overlapping `(updated_at, repository_id, alert_number)` high-water mark. Webhooks are hints followed by authoritative reads. Only complete full alert reads support absence closure. |
| Webhooks (header, algorithm) | `X-Hub-Signature-256` contains `sha256=` plus HMAC-SHA256 over exact raw bytes; dedupe with `X-GitHub-Delivery` and select parsers with `X-GitHub-Event`. Acknowledge within 10 seconds; no timestamp is signed. https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries |
| MCP server and SDKs | Official Go MIT server supports local stdio and hosted Streamable HTTP at `https://api.githubcopilot.com/mcp/`; it is not a GHES sync replacement. Octokit licenses are [UNVERIFIED: licenses not checked in this pass]. https://github.com/github/github-mcp-server/ |
| Comparable open-source integrations | Airbyte documents full/incremental repository and development streams and their backfill, request multiplication, and skipped-403 gaps: https://docs.airbyte.com/integrations/sources/github. Backstage discovery consumes catalog repositories and webhooks: https://backstage.io/docs/integrations/github/discovery/. Port Ocean has a first-party GitHub integration [UNVERIFIED: directory not opened in this pass] that uses resync and live events: https://github.com/port-labs/ocean (framework license Apache-2.0 [UNVERIFIED]). DefectDojo separates asset and security imports: https://docs.defectdojo.com/connectors/toolreference/upstream/ |
| Gotchas | Alert numbers are repository-scoped; organization code-scanning lists are not every repository/ref read. SARIF acceptance is asynchronous. Capability probes must report denied security, administration, audit, or SSO access as `not_evaluated`. Audit streaming is at-least-once with a seven-day pause buffer. |

#### Connector spec

Edition note: `github_enterprise_server` uses the configured GHES host, version-specific capability probes and fixtures, and private-CA trust; it never inherits cloud limits or feature availability implicitly.

| Stream | OCSF class | Cursor kind | Modes | Source record ID | Fingerprint inputs | AssetRef form |
|---|---|---|---|---|---|---|
| code_scanning_alerts | 2002 | time_id | incremental,full | `{connection}:{repository.id}:code_scanning:{number}` | Repository UID, tool identity, rule ID, normalized path/region, logical ref | `repository:{canonical-host}/{owner}/{repo}` |
| dependabot_alerts | 2002 | time_id | incremental,full | Repository numeric ID plus alert number | Repository UID, ecosystem, package, manifest, advisory ID | `repository:{canonical-host}/{owner}/{repo}` |
| secret_scanning_alerts | 2004 | time_id | incremental,full | Repository numeric ID plus alert number | Repository UID, secret type, stable location/alert identity; never secret value | `repository:{canonical-host}/{owner}/{repo}` |
| branch_protection | 2003 plus non-finding configuration | snapshot | full | Repository ID plus protected branch/ruleset ID | Repository and branch/ruleset identity | `repository:{canonical-host}/{owner}/{repo}` |
| pull_requests,reviews,review_comments | TicketRecord,CommentRecord | time_id | incremental,full | Repository identity plus vendor object ID [INFERENCE: design choice] | Stable repository and object identity | `repository:{canonical-host}/{owner}/{repo}` |
| audit_events | 6003 | time_id | incremental,full | Vendor event/document ID | Vendor event ID | Enterprise or repository asset from event target |
| audit_stream_files | 6003 | sequence | incremental | Destination object key | Object key plus event/document ID dedupe | Enterprise asset |

| Operation | Endpoint | Notes |
|---|---|---|
| List code-scanning alerts | Organization/repository code-scanning alert lists; exact paths not sourced | Ascending update order, overlap, and `Link` traversal |
| Get alert, instances, or analysis | not sourced | Reconcile alert and asynchronous SARIF state |
| Get Dependabot or secret alert | not sourced | Read after webhook hints and during full reconciliation |
| Get branch protection/ruleset | not sourced | Requires administration read |
| Get PR, review, or comment | not sourced | Preserve linked non-finding development records |
| Search audit events | Enterprise audit REST; exact path not sourced | Time filter plus vendor cursor traversal and durable time high-water mark |
| Get rate-limit status | not sourced | Track credential and resource buckets independently |

| Action | Classification | Idempotency | Precondition |
|---|---|---|---|
| upload_code_scanning_sarif | write | natural_key | Valid SARIF, `commit_sha`, `ref`, analysis metadata; reconcile returned analysis ID |
| update_code_scanning_alert | write | natural_key | Current repository plus alert number, state, and `updated_at`; read back |
| create_pr_comment or create_review_comment | write | key | Search persisted hidden ICUHUB action-key marker before create |
| create_review | write | natural_key | Check existing reviews for PR, head SHA, and review action |
| create_pull_request | write | natural_key | Query existing open PR for source repository, source branch, target branch |
| merge_pull_request | destructive | natural_key | Explicit approval and head-SHA precondition |

| Field | Value |
|---|---|
| scheme | HMAC-SHA256 over exact raw body with constant-time comparison |
| header | `X-Hub-Signature-256`; reject legacy SHA-1 selection |
| dedupe key | `X-GitHub-Delivery` |
| replay protection | Persist delivery IDs and check payload revisions; standard signature has no timestamp |
| known gaps | No undocumented automatic retry assumption; redelivery still requires dedupe |

| Capability | Scope or permission |
|---|---|
| Baseline discovery | `Metadata: read` |
| Code scanning reads | `Code scanning alerts: read` |
| SARIF upload or alert dismissal | `Code scanning alerts: write` |
| Dependabot or secret scanning | `Dependabot alerts: read` or `Secret scanning alerts: read` |
| PR reads and writes | `Pull requests: read` or `write` |
| Branch protection | `Administration: read` |
| Enterprise audit | Enterprise-owner credential and documented administration scope [UNVERIFIED: page not read in this pass] |

Top risks:
- GHES feature skew and Advanced Security or SSO authorization gaps.
- Partial organization reads causing false absence closure.
- Secondary throttling and nonportable cloud rate assumptions.
- SARIF accepted before asynchronous processing fails.
- Duplicate audit events and bounded pause recovery.
- Secret values or token-like SARIF content entering stored evidence.

### GitLab

GitLab coverage includes GitLab.com, GitLab Self-Managed, and GitLab Dedicated, with Ultimate-tier security exports, development records, and audit streaming. This subsection defines `gitlab` for GitLab.com and `gitlab_self_managed` for Self-Managed and Dedicated. Native HTTP, GraphQL where confirmed, exports, and streaming are authoritative; MCP is interactive only.

#### Facts

| Topic | Fact |
|---|---|
| Editions and API versions and sunsets | REST is `/api/v4`; cited security pages are version 19.6 (REST page version not checked [UNVERIFIED]). Security findings, exports, SARIF ingestion, and audit streaming are Ultimate-tier. Free-tier namespace limits from 2026-10-19 are reported only by Airbyte [UNVERIFIED on a GitLab primary page]. REST vulnerabilities endpoints are deprecated/unstable and GraphQL is recommended. https://docs.gitlab.com/api/vulnerabilities/ |
| Authentication and scopes | Personal, project, and group access tokens, OAuth applications, and CI job tokens are options; exact REST scope names are [UNVERIFIED]. MCP accepts OAuth `mcp` or a fine-grained PAT with MCP Execute permission. Export permission role matrix is [UNVERIFIED]. SAML SSO and IP allowlist behavior is [UNVERIFIED]. https://docs.gitlab.com/api/rest/authentication/ [UNVERIFIED: page not read in this pass] |
| Base URLs | REST `https://<host>/api/v4`, GitLab.com `https://gitlab.com/api/v4`, MCP `https://<host>/api/v4/mcp`. Dedicated tenant host shape is [UNVERIFIED]. Encode namespaced paths and follow `Location` after project moves. |
| Rate limits and pagination | Limits are instance-configurable; numeric GitLab.com values and pagination headers/maxima/keyset support are [UNVERIFIED]. Honor `429` and `Retry-After`. One vulnerability export per user per project/group may be in progress. Page-number pagination can skip concurrent updates, so use overlapping time windows. GitLab.com numeric values on https://docs.gitlab.com/user/gitlab_com/rate_limits/ were not read [UNVERIFIED]. |
| Incremental support | MR list supports `updated_after`, `updated_before`, `order_by=updated_at`, and requires `scope=all`. Vulnerability exports are asynchronous point-in-time snapshots. No deletion tombstone was confirmed; absence closure requires a complete snapshot. |
| Webhooks (header, algorithm) | Standard Webhooks `webhook-id`, `webhook-timestamp`, `webhook-signature`; HMAC-SHA256 over `{id}.{timestamp}.{body}` with `whsec_` token and `v1,{base64}` signature. GA in 19.1. Legacy plaintext `X-Gitlab-Token` is not recommended. https://docs.gitlab.com/user/project/integrations/webhooks/ |
| MCP server and SDKs | GA since 19.5 at `https://<host>/api/v4/mcp`; select toolsets with `X-Gitlab-Enabled-Mcp-Server-Toolsets`. Server repository/license and python-gitlab status/license are [UNVERIFIED]. https://docs.gitlab.com/user/model_context_protocol/mcp_server/ |
| Comparable open-source integrations | Airbyte documents 180-day windows, update filters, `Retry-After`, skipped-403 gaps, and page skips: https://docs.airbyte.com/integrations/sources/gitlab. Port GitLab v2: https://docs.port.io/context-lake/ingestion/ingest-data-into-port/native-integrations/available-integrations/git/gitlab-v2/. Other named integrations are [UNVERIFIED]. |
| Gotchas | Pushes affecting more than three branches/tags trigger no webhooks by default. Long query strings return `414`; send JSON bodies instead. Audit batches retry as whole arrays and duplicate every event. SARIF has a 10 MB artifact limit, 20 runs, and 5,000 results/run. |

#### Connector spec

Edition note: `gitlab_self_managed` covers Self-Managed and Dedicated, with per-host tier and feature probes. Instance audit streaming is unavailable on GitLab.com; GitLab.com-only batched delivery and feature flags must not be assumed on self-managed installations.

| Stream | OCSF class | Cursor kind | Modes | Source record ID | Fingerprint inputs | AssetRef form |
|---|---|---|---|---|---|---|
| vulnerabilities | 2002 | snapshot (full); time_id (incremental via GraphQL [UNVERIFIED]) | full,incremental [UNVERIFIED] | Vulnerability global ID [UNVERIFIED: GraphQL object field names not read] | Scanner identity, rule, normalized location; exclude state/severity [INFERENCE: design choice] | `gitlab:<host>/<full_path>` |
| merge_requests | TicketRecord | time_id | incremental,full | Project global ID plus MR `iid` [INFERENCE: design choice] | Project and MR identity | `gitlab:<host>/<full_path>` |
| audit_events | 6003 | time_id | incremental,full | Event `id` | Event ID dedupe | `gitlab:<host>/<full_path>` or group path |
| audit_stream_objects | 6003 | sequence [UNVERIFIED] | incremental | Batched object key `YYYY/MM/DD/<timestamp>_<id>.json` (GitLab.com batched path) | Object-key checkpoint plus event `id` dedupe [INFERENCE: design choice] | not sourced |

| Operation | Endpoint | Notes |
|---|---|---|
| List merge requests | `GET /merge_requests` | Use `scope=all`, update windows, and overlap |
| Get merge request | `GET /projects/:id/merge_requests/:iid` | `id` is global; `iid` is project-scoped |
| List MR notes/discussions | not sourced | Non-finding CommentRecord inputs |
| Get vulnerability | GraphQL query not sourced | REST vulnerabilities API is deprecated/unstable |
| Create vulnerability export | Project, group, or instance export `POST`; exact paths not sourced | Ultimate; one active export per user/scope |
| Poll vulnerability export | `GET /security/vulnerability_exports/:id` | Returns `202` until finished |
| Download vulnerability export | Export download path not sourced | Returns `404` until finished; CSV/PDF snapshot |
| Get project/group metadata | not sourced | Establish full path and asset identity |

| Action | Classification | Idempotency | Precondition |
|---|---|---|---|
| create_merge_request | write | natural_key | Query open MRs for source and target branches |
| create_mr_note_or_discussion | write | key | Search hidden ICUHUB action-key marker |
| approve_merge_request | write | natural_key | MR `iid` plus head `sha`; check existing approval |
| change_vulnerability_state | write | natural_key | Read-before-write state check and read-back; deprecated REST endpoint |
| merge_merge_request | destructive | natural_key | Explicit approval and head `sha` precondition [UNVERIFIED: merge endpoint parameters not read] |
| create_vulnerability_export | read | none | Respect active-export concurrency and retry `429` |

| Field | Value |
|---|---|
| scheme | HMAC-SHA256 over `{webhook-id}.{webhook-timestamp}.{raw body}` using `whsec_` signing token |
| header | `webhook-signature` as `v1,{base64}` |
| dedupe key | `webhook-id`; audit event `id` for streaming |
| replay protection | Enforce a timestamp replay window |
| known gaps | Reject `X-Gitlab-Token`-only new connections; full event/retry behavior is [UNVERIFIED] |

| Capability | Scope or permission |
|---|---|
| REST reads and writes | Endpoint-specific scopes [UNVERIFIED] |
| MCP | OAuth `mcp` or fine-grained PAT with MCP Execute permission |
| Vulnerability data and exports | Ultimate security dashboard plus target create-vulnerability permission; role matrix [UNVERIFIED] |
| Group audit streaming | Ultimate-tier, group level on GitLab.com, Self-Managed, and Dedicated; exact role not sourced |
| Instance audit streaming | Instance-level streaming on Self-Managed and Dedicated; administrator role [UNVERIFIED: proposal-derived, not confirmed on the audit streaming page] |

Top risks:
- Tier or permission `403` responses misreported as zero findings.
- Deprecated REST and GraphQL vulnerability ID/schema divergence [UNVERIFIED].
- Export concurrency `429` and premature `404` downloads.
- Duplicate events from whole-batch audit retries.
- Page-number skips and pushes above the webhook branch/tag limit.
- SARIF drops or unsuccessful jobs silently reducing findings.

### Bitbucket Cloud

Bitbucket Cloud uses REST API 2.0 for pull requests, repository policy, and commit-scoped Code Insights. This subsection defines `bitbucket_cloud`; fixtures and behavior are not shared with Data Center. Native HTTP is authoritative for sync, while the Atlassian MCP wrapper is interactive only.

#### Facts

| Topic | Fact |
|---|---|
| Editions and API versions and sunsets | Cloud REST API 2.0; OpenAPI document https://dac-static.atlassian.com/cloud/bitbucket/swagger.v3.json. Code Insights is not SARIF or a code-scanning alert store. App-password deprecation timeline is [UNVERIFIED]. |
| Authentication and scopes | OAuth 2.0, Connect/Forge apps, workspace/repository/project access tokens, and scoped API tokens. `read:repository:bitbucket` does not imply PR access. SAML and IP allowlist behavior is [UNVERIFIED]. https://support.atlassian.com/bitbucket-cloud/docs/api-token-permissions/ |
| Base URLs | REST `https://api.bitbucket.org/2.0`, repository paths `{workspace}/{repo_slug}`, web host `https://bitbucket.org`. Regional data-residency host support is [UNVERIFIED]. |
| Rate limits and pagination | One-hour rolling resource buckets; authenticated Git 60,000/hour, raw files 5,000/hour, archives 1,500/hour, webhook data 1,000/hour, with scaled repository-data limits for eligible workspaces. Follow `next` verbatim; maximum `pagelen` is [UNVERIFIED]. https://support.atlassian.com/bitbucket-cloud/docs/api-request-limits/ |
| Incremental support | No general PR modified-since filter was confirmed; `q` filter/sort fields are [UNVERIFIED]. Reconcile PR activity and commits after webhook hints. Branch restrictions/default reviewers use full snapshots; no tombstone endpoint was confirmed. |
| Webhooks (header, algorithm) | `X-Hub-Signature` with `method=signature`, HMAC-SHA256 over raw body; Atlassian says the method might change. Retry, timeout, 256 KB drop, and string event-key claims are [UNVERIFIED]. https://support.atlassian.com/bitbucket-cloud/docs/manage-webhooks/ |
| MCP server and SDKs | Atlassian MCP wrapper is documented at https://support.atlassian.com/bitbucket-cloud/docs/interacting-with-bitbucket-via-mcp/. Transport, hosting, license, and official Python SDK are [UNVERIFIED]. Use httpx for sync. |
| Comparable open-source integrations | Backstage Cloud discovery uses repository listing and push webhooks: https://backstage.io/docs/integrations/bitbucketCloud/discovery/. Other open-source Cloud security integrations are [UNVERIFIED]. |
| Gotchas | Scope gaps must yield `not_evaluated`, not empty findings. Track `X-RateLimit-Resource`. Verify `method=signature` and reject unknown methods. Code Insights annotations map to findings only for vulnerability-scanner reports. |

#### Connector spec

| Stream | OCSF class | Cursor kind | Modes | Source record ID | Fingerprint inputs | AssetRef form |
|---|---|---|---|---|---|---|
| pull_requests | TicketRecord | time_id | incremental,full | `{workspace}/{repo_slug}#{pr_id}` | Workspace, repository, PR ID; `updated_on` high-water field [UNVERIFIED] | `repository:bitbucket.org/{workspace}/{repo_slug}` |
| pr_comments,pr_activity | CommentRecord plus non-finding activity | time_id | incremental,full | not sourced | Stable PR and vendor object identity | `repository:bitbucket.org/{workspace}/{repo_slug}` |
| code_insights_reports | 2002 only for vulnerability insights; otherwise non-finding | snapshot | full | Commit, report/insight key, annotation key | Commit, insight, annotation identity; exclude mutable fields | `repository:bitbucket.org/{workspace}/{repo_slug}` |
| branch_restrictions | 2003 plus non-finding configuration | snapshot | full | not sourced | Workspace, repository, restriction identity | `repository:bitbucket.org/{workspace}/{repo_slug}` |

| Operation | Endpoint | Notes |
|---|---|---|
| List/get pull request | Pull requests group; exact paths not sourced | Use `q` and `sort` only after field confirmation |
| List PR comments/activity/commits/statuses/diffstat | Pull requests group; exact paths not sourced | Per-PR reconciliation after hints |
| List commit pull requests | `GET .../commit/{commit}/pullrequests` | Requires PR read permission |
| List branch restrictions | Branch restrictions group; exact path not sourced | Complete full snapshot |
| Get reports/annotations | `/reports` group; exact paths not sourced | Commit-scoped Code Insights, not SARIF |
| List hook events | `GET /hook_events` or `GET /hook_events/{subject_type}` | Public event catalog |

| Action | Classification | Idempotency | Precondition |
|---|---|---|---|
| create_pull_request | write | natural_key | Query open PRs for source and destination branches |
| create_or_reply_comment | write | key | Search hidden ICUHUB action-key marker |
| resolve_or_reopen_comment | write | natural_key | Read current comment state |
| approve_or_unapprove | write | natural_key | PR ID plus user; read approval state |
| request_changes | write | natural_key | PR ID plus user; paired POST/DELETE lifecycle |
| decline_pull_request | write | natural_key | Current PR state; reopen only where policy allows |
| merge_pull_request | destructive | natural_key | Source commit hash, explicit approval, task-status and PR-state reconciliation |
| change_branch_restriction | destructive | natural_key | Read-before-write and explicit approval |
| put_code_insights_report | write | natural_key | Commit plus insight key; idempotent overwrite |

| Field | Value |
|---|---|
| scheme | HMAC-SHA256 over raw body |
| header | `X-Hub-Signature` with `method=signature` |
| dedupe key | Request UUID header; exact header name not sourced |
| replay protection | Persist request UUIDs and reconcile through REST; no signed timestamp sourced |
| known gaps | Retry, timeout, payload-size drop, and exact event keys are [UNVERIFIED]; signature method might change |

| Capability | Scope or permission |
|---|---|
| Pull request reads | OAuth `pullrequest` or API token `read:pullrequest:bitbucket` |
| Pull request writes | `pullrequest` write |
| Repository/Code Insights reads | OAuth `repository` or API token `read:repository:bitbucket` |
| Branch restrictions | OAuth `repository:admin` or `admin:repository:bitbucket` |
| Code Insights writes | `repository` |

Top risks:
- Unverified payload-drop behavior requiring REST reconciliation after every hint.
- Repository-read scope mistaken for PR access.
- Per-resource throttling and unconfirmed page-size limits.
- Code Insights mislabeled as SARIF or unconditional vulnerability evidence.
- Merge accepted with unknown outcome without task/state reconciliation.
- Signature method changes or unknown methods accepted silently.

### Bitbucket Data Center

Bitbucket Data Center coverage uses self-hosted REST, webhooks, and node-local audit log files, with REST v1004 and 10.5 documentation as the sourced baseline. This subsection defines `bitbucket_data_center`. Native HTTP and the audit file reader are authoritative; the MCP plugin is interactive only.

#### Facts

| Topic | Fact |
|---|---|
| Editions and API versions and sunsets | REST v1004 index: https://developer.atlassian.com/server/bitbucket/rest/v1004/. Webhook, audit, rate-limit, and token facts are verified for 10.5; newer REST versions are [UNVERIFIED]. Legacy audit format was removed in 8.0. |
| Authentication and scopes | Repository, project, and personal HTTP access tokens, basic auth, and OAuth 2.0 [UNVERIFIED: OAuth page not read]. Project/repository tokens require a Data Center license and immutable expiry; they cannot merge PRs. REST Basic username form and admin-token requirements are [UNVERIFIED]. https://confluence.atlassian.com/bitbucketserver/http-access-tokens-939515499.html |
| Base URLs | REST `https://<bitbucket-host>/rest/api/1.0/...` [UNVERIFIED: path base not read in this pass]. MCP `https://<host>/rest/mcp/1.0/` [UNVERIFIED]. TLS private-CA trust is deployment-specific. |
| Rate limits and pagination | Per-user, per-node token bucket defaults to 60 tokens and 5 tokens/second; limited requests return `429`. Cluster nodes have independent buckets. Pagination `start`, `limit`, `nextPageStart`, `isLastPage` is [UNVERIFIED]. https://confluence.atlassian.com/bitbucketserver/improving-instance-stability-with-rate-limiting-976171954.html |
| Incremental support | PR/repository update filters are [UNVERIFIED]. Audit JSONL files rotate at midnight or 100 MB with 100 files retained by default; checkpoint file name plus byte offset. No native audit push was confirmed [UNVERIFIED] and no deletion tombstone was confirmed; complete full reads alone support absence closure. |
| Webhooks (header, algorithm) | Project or repository scope; `X-Hub-Signature: sha256=<hex>` using HMAC-SHA256 over raw body. Delivery IDs and retry policy are [UNVERIFIED], so dedupe by event key plus payload digest. https://confluence.atlassian.com/bitbucketserver/manage-webhooks-938025878.html |
| MCP server and SDKs | Official plugin page https://confluence.atlassian.com/bitbucketserver/mcp-for-bitbucket-dc-1822723926.html. Endpoint, bearer auth, `BITBUCKET_HOME/shared/mcp-tools.json` whitelist, license, and official Python SDK are [UNVERIFIED]. |
| Comparable open-source integrations | Backstage Server discovery uses repository discovery and webhooks: https://backstage.io/docs/integrations/bitbucketServer/discovery/. Other open-source Data Center integrations are [UNVERIFIED]. |
| Gotchas | UPM plugin disablement stops webhooks instance-wide; sender error behavior is [UNVERIFIED]. Audit rotation can destroy uncollected history. Token rotation requires a new token. Code Insights endpoint, limits, retention, and creator restriction are [UNVERIFIED]. |

#### Connector spec

| Stream | OCSF class | Cursor kind | Modes | Source record ID | Fingerprint inputs | AssetRef form |
|---|---|---|---|---|---|---|
| pull_requests | TicketRecord | time_id | incremental,full | not sourced | Project, repository, PR identity; overlapping list reads | `repository:<bitbucket-host>/<project>/<repo>` |
| code_insights_reports | 2002 only for vulnerability insights; otherwise non-finding | snapshot | full | `{project}/{repo}/{commit}/{insightKey}/{annotationKey}` [INFERENCE: design choice; insight details UNVERIFIED] | Commit, insight, annotation identity; exclude mutable fields | `repository:<bitbucket-host>/<project>/<repo>` |
| audit_log_files | 6003 | sequence | incremental | Audit file name, byte offset, event identity | File checkpoint plus event content dedupe | Data Center node or target repository from event |
| repositories,projects | ProjectRecord plus non-finding inventory | snapshot | full | Project/repository stable key | Host, project, repository identity | `repository:<bitbucket-host>/<project>/<repo>` |

| Operation | Endpoint | Notes |
|---|---|---|
| List/get PRs, comments, activity | REST v1004 Pull Requests module; exact paths not sourced | Use overlap and webhook hints |
| List repositories/projects | REST v1004 Repository/Project modules; exact paths not sourced | Complete full snapshots for inventory |
| Get Code Insights report/annotations | not sourced | Cited how-to page was not read |
| Read audit log files | `YYYYMMDD-XXXXX.audit.log` under `<home>/log/audit/` [UNVERIFIED path] | JSON object per line; track file and byte offset |
| Put Code Insights report | `PUT {baseUrl}/rest/projects/{projectKey}/repos/{repositorySlug}/commits/{commitId}/reports/{insightKey}` [UNVERIFIED] | Report details and 60-day retention are [UNVERIFIED] |

| Action | Classification | Idempotency | Precondition |
|---|---|---|---|
| create_pull_request | write | natural_key | Query open PRs for source and target branches |
| create_comment_or_review | write | key | Search hidden ICUHUB action-key marker and read back |
| approve_or_unapprove | write | natural_key | PR ID plus user |
| put_code_insights_report | write | natural_key | Commit plus insight key; credential must be report creator [UNVERIFIED] |
| merge_pull_request | destructive | natural_key | User credential with merge permission [UNVERIFIED], head-commit precondition, explicit approval |
| change_branch_permission_or_restriction | destructive | natural_key | Read-before-write and explicit approval |

| Field | Value |
|---|---|
| scheme | HMAC-SHA256 over raw body using project or repository secret |
| header | `X-Hub-Signature: sha256=<hex>` |
| dedupe key | Payload content digest plus event key |
| replay protection | Persist digest/event dedupe and run scheduled authoritative reads |
| known gaps | Delivery IDs and retry policy [UNVERIFIED]; UPM disablement may stop delivery without a signal [UNVERIFIED] |

| Capability | Scope or permission |
|---|---|
| Repository/project reads | HTTP access token read at required scope |
| Repository/project writes | HTTP access token write at required scope |
| Administrative changes | Project/repository admin as applicable |
| Audit files and instance settings | System administrator [UNVERIFIED for token restriction] |
| Merge pull request | User credential with required permission [UNVERIFIED exact model]; access tokens cannot merge |

Top risks:
- Audit files rotating away before collection, causing permanent history loss.
- Webhooks silently stopping when UPM plugins are disabled [UNVERIFIED signal behavior].
- Independent per-node rate buckets producing inconsistent throttling.
- Immutable token expiry requiring planned credential cutover.
- Unconfirmed native findings API leading to unsupported Code Insights assumptions.
- Merge attempted with an access token even though a user credential is required.

## 4. Ticketing and knowledge

### Jira Cloud

Jira Cloud connector syncs issues, projects, comments, and optional administrative audit records, with ticket writes for finding workflows. It defines kind `jira_cloud` for Jira Cloud only, using native HTTP for authoritative synchronization and optional Rovo MCP for interactive operations.

#### Facts

| Topic | Fact |
|---|---|
| Editions and API versions and sunsets | REST v3 is the default; Agile uses `/rest/agile/1.0`. Replace deprecated `/rest/api/{2\|3}/search` with `/rest/api/{2\|3}/search/jql`. Connect end-of-support dates are [UNVERIFIED]. [REST v3](https://developer.atlassian.com/cloud/jira/platform/rest/v3/intro), [search](https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issue-search). |
| Authentication and scopes | OAuth 2.0 (3LO) authorization code with rotating refresh tokens and `offline_access`; scoped service-account tokens or email-plus-token Basic through the documented gateway. Tokens expire in 1 to 365 days; legacy staged dates and SAML/two-step interactions are [UNVERIFIED]. Permissions remain authoritative. [OAuth](https://developer.atlassian.com/cloud/jira/platform/oauth-2-3lo-apps), [tokens](https://support.atlassian.com/atlassian-account/docs/manage-api-tokens-for-your-atlassian-account/). |
| Base URLs | Direct: `https://<site>.atlassian.net/rest/api/3/`; gateway: `https://api.atlassian.com/ex/jira/{cloudId}/rest/api/3/`; tenant discovery: `GET https://api.atlassian.com/oauth/token/accessible-resources`. Store `cloudId`, treating site URL as an alias. |
| Rate limits and pagination | Default app Global Pool is 65,000 points/hour plus burst and per-tenant limits; tier caps and API-token coverage are [UNVERIFIED]. Honor 429, `Retry-After`, and rate headers. Enhanced JQL uses traversal-only `nextPageToken`; older collections use `startAt`/`maxResults`. [Limits](https://developer.atlassian.com/cloud/jira/platform/rate-limiting). |
| Incremental support | JQL `updated >= overlap ORDER BY updated ASC, key ASC` with durable `time_id(updated, IDs, overlap)`. Enhanced search is eventually consistent; use overlap, stable numeric IDs, and complete full reconciliation for absence. [Reconciliation](https://developer.atlassian.com/cloud/jira/platform/search-and-reconcile). |
| Webhooks (header, algorithm) | Admin HMAC-SHA256 over raw bytes with `X-Hub-Signature: sha256=<hex>` is [UNVERIFIED] for Cloud. OAuth uses bearer JWT; Connect uses installation JWT with [UNVERIFIED] claim details. `X-Atlassian-Webhook-Identifier` deduplicates retries. [Guide](https://developer.atlassian.com/cloud/jira/platform/webhooks). |
| MCP server and SDKs | Rovo MCP at `https://mcp.atlassian.com/v2/mcp` is interactive only. Jira search/write/delete/manage scope variants and credits are [UNVERIFIED]. No general official async Python REST SDK; SDK license terms are [UNVERIFIED]. Use `httpx`. [Rovo](https://developer.atlassian.com/cloud/rovo-mcp/), [Forge](https://developer.atlassian.com/platform/forge/). |
| Comparable open-source integrations | [Port Ocean](https://raw.githubusercontent.com/port-labs/ocean/main/integrations/jira/main.py) JQL plus webhook resources are [UNVERIFIED]; [Airbyte](https://raw.githubusercontent.com/airbytehq/airbyte/master/airbyte-integrations/connectors/source-jira/manifest.yaml) stream details are [UNVERIFIED]; [DefectDojo](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/dev/dojo/jira/helper.py) demonstrates echo races; [Steampipe](https://github.com/turbot/steampipe-plugin-jira) table coverage is [UNVERIFIED]. |
| Gotchas | Mutable keys, permission filtering, index lag, expiring tokens/registrations, project-specific workflows, ADF/custom fields, payload quotas, stale webhook echoes, and no tenant-wide CDC. Never infer ticket deletion from an incomplete run. |

#### Connector spec

| Stream | OCSF class | Cursor kind | Modes | Source record ID | Fingerprint inputs | AssetRef form |
|---|---|---|---|---|---|---|
| issues | TicketRecord | time_id | incremental, full, event | `jira_issue:<cloudId>/<numeric-id>` | finding fingerprint for linked tickets; `id` + `updated` revision | `jira_project:<cloudId>/<project-id>` |
| projects | ProjectRecord | snapshot | full | cloud ID + project ID | project ID + complete snapshot revision | `jira_project:<cloudId>/<project-id>` |
| comments | CommentRecord | time_id | incremental, full | cloud ID + issue ID + comment ID | comment ID + issue `updated` | `jira_project:<cloudId>/<project-id>` |
| audit_records | API Activity 6003 | time_id | incremental, full | audit record ID | audit ID + event timestamp | not sourced |

| Operation | Endpoint | Notes |
|---|---|---|
| Resolve tenant | `GET https://api.atlassian.com/oauth/token/accessible-resources` | Select explicit tenant; never assume first site. |
| Check identity | `GET /rest/api/3/myself` | Also probe project visibility, fields, and enabled permissions. |
| Search issues | `GET /rest/api/3/search/jql` | Bounded fields; token remains inside active traversal. |
| Read issue details | not sourced | Selected fields, comments, and changelog; endpoint path not sourced. |
| List transitions | `/issue/{idOrKey}/transitions` (REST v3 base) | Use returned transition ID, never a name. |
| Read metadata | not sourced | Project, field, create/edit metadata, and serverInfo; endpoint paths not sourced. |

| Action | Classification | Idempotency | Precondition |
|---|---|---|---|
| create_issue | write | natural_key | Route key persisted in issue property/label; reconcile after uncertain outcome. |
| update_issue_fields | write | none | Fresh `id`, `updated`, status, and replaced-field plan. |
| add_comment | write | key | ICUHUB comment property marker. |
| transition_issue | write | none | Fresh transition ID plus current status and `updated`. |
| link_issue / add_remote_link | write | natural_key | Natural link tuple. |
| delete_issue | destructive | none | Disabled by default; explicit issue ID and absence readback. |

| Field | Value |
|---|---|
| scheme | Optional admin HMAC-SHA256 [UNVERIFIED for Cloud]; separate OAuth or Connect JWT verifier by app mode. |
| header | `X-Hub-Signature` for admin; bearer/installation JWT in authorization flow for dynamic apps. |
| dedupe key | `X-Atlassian-Webhook-Identifier`; otherwise tenant, event, entity, and raw-body digest. |
| replay protection | No signed timestamp; constant-time verification, dedupe, durable enqueue, JQL polling, and readback. |
| known gaps | Cloud HMAC registration, Connect claims, and retry timing are [UNVERIFIED]; dynamic registrations expire after 30 days. |

| Capability | Scope or permission |
|---|---|
| Read issues, projects, search | `read:jira-work` or granular equivalents; Browse Projects. |
| Write issues and comments | `write:jira-work` or granular issue/comment/link scopes; matching project permissions. |
| Dynamic webhooks | `manage:jira-webhook` plus Jira administration for admin setup. |

Top risks:
- JQL eventual consistency and removal of legacy search can skip or duplicate changes.
- Uncertain creates can duplicate tickets without route-key reconciliation.
- Stale echoes and webhook loss require service-identity suppression and final-state reads.
- ADF, custom-field types, screens, and workflow IDs vary by project and issue type.
- Quotas, expiring tokens, and dynamic registration expiry can halt synchronization.

### Jira Data Center

Jira Data Center connector supports operator-hosted Data Center releases, not unsupported Jira Server. It defines kind `jira_dc`, with PAT authentication, version-gated native REST parsing, ticket publishing, and optional signed webhooks; Rovo MCP does not serve this edition.

#### Facts

| Topic | Fact |
|---|---|
| Editions and API versions and sunsets | Use `/rest/api/2` and supported `/rest/agile/1.0`; no Cloud v3/ADF parity. Server end-of-support 2024-02-15 is [UNVERIFIED]; DC 2029-03-28 appears in a guide footer. Jira 10 defaults to asynchronous webhooks and changes URL variables; registration path is [UNVERIFIED]. [REST](https://developer.atlassian.com/server/jira/platform/rest/v11003/), [webhooks](https://developer.atlassian.com/server/jira/platform/webhooks/). |
| Authentication and scopes | Dedicated least-privilege service-account PAT as `Authorization: Bearer <token>` on Jira 8.14+. PAT inherits current user permissions and may expire; it is not granular OAuth. Legacy Basic/cookie auth is disabled for new connections. [PAT](https://confluence.atlassian.com/enterprise/using-personal-access-tokens-1026032365.html). |
| Base URLs | Operator `https://jira.example[:port][/context]`; core `<base>/rest/api/2`; Agile `<base>/rest/agile/1.0`; PAT administration `<base>/rest/pat/latest/tokens` [UNVERIFIED]. Preserve context paths and validate payload links against configured origin. |
| Rate limits and pagination | Administrator-configured quotas return 429 and `X-RateLimit-*`/`retry-after`; no universal quota. `/rest/api/2/search` uses JQL `startAt`/`maxResults`, normally bounded to 50 or 100. [Rate guide](https://confluence.atlassian.com/adminjiraserver/adjusting-your-code-for-rate-limiting-987143384.html), [JQL example](https://developer.atlassian.com/server/jira/platform/jira-rest-api-example-query-issues-6291606/). |
| Incremental support | Fresh bounded JQL `updated >= overlap ORDER BY updated ASC, key ASC` with `time_id`. Never persist `startAt` incrementally; split or degrade on timestamp-tie overflow. Complete per-project snapshots alone permit absence closure. |
| Webhooks (header, algorithm) | HMAC-SHA256 over exact body with `X-Hub-Signature: sha256=<hex>`. No portable delivery ID or retry SLA; derive a digest and poll. Jira 10 tracker issues are [UNVERIFIED]. [Guide](https://developer.atlassian.com/server/jira/platform/webhooks/). |
| MCP server and SDKs | No vendor-official DC MCP server was identified [UNVERIFIED]. Plugin SDK is Java/Maven for in-process apps; official Python REST SDK is not asserted [UNVERIFIED]. Use native `httpx`. [Plugin SDK](https://developer.atlassian.com/server/framework/atlassian-sdk/). |
| Comparable open-source integrations | [Steampipe](https://github.com/turbot/steampipe-plugin-jira) PAT table subset is [UNVERIFIED]; [DefectDojo](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/dev/dojo/jira/helper.py) supports DC writes; [Port Ocean](https://github.com/port-labs/ocean/tree/main/integrations/jira) is Cloud-oriented; [community client](https://github.com/atlassian-api/atlassian-python-api) token-misconfiguration warning is [UNVERIFIED]. |
| Gotchas | Version skew, context paths, mutable keys, JQL timezone/index lag, timestamp ties, PAT permission drift, plugin fields, production load, and sparse/duplicate webhooks. Reduced visibility blocks deletion closure. |

#### Connector spec

| Stream | OCSF class | Cursor kind | Modes | Source record ID | Fingerprint inputs | AssetRef form |
|---|---|---|---|---|---|---|
| issues | TicketRecord | time_id | incremental, full, event | `jira_issue:<connection-installation>/<numeric-id>` | finding fingerprint for linked tickets; `id` + `updated` revision | `jira_project:<connection-installation>/<project-id>` |
| projects | ProjectRecord | snapshot | full | installation + project ID | project ID + complete snapshot revision | `jira_project:<connection-installation>/<project-id>` |
| comments | CommentRecord | time_id | incremental, full | installation + issue ID + comment ID | comment ID + issue `updated` | `jira_project:<connection-installation>/<project-id>` |
| audit_records | API Activity 6003 | time_id | incremental, full | not sourced | audit ID + event timestamp | not sourced |

| Operation | Endpoint | Notes |
|---|---|---|
| Check server and identity | not sourced | serverInfo and myself; endpoint paths not sourced. Record product version; probe without requiring admin rights. |
| Search issues | `GET /rest/api/2/search` | Fresh incremental windows; offset only within full snapshots. |
| Read issue details | not sourced | Issue, changelog, and comments; endpoint paths not sourced. Preserve wiki text and raw plugin fields. |
| List transitions | `/transitions` on the issue resource | Fresh read before apply; exact full path not sourced. |
| Read metadata | `/field`, create metadata, projects, and workflow status resources | Discover per-version schemas and permissions. |

| Action | Classification | Idempotency | Precondition |
|---|---|---|---|
| create_issue | write | natural_key | Deterministic property/label route key; reconcile by JQL after timeout. |
| update_issue_fields | write | none | Fresh `updated`, status, fields, and discovered schema. |
| add_comment | write | key | Entity property or body marker; persist remote ID immediately. |
| transition_issue | write | none | Fresh transition ID, current status, and changelog verification. |
| link_issue / add_attachment | write | natural_key | Link tuple or issue, filename, size, and content hash. |
| delete issue/comment/attachment | destructive | none | Disabled by default; explicit approval and absence readback. |

| Field | Value |
|---|---|
| scheme | HMAC-SHA256 with constant-time comparison over raw request bytes. |
| header | `X-Hub-Signature: sha256=<hex>`. |
| dedupe key | Connection, event, timestamp, issue ID, and raw-body digest; collisions remain possible. |
| replay protection | Durable enqueue before 2xx, dedupe, readback, and continuing JQL reconciliation. |
| known gaps | No portable delivery ID or retry SLA; Jira 10 registration and tracker-issue details are [UNVERIFIED]. |

| Capability | Scope or permission |
|---|---|
| Read sync | PAT user with Browse Projects and visible content. |
| Ticket writes | Create/Edit Issue, Add Comments, Transition Issues, links/attachments as enabled. |
| Webhook management | Jira Administrators global permission only. |

Top risks:
- Product-version skew changes search, identity, fields, and webhook behavior.
- Same-timestamp boundaries can hide issues if mutable offsets are reused.
- Permission narrowing can masquerade as deletion during full reconciliation.
- Changelog, attachment, and plugin-field expansion can overload production.
- Sparse, stale, or duplicate events require readback rather than payload trust.

### Confluence Cloud

Confluence Cloud connector synchronizes spaces, pages, comments, and optional audit records and publishes report documentation. It defines kind `confluence_cloud` across REST v1 and v2, with native HTTP authoritative for sync and Rovo MCP restricted to interactive use.

#### Facts

| Topic | Fact |
|---|---|
| Editions and API versions and sunsets | Use `/wiki/api/v2` for covered page/space operations and `/wiki/rest/api` for CQL, conversion, audit, and gaps. V2 create supports current/draft and storage/ADF bodies; updates require current version plus one, except draft version 1. Connect sunset dates are [UNVERIFIED]. [V2 pages](https://developer.atlassian.com/cloud/confluence/rest/v2/api-group-page), [v1](https://developer.atlassian.com/cloud/confluence/rest/v1/intro). |
| Authentication and scopes | OAuth 2.0 (3LO), scoped/service-account tokens through the gateway, or email-plus-token Basic. Tokens expire in 1 to 365 days. Scopes do not override space/page restrictions. [Scopes](https://developer.atlassian.com/cloud/confluence/scopes-for-oauth-2-3LO-and-forge-apps), [Basic](https://developer.atlassian.com/cloud/confluence/basic-auth-for-rest-apis). |
| Base URLs | Direct `https://<site>.atlassian.net/wiki`; gateway `https://api.atlassian.com/ex/confluence/{cloudId}/wiki`; then `/rest/api` or `/api/v2`. Store `cloudId`; resolve relative links only against the trusted tenant. |
| Rate limits and pagination | Default app Global Pool is 65,000 points/hour; tier caps/dates are [UNVERIFIED]. V2 uses opaque `cursor` links; 250 maximum is [UNVERIFIED]. CQL defaults to 25 and expansion cap claims are [UNVERIFIED]. [Limits](https://developer.atlassian.com/cloud/confluence/rate-limiting), [v2](https://developer.atlassian.com/cloud/confluence/rest/v2/intro). |
| Incremental support | Per-space CQL on `lastModified` with overlap and `time_id`; hydrate bodies separately. CQL cursors are traversal-only. Full `snapshot` tracks completed space IDs and tokens; only complete visible snapshots support absence closure. |
| Webhooks (header, algorithm) | No native admin HMAC webhook is declared. Optional Connect sends installation JWT in `Authorization`; event coverage is [UNVERIFIED], delivery is best effort, and polling is mandatory. Forge requires an authenticated bridge. [Module](https://developer.atlassian.com/cloud/confluence/modules/webhook). |
| MCP server and SDKs | Rovo MCP at `https://mcp.atlassian.com/v2/mcp` exposes read/write groups interactively; operation coverage, agent scopes, and credits are [UNVERIFIED]. Forge SDK license terms are [UNVERIFIED]. Use `httpx` for deterministic export. [Rovo](https://developer.atlassian.com/cloud/rovo-mcp/), [catalog](https://developer.atlassian.com/cloud/rovo-mcp/guides/supported-tools/). |
| Comparable open-source integrations | [Backstage](https://github.com/backstage/community-plugins/tree/main/workspaces/confluence/plugins/search-backend-module-confluence-collator) partitions CQL by space but schedule details are [UNVERIFIED]; [Airbyte](https://raw.githubusercontent.com/airbytehq/airbyte/master/airbyte-integrations/connectors/source-confluence/manifest.yaml) cursor/stream details are [UNVERIFIED]; [community client](https://github.com/atlassian-api/atlassian-python-api) storage examples are [UNVERIFIED]. |
| Gotchas | V1/v2 drift, CQL lag and permission filtering, draft divergence, version conflicts, lossy macros/rendering, token expiry, large bodies, and no generic signed admin webhook. Deletion event names are [UNVERIFIED]. |

#### Connector spec

| Stream | OCSF class | Cursor kind | Modes | Source record ID | Fingerprint inputs | AssetRef form |
|---|---|---|---|---|---|---|
| spaces | SpaceRecord | snapshot | full | `confluence_space:<cloudId>/<space-id>` | space ID + complete snapshot revision | `confluence_space:<cloudId>/<space-id>` |
| pages | DocumentRecord | time_id | incremental, full, event | `confluence_page:<cloudId>/<content-id>` | content ID + `version.number`; report key property | `confluence_space:<cloudId>/<space-id>` |
| comments | CommentRecord | time_id | incremental, full | cloud ID + page ID + comment ID | comment ID + page version/revision | `confluence_space:<cloudId>/<space-id>` |
| audit_records | API Activity 6003 | time_id | incremental, full | audit record ID | audit ID + event timestamp | not sourced |

| Operation | Endpoint | Notes |
|---|---|---|
| Discover spaces | not sourced | v2 space operations under `/wiki/api/v2`; substitute gateway base for OAuth/scoped tokens. |
| Search content | `/wiki/rest/api/search` or `/wiki/rest/api/content/search` | Per-space CQL; use portable limit 25. |
| Read pages | not sourced | v2 page operations under `/wiki/api/v2`; get by ID, selected body representation, and version. |
| Read history and related content | not sourced | Versions, comments, attachments, properties, and restrictions; independent reads, endpoint paths not sourced. |
| Read audit | not sourced | Optional v1 audit resource when enabled; endpoint path not sourced. |

| Action | Classification | Idempotency | Precondition |
|---|---|---|---|
| create_report_page | write | natural_key | `(spaceId, parentId, deterministic title)` plus report-key property; reconcile uncertain creates. |
| update_report_page | write | none | Bind ID, version, title, parent, body hash; send current version plus one. |
| add_comment / add_label | write | key | Content property or deterministic marker. |
| upload_attachment | write | natural_key | Page, filename, and hash reconciliation. |
| delete_page / purge_trash | destructive | none | Disabled by default; explicit approval and readback. |
| change restrictions / delete space | destructive | none | Disabled by default; high-risk plan and target review. |

| Field | Value |
|---|---|
| scheme | `none` for base connector; optional Connect installation JWT or separately authenticated Forge bridge. |
| header | `Authorization` for optional Connect installation JWT. |
| dedupe key | Event, content ID, version/timestamp, and raw-body digest. |
| replay protection | Stored sharedSecret and claims for Connect; dedupe, page-ID/version readback, and CQL polling. |
| known gaps | No delivery guarantee or general retry/delivery ID; event coverage and deletion names are [UNVERIFIED]. |

| Capability | Scope or permission |
|---|---|
| Read bodies | `read:confluence-content.all` or `read:page:confluence`; view permission. |
| Read metadata and spaces | `read:confluence-content.summary`, `read:confluence-space.summary`, or `read:space:confluence`. |
| CQL search | `search:confluence`. |
| Publish | `write:confluence-content` or `write:page:confluence`; Can Use, create, and update permissions. |
| Audit | `read:audit-log:confluence` when enabled. |

Top risks:
- Stale drafts and version conflicts can overwrite divergent content.
- Published reports can notify watchers or expose sensitive finding data.
- CQL lag and restrictions can make live pages appear deleted.
- ADF/storage conversion and macros can lose or alter report content.
- V1/v2 differences and best-effort push prevent webhook-only synchronization.

### Confluence Data Center

Confluence Data Center connector supports operator-hosted Data Center releases with version-gated REST, PAT authentication, report publishing, and signed admin webhooks. It defines kind `confluence_dc`; it does not reuse Cloud `/wiki`, v2, OAuth 3LO, ADF, or Rovo MCP assumptions.

#### Facts

| Topic | Fact |
|---|---|
| Editions and API versions and sunsets | Use v1-style `/rest/api` content, space, CQL, conversion, and webhook resources. Webhooks 7.7+, PATs 7.9+, and content scan 7.18+ are [UNVERIFIED]. DC support ending 2029-03-28 is [UNVERIFIED]. [REST](https://developer.atlassian.com/server/confluence/confluence-server-rest-api), [webhooks](https://developer.atlassian.com/server/confluence/webhooks/). |
| Authentication and scopes | Dedicated service-account PAT as `Authorization: Bearer <token>`; availability from 7.9 is [UNVERIFIED]. PAT inherits current permissions and admin-set expiry. Basic is legacy; SAML does not provide a REST token. [PAT](https://confluence.atlassian.com/enterprise/using-personal-access-tokens-1026032365.html). |
| Base URLs | Operator `https://confluence.example[:port][/context]`; content `<base>/rest/api/content`; CQL `<base>/rest/api/content/search` or `<base>/rest/api/search`; spaces `<base>/rest/api/space`; webhooks `<base>/rest/api/webhooks`. Never force `/wiki`. |
| Rate limits and pagination | Admin-configured 429/rate headers; Confluence header names are [UNVERIFIED]. General collections use `start`/`limit`; CQL 25 with expansions is [UNVERIFIED]. `/rest/api/content/scan` cursor support/filter limits are [UNVERIFIED]. [Pagination](https://developer.atlassian.com/server/confluence/pagination-in-the-rest-api). |
| Incremental support | Per-space CQL `lastModified` with overlap and `time_id`; no documented `id > cursor` tiebreaker. Split/degrade tie overflow. Full uses snapshot-only scan cursors or offsets; complete visibility is required for absence closure. [CQL](https://developer.atlassian.com/server/confluence/advanced-searching-using-cql). |
| Webhooks (header, algorithm) | HMAC-SHA256 over raw body with `X-Hub-Signature`, secret rotation, sparse-payload readback, and derived dedupe digest. Registration path, payload fields, circuit thresholds, and deletion semantics are [UNVERIFIED]. [Administration](https://confluence.atlassian.com/doc/managing-webhooks-1021225606.html). |
| MCP server and SDKs | No vendor-official DC MCP server was identified [UNVERIFIED]. Plugin SDK is Java/Maven; official general Python SDK is not asserted [UNVERIFIED]. Use native `httpx`. [Plugin SDK](https://developer.atlassian.com/server/framework/atlassian-sdk/). |
| Comparable open-source integrations | [Backstage](https://github.com/backstage/community-plugins/tree/main/workspaces/confluence/plugins/search-backend-module-confluence-collator) confirms PAT, base URL, and space/CQL filtering; multi-instance/cache details are [UNVERIFIED]. [Community client](https://github.com/atlassian-api/atlassian-python-api) supports DC PAT. No DefectDojo publisher or Port Ocean integration is claimed [UNVERIFIED]. |
| Gotchas | Version/edition detection, CQL ties, storage XML and macros, sparse webhooks, circuit breaking, reverse proxies, PAT drift, and search load. Legacy wiki conversion and attachment anti-XSSI header are [UNVERIFIED]. |

#### Connector spec

| Stream | OCSF class | Cursor kind | Modes | Source record ID | Fingerprint inputs | AssetRef form |
|---|---|---|---|---|---|---|
| spaces | SpaceRecord | snapshot | full | installation + space ID/key | space ID/key + complete snapshot revision | `confluence_space:<connection-installation>/<space-id>` |
| pages | DocumentRecord | time_id | incremental, full, event | `confluence_page:<connection-installation>/<content-id>` | content ID + `version.number`; report key property | `confluence_space:<connection-installation>/<space-id>` |
| comments | CommentRecord | time_id | incremental, full | installation + page ID + comment ID | comment ID + page version/revision | `confluence_space:<connection-installation>/<space-id>` |
| audit_records | API Activity 6003 | time_id | incremental, full | not sourced | audit ID + event timestamp | not sourced |

| Operation | Endpoint | Notes |
|---|---|---|
| Check server and spaces | `<base>/rest/api/space`; server info path not sourced | Detect version and probe visible content and target permissions. |
| Search content | `<base>/rest/api/content/search` or `<base>/rest/api/search` | Fresh incremental CQL windows with overlap. |
| Scan full content | `<base>/rest/api/content/scan` | Version-gated; cursor persists only within active snapshot. |
| Read content | `<base>/rest/api/content` | Storage body, history/version, ancestors, labels, properties, comments, attachments, restrictions. |
| Check webhooks | `<base>/rest/api/webhooks` | Registration/status is admin-only; registration POST path is [UNVERIFIED]. |

| Action | Classification | Idempotency | Precondition |
|---|---|---|---|
| create_report_page | write | natural_key | Space, parent, deterministic title, report key; reconcile by title/CQL after uncertainty. |
| update_report_page | write | none | Bind ID, version, body hash, title, space; send current version plus one. |
| add comment/label/property | write | key | Deterministic marker or content property. |
| upload_attachment | write | natural_key | Page, filename, content hash/version; anti-XSSI header is [UNVERIFIED]. |
| move/delete/purge/restrictions | destructive | none | Disabled by default; explicit approval, validated target, and readback. |

| Field | Value |
|---|---|
| scheme | HMAC-SHA256 with constant-time comparison and current/previous secrets during rotation. |
| header | `X-Hub-Signature`. |
| dedupe key | Connection, event, timestamp, content ID, and raw-body digest. |
| replay protection | Durable enqueue, fast acknowledgement, sparse-ID readback, and polling for circuit-broken deliveries. |
| known gaps | No portable delivery ID; registration, payload names, circuit thresholds, and trash/purge semantics are [UNVERIFIED]. |

| Capability | Scope or permission |
|---|---|
| Read sync | PAT user with Can Use and space/page view permission. |
| Publish | Create/update page in target space. |
| Webhook management | Confluence Administrator or System Administrator global permission only. |

Top risks:
- Timestamp ties without an ID keyset can silently skip changed pages.
- Invalid storage XML or macro handling can corrupt published reports.
- Sparse or circuit-broken webhooks require readback and polling recovery.
- Permission drift and incomplete scans can produce false absence decisions.
- Version skew and broad CQL/body reads can degrade production instances.

## 5. Container platforms

### Kubernetes

Kubernetes covers upstream and managed or self-managed distributions that expose the standard HTTPS resource API. This subsection defines the native `kubernetes` connector for resource inventory, Kyverno/OpenReports and Gatekeeper policy evidence, and API audit activity; optional MCP access is interactive only, while native HTTP owns synchronization and checkpoints.

#### Facts

| Topic | Fact |
|---|---|
| Editions and API versions and sunsets | Core resources use `/api/v1`; named groups use `/apis/GROUP/VERSION`. Discover served versions through `/api`, `/apis`, and `/openapi/v3`, and probe `/version`; aggregated discovery is stable since 1.30 and OpenAPI v3 since 1.27. At research time, 1.37, 1.36, and 1.35 are maintained, but minors must not be hardcoded. Prefer GA APIs and follow the [API overview](https://kubernetes.io/docs/concepts/overview/kubernetes-api/), [version skew policy](https://kubernetes.io/releases/version-skew-policy/), and [deprecation policy](https://kubernetes.io/docs/reference/using-api/deprecation-policy/). |
| Authentication and scopes | Use a dedicated ServiceAccount bearer token directly or through kubeconfig, in-cluster credentials, OIDC/JWT bearer tokens, or X.509 client certificates. Prefer bound, audience-scoped, rotating tokens; least-privilege RBAC uses `get`, `list`, and `watch`, with `watch` granted separately. Exclude Secrets by default ([authentication](https://kubernetes.io/docs/reference/access-authn-authz/authentication/), [RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)). |
| Base URLs | One API server URL per kubeconfig context or explicit target, normally `https://host:port`. Core paths are `/api/v1/...`, named groups are `/apis/<group>/<version>/...`, and namespace paths insert `/namespaces/<namespace>/`; configure the cluster CA without disabling verification ([resource URIs](https://kubernetes.io/docs/reference/using-api/api-concepts/#resource-uris)). |
| Rate limits and pagination | No universal account quota or `X-RateLimit-*` contract exists. API Priority and Fairness can return 429; back off and honor `Retry-After`. Lists use `limit` and opaque `metadata.continue`; tokens normally expire after five minutes by default and can yield 410. Watches require bounded `timeoutSeconds` ([flow control](https://kubernetes.io/docs/concepts/cluster-administration/flow-control/), [chunked lists](https://kubernetes.io/docs/reference/using-api/api-concepts/#retrieving-large-results-sets-in-chunks)). |
| Incremental support | LIST retains collection `metadata.resourceVersion`; WATCH uses that opaque per-partition token with bookmarks. Process `ADDED`, `MODIFIED`, and `DELETED`; on 410, discard the partition cache, relist, and rewatch. Only complete full lists close absence. Gatekeeper status defaults to 20 violations per constraint and cannot close absence when truncated ([watch semantics](https://kubernetes.io/docs/reference/using-api/api-concepts/#efficient-detection-of-changes), [Gatekeeper audit](https://open-policy-agent.github.io/gatekeeper/website/docs/audit/)). |
| Webhooks (header, algorithm) | The audit backend POSTs `audit.k8s.io` events using kubeconfig-selected bearer or mTLS authentication. No standard HMAC signature or independent delivery ID header exists; dedupe on `API source + auditID + stage`. Batch buffers can overflow and drop events, so expose lag and gap health ([audit backend](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)). |
| MCP server and SDKs | [`containers/kubernetes-mcp-server`](https://github.com/containers/kubernetes-mcp-server) supports Kubernetes and OpenShift over stdio or Streamable HTTP `/mcp`; its guardrails do not replace RBAC. Official clients include [Go client-go](https://github.com/kubernetes/client-go/) and [Python kubernetes-client/python](https://github.com/kubernetes-client/python/), but native async HTTP is authoritative for sync. |
| Comparable open-source integrations | [Backstage](https://backstage.io/docs/features/kubernetes/configuration/) provides multi-cluster inventory and optional Pod deletion; [Steampipe](https://github.com/turbot/steampipe-plugin-kubernetes) offers point-in-time SQL extraction and dynamic CRD tables; [Prowler](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/kubernetes/kubernetes_provider.py) performs point-in-time checks. [Kyverno reports](https://kyverno.io/docs/guides/reports/) and Gatekeeper audit are the closest finding-source precedents; Kyverno reports reflect current state only, and Gatekeeper constraint status is capped while export can be lossy. |
| Gotchas | A 403 is partial coverage, not an empty result. Resource versions are collection-scoped and opaque; finalizers expose `deletionTimestamp` before `DELETED`; Kyverno Enforce denials do not create failure report entries. A Pod referencing an image does not itself establish image CVEs without scanner evidence, and ordinary core Events are not automatically Detection Findings. |

#### Connector spec

| Stream | OCSF class | Cursor kind | Modes | Source record ID | Fingerprint inputs | AssetRef form |
|---|---|---|---|---|---|---|
| `policy_report_changes` | Compliance Finding (2003) | `page_token` | `incremental` | Report `metadata.uid` + policy + rule + result + subject identity | Algorithm version + cluster + policy + rule + subject group/kind/namespace/name or UID | `k8s_resource:<cluster>/<group>/<kind>/<namespace>/<name>` |
| `policy_report_snapshot` | Compliance Finding (2003) | `snapshot` | `full` | Same report result identity | Same stable policy, rule, and subject identity; exclude status and report resourceVersion | Same subject resource identity |
| `gatekeeper_constraint_changes` | Compliance Finding (2003) | `page_token` | `incremental` | Constraint UID/name + audit run + violated resource | Constraint kind/name + resource identity; exclude `auditTimestamp` | Violated resource group/kind/namespace/name |
| `gatekeeper_audit_snapshot` | Compliance Finding (2003) | `snapshot` | `full` | Constraint UID/name + confirmed complete `audit_id` + violated resource | Constraint kind/name + resource identity | Violated resource identity plus enforcement action |
| `resource_inventory_changes` | Non-finding inventory/configuration | `page_token` | `incremental` | Object `metadata.uid`; revision `metadata.resourceVersion` | Cluster + group/kind + namespace/name + UID | Canonical cluster resource identity; retain owners, IPs, and image digests |
| `resource_inventory_snapshot` | Non-finding inventory/configuration | `snapshot` | `full` | Object `metadata.uid`; revision `metadata.resourceVersion` | Cluster + group/kind + namespace/name + UID | Canonical cluster resource identity |
| `audit_events` | API Activity (6003) | `sequence`; webhook deliveries have no file cursor | `incremental`, `full`, `event` | `API source + auditID + stage`; file cursor is `(API source,node,file)` byte offset | API source + auditID + stage | `objectRef` resource identity plus `sourceIPs` |

| Operation | Endpoint | Notes |
|---|---|---|
| `get_resource` | `GET /api/v1/...` or `GET /apis/<group>/<version>/...` | Discovery-driven single-object read |
| `list_resources` | Same resource paths with `limit` and `continue` | Preserve selectors and pagination parameters |
| `get_policy_report` | Discovered PolicyReport or ClusterPolicyReport resource path | Supports Kyverno and OpenReports after discovery |
| `list_api_resources` | `GET /api` and `GET /apis` | Refresh discovery on 404, 410, or schema changes |
| `get_openapi_schema` | `GET /openapi/v3` | Use served schemas rather than assumed beta APIs |
| `get_gatekeeper_constraint` | Discovered constraint resource path | Report truncated violation status as degraded coverage |
| `get_server_version` | `GET /version` | Retain server version in health metadata |

| Action | Classification | Idempotency | Precondition |
|---|---|---|---|
| `annotate_or_label_resource` | write | `natural_key` | Expected `metadata.resourceVersion`; planned before/after patch; HTTP 409 becomes `stale_plan` |
| `scale_workload` | write | not sourced | Expected resourceVersion and desired/current replica diff; availability-affecting approval |
| `delete_pod` | destructive | not sourced | Explicit approval plus expected Pod UID/resourceVersion; never treat deletion as rollback |

| Field | Value |
|---|---|
| scheme | `kubernetes_audit` with configured mTLS or bearer authentication over the raw request |
| header | No standard HMAC signature header or independent delivery ID header |
| dedupe key | `API source + auditID + stage` |
| replay protection | not sourced; dedupe on `API source + auditID + stage` only; watch reconnects use resourceVersion |
| known gaps | Audit batch overflow can drop events; admission webhooks are not an ingestion feed |

| Capability | Scope or permission |
|---|---|
| Inventory and policy reads | `get`, `list`, `watch` on each enabled core or discovered resource |
| Discovery and health | `/version`, `/api`, `/apis`, and `/openapi/v3` when normal discovery access is absent |
| Audit ingestion | Explicit audit file or webhook configuration and receiving-endpoint bearer/mTLS authorization |
| Annotation, scaling, or deletion | Action-specific `patch`, scale-subresource, or `delete` permission only when that action is enabled |

Top risks:
- Expired watches or continue tokens can cause false closure unless the affected partition is relisted.
- Partial RBAC, denied namespaces, and disappearing CRDs can masquerade as empty coverage.
- Gatekeeper truncation and lossy export prevent unguarded absence closure.
- Audit batch loss, sensitive bodies, and high cardinality require health signals and bounded retention.
- Unbounded lists, watches, and all-CRD discovery can overload the API server.
- TLS, proxy, and control-plane egress restrictions require explicit configuration.

### OpenShift

OpenShift Container Platform 4.x and 5.x, including reachable managed offerings, retain Kubernetes discovery, list/watch, RBAC, and audit structures while adding OpenShift resource groups. This subsection defines the native `openshift` connector with OpenShift-specific Route, SCC, Build, and ImageStream parsers and assessments; native HTTP remains authoritative for durable synchronization.

#### Facts

| Topic | Fact |
|---|---|
| Editions and API versions and sunsets | OpenShift 4.x and 5.x add `route.openshift.io/v1`, `security.openshift.io/v1`, `build.openshift.io/v1`, and `image.openshift.io/v1`. OpenShift 5 minors receive 12 months Full Support plus 12 months Maintenance Support under the current [lifecycle policy](https://access.redhat.com/support/policy/updates/openshift). SCC exposure through the core Kubernetes group is deprecated without a stated removal date; use `security.openshift.io`. `ImageStream.spec.dockerImageRepository` is deprecated; use `spec.tags[].from` ([SCC source](https://github.com/openshift/api/blob/master/security/v1/types.go), [ImageStream source](https://github.com/openshift/api/blob/master/image/v1/types.go)). |
| Authentication and scopes | OAuth access tokens or X.509 client certificates authenticate over HTTPS; bearer tokens use `Authorization: Bearer ...`. Prefer a dedicated ServiceAccount token and never automate a browser SAML flow. Use least-privilege `get`, `list`, and `watch`, not `cluster-admin`; audit access is separate ([API authentication](https://github.com/openshift/openshift-docs/blob/main/modules/rbac-api-authentication.adoc), [OAuth token requests](https://github.com/openshift/openshift-docs/blob/main/modules/oauth-token-requests.adoc)). |
| Base URLs | Use the kubeconfig cluster API endpoint, commonly `https://api.<cluster>.<domain>:6443`; console and OAuth Route URLs are not API bases. OpenShift resources use `/apis/<group>/<version>/...`, core resources remain `/api/v1/...`, and discovery/OpenAPI paths are unchanged from Kubernetes ([OpenShift Python client](https://github.com/openshift/openshift-restclient-python)). |
| Rate limits and pagination | OpenShift inherits API Priority and Fairness, 429/backoff, `limit`/`continue`, opaque tokens, and resourceVersion watches. No separate universal numeric Red Hat quota or `X-RateLimit-*` contract exists. Restart the affected snapshot or watch on 410 ([Kubernetes API concepts](https://kubernetes.io/docs/reference/using-api/api-concepts/)). |
| Incremental support | Routes, SCCs, BuildConfigs, Builds, ImageStreams, and optional CRDs use LIST + WATCH with per-resource resourceVersion and relist on 410. `DELETED` is explicit; only complete full lists close absence. ImageStream tags are mutable and history can be pruned, while digest-named Images are immutable. Audit JSONL uses file identity and offset across four API sources per control-plane node ([ImageStream semantics](https://github.com/openshift/api/blob/master/image/v1/types.go)). |
| Webhooks (header, algorithm) | Where exposed, the Kubernetes audit webhook contract applies: configured bearer/mTLS, exponential backoff, batching, and possible drops. No standard Red Hat HMAC signature or delivery-ID header exists; dedupe on `API source + auditID + stage`. BuildConfig incoming triggers start Builds and are not outbound ingestion feeds. |
| MCP server and SDKs | [`openshift/openshift-mcp-server`](https://github.com/openshift/openshift-mcp-server) supports stdio and Streamable HTTP `/mcp`, generic resources, Projects, diagnostics, Helm, and optional OpenShift toolsets. Official [Go client](https://github.com/openshift/client-go) and [Python dynamic client](https://github.com/openshift/openshift-restclient-python) are Apache-2.0; the generated Swagger Python approach is deprecated. MCP guardrails supplement RBAC and do not own sync cursors. |
| Comparable open-source integrations | [Backstage](https://backstage.io/docs/features/kubernetes/configuration/) and [Steampipe](https://github.com/turbot/steampipe-plugin-kubernetes) can address Kubernetes-compatible APIs but do not document OpenShift-specific finding sync. [Prowler](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/kubernetes/kubernetes_provider.py) supplies assessment patterns, not watch checkpoints. [`containers/kubernetes-mcp-server`](https://github.com/containers/kubernetes-mcp-server) demonstrates OpenShift Projects and discovery-driven reads, not durable finding cursors. |
| Gotchas | Managed offerings can require support-mediated audit retrieval. Four audit sources create rotation, duplication, and volume concerns. SCC changes have cluster-wide security impact; Route private keys must be redacted. Join image evidence by digest, not mutable tag. Optional operator APIs can vanish during upgrades, and ImageStreams alone do not establish Vulnerability Findings. |

#### Connector spec

| Stream | OCSF class | Cursor kind | Modes | Source record ID | Fingerprint inputs | AssetRef form |
|---|---|---|---|---|---|---|
| `route_scc_assessment_changes` | Compliance Finding (2003) | `page_token` | `incremental` | Route UID or SCC UID + explicit rule ID | Algorithm version + cluster + rule ID + Route namespace/name or cluster-scoped SCC identity | `k8s_resource:<cluster>/route.openshift.io/Route/<namespace>/<name>` or SCC identity |
| `route_scc_assessment_snapshot` | Compliance Finding (2003) | `snapshot` | `full` | Route UID or SCC UID + explicit rule ID | Same stable rule and assessed-object identity; exclude mutable status | Assessed Route or SCC resource identity |
| `policy_report_changes` | Compliance Finding (2003) | `page_token` | `incremental` | Report/constraint identity + policy/rule + subject resource | Cluster + policy/rule + subject identity | OpenShift cluster plus subject resource |
| `policy_report_snapshot` | Compliance Finding (2003) | `snapshot` | `full` | Report/constraint identity + policy/rule + subject resource | Stable policy/rule and subject identity | OpenShift cluster plus subject resource |
| `openshift_inventory_changes` | Non-finding configuration, build, execution, and image inventory | `page_token` | `incremental` | Route/SCC/BuildConfig/Build/ImageStream UID + resourceVersion; immutable Image name/digest | Cluster + API group/kind + namespace/name + UID; digest for Images | Route/SCC identity, owning BuildConfig, or registry/repository/tag plus digest |
| `openshift_inventory_snapshot` | Non-finding configuration, build, execution, and image inventory | `snapshot` | `full` | Same OpenShift object identity and revision | Same stable object identity; preserve observed tag-to-digest revisions | Same OpenShift resource or image identity |
| `audit_events` | API Activity (6003) | `sequence`; webhook deliveries have no file cursor | `incremental`, `full`, `event` | `API source + auditID + stage`; file cursor is `(API source,node,file)` byte offset | API source + auditID + stage | `objectRef`, requestURI, user, sourceIPs, and response status |

| Operation | Endpoint | Notes |
|---|---|---|
| `get_route` | `GET /apis/route.openshift.io/v1/...` | Read desired host/TLS and independent ingress status |
| `get_scc` | `GET /apis/security.openshift.io/v1/...` | Use the non-deprecated API group |
| `get_buildconfig` | `GET /apis/build.openshift.io/v1/...` | Read configuration separately from Builds |
| `get_build` | `GET /apis/build.openshift.io/v1/...` | Retain phase, timestamps, output, and config reference |
| `get_imagestream` | `GET /apis/image.openshift.io/v1/...` | Use `spec.tags[].from`; tags are mutable |
| `get_imagestream_tag` | Discovered ImageStreamTag resource path | Preserve observed tag-to-digest revision |
| `get_policy_report` | Discovered policy-report resource path | Optional Kyverno/OpenReports capability |
| `list_api_resources` | `GET /api` and `GET /apis` | Discovery determines optional operator availability |
| `get_cluster_version` | not sourced | Only when authorized |

| Action | Classification | Idempotency | Precondition |
|---|---|---|---|
| `annotate_route` | write | `natural_key` | Route UID/resourceVersion and namespace/name + annotation natural key |
| `update_route_tls` | write | not sourced | ResourceVersion, redacted exact diff, approval, and post-change router/status verification |
| `instantiate_buildconfig` | write | `none` | Persist plan before send; reconcile by owning BuildConfig and time window, returning `outcome_unknown` rather than blindly retrying |
| `update_scc` | destructive | not sourced | Exact field diff, resourceVersion, explicit approval, and post-change assessment |

| Field | Value |
|---|---|
| scheme | `openshift_audit` with configured bearer or mTLS authentication |
| header | No standard Red Hat HMAC signature or independent delivery-ID header |
| dedupe key | `API source + auditID + stage` |
| replay protection | not sourced; dedupe on `API source + auditID + stage` only; resource watches carry resourceVersion resume tokens |
| known gaps | Batching can drop events; managed node-log access may be unavailable; Build triggers are not ingestion webhooks |

| Capability | Scope or permission |
|---|---|
| OpenShift and policy reads | `get`, `list`, `watch` on enabled Route, SCC, Build, ImageStream, and discovered policy resources |
| Audit ingestion | Separate audit-source access or supported forwarding/webhook configuration |
| Route annotation or TLS update | Action-specific `patch` permission only when enabled |
| Build instantiation or SCC update | Action-specific `create` or `patch` permission with explicit action policy |

Top risks:
- Managed audit restrictions and multi-source rotation can produce incomplete or duplicated activity.
- Route payloads and action plans can expose private keys without declared redaction.
- SCC updates can widen or revoke workload privileges across the cluster.
- Mutable image tags and pruned history break lineage unless digest revisions are preserved.
- Uncertain Build instantiation outcomes must not trigger blind duplicate requests.
- Optional APIs, version skew, private CAs, and stale full-object updates can degrade coverage or writes.

## 6. Cloud posture

### Prisma Cloud

Prisma Cloud covers Cloud Security/CSPM posture and Runtime Security/Compute/CWPP workload scanning through separate endpoint and authentication profiles. This subsection defines kind `prisma_cloud` with profiles `cspm` and `compute`, spanning Prisma Cloud Enterprise and self-managed Compute Console. Native HTTP is authoritative for sync; no MCP-backed or file-parser dependency is required.

#### Facts

| Topic | Fact |
|---|---|
| Editions and API versions and sunsets | CSPM provides unversioned alert endpoints, `POST /v2/alert`, and versioned compliance endpoints. Compute is available in Enterprise and self-managed Console; its endpoint paths embed the Console version (`/api/v<VERSION>/<ENDPOINT_PATH>`), so ICUHUB must configure or probe the version rather than hardcode `34.05`. Legacy alert listing is capped at 10,000 results. Alert `riskDetail` is deprecated with no removal date and must not be mapped. Sunset dates: not sourced. |
| Authentication and scopes | CSPM (`cspm`) exchanges access key ID and secret at `POST /login` for a ten-minute JWT; keys inherit the creator's permission group. Compute (`compute`) accepts Basic credentials or `POST /api/v<VERSION>/authenticate` for a Bearer token, valid 30 minutes by default and configurable in Console. Cache tokens and refresh once per connection before expiry. Exact minimum CSPM custom-role permission names are tenant/release dependent [UNVERIFIED]. Compute declares `monitorImages`, `monitorHosts`, and `monitorRuntimeIncidents` independently. Do not automate SAML or browser login. SSO-only Compute local-user behavior is not confirmed [UNVERIFIED]. |
| Base URLs | CSPM uses the configured tenant-region API host from the table below (source: https://pan.dev/prisma-cloud/api/cspm/api-urls/). Compute uses the exact Path to Console from Compute Manage > System > Downloads plus `/api/v<VERSION>/<ENDPOINT_PATH>`; self-managed host, port, prefix, project, and CA can differ. Never derive Compute URLs from CSPM hosts, and keep the two profiles' credentials separate. |
| Rate limits and pagination | CSPM limits are per user across that user's tokens and vary by endpoint; honor the `X-RateLimit-Burst-Capacity`, `X-RateLimit-Remaining`, `X-RateLimit-Replenish-Rate`, and `X-RateLimit-Requested-Tokens` headers and back off on 429. No universal Retry-After value is documented. V2 alert list and async export submission allow 2 requests/second sustained and burst 10/second; alert detail allows 5/second and burst 10/second. V2 uses `limit`, `offset`, `pageToken`, and `nextPageToken`; maximum V2 page size: not sourced. Compute paginated requests use `limit` and `offset`, capped at and defaulting to 50; image, host, container, and registry endpoints each allow 30 requests per 30 seconds. Endpoint-specific limits take precedence over a connection-wide default. |
| Incremental support | CSPM alerts use `time_id` on Unix-millisecond `alert.time` plus `alert.id`, ascending with bounded overlap and a persisted batch end time. This is new-alert discovery, not a modification feed; reconcile status through scoped detail reads and complete async exports. Compliance posture, reports, and asset inventory use a separate time model (absolute end time from onboarding, or `to_now` with `epoch` only). Compute scans are snapshot-oriented, with full offset pagination partitioned by Console, project, collection, and asset type. Compute absence closure requires every included collection and every acknowledgment state read completely. |
| Webhooks (header, algorithm) | Initial CSPM has no verifier: no general alert signature algorithm, retry schedule, or delivery-ID header was confirmed [UNVERIFIED]. Compute alert profiles can push vulnerability, compliance, audit, cloud-discovery, Runtime, and WAAS alerts to a provider; generic HMAC, raw-byte signing, retry, and delivery-ID semantics are destination-specific [UNVERIFIED]. Polling remains authoritative. |
| MCP server and SDKs | No official Palo Alto Networks Prisma MCP server was confirmed; a GitHub search scoped to `org:PaloAltoNetworks` for `prisma mcp` returned zero results (https://api.github.com/search/repositories?q=org%3APaloAltoNetworks%20prisma%20mcp). Third-party Prisma MCP packages are unreviewed. [`PaloAltoNetworks/prismacloud-api-python`](https://github.com/PaloAltoNetworks/prismacloud-api-python) covers CSPM, CWPP, and CCS under ISC license but is best-effort and explicitly not supported by Palo Alto Networks. Use native async HTTP for token lifecycle, limiters, pagination, and export jobs. |
| Comparable open-source integrations | [DefectDojo Twistlock parser](https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/tools/twistlock/parser.py) imports JSON and CSV vulnerabilities and compliance issues but is not live sync. [XSOAR PrismaCloudV2](https://github.com/demisto/content/blob/master/Packs/PrismaCloud/Integrations/PrismaCloudV2/README.md) demonstrates lookback polling and status mirroring, with duplicate-incident and reopen caveats. [XSOAR Prisma Cloud Compute](https://github.com/demisto/content/tree/master/Packs/PrismaCloudCompute) demonstrates provider push, custom CA, and `aggregatedAlerts` expansion. |
| Gotchas | V2 `fields` is compact and omits alert rules; use `detailed=true` or alert detail for full mapping. Compliance posture is aggregate metrics, not resource-level 2003 findings. Async alert jobs ignore `sortBy`, `limit`, and `pageToken`. Do not use `compact=true` where detailed Compute CVE or compliance mapping is required. Regular registry scans serialize; on-demand scans run in parallel and cannot be stopped. Default Compute incident reads return only unacknowledged records. Precise behavior of every IdP configuration is [UNVERIFIED]. |

Regional CSPM console-to-API host mapping, reproduced from the pack (source: https://pan.dev/prisma-cloud/api/cspm/api-urls/):

| Console | API |
|---|---|
| `https://app.prismacloud.io` | `https://api.prismacloud.io` |
| `https://app2.prismacloud.io` | `https://api2.prismacloud.io` |
| `https://app3.prismacloud.io` | `https://api3.prismacloud.io` |
| `https://app4.prismacloud.io` | `https://api4.prismacloud.io` |
| `https://app.anz.prismacloud.io` | `https://api.anz.prismacloud.io` |
| `https://app.eu.prismacloud.io` | `https://api.eu.prismacloud.io` |
| `https://app2.eu.prismacloud.io` | `https://api2.eu.prismacloud.io` |
| `https://app.gov.prismacloud.io` | `https://api.gov.prismacloud.io` |
| `https://app.prismacloud.cn` | `https://api.prismacloud.cn` |
| `https://app.ca.prismacloud.io` | `https://api.ca.prismacloud.io` |
| `https://app.sg.prismacloud.io` | `https://api.sg.prismacloud.io` |
| `https://app.uk.prismacloud.io` | `https://api.uk.prismacloud.io` |
| `https://app.ind.prismacloud.io` | `https://api.ind.prismacloud.io` |
| `https://app.jp.prismacloud.io` | `https://api.jp.prismacloud.io` |
| `https://app.fr.prismacloud.io` | `https://api.fr.prismacloud.io` |
| `https://app.id.prismacloud.io` | `https://api.id.prismacloud.io` |

#### Connector spec

The kit supplies `time_id` and `snapshot` cursors, complete-snapshot absence closure, credential refresh, plan/apply action states, natural idempotency keys, and provider-specific webhook verification. Inventory, posture metrics, and configuration remain non-finding records; only mapped scanner or policy evidence uses OCSF finding classes. Stream and operation names carry their profile as the prefix or in parentheses.

| Stream | OCSF class | Cursor kind | Modes | Source record ID | Fingerprint inputs | AssetRef form |
|---|---|---|---|---|---|---|
| `cspm_config_alerts` (cspm) | 2003 | `time_id` | `incremental` | `alert.id` | Algorithm version, tenant, policy ID, compliance standard/requirement/section, resource RRN or ID | `resource.rrn`, account ID, region, service, resource type |
| `cspm_config_alerts_snapshot` (cspm) | 2003 | `snapshot` | `full` | `alert.id` | Same as `cspm_config_alerts` | Same as `cspm_config_alerts` |
| `cspm_vulnerability_alerts` (cspm) | 2002 | `time_id` | `incremental` | `alert.id` | Policy/vulnerability identity, package/component when present, resource identity; excludes severity, status, and lastSeen | Cloud resource plus affected package/component |
| `cspm_vulnerability_alerts_snapshot` (cspm) | 2002 | `snapshot` | `full` | `alert.id` | Same as `cspm_vulnerability_alerts` | Same as `cspm_vulnerability_alerts` |
| `cspm_detection_alerts` (cspm) | 2004 | `time_id` | `incremental` | `alert.id` | Policy ID, resource, stable finding-type evidence; only policy types explicitly classified as detections | Cloud account, region, resource, network evidence where supplied |
| `cspm_detection_alerts_snapshot` (cspm) | 2004 | `snapshot` | `full` | `alert.id` | Same as `cspm_detection_alerts` | Same as `cspm_detection_alerts` |
| `cspm_compliance_posture` (cspm) | Non-finding metrics | `snapshot` | `full` | Tenant + standard/requirement/section + posture end time | Tenant, standard hierarchy, posture end time | Account group, cloud account, region filters |
| `compute_image_vulnerabilities` (compute) | 2002 | `snapshot` | `full` | Console/project + scan/asset ID + CVE + package name/version/path + target type | Stable asset, CVE, package and location | Image digest, registry, repository, tag; digest wins over tag |
| `compute_host_vulnerabilities` (compute) | 2002 | `snapshot` | `full` | Console/project + host/scan ID + CVE + package name/version/path | Stable host, CVE, package and location | Hostname, scan ID, cloud metadata |
| `compute_compliance` (compute) | 2003 | `snapshot` | `full` | Asset/scan ID + compliance issue ID + target type | Compliance ID, stable asset | Image digest, container, host, collection, cluster |
| `compute_runtime_incidents` (compute) | 2004 | `snapshot` | `full`; optional `event` only after provider verification | Incident/audit ID; nested alerts keep their own source identity and parent delivery ID | Stable incident identity and evidence | Workload, container, host, cluster, image, cloud metadata |

| Operation | Endpoint | Notes |
|---|---|---|
| `get_alert` (cspm) | `GET /alert/:id` | Detail and status reconciliation; 5/second, burst 10/second |
| `list_alert_filters` (cspm) | not sourced | Alert filter read capability probe |
| `list_alerts_v2` (cspm) | `POST /v2/alert` | Time windows in Unix milliseconds, filters, sorting, `limit`, `offset`, `pageToken`; 2/second sustained, burst 10/second; use `detailed=true` or `get_alert` for full mapping |
| `submit_alert_export` (cspm) | `POST /alert/jobs` | Async JSON or CSV export for backfill and status reconciliation; 2/second sustained, burst 10/second |
| `get_alert_export_status` (cspm) | not sourced | Poll job status rather than paginating the job |
| `download_alert_export` (cspm) | not sourced | Download completed export |
| `get_compliance_posture` (cspm) | https://pan.dev/prisma-cloud/api/cspm/compliance-posture/ | Aggregate statistics and trends only; special time model |
| `get_compute_image` (compute) | https://pan.dev/prisma-cloud/api/cwpp/get-images/ | Full detailed scan pages with `limit` and `offset`; avoid `compact=true`; requires `monitorImages` |
| `get_compute_host` (compute) | https://pan.dev/prisma-cloud/api/cwpp/get-hosts/ | Offset pages, maximum 50; requires `monitorHosts` |
| `get_compute_container` (compute) | https://pan.dev/prisma-cloud/api/cwpp/get-containers/ | Offset pages, maximum 50; requires `monitorImages` |
| `get_compute_registry_image` (compute) | https://pan.dev/prisma-cloud/api/cwpp/get-registry/ | Registry image reads and scan reconciliation; requires `monitorImages` |
| `list_collections` (compute) | https://pan.dev/prisma-cloud/api/cwpp/collections/ | Console/project partition discovery; percent-encode collection names in URLs |
| `get_runtime_incident` (compute) | https://pan.dev/prisma-cloud/api/cwpp/get-audits-incidents/ | Default returns unacknowledged incidents only; read every acknowledgment state for complete closure; requires `monitorRuntimeIncidents` |

| Action | Classification | Idempotency | Precondition |
|---|---|---|---|
| `dismiss_alert` (cspm) | write | natural_key | Read current status and no-op if already dismissed; key is alert ID + target status + dismissal window; read back after apply |
| `snooze_alert` (cspm) | write | natural_key | Read current status; key is alert ID + target status + future dismissal window; read back after apply |
| `reopen_alert` (cspm) | write | natural_key | Alert currently dismissed or snoozed; key is alert ID + open target; read back and account for Resolved-status limitation |
| `remediate_alert` (cspm) | destructive | natural_key | Alert ID, policy/remediation diff, expected open status, explicit approval; verify alert and resource; never retry blindly after timeout (no ETag or version precondition documented) |
| `start_registry_scan` (compute) | write | natural_key | Console + registry/repository/digest + on-demand mode; regular scans serialize and on-demand scans cannot be stopped; reconcile through registry results |
| `create_or_update_collection` (compute) | write | natural_key | Collection `name` as key; changes policy scoping, so plan and read back |
| `delete_collection` (compute) | destructive | natural_key | Collection `name`; plan policy-scope impact and reconcile by name |

| Field | Value |
|---|---|
| scheme | `none` for both profiles initially; optional `compute_alert_profile` stays disabled until a destination contract is selected |
| header | `none` initially; Compute delivery-ID header is destination-specific [UNVERIFIED] |
| dedupe key | Not applicable initially; a later Compute mapping must preserve parent delivery ID and each nested alert identity |
| replay protection | Not applicable initially; a later verifier must implement the selected provider contract |
| known gaps | CSPM signature, retry, and delivery ID unconfirmed [UNVERIFIED]; Compute HMAC, raw-byte signing, retry, and delivery ID unconfirmed [UNVERIFIED] |

| Capability | Scope or permission |
|---|---|
| CSPM alert list, filter, and detail reads | Tenant role or permission group sufficient for each resource; exact minimum custom-role names [UNVERIFIED]; System Admin not required for read-only ingestion |
| CSPM compliance posture, asset inventory, and audit log reads | Separate probes per resource under the tenant role or permission group |
| CSPM alert state writes | Alert write permission, enabled only for dismiss, snooze, or reopen |
| CSPM remediation | Remediation permission, enabled only for approved remediation |
| Compute image, container, and registry reads | `monitorImages` |
| Compute host reads | `monitorHosts` |
| Compute runtime incidents | `monitorRuntimeIncidents` |
| Compute registry scans and collection writes | Separate registry-scan or collection write privileges; a missing permission yields `not_evaluated` for the affected capability |

Top risks:
- Wrong regional host, confused CSPM and Compute credentials, and short token lifetimes can invalidate every sync; keep profiles separate and refresh with single-flight locking.
- Alert-time pagination misses later status changes; close only on explicit source resolution or a complete reconciliation snapshot, never on absence from a bounded query.
- Compute offset pages over changing collections can duplicate or skip records; mark snapshots incomplete on any 429, 5xx, or permission failure.
- Default incident reads return unacknowledged records only, and aggregated deliveries hold many alerts; read all acknowledgment states and expand every nested alert.
- Remediation and registry scans have operational effects that are hard to undo; reconcile by source ID and never blindly retry ambiguous submissions.
- Self-managed Compute can use a private CA; accept a CA bundle and never default to skip-verify. Project and collection scope can make an empty result misleading.

## 7. Application security testing

### Fortify Software Security Center (SSC)

Fortify SSC is the self-managed Fortify findings server. This specification covers SSC 24.2 and later REST APIs, using the target server's own specification for capability discovery and the 25.4 public specification as a baseline. It defines kind `fortify_ssc` with native HTTP synchronization, optional FPR evidence replay, and optional interactive fcli MCP operations.

#### Facts

| Topic | Fact |
|---|---|
| Editions and API versions and sunsets | Self-managed SSC; REST `/api/v1`; documented indexes include 24.2.x, 24.4.x, 25.2.x, and 25.4.x. Public `master` identifies 25.4.0.0137; a 26.2.x listing was not confirmed [UNVERIFIED]. No public API sunset date found. [Documentation](https://www.microfocus.com/documentation/fortify-software-security-center/) and [specification](https://raw.githubusercontent.com/fortify/ssc-restapi-client/master/src/swagger/spec.json). |
| Authentication and scopes | `Authorization: FortifyToken <encoded-token>` preferred; Basic also exists. `AutomationToken` suits longer automation and inherits issuing-user permissions; narrow token types exist. Tokens cannot exceed user permissions; exact role permission names vary by release and configuration [UNVERIFIED]. |
| Base URLs | Operator-supplied root, normally `https://host[:port]/ssc`, plus `/api/v1`; discovery returns the effective context root and specification URL. No regional cloud hosts. |
| Rate limits and pagination | `start`, `limit`, `orderby`, `fields`, and usually `withoutCount`; responses generally contain `data`, `count`, and links. No universal numeric maximum, request quota, `Retry-After`, or `X-RateLimit-*` contract found [UNVERIFIED]. Use bounded pages and adaptive concurrency. |
| Incremental support | `issuesDeltaExports` uses `deltaSinceDate`; activity events provide numeric IDs. Issue full reads include removed, suppressed, and hidden records. FPR processing and indexing are asynchronous. |
| Webhooks (header, algorithm) | `X-SSC-Signature: sha256=<hex>`; HMAC-SHA256 over exact raw body bytes plus the HTTP `Date` value. One event per delivery; automatic retry count/backoff and unique delivery header not found [UNVERIFIED]. |
| MCP server and SDKs | Official fcli provides stdio and HTTP MCP; HTTP exposes `/mcp` and accepts `X-AUTH-SSC`. Official Java `ssc-restapi-client` and fcli are MIT licensed. [fcli MCP](https://fortify.github.io/fcli/latest/manpage/fcli-ai-assist-mcp-start-http.html), [Java client](https://github.com/fortify/ssc-restapi-client), and [fcli](https://github.com/fortify/fcli). MCP is interactive only; native HTTP is authoritative for sync. |
| Comparable open-source integrations | [DefectDojo parser](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/tools/fortify/parser.py), [DefectDojo connector reference](https://docs.defectdojo.com/connectors/toolreference/fortify/), and [FortifyVulnerabilityExporter](https://github.com/fortify/FortifyVulnerabilityExporter/blob/main/USAGE.md). These preserve audit state and wait for processing/indexing. A [historical XML import failure](https://github.com/DefectDojo/django-DefectDojo/issues/7154) illustrates schema/version fragility. |
| Gotchas | Version skew, mutable offset pages, default-hidden issue states, large expiring ZIP/FPR evidence, revision conflicts, private CAs, and deprecated `folderId`; use `folderGuid`. |

#### Connector spec

| Stream | OCSF class | Cursor kind | Modes | Source record ID | Fingerprint inputs | AssetRef form |
|---|---|---|---|---|---|---|
| issues | Vulnerability Finding (2002) | time_id | incremental, full | `issueInstanceId`; retain numeric `id` and `revision` | `primaryRuleGuid`, category/kingdom, normalized file/location/line, algorithm version | `application:<ssc-host>/<project-id>` and `application_version:<ssc-host>/<projectVersionId>` |
| artifacts | non-finding scan/artifact record | snapshot | full | artifact ID | not sourced | `application_version:<ssc-host>/<projectVersionId>` |
| activity | non-finding audit/activity record | sequence | incremental, full | numeric activity event ID | not sourced | `application_version:<ssc-host>/<projectVersionId>` |

| Operation | Endpoint | Notes |
|---|---|---|
| get_project_version | not sourced | Discovery uses `/projectVersions?limit=1`; retain stable numeric IDs and status |
| get_issue | not sourced | Collection filtering is under `/projectVersions/{parentId}/issues` |
| get_issue_details | not sourced | Bounded detail and evidence response |
| list_issue_audit | not sourced | Audit history is non-finding activity |
| list_comments | not sourced | Comments remain issue enrichment |
| get_artifact | not sourced | Reconcile processing status and `indexed` |
| download_fpr | `Artifact.fileURL` | Single-use `DOWNLOAD` file token passed as `mat`; stream and hash evidence |
| get_delta_export | `GET /issuesDeltaExports/{id}` | Poll started/completed/failed; checkpoint only after ZIP consumption |
| get_webhook_delivery | not sourced | Delivery history has ID and pending/sent/success/failed states |

| Action | Classification | Idempotency | Precondition |
|---|---|---|---|
| audit_issue | write | none | `EntityStateIdentifier(id, revision)`; plan from current revision and read back |
| set_issue_suppression | write | natural_key | `(projectVersionId, id, revision, suppressed)`; no blind retry |
| assign_issue | write | none | Issue ID and current revision; read back |
| add_issue_comment | write | none | `EntityStateIdentifier(id, revision)`; read back |
| upload_fpr | write | natural_key | Project version and artifact SHA-256; reconcile asynchronous artifact status |
| create_webhook | write | none | `WebHookDefinition.objectVersion` optimistic lock |
| purge_artifact | destructive | none | Artifact ID, current processing state, `versionNumber`, explicit approval |
| purge_project_version | destructive | none | Project version ID and explicit approval; never automatic retry |

| Field | Value |
|---|---|
| scheme | `hmac_sha256` over exact raw body plus `Date`; hexadecimal prefixed `sha256=` |
| header | `X-SSC-Signature`; freshness uses HTTP `Date` |
| dedupe key | Derived from `webhookId`, `triggeredAt`, and canonical body digest |
| replay protection | Proposed 300-second Date freshness window |
| known gaps | Automatic retry count/backoff and unique delivery header [UNVERIFIED] |

| Capability | Scope or permission |
|---|---|
| Discover applications and versions | Application/version view |
| Read issues and enrichment | Issue view including removed/suppressed; issue detail and audit-history view |
| Audit, assign, or suppress issues | Issue audit/suppress permission, only on write-enabled connections |
| Read or upload artifacts | Artifact read/upload separately |
| Read reports | Report permission separately |
| Provision webhooks | Webhook management; Administrator or Security Lead with entity visibility |

Top risks:
- Target-server capability drift across SSC releases.
- Delta ZIP expiration and large evidence files.
- False closure when removed, suppressed, or hidden issues are omitted.
- Treating upload completion as processed and indexed findings.
- Revision conflicts and partial merge conflicts during issue audits.

### Fortify on Demand (FoD)

Fortify on Demand is OpenText's multi-tenant SaaS application security service, with no self-managed edition. This specification covers Web API v3 and defines kind `fortify_fod` as a native HTTP OAuth2 connector. fcli MCP is optional for interactive operations; synchronization remains poll-based over native HTTP.

#### Facts

| Topic | Fact |
|---|---|
| Editions and API versions and sunsets | Multi-tenant SaaS only; Web API v3 at `/api/v3`; no v2 compatibility requirement and no v3 sunset found. `fod-uploader-java` is in maintenance mode, not an API deprecation. [API Explorer](https://api.ams.fortify.com/swagger/ui/index), [Swagger](https://api.ams.fortify.com/swagger/docs/v3), and [uploader status](https://github.com/fod-dev/fod-uploader-java). |
| Authentication and scopes | `POST <api-host>/oauth/token`; OAuth2 `client_credentials` or `password` grant with `Tenant\Username` and password/PAT. Bearer access token; production uses least-privilege client credentials. Scopes include `api-tenant`, `view-apps`, `view-issues`, `manage-issues`, `view-reports`, and `manage-reports`. |
| Base URLs | `https://api.ams.fortify.com` and `https://api.emea.fortify.com`, each with `/oauth/token` and `/api/v3`. API host follows tenant portal region; other regions/hostnames are [UNVERIFIED]. Tenant code is an auth value, not a path segment. |
| Rate limits and pagination | Zero-based `offset`, `limit`, `orderBy`, `orderByDirection`, `fields`, and usually `totalCount`; maximum 50 for applications/releases/scans/reports. Vulnerability page cap is tenant-configured. No universal numeric quota or standard limit headers found [UNVERIFIED]. Honor 202 repository-updating and 429 backoff. |
| Incremental support | Applications/releases use `modifiedStartDate`; issues use date-only `lastModifiedDate` with `includeFixed` and `includeSuppressed`. Use full-day overlap and ID dedupe. Complete release snapshots drive absence closure; no dedicated tombstone feed. |
| Webhooks (header, algorithm) | Reviewed v3 OpenAPI has no webhook-management endpoints. Event types, signature header/algorithm, delivery ID, and retries are [UNVERIFIED]; initial manifest is polling only. [Delivery viewer page](https://docs.microfocus.com/doc/2197/25.4/bb98c32036b6_webhooks_deliveries). |
| MCP server and SDKs | Official fcli supports stdio/HTTP MCP and `X-AUTH-FOD`; Java uploader is in maintenance mode. No separate general-purpose official Python SDK identified [UNVERIFIED]. [fcli MCP](https://fortify.github.io/fcli/latest/manpage/fcli-ai-assist-mcp-start-http.html) and [FoD skill](https://github.com/fortify/skills/blob/main/skills/fortify-fod/SKILL.md). |
| Comparable open-source integrations | [DefectDojo connector reference](https://docs.defectdojo.com/connectors/toolreference/fortify/), [FortifyVulnerabilityExporter](https://github.com/fortify/FortifyVulnerabilityExporter/blob/main/USAGE.md), and official [issue-investigation guidance](https://raw.githubusercontent.com/fortify/skills/main/skills/fortify-fod/references/use-case-issue-investigation.md). |
| Gotchas | Date-only deltas, mutable offsets, 202 inconsistent snapshots, N+1 embed cost, tenant-specific statuses, asynchronous imports without scan IDs, billable scan starts, and possible HTTP 500 from multi-`instanceId` set filters. |

#### Connector spec

| Stream | OCSF class | Cursor kind | Modes | Source record ID | Fingerprint inputs | AssetRef form |
|---|---|---|---|---|---|---|
| issues | Vulnerability Finding (2002) | time_id | incremental, full | `instanceId` UUID; retain `vulnId` and numeric `id` | `instanceId`, rule/check/category, normalized location/line, source/sink, package | `application:<fod-tenant>/<applicationId>` and `application_release:<fod-tenant>/<releaseId>` |
| scans | non-finding scan record | time_id | incremental, full | `scanId` | not sourced | `application_release:<fod-tenant>/<releaseId>` |
| data_exports | non-finding asynchronous export job | snapshot | full | not sourced | not sourced | not sourced |

| Operation | Endpoint | Notes |
|---|---|---|
| get_release | not sourced | Discover applications, microservices, releases, and scan capabilities |
| get_issue | not sourced | Use one equality query per `instanceId`; avoid multi-instance set filters |
| get_issue_details | not sourced | Bound enrichment; avoid `allData` fan-out |
| get_issue_history | not sourced | History enriches the same finding |
| get_recommendations | not sourced | Recommendations and traces are finding enrichment |
| list_scans | not sourced | Maximum page size 50 |
| get_scan | not sourced | Reconcile current and in-progress scan state |
| download_fpr | not sourced | Available per release+scanType and per scan; may return 202 |
| get_report | not sourced | Poll asynchronous report status |
| download_data_export | `/reports/dataexports` | Supports issues, scans, releases, applications, and entitlement consumption |

| Action | Classification | Idempotency | Precondition |
|---|---|---|---|
| bulk_audit_issues | write | natural_key | `(releaseId, sorted vulnId set, desired patch)`; compare current state and inspect per-item results |
| start_scan | write | none | Release, assessment, entitlement, profile, payload hash, and no conflicting in-progress scan; billable |
| cancel_scan | destructive | none | Scan ID and nonterminal state |
| import_scan | write | natural_key | Release and payload SHA-256; imports return no scan ID, so reconcile release current scan |
| create_report | write | natural_key | Natural request fingerprint; poll report/export ID |
| delete_release_application_report | destructive | none | Exact ID and explicit approval; disabled by default |

| Field | Value |
|---|---|
| scheme | none; polling only until tenant evidence establishes raw-body signature semantics |
| header | none |
| dedupe key | none; delivery ID [UNVERIFIED] |
| replay protection | none |
| known gaps | Supported events, signature algorithm/header, delivery ID, and retry behavior [UNVERIFIED] |

| Capability | Scope or permission |
|---|---|
| Discover applications, releases, and scans | `view-apps` |
| Read issues, FPR, and history | `view-issues` |
| Read/download data exports | `view-reports` |
| Create reports | `manage-reports` |
| Bulk audit and release audit actions | `manage-issues` |
| Start scans | not sourced (OAuth scope name); also requires release assessment type, entitlement, and user role |

Top risks:
- Day-precision issue deltas and mutable offset pagination.
- N+1 detail traffic and tenant-specific page caps or statuses.
- Incomplete snapshots while the repository returns 202.
- Non-idempotent, billable scan starts and asynchronous imports.
- Confusing `instanceId`, `vulnId`, and numeric `id` identity roles.

### Invicti Enterprise

Invicti Enterprise On-Demand and On-Premises share REST API 1.0 and a common OpenAPI document. This subsection defines `invicti_enterprise` for native HTTP issue, scan, and scan-result synchronization, with authenticated issue-export webhooks.

#### Facts

| Topic | Fact |
|---|---|
| Editions and API versions and sunsets | On-Demand and On-Premises use REST API 1.0; OpenAPI: https://www.netsparkercloud.com/swagger/docs/v1. Release-note content was not reviewed in detail [UNVERIFIED]. Newer releases may add selected profile/policy PATCH semantics [UNVERIFIED]. |
| Authentication and scopes | HTTP Basic with User ID as username and API Token as password. Permissions inherit from the API user; exact role bundles are tenant/version dependent [UNVERIFIED]. Overview: https://docs.invicti.com/ie-is/api-settings-overview. |
| Base URLs | On-Demand: `https://www.netsparkercloud.com/api/1.0`. On-Premises: configured HTTPS root plus `/api/1.0`; reverse-proxy prefix variations are [UNVERIFIED]. |
| Rate limits and pagination | Most endpoints: 200 requests/minute. `/issues/allissues` and `/issues/summary`: 10/minute, 600/hour, 14,400/day. `page`/`pageSize`, 1-200; Retry-After and rate-limit headers are [UNVERIFIED]. |
| Incremental support | Issues filter by `lastSeenDate`; scans use `StateChanged` windows. Triage-only edits may not advance last-seen [UNVERIFIED], so periodic full issue snapshots are mandatory. |
| Webhooks (header, algorithm) | Configurable issue-export and notification webhooks support Basic credentials and custom headers. Built-in HMAC, signed timestamps, delivery IDs, and retry schedules are not documented [UNVERIFIED]. |
| MCP server and SDKs | No vendor-official public MCP server or general-purpose official Enterprise SDK identified [UNVERIFIED]. Official organization: https://github.com/Invicti-Security. |
| Comparable open-source integrations | DefectDojo file parsers: https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/tools/invicti/parser.py and https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/tools/netsparker/parser.py. Official CI examples: https://github.com/netsparker/Netsparker-Cloud-GitHub-Actions and https://github.com/netsparker/netsparker-orb. |
| Gotchas | Expensive issue endpoints need a credential-wide bucket; bound raw HTTP/HTML evidence; use PUT rather than deprecated POST issue updates; webhook bodies are configurable templates; scan creation has no documented idempotency key [UNVERIFIED]. |

#### Connector spec

| Stream | OCSF class | Cursor kind | Modes | Source record ID | Fingerprint inputs | AssetRef form |
|---|---|---|---|---|---|---|
| `issues` | Vulnerability Finding (2002) | `time_id`: `LastSeenDate` + issue UUID, with overlap | `incremental`, `full` | Issue UUID | Issue type/check, normalized URL/parameter, website ID, algorithm version | `web_application:<invicti-account>/<websiteId>` |
| `scans` | Non-finding scan execution | `time_id`: `StateChanged` + scan UUID | `incremental`, `full` | Scan UUID | not sourced | `web_application:<invicti-account>/<websiteId>` |
| `scan_results` | Vulnerability Finding (2002) | `snapshot` per completed scan | `full` | not sourced | not sourced | `web_application:<invicti-account>/<websiteId>` |

| Operation | Endpoint | Notes |
|---|---|---|
| `list_issues` | `/issues/allissues` | Filter by `lastSeenDate`, sort, severity, website, and source type; 10/minute bucket |
| `list_scans` | `/scans/list`, `/scans/listbystatechanged` | Windows by `initiatedDate` or required `StateChanged` start/end |
| `get_website` | not sourced | Discover UUID, root URL, and groups |
| `get_issue` | not sourced | Read canonical issue and bounded evidence; `PUT /issues/{id}` is the sourced update route |
| `get_issue_history` | not sourced | Read issue state history |
| `get_scan` | not sourced | Read status and timestamps |
| `get_scan_result` | `/scans/result/{id}` | Full per-scan observations |
| `download_report` | `/scans/report` | Also supports custom report downloads |
| `list_notifications` | not sourced | Inspect notification and integration configuration |

| Action | Classification | Idempotency | Precondition |
|---|---|---|---|
| `update_issue` | write | `natural_key`: issue UUID + desired state/assignee/tags | Read current issue; Manage Issue permission |
| `start_scan` | write | `natural_key`: website + profile + target + requested schedule | Start Scan permission; approved target and profile; reconcile by target/profile/initiated time |
| `retest_scan` | write | `natural_key`: website + profile + target + requested schedule | Approved active retest and current target/profile |
| `pause_scan` / `resume_scan` | write | `natural_key`: scan UUID + desired state | Expected current scan state |
| `cancel_scan` | destructive | `natural_key`: scan UUID + cancelled state | Explicit approval and expected running state; no blind retry |
| `delete_scan` | destructive | `natural_key`: scan UUID + deleted state | Explicit approval; no blind retry |
| `manage_website_or_agent` | write / destructive | `natural_key`: resource UUID + desired config | Current config read first; delete disabled by default |
| `manage_notification` | write | `natural_key`: notification/integration ID or name + event + scope | Narrow website/user scope; avoid Any Website plus Any User |

| Field | Value |
|---|---|
| scheme | `static_header` or `basic_auth` over TLS; no HMAC asserted |
| header | Operator-configured high-entropy custom header or Basic credentials |
| dedupe key | Issue ID + update/last-seen timestamp + integration ID + body digest |
| replay protection | Persist raw body, parser version, integration ID, and configuration revision; treat delivery as at-least-once |
| known gaps | Signed timestamp, vendor delivery ID, and automatic retry contract not documented [UNVERIFIED] |

| Capability | Scope or permission |
|---|---|
| Read websites, issues, scans | Website/scan/issue visibility for the dedicated API user |
| Start or retest scans | Start Scan |
| Update or export issues | Manage Issue |
| Manage notifications | Notification management, separately probed |

Top risks:
- Low quotas on expensive issue endpoints are shared across workers and replicas.
- Last-seen incremental sync can miss triage edits; full snapshots provide authoritative absence closure.
- Template payload drift and untrusted HTML/HTTP evidence require versioned parsing and bounded storage.
- Scan initiation actively tests a target and requires allowlists, profile review, and approval.
- On-premises path prefixes, private CAs, IP restrictions, SSO behavior, and version skew can differ by deployment.

### Invicti Standard

Invicti Standard is the desktop edition with JSON report ingestion and outbound Send To Actions, not the Enterprise REST surface. This subsection defines `invicti_standard` as a native JSON file parser plus a generic authenticated webhook receiver.

#### Facts

| Topic | Fact |
|---|---|
| Editions and API versions and sunsets | Desktop Standard; public integration category: https://docs.invicti.com/ie-is/category/api-1. Enterprise REST compatibility must not be inferred [UNVERIFIED]. Release-note content was not reviewed in detail [UNVERIFIED]. |
| Authentication and scopes | Send To Actions support optional Basic username/password and arbitrary HTTP headers; no OAuth service-account flow is documented. Local report access and the webhook secret are the connector credentials. |
| Base URLs | Report ingestion is file-based. Webhooks target the operator-supplied ICUHUB HTTPS endpoint. |
| Rate limits and pagination | not sourced |
| Incremental support | No reviewed incremental REST feed. Each exported JSON report is a full scan snapshot reconciled by report/scan and issue identity. |
| Webhooks (header, algorithm) | GET/POST/PUT with Form/JSON/XML/QueryString, templates, Basic credentials, and custom headers: https://docs.invicti.com/ie-is/integrating-invicti-standard-webhook. Built-in HMAC, signed timestamps, delivery IDs, and retry schedules are not documented [UNVERIFIED]. |
| MCP server and SDKs | No vendor-official public MCP server identified [UNVERIFIED]; Standard SDK not sourced. |
| Comparable open-source integrations | DefectDojo maps Invicti JSON through the Netsparker parser: https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/tools/invicti/parser.py and https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/tools/netsparker/parser.py. |
| Gotchas | Manual and Auto Send To Actions produce configurable, non-versioned payloads. Reports may lack website UUIDs; retain report ID and use configured website mapping or canonical URL. Do not point the Enterprise client at Standard. |

#### Connector spec

| Stream | OCSF class | Cursor kind | Modes | Source record ID | Fingerprint inputs | AssetRef form |
|---|---|---|---|---|---|---|
| `report_issues` | Vulnerability Finding (2002) | `snapshot`: report hash + parsed target | `full`, `replay` | Report ID + parsed vulnerability identity | Issue type/check, normalized URL/parameter, configured website ID or canonical URL, algorithm version | Configured `web_application:<invicti-account>/<websiteId>` or canonical URL asset |
| `webhook_issues` | Vulnerability Finding (2002) | not sourced | `event` | not sourced | Body digest (pack proposal); issue type/check, normalized URL/parameter, configured website ID or canonical URL, algorithm version | Configured website asset or canonical URL asset |

| Operation | Endpoint | Notes |
|---|---|---|
| `parse_report` | Uploaded JSON report artifact | Validate readability, report ID, target URL, metadata, and `Vulnerabilities[]` |

| Action | Classification | Idempotency | Precondition |
|---|---|---|---|
| none in pack | none in pack | none in pack | none in pack |

| Field | Value |
|---|---|
| scheme | `static_header` or `basic_auth` over TLS; no HMAC asserted |
| header | Operator-configured high-entropy custom header or Basic credentials |
| dedupe key | Body digest (pack proposal); issue ID and integration ID not sourced for Standard payloads |
| replay protection | Persist raw body, parser version, and configuration revision; treat delivery as at-least-once |
| known gaps | Signed timestamp, vendor delivery ID, and automatic retry contract not documented [UNVERIFIED] |

| Capability | Scope or permission |
|---|---|
| Parse exported reports | Local report read |
| Receive webhook issues | Configured webhook secret |

Top risks:
- Standard and Enterprise integration surfaces differ; no remote scan action is defined.
- Configurable webhook templates can drift and omit stable issue or website identifiers.
- Full report snapshots must complete before absence can close findings.
- Webhook secrets and raw request/response evidence require protected, bounded storage.

### Mend SCA

Mend SCA is SaaS with regional and dedicated instances and legacy WhiteSource hostnames. This subsection defines `mend_sca` for native HTTP with an explicit `api_version: 3.0 | 2.0`; separate connections are required when both versions cover the same organizational scope.

#### Facts

| Topic | Fact |
|---|---|
| Editions and API versions and sunsets | Platform API 3.0: https://api-docs.mend.io/platform/3.0. Legacy SCA API 2.0 remains listed: https://api-docs.mend.io/sca/2.0. HTTP API 1.3/1.4 is legacy and out of scope; no 2.0 sunset date was found. |
| Authentication and scopes | Email + user key + organization token/UUID at `/login`, then organization-scoped JWT Bearer auth; 3.0 also supports `/login/accessToken` with `wss-refresh-token`. Exact per-endpoint role mapping is [UNVERIFIED]. |
| Base URLs | 2.0 default `https://api-saas.mend.io`; 3.0 includes `https://api-app.mend.io/api/v3.0`, `https://api-saas.mend.io/api/v3.0`, and `https://api-saas-eu.mend.io/api/v3.0`. Dedicated URLs are operator supplied: https://docs.mend.io/platform/latest/getting-started-with-mend-api-3-0. |
| Rate limits and pagination | 2.0 uses zero-based `page`/`pageSize`; 3.0 uses `cursor`/`limit`. Defaults are 50 and reviewed maxima reach 10,000. Universal quotas, 429 declarations, and header contracts are [UNVERIFIED]. |
| Incremental support | 2.0 security alerts filter and sort by `modifiedAt`. 3.0 project last-scan deltas miss finding-only edits; scheduled full project findings are authoritative. Activity events use timestamp + UUID. |
| Webhooks (header, algorithm) | No webhook endpoints in either OpenAPI document; no generic signed Automation Workflow webhook identified [UNVERIFIED]: https://docs.mend.io/platform/latest/workflow-configuration-parameters. Connector is polling only. |
| MCP server and SDKs | No vendor-official public MCP server identified [UNVERIFIED]. Official Apache-2.0 Java agents/client project: https://github.com/whitesource/agents; native HTTP against OpenAPI is preferred. |
| Comparable open-source integrations | Port Ocean polling and forced-full model: https://github.com/port-labs/ocean/tree/main/integrations/mend. DefectDojo JSON parser: https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/tools/mend/parser.py. |
| Gotchas | Tokens and UUIDs are not interchangeable across 2.0/3.0; documented JWT lifetime varies between 10 and 30 minutes; use returned TTL. `findingInfo.status` is deprecated in favor of `findingInfo.findingStatus`. No universal ETag/idempotency header was found [UNVERIFIED]. |

#### Connector spec

| Stream | OCSF class | Cursor kind | Modes | Source record ID | Fingerprint inputs | AssetRef form |
|---|---|---|---|---|---|---|
| `security_findings` (3.0) | Vulnerability Finding (2002) | `snapshot`: snapshot ID + high-water start + targets done | `full`; non-authoritative project `time_id` candidate refresh | Finding UUID | Project UUID, CVE/vulnerability, PURL or coordinates, dependency path/context, algorithm version | `project:<mend-org>/<projectUuid>` |
| `legal_violations` (3.0) | Compliance Finding (2003) | `snapshot` | `full` | not sourced | Project UUID, policy/rule, license, component; algorithm version not sourced | `project:<mend-org>/<projectUuid>` |
| `libraries` (3.0) | Non-finding package inventory | `snapshot` | `full` | Library UUID | Project UUID, canonical PURL or coordinates/version/type | `project:<mend-org>/<projectUuid>`; application asset where applicable |
| `activity` (3.0) | Non-finding audit event | `time_id`: event timestamp + event UUID | `incremental`, `full` | Event UUID | Event UUID | Organization, application, or project UUID from event scope |
| `security_alerts` (2.0) | Vulnerability Finding (2002) | `time_id`: `alertInfo.modifiedAt` + alert UUID | `incremental`, `full` | Alert UUID | Project UUID, CVE/vulnerability, PURL or coordinates, dependency path/context, algorithm version | `project:<mend-org>/<projectUuid>` |
| `legal_alerts` (2.0) | Compliance Finding (2003) | `snapshot` | `full` | Alert UUID | Project UUID, policy/rule, license, component; algorithm version not sourced | `project:<mend-org>/<projectUuid>` |

| Operation | Endpoint | Notes |
|---|---|---|
| `list_security_alerts` (2.0) | not sourced | `modifiedAt:between:start,end` filter and `sort=modifiedAt`; `page`/`pageSize` |
| `list_security_findings` (3.0) | not sourced | `cursor`/`limit`; no general `modifiedAt` filter in reviewed endpoint |
| `get_project` | not sourced | Discover stable application/product and project identity |
| `get_finding` | not sourced | Versioned 2.0 alert or 3.0 finding parser |
| `get_library` | not sourced | Bound library and source-file volume |
| `get_dependency_paths` | not sourced | Preserve transitive dependency contexts |
| `get_vulnerability_profile` | not sourced | Read CVE/MSC, CVSS, threat, and fix metadata |
| `get_remediation` | not sourced | Read topFix/update guidance without fingerprinting on it |
| `get_policy` | not sourced | Read policy and priority configuration |
| `get_report_status` | `/orgs/{orgUuid}/reports/{reportUuid}` | 3.0 asynchronous report status |
| `download_report` | not sourced | Download by report UUID |
| `get_permissions` | `/orgs/{orgToken}/permissions`, `/products/{productToken}/permissions`, `/projects/{projectToken}/permissions`, `/permissions/byRole` | 2.0 role and capability probes |

| Action | Classification | Idempotency | Precondition |
|---|---|---|---|
| `set_alert_status` (2.0) | write | `natural_key`: projectToken + alert UUID + desired status | Read current state/comment; alert triage permission |
| `set_finding_status` (3.0) | write | `natural_key`: projectUuid + rootLibraryUuid + desired findingStatus | Verify current finding and permitted root-library transition |
| `create_or_update_policy` | write | `natural_key`: scope + name or policy UUID | Full filter/action diff and policy administration |
| `apply_policy` | write | `key`: asynchronous status UUID | Review broad scope; reconcile async status |
| `import_sbom` | write | `natural_key`: project UUID + SBOM SHA-256 | Approved project and queued scan/status reconciliation |
| `create_project` | write | `natural_key`: scope + name; existing project returned on create | Read first to detect existing project/product/application |
| `update_project_metadata` | write | `natural_key`: exact UUID + current parent/value | Reassign project, mark library in-house, edit copyright/license; separate high-impact approval |
| `delete_resource` | destructive | `natural_key`: exact UUID | Explicit approval for policy, project, product, report, or user/library metadata; no blind retry |

| Field | Value |
|---|---|
| scheme | `none`: polling only; neither API defines webhook endpoints and no signed workflow webhook was identified [UNVERIFIED] |
| header | none |
| dedupe key | none; activity event UUID is available only as a hint |
| replay protection | none; activity logs are hints and scheduled full findings remain authoritative |
| known gaps | No vendor HMAC, delivery ID, or retry contract asserted |

| Capability | Scope or permission |
|---|---|
| Findings and libraries | Organization/project finding and library read with least-privileged member/user role |
| Legal and violations | Legal/violation read, separately probed |
| Activity | Activity-log read, separately probed and license dependent |
| Alert/finding triage | Alert triage such as `ALERTS_IGNORER` or permitted finding suppression role |
| Policy and SBOM/report actions | Policy administration, `SBOM_EXPORTER` where enforced, and report roles separately |

Top risks:
- Large full findings, library, legal, and source-file exports require separate budgets and bounded pages.
- Project last-scan deltas miss suppression, status, and topFix edits; only complete snapshots close absence.
- Dual-version identities, response envelopes, and renamed fields require explicit versioned parsers.
- JWT lifetime ambiguity and concurrent refreshes require returned-TTL handling and one refresh retry.
- Suppression, policy application, inventory import, and destructive operations can have broad side effects.

## 8. Vulnerability management

### Qualys (VMDR and WAS)

Qualys Enterprise subscriptions expose VM/PC, KnowledgeBase, WAS, and GAV/CSAM APIs with subscription-dependent enablement. This subsection defines `qualys_enterprise` with independently enabled `vmdr` and `was` profiles; CSAM assets enrich VMDR and are not finding identity.

#### Facts

| Topic | Fact |
|---|---|
| Editions and API versions and sunsets | HLD XML v6 is Active; v5 EOS Feb 2027 and EOL Aug 2027; v4/v3 EOS Dec 2025 and EOL Jun 2027. KnowledgeBase endpoint is v4.0 XML; v3 EOS Aug 2026 and EOL Feb 2027; v2 EOS Dec 2025 and EOL Dec 2026. VMRS JSON HLD is described as Draft in the Qualys 10.41 Limited Customer Release notice dated 2026-10-22; GA in the target subscription is `[UNVERIFIED]`. WAS uses QPS REST 3.0; CSAM uses Gateway API v2.9, with newer 2.x changes `[UNVERIFIED]`. |
| Authentication and scopes | VM/PA baseline is HTTP Basic over TLS; session and JWT mechanics are `[UNVERIFIED]`. CSAM `POST /auth` returns a four-hour JWT for `Authorization: Bearer <token>`. Results follow business-unit, tag, and asset-group scope; role mapping is `[UNVERIFIED]`. Use a dedicated integration user per connection so `check` can report scope. WAS requires the module and API access; ignore/activate permission names are `[UNVERIFIED]`. |
| Base URLs | Persist `api_server_url` and `api_gateway_url` separately. US1 examples are `https://qualysapi.qualys.com` and `https://gateway.qg1.apps.qualys.com`; Private Cloud patterns are `https://qualysapi.<customer_base_url>` and `https://qualysgateway.<customer_base_url>`. The full region list is `[UNVERIFIED]`. |
| Rate limits and pagination | The 2018 [limits document](https://cdn2.qualys.com/docs/qualys-api-limits.pdf) lists Express 1 concurrent/50 daily, Standard 2/300 hourly, Enterprise 5/750 hourly, Premium 10/2,000 hourly for VM/PC only; current tenant limits are `[UNVERIFIED]`. Honor rate/concurrency headers and XML errors 1960/1965, including HTTP 409. HLD uses truncation warning plus `id_min`; VMRS uses `requestId` plus `pageNumber`; QPS uses `lastId`; CSAM uses `lastSeenAssetId`. CSAM maximum page size is `[UNVERIFIED]`. |
| Incremental support | HLD detection-update filters and KnowledgeBase modification filters support overlap windows, but exact names/defaults are `[UNVERIFIED]`. WAS has no single modified-since field covering every mutation, so use overlap plus periodic full reconciliation `[INFERENCE]`. Complete same-scope CSAM traversal is the inventory snapshot; a deleted-asset feed is `[UNVERIFIED]`. |
| Webhooks (header, algorithm) | No signed VMDR HLD, KnowledgeBase, or WAS push contract was found. Event types, signatures, retries, and delivery IDs are `[UNVERIFIED]`; Qualys ETM webhooks are a separate product. Poll only. |
| MCP server and SDKs | No vendor-official general MCP server was found `[UNVERIFIED for absence]`. The [official sample repository](https://github.com/QualysAPI/Qualys-API-Doc-Center) contains samples rather than a packaged SDK; its license is `[UNVERIFIED]`. |
| Comparable open-source integrations (with pack links) | [DefectDojo](https://github.com/DefectDojo/django-DefectDojo) has host XML/CSV and WAS file parsers, not API sync. Select the parser by root element or envelope rather than filename. |
| Gotchas | XML HLD, VMRS JSON, and QVS are distinct contracts. `Fixed` is remediation, not host deletion. Scoped responses can be valid but partial. `truncation_limit=0`, evidence, and WAS payloads create volume risk. Server and gateway hosts are not interchangeable, and confusing them yields credential-like auth or 404 errors. Private Cloud needs a configurable trust bundle; subscription-wide concurrency is shared. |

#### Connector spec

| Stream | OCSF class | Cursor kind | Modes | Source record ID | Fingerprint inputs | AssetRef form |
|---|---|---|---|---|---|---|
| `vmdr.host_detections` | 2002 confirmed/potential; 2004 information-gathered | `time_id` on update time with overlap; tie host + QID + instance | `incremental`, `full` | connection + host ID + QID + unique vulnerability ID + port/instance `[UNVERIFIED for uniqueness statement]` | host identity + QID + port + protocol | host/asset ID or cloud resource ID; IP/DNS attributes only |
| `was.findings` | 2002 vulnerabilities; 2004 informational/sensitive-content or retained evidence | `time_id` on last detected; tie `uniqueId` | `incremental`, `full` | `uniqueId` | web app ID + URL/path + parameter + payload | web app ID + base URL |
| `vmdr.knowledgebase` | non-finding VulnIntel | `time_id` on service modification time; tie QID | `incremental`, `full` | QID | not sourced | none; join detections by QID |
| `vmdr.assets` | non-finding asset records | `snapshot` with snapshot ID and `targets_done` | `full` | host/asset ID or cloud resource ID | not sourced | host/asset ID or cloud resource ID |

| Operation | Endpoint | Notes |
|---|---|---|
| `vmdr.get_host_detections` | `/api/{v}/fo/asset/host/vm/detection/?action=list` | Start with XML v6; GET or POST; bounded truncation and `id_min` continuation. |
| `vmdr.get_qid` | `/api/4.0/fo/knowledge_base/vuln/?action=list` | XML KnowledgeBase; do not substitute QVS JSON. |
| `was.search_findings` | `POST /qps/rest/3.0/search/was/finding` | QPS keyset continuation with `lastId`. |
| `was.get_finding` | not sourced | Read current state for action planning and read-back. |
| `vmdr.search_assets` | `/rest/2.0/search/am/asset` | Gateway host; complete same-scope traversal for snapshots. |
| `vmdr.count_assets` | `/rest/2.0/count/am/asset` | Gateway host; count endpoint from the CSAM v2.9 guide. |
| `vmdr.get_api_usage` | not sourced | Expose rate and concurrency headers in health checks. |

| Action | Classification | Idempotency | Precondition |
|---|---|---|---|
| `was.ignore_finding` | write | `natural_key`: finding `uniqueId` | `plan` reads ignore state, reason, and comment; identical state returns `no_op`; `apply` verifies by read-back. |
| `was.reactivate_finding` | write | `natural_key`: finding `uniqueId` | Target only the named finding with current-state read and read-back; never use collection-level activation. |

| Field | Value |
|---|---|
| Verifier | none; no documented VMDR or WAS signed push contract, so native polling is authoritative. |

| Capability | Scope or permission |
|---|---|
| VMDR detections and KnowledgeBase | VM API and KnowledgeBase access with intended host scope; exact role mapping `[UNVERIFIED]`. |
| WAS reads | WAS module plus API access. |
| WAS ignore/reactivate | Write permission; exact permission names `[UNVERIFIED]`. |
| CSAM assets | CSAM read access; probe each service independently in `check`. |

Top risks:
- XML/JSON version skew and silent legacy-parameter translation.
- Partial RBAC visibility and unsafe absence closure after scope changes.
- WAS metadata/ignore mutations escaping incremental detection.
- Shared concurrency, HTTP 409/XML errors, and server/gateway mix-ups.
- Large evidence payloads and Private Cloud certificate trust.

### Tenable Vulnerability Management

Tenable Vulnerability Management is the cloud product at `https://cloud.tenable.com`; self-managed Nessus does not use this export surface. This subsection defines the read-only `tenable_vm` native connector around asynchronous vulnerability and asset exports.

#### Facts

| Topic | Fact |
|---|---|
| Editions and API versions and sunsets | Use `POST /vulns/export` and `POST /assets/v2/export`, not deprecated workbench vulnerability export. The `vpr_v2_score` filter and `plugin.vpr_v2` were removed 2026-10-01 and now produce 400 `BAD_REQUEST_UNKNOWN_PROPERTY`. |
| Authentication and scopes | Send `X-ApiKeys: accessKey=<ACCESS_KEY>;secretKey=<SECRET_KEY>`. Exports require Basic [16] or `VM.VM_EXPLORE.VM_EXPLORE.EXPORT`, plus Can View on asset objects; the wider role matrix and OAuth/service-account options are `[UNVERIFIED]`. Use a unique integration user. |
| Base URLs | `https://cloud.tenable.com`; regional hosts are `[UNVERIFIED]`. |
| Rate limits and pagination | Dynamic per-key per-minute budget; HTTP 429 carries `retry-after`. Ten concurrent vulnerability/asset/compliance/WAS exports per container. Identical filters still PROCESSING within three days return 429. Vulnerability `num_assets` is 50-5000; asset `chunk_size` is required and 100-10000. Chunks complete out of order and are addressed by `chunk_id`. |
| Incremental support | Vulnerability filters include `since`, found/fixed times, state, severity, plugin/CVE, source, VPR, and tags. With no time filter only 30 days are returned. Assets expose `updated_at`, `terminated_at`, `deleted_at`, and `since`; use termination/deletion fields for reconciliation. |
| Webhooks (header, algorithm) | No native webhook or signed push contract was found `[UNVERIFIED for absence]`; poll exports. |
| MCP server and SDKs | Official [pyTenable](https://github.com/tenable/pyTenable) is MIT and covers VM exports. No Tenable-official MCP server was found; community MCP tooling is not vendor-official. |
| Comparable open-source integrations (with pack links) | [DefectDojo](https://github.com/DefectDojo/django-DefectDojo) parses Tenable XML and CSV files rather than synchronizing the API. Issue #10051 documents the risk of deriving severity from CVSS instead of Tenable `risk_factor`. No other API-sync comparable was verified `[UNVERIFIED]`. |
| Gotchas | Vulnerability chunk expiry is documented as both 24 hours and three days; design for 24 hours. Asset chunks expire after 24 hours. Duplicate filters require backoff rather than resubmission. Plugin output defaults on, is capped at 1,024 KB per plugin, and needs explicit bounds. |

#### Connector spec

| Stream | OCSF class | Cursor kind | Modes | Source record ID | Fingerprint inputs | AssetRef form |
|---|---|---|---|---|---|---|
| `vulnerability_export` | 2002 | `time_id` on `last_found`/`last_fixed` with overlap; tie asset UUID + plugin ID + port | `incremental`, `full` | asset UUID + plugin ID + port + protocol `[INFERENCE]` | asset identity + plugin ID + port + protocol | `asset.uuid`; hostname/FQDN and IPv4 are attributes |
| `asset_export` | non-finding asset records | `time_id` on `updated_at`; full snapshots reconcile deletion | `incremental`, `full` | asset UUID | not sourced | asset UUID with `sources` and host/webapp `types` |

| Operation | Endpoint | Notes |
|---|---|---|
| `create_vulnerability_export` | `POST /vulns/export` | Always supply a time bound; explicitly control plugin output. |
| `create_asset_export` | `POST /assets/v2/export` | Supply `chunk_size`; include lifecycle filters needed for reconciliation. |
| `get_vulnerability_export_status` | `GET /vulns/export/{export_uuid}/status` | Track status, available/failed chunks, and completion. |
| `download_vulnerability_chunk` | `GET /vulns/export/{export_uuid}/chunks/{chunk_id}` | Idempotent upsert; never infer sequence from arrival order. |
| `get_asset_export_status` | `GET /assets/export/{export_uuid}/status` | Poll asynchronously. |
| `download_asset_chunk` | `GET /assets/export/{export_uuid}/chunks/{chunk_id}` | Consume before the 24-hour expiry. |
| `cancel_export` | `[UNVERIFIED]` exact path | Do not hard-code a path until verified. |

| Action | Classification | Idempotency | Precondition |
|---|---|---|---|
| none in pack | read | none | Initial connector is read-only; broader tags and scan writes need separate designs. |

| Field | Value |
|---|---|
| Verifier | none; no native signed push contract found, so export polling is authoritative. |

| Capability | Scope or permission |
|---|---|
| Vulnerability export | Basic [16] or `VM.VM_EXPLORE.VM_EXPLORE.EXPORT`. |
| Asset export and asset references | Can View on asset objects. |

Top risks:
- Silent 30-day truncation when a time filter is omitted.
- Conflicting chunk-expiry guidance and failed/expired chunk recovery.
- Duplicate-filter 429 responses and shared per-key/container budgets.
- Removed `vpr_v2` properties breaking older requests.
- Out-of-order chunks and bounded plugin-output retention.

### Tenable Security Center

Tenable Security Center is the on-premises REST product under `/rest/`, with no backward-compatibility guarantee and version-dependent schemas. This subsection defines `tenable_sc` for cumulative and patched vulnerability analysis; notifications remain gated by their read side effect.

#### Facts

| Topic | Fact |
|---|---|
| Editions and API versions and sunsets | Security Center 6.7.0 introduces universal identity: `hostUniqueness` = `repositoryID,hostUUID`, `vulnUniqueness` = `repositoryID,vulnUUID`; migrate stored identities across the upgrade. Use the [Analysis reference](https://docs.tenable.com/security-center/api/Analysis.htm), [API PDF](https://docs.tenable.com/security-center/api/pdf/Tenablesc_API.pdf), and [API root](https://docs.tenable.com/security-center/api/) with per-version schema tests. |
| Authentication and scopes | Header is `x-apikey: accessKey=<ACCESS_KEY>;secretKey=<SECRET_KEY>`. Token/session reference URLs returned 404, so login-token flow is `[UNVERIFIED]`. Role and repository data-scope mapping are `[UNVERIFIED]`; use a dedicated analysis-read user. |
| Base URLs | `https://<sc-host>/rest/`; port and certificate defaults are `[UNVERIFIED]`. Configure a trust bundle for self-signed/private-CA deployments. |
| Rate limits and pagination | Numeric limits are `[UNVERIFIED]`; Tenable recommends against multi-threaded SC API calls. `POST /rest/analysis` uses inclusive `startOffset` and exclusive `endOffset`; advance by `returnedRecords` to string-valued `totalRecords`. |
| Incremental support | Relative day filters use `<minDaysBack>:<maxDaysBack>`, requiring at least one-day overlap. `firstSeen`/`lastSeen` require `cumulative`; `lastMitigated` requires `patched`; `individual` additionally requires root `scanID` and `view`. Patched results signal remediation; cumulative absence alone does not. |
| Webhooks (header, algorithm) | No native webhook contract was found. Alerts support email, notification, report, scan, syslog, and ticket; syslog signing and format are `[UNVERIFIED]`. `/rest/notification` polling changes status from `new` to `sent`. |
| MCP server and SDKs | Official [pyTenable](https://github.com/tenable/pyTenable) exposes `TenableSC`, including `sc.analysis.vulns()`. No Tenable-official MCP server was found; community SC MCP servers and Tenable Exchange tooling are not vendor-official. |
| Comparable open-source integrations (with pack links) | [DefectDojo](https://github.com/DefectDojo/django-DefectDojo) consumes SC CSV/XML exports as files. Its issue #10051 severity-mapping lesson applies. |
| Gotchas | Day-granular windows require overlap. Notification reads mutate state and can hide events from another consumer. Parse `totalRecords` explicitly. `/rest/analysis/download` returns CSV with a `columns` array, not JSON. Version upgrades can change both schema and identity; session mechanics are unverified, so do not hard-code a login flow; on-prem TLS needs a configured trust bundle. |

#### Connector spec

| Stream | OCSF class | Cursor kind | Modes | Source record ID | Fingerprint inputs | AssetRef form |
|---|---|---|---|---|---|---|
| `analysis_cumulative` | 2002 | `time_id` on `lastSeen` with one-day overlap; tie repository + host UUID + vuln UUID | `incremental`, `full` | repository ID + host UUID + vuln UUID, or universal identity values | repository + host identity + plugin ID + port + protocol | repository-scoped `hostUUID`; IP attribute |
| `analysis_patched` | 2002 state update `[INFERENCE]` | `time_id` on `lastMitigated` | `incremental` | repository ID + host UUID + vuln UUID `[INFERENCE]` | repository + host identity + plugin ID + port + protocol `[INFERENCE]` | repository-scoped `hostUUID`; IP attribute |
| `notifications` | non-finding event telemetry | none until status side effect is handled | `event` | not sourced | not sourced | not sourced |

| Operation | Endpoint | Notes |
|---|---|---|
| `query_analysis_vulns` | `POST /rest/analysis` | Support `vulndetails`/`listvuln`, cumulative/patched/individual, `wasVuln`, filters, and offset pages. |
| `download_analysis_csv` | `POST /rest/analysis/download` | Parse CSV using returned `columns`; do not expect JSON. |
| `list_alerts` | `GET /rest/alert` | Configuration read only; do not create, execute, update, or delete alerts. |

| Action | Classification | Idempotency | Precondition |
|---|---|---|---|
| none in pack | read | none | Initial connector excludes alert writes and execution because they can start scans or tickets. |

| Field | Value |
|---|---|
| Verifier | none; syslog is only a possible alert path and its signing/format are `[UNVERIFIED]`. Notification polling is state-mutating, not a webhook verifier. |

| Capability | Scope or permission |
|---|---|
| Cumulative and patched analysis | Dedicated SC user with analysis read on intended repositories; exact role `[UNVERIFIED]`. |
| Repository and scan metadata | Read access within the same intended repositories. |

Top risks:
- Repository/host/vulnerability identity changes at 6.7.0.
- Day-granular filters and invalid cumulative/patched/individual combinations.
- Notification reads consuming events by changing their status.
- No backward-compatibility guarantee and per-version schema drift.
- Unverified token mechanics plus on-prem TLS/version skew.

### Nessus

Nessus coverage combines a primary `.nessus` file parser with license-gated live scan export for supported Professional, Expert, Manager, or enterprise deployments. This subsection defines `nessus`; Essentials cannot create exports or reports, and scan configuration or launch remains excluded.

#### Facts

| Topic | Fact |
|---|---|
| Editions and API versions and sunsets | Nessus Essentials cannot export. Professional/Expert API Keys tab availability by license is `[UNVERIFIED]`; Manager uses API keys with System Administrator. Research used Nessus 10.12 export/list/history documentation. pyTenable's Nessus module is Technology Preview. |
| Authentication and scopes | Nessus Manager and cloud use `X-ApiKeys: accessKey=<ACCESS_KEY>;secretKey=<SECRET_KEY>`; standalone header and read-only export scope are `[UNVERIFIED]`. Generating a new key replaces existing keys and deauthorizes linked applications. Direct scanning API configuration/launch is restricted except as permitted through Security Center and Tenable One enterprise solutions. |
| Base URLs | Local or managed Nessus host with its port; the default port is `[UNVERIFIED]`. Manager and cloud are separate hosts. Configure a trust bundle for common self-signed certificates. |
| Rate limits and pagination | Rate limits are `[UNVERIFIED]`. `GET /scans` filters by modification/start times; `GET /scans/{scan_id}/history` uses `limit`, `offset`, `sort`, and required `exclude_rollover`. Export is asynchronous create, status, then download. |
| Incremental support | Poll changed scans by `last_modification_date`, then enumerate history runs. Each history run is a complete `.nessus` snapshot; compare same-scope runs for absence. Details are effectively archived after 35 days; after 60 days only nessus/csv are available and filters fail with HTTP 400. |
| Webhooks (header, algorithm) | No webhook was found; ingestion is uploaded-file parsing or live export polling. |
| MCP server and SDKs | Official [pyTenable](https://github.com/tenable/pyTenable) Nessus `ScansAPI` wraps export creation/status/download and exposes history/details/list; it is Technology Preview. No Nessus-official MCP server was found. |
| Comparable open-source integrations (with pack links) | [DefectDojo](https://github.com/DefectDojo/django-DefectDojo) `dojo/tools/tenable/xml_format.py` parses `NessusClientData_v2`; issue #10051 demonstrates why connector severity must not be recomputed from CVSS. |
| Gotchas | Unfiltered `.nessus` plugin output truncates at 5 MB with `TRUNCATED`. Credential secrets and credentialed-check status are stripped. DB export is encrypted/proprietary; policy export is JSON; DB export requires `history_id`, `asset_id`, and `password`; agent scans export single hosts and triggered agent scans cannot be exported. Export state is `New` when `first_observed` is within 14 days, otherwise `Active`. VPR is static until rescan, while `risk_factor` can derive from CVSS v2; preserve Nessus severity and risk factor separately. |

#### Connector spec

| Stream | OCSF class | Cursor kind | Modes | Source record ID | Fingerprint inputs | AssetRef form |
|---|---|---|---|---|---|---|
| `scan_runs` | non-finding scan-run records | `time_id` on history `time_end` | `incremental`, `full` | history ID | not sourced | history-run `targets`/`incomplete_targets` |
| `export_findings` | 2002 severity 1-4; 2004 severity 0 `[INFERENCE]` | `snapshot` with history ID and `targets_done` | `full`, `replay` | report/run ID + host + plugin ID + port + protocol | host + plugin ID + port + protocol | `ReportHost` name plus `host-fqdn` and `host-ip` tags |

| Operation | Endpoint | Notes |
|---|---|---|
| `list_scans` | `GET /scans` | Use `last_modification_date` for discovery; folder/start filters are available. |
| `list_history` | `GET /scans/{scan_id}/history` | Page runs and retain history ID, times, status, archival, and targets; `exclude_rollover` is required. |
| `create_export` | `POST /scans/{scan_id}/export` | `scan_id` accepts recommended `schedule_uuid` or `id`; returns `file` and `temp_token`. |
| `get_export_status` | `GET /scans/{scan_id}/export/{file_id}/status` | Poll until `ready`. |
| `download_export` | `GET /scans/{scan_id}/export/{file_id}/download` | Parse one history run as a complete snapshot; `.nessus` root is `NessusClientData_v2`; detect `TRUNCATED`. |

| Action | Classification | Idempotency | Precondition |
|---|---|---|---|
| none in pack | read | none | File ingestion has no writes; live scan launch, policy creation, and scan configuration are excluded. |

| Field | Value |
|---|---|
| Verifier | none; no webhook was found, so file import and native export polling are authoritative. |

| Capability | Scope or permission |
|---|---|
| Uploaded `.nessus` ingestion | No vendor permission beyond the supplied file. |
| Manager live export | API key with export rights and System Administrator role. |
| Standalone live export | Licensing and read-only export scope `[UNVERIFIED]`; confirm before enabling. |

Top risks:
- Five-MB plugin-output truncation and silent evidence loss.
- Thirty-five-day archival and sixty-day format/filter restrictions.
- Credential-status stripping and unsafe severity re-derivation.
- License/API restrictions, including Essentials having no export capability.
- API-key replacement breaking every linked application.

## 9. Open questions to verify at adoption

- Gaps against open-source integration platforms are tracked in `COVERAGE_GAPS.md` (GAP-* IDs); each phase's Write step absorbs the `must` gaps listed in its section 9.

- Release prerequisite for every kind: a vendor sandbox, trial, or test tenant with credentials for live acceptance (`ICUHUB_ACC=1`); kinds without one stay unreleased as `core`.

- GitHub: Enterprise audit REST requires an enterprise-owner credential and administration scope; page not read in this pass (## 2. Authentication options and required permissions)
- GitHub: Enterprise audit administration scope in Required scopes row; page not read in this pass (## 2. Authentication options and required permissions)
- GitHub: Data-resident tenant host format `{tenant}.ghe.com`; host format not read in this pass (## 3. Base URL patterns and tenant hosts)
- GitHub: Installation rate-limit scaling and caps paraphrase not confirmed on the rate-limit page (## 4. Rate limits, headers, and pagination)
- GitHub: Octokit.js, Octokit.rb, and Octokit.NET licenses not checked in this pass (## 9. Vendor-official MCP server and SDKs)
- GitHub: Port Ocean first-party GitHub integration directory not opened in this pass (## 10. Comparable open-source integrations)
- GitHub: Port Ocean framework license Apache-2.0 not verified (## 10. Comparable open-source integrations)
- GitHub: Exact path for listing code-scanning alerts not sourced (## Proposed ICUHUB connector: GitHub)
- GitHub: Exact path for getting an alert, its instances, or its analysis not sourced (## Proposed ICUHUB connector: GitHub)
- GitHub: Exact path for getting Dependabot or secret scanning alerts not sourced (## Proposed ICUHUB connector: GitHub)
- GitHub: Exact path for getting branch protection or rulesets not sourced (## Proposed ICUHUB connector: GitHub)
- GitHub: Exact path for getting a PR, review, or comment not sourced (## Proposed ICUHUB connector: GitHub)
- GitHub: Exact path for searching enterprise audit events not sourced (## Proposed ICUHUB connector: GitHub)
- GitHub: Exact path for rate-limit status not sourced (## Proposed ICUHUB connector: GitHub)
- GitLab: REST page version not checked; cited security pages are version 19.6 (## 1. Product editions and API versions in scope)
- GitLab: Free-tier namespace limits from 2026-10-19 reported only by the Airbyte source docs; not verified on a GitLab primary page (## 11. Gotchas and operational risks)
- GitLab: Exact REST scope names per endpoint not read (## 2. Authentication options and required permissions)
- GitLab: REST authentication page not read in this pass (## 2. Authentication options and required permissions)
- GitLab: SAML SSO and IP allowlist behavior not read (## 2. Authentication options and required permissions)
- GitLab: Vulnerability export permission role matrix not confirmed (## 2. Authentication options and required permissions)
- GitLab: Dedicated tenant host shape not confirmed (## 3. Base URL patterns and tenant hosts)
- GitLab: GitLab.com numeric rate-limit values not read (## 4. Rate limits, headers, and pagination)
- GitLab: Pagination headers, maximum page size, and keyset support not confirmed from the REST pagination section (## 4. Rate limits, headers, and pagination)
- GitLab: Vulnerability global ID and GraphQL object field names not read (## 7. Data and natural OCSF 1.9.0 mapping)
- GitLab: Vulnerabilities incremental `time_id` via GraphQL and the `full,incremental` modes not confirmed (## Proposed ICUHUB connector: GitLab)
- GitLab: Audit stream objects cursor kind `sequence` not confirmed (## Proposed ICUHUB connector: GitLab)
- GitLab: Audit stream objects source record ID and fingerprint are not sourced (## Proposed ICUHUB connector: GitLab)
- GitLab: Webhook full event and retry behavior not confirmed; X-Gitlab-Token-only rejection is a design recommendation (## 6. Webhooks and push delivery)
- GitLab: MCP server repository and license not confirmed (## 9. Vendor-official MCP server and SDKs)
- GitLab: python-gitlab status and license not checked (## 9. Vendor-official MCP server and SDKs)
- GitLab: Mixing the deprecated REST vulnerabilities API with GraphQL yields different ID shapes; not confirmed (## 11. Gotchas and operational risks)
- GitLab: Endpoint-specific REST read and write scopes not confirmed (## 2. Authentication options and required permissions)
- GitLab: Group audit streaming exact role not sourced (## 1. Product editions and API versions in scope)
- GitLab: Instance audit streaming administrator role is proposal-derived and not confirmed on the audit streaming page (## Proposed ICUHUB connector: GitLab)
- GitLab: Exact path for listing MR notes and discussions not sourced (## Proposed ICUHUB connector: GitLab)
- GitLab: GraphQL query for getting a vulnerability not sourced (## Proposed ICUHUB connector: GitLab)
- GitLab: Exact paths for creating a vulnerability export not sourced (## Proposed ICUHUB connector: GitLab)
- GitLab: Download path for a vulnerability export not sourced (## Proposed ICUHUB connector: GitLab)
- GitLab: Endpoint for getting project or group metadata not sourced (## Proposed ICUHUB connector: GitLab)
- GitLab: Merge endpoint parameters for merge_merge_request not read (## 8. Useful write actions, risk, and idempotency)
- GitLab: Deprecated REST and GraphQL vulnerability ID and schema divergence not confirmed (## 11. Gotchas and operational risks)
- Bitbucket Cloud: App-password deprecation timeline not confirmed (## 1. Product editions and API versions in scope)
- Bitbucket Cloud: SAML and IP allowlist behavior not read (## 2. Authentication options and required permissions)
- Bitbucket Cloud: Regional data-residency host support not confirmed (## 3. Base URL patterns and tenant hosts)
- Bitbucket Cloud: Maximum `pagelen` not confirmed (## 4. Rate limits, headers, and pagination)
- Bitbucket Cloud: `q` filter and sort fields not confirmed; exact filtering page not read (## 5. Incremental sync, exports, and deletion signals)
- Bitbucket Cloud: PR `updated_on` high-water field name not confirmed (## Proposed ICUHUB connector: Bitbucket Cloud)
- Bitbucket Cloud: Webhook retry, 10-second timeout, `X-Attempt-Number` header, 256 KB drop, and string event-key claims not confirmed (## 6. Webhooks and push delivery)
- Bitbucket Cloud: Webhook request UUID header name not sourced; no signed timestamp sourced (## 6. Webhooks and push delivery)
- Bitbucket Cloud: MCP transport, hosting, license, and official Python SDK not confirmed (## 9. Vendor-official MCP server and SDKs)
- Bitbucket Cloud: Other open-source Cloud security integrations not confirmed (## 10. Comparable open-source integrations)
- Bitbucket Cloud: Source record ID for PR comments and activity not sourced (## Proposed ICUHUB connector: Bitbucket Cloud)
- Bitbucket Cloud: Source record ID for branch restrictions not sourced (## Proposed ICUHUB connector: Bitbucket Cloud)
- Bitbucket Cloud: Exact paths for listing and getting PRs not sourced (## Proposed ICUHUB connector: Bitbucket Cloud)
- Bitbucket Cloud: Exact paths for PR comments, activity, commits, statuses, and diffstat not sourced (## Proposed ICUHUB connector: Bitbucket Cloud)
- Bitbucket Cloud: Exact paths for listing branch restrictions not sourced (## Proposed ICUHUB connector: Bitbucket Cloud)
- Bitbucket Cloud: Exact paths for reports and annotations not sourced (## Proposed ICUHUB connector: Bitbucket Cloud)
- Bitbucket Data Center: REST v1004 is the baseline; newer REST versions not confirmed (## 1. Product editions and API versions in scope)
- Bitbucket Data Center: OAuth 2.0 page not read in this pass (## 2. Authentication options and required permissions)
- Bitbucket Data Center: REST Basic username form and admin-token requirements not confirmed (## 2. Authentication options and required permissions)
- Bitbucket Data Center: REST path base `https://<bitbucket-host>/rest/api/1.0/...` not read in this pass (## 3. Base URL patterns and tenant hosts)
- Bitbucket Data Center: MCP plugin path `https://<host>/rest/mcp/1.0/` not confirmed (## 3. Base URL patterns and tenant hosts)
- Bitbucket Data Center: Pagination fields `start`, `limit`, `nextPageStart`, and `isLastPage` not confirmed from a fetched page (## 4. Rate limits, headers, and pagination)
- Bitbucket Data Center: PR and repository update filters not confirmed (## 5. Incremental sync, exports, and deletion signals)
- Bitbucket Data Center: Audit storage directory `<home>/log/audit/` and audit file properties not confirmed (## 5. Incremental sync, exports, and deletion signals)
- Bitbucket Data Center: Native audit push not confirmed (## 5. Incremental sync, exports, and deletion signals)
- Bitbucket Data Center: Webhook delivery IDs and retry policy not confirmed (## 6. Webhooks and push delivery)
- Bitbucket Data Center: UPM webhook plugin disablement may stop delivery without a signal; sender error behavior not confirmed (## 6. Webhooks and push delivery)
- Bitbucket Data Center: Code Insights report details, endpoint, limits, 60-day retention, and creator-only update restriction not confirmed; cited page not read (## 7. Data and natural OCSF 1.9.0 mapping)
- Bitbucket Data Center: MCP endpoint, bearer auth, `BITBUCKET_HOME/shared/mcp-tools.json` whitelist, license, and official Python SDK not confirmed (## 9. Vendor-official MCP server and SDKs)
- Bitbucket Data Center: Other open-source Data Center integrations not confirmed (## 10. Comparable open-source integrations)
- Bitbucket Data Center: Source record ID for pull requests not sourced (## Proposed ICUHUB connector: Bitbucket Data Center)
- Bitbucket Data Center: Code Insights report and annotation read endpoint not sourced (## Proposed ICUHUB connector: Bitbucket Data Center)
- Bitbucket Data Center: Exact paths for listing and getting PRs, comments, and activity not sourced (## Proposed ICUHUB connector: Bitbucket Data Center)
- Bitbucket Data Center: Exact paths for listing repositories and projects not sourced (## Proposed ICUHUB connector: Bitbucket Data Center)
- Bitbucket Data Center: Code Insights PUT endpoint and its report-detail limits not confirmed (## Proposed ICUHUB connector: Bitbucket Data Center)
- Bitbucket Data Center: `put_code_insights_report` creator-only restriction not confirmed (## 8. Useful write actions, risk, and idempotency)
- Bitbucket Data Center: `merge_pull_request` permission model with user credential not confirmed (## 8. Useful write actions, risk, and idempotency)
- Bitbucket Data Center: Administrator requirement for audit files and instance settings, including token restriction, not confirmed (## 2. Authentication options and required permissions)
- Bitbucket Data Center: Merge permission model for user credentials not confirmed (## 2. Authentication options and required permissions)
- Jira Cloud: Connect end-of-support dates (1. Product editions and API versions)
- Jira Cloud: API-token staged expiration dates (2. Authentication and required permissions)
- Jira Cloud: SAML and two-step verification interaction with API-token use (2. Authentication and required permissions)
- Jira Cloud: per-tenant rate-limit tier caps and whether API-token traffic is subject to them (4. Rate limits and pagination)
- Jira Cloud: admin webhook HMAC secret support on Cloud, registration path not fetched (6. Webhooks and push delivery)
- Jira Cloud: Connect webhook claim validation details (issuer, audience, query-hash) (6. Webhooks and push delivery)
- Jira Cloud: webhook retry count and timing (6. Webhooks and push delivery)
- Jira Cloud: MCP search, write, delete, and manage scope groups beyond read:jira:agent-interface (9. Vendor MCP server and SDKs)
- Jira Cloud: Rovo MCP credit consumption (9. Vendor MCP server and SDKs)
- Jira Cloud: package-by-package SDK license terms (9. Vendor MCP server and SDKs)
- Jira Cloud: Port Ocean resource list and webhook processors (10. Comparable open-source integrations)
- Jira Cloud: Airbyte stream, auth, and pagination details (10. Comparable open-source integrations)
- Jira Cloud: DefectDojo feature claims beyond status push and deleted-finding close, and line numbers 1186-1193 (10. Comparable open-source integrations)
- Jira Cloud: Steampipe table list (10. Comparable open-source integrations)
- Jira Cloud: read issue details endpoint path not sourced (Proposed ICUHUB connector: Jira Cloud)
- Jira Cloud: read metadata endpoint paths not sourced (Proposed ICUHUB connector: Jira Cloud)
- Jira Cloud: audit_records AssetRef form not sourced (Proposed ICUHUB connector: Jira Cloud)
- Jira Data Center: Jira Server end-of-support date 2024-02-15 (1. Product editions and API versions)
- Jira Data Center: Jira 10 webhook registration path (1. Product editions and API versions)
- Jira Data Center: PAT administration path under rest/pat/latest/tokens (3. Base URLs and on-prem paths)
- Jira Data Center: Jira 10 asynchronous webhook tracker issues JRASERVER-78697 and JRASERVER-74312, content not fetched (6. Webhooks and push delivery)
- Jira Data Center: no vendor-official Data Center MCP server identified (9. Vendor MCP server and SDKs)
- Jira Data Center: official Python REST SDK not asserted (9. Vendor MCP server and SDKs)
- Jira Data Center: Steampipe PAT-supported table names (10. Comparable open-source integrations)
- Jira Data Center: Cloud API token used where DC PAT expected, client warning not verified (10. Comparable open-source integrations)
- Jira Data Center: serverInfo and myself endpoint paths not sourced (Proposed ICUHUB connector: Jira Data Center)
- Jira Data Center: read issue details endpoint paths not sourced (Proposed ICUHUB connector: Jira Data Center)
- Jira Data Center: transitions full path not sourced (Proposed ICUHUB connector: Jira Data Center)
- Jira Data Center: audit_records source record ID and AssetRef form not sourced (Proposed ICUHUB connector: Jira Data Center)
- Confluence Cloud: Connect end-of-support timing (1. Product editions and API versions)
- Confluence Cloud: V2 list maximum of 250 per operation (4. Rate limits and pagination)
- Confluence Cloud: CQL expansion cap of 25 with body.export_view and body.styled_view (4. Rate limits and pagination)
- Confluence Cloud: rate-limit tier caps and effective dates (4. Rate limits and pagination)
- Confluence Cloud: page_removed and page_trashed Connect event names (5. Incremental sync and deletion signals)
- Confluence Cloud: Connect webhook event coverage beyond the module page (6. Webhooks and push delivery)
- Confluence Cloud: Rovo MCP per-operation coverage of read_confluence and write_confluence (9. Vendor MCP server and SDKs)
- Confluence Cloud: Confluence agent-interface scope names (9. Vendor MCP server and SDKs)
- Confluence Cloud: Rovo credit cost (9. Vendor MCP server and SDKs)
- Confluence Cloud: Forge SDK package license terms (9. Vendor MCP server and SDKs)
- Confluence Cloud: Backstage default two-hour schedule (10. Comparable open-source integrations)
- Confluence Cloud: Airbyte incremental cursor, stream list, pagination, and auth details (10. Comparable open-source integrations)
- Confluence Cloud: community client storage-format examples (10. Comparable open-source integrations)
- Confluence Cloud: discover spaces, read pages, read history, and read audit endpoint paths not sourced (Proposed ICUHUB connector: Confluence Cloud)
- Confluence Cloud: audit_records source record ID and AssetRef form not sourced (Proposed ICUHUB connector: Confluence Cloud)
- Confluence Data Center: webhooks available from 7.7 (1. Product editions and API versions)
- Confluence Data Center: PATs require 7.9 (1. Product editions and API versions)
- Confluence Data Center: content scan cursor browsing requires 7.18 (1. Product editions and API versions)
- Confluence Data Center: end of support 2029-03-28 footer attribution (1. Product editions and API versions)
- Confluence Data Center: PAT availability from 7.9 (2. Authentication and required permissions)
- Confluence Data Center: rate-limit header names (4. Rate limits and pagination)
- Confluence Data Center: CQL default limit of 25 with expansions (4. Rate limits and pagination)
- Confluence Data Center: content scan support for all content filters and types (4. Rate limits and pagination)
- Confluence Data Center: webhook registration via POST rest/api/webhooks (6. Webhooks and push delivery)
- Confluence Data Center: webhook payload field names timestamp, event, userKey, and page ID (6. Webhooks and push delivery)
- Confluence Data Center: webhook circuit-breaking thresholds (6. Webhooks and push delivery)
- Confluence Data Center: page_removed and page_trashed event semantics (6. Webhooks and push delivery)
- Confluence Data Center: rest/api/contentbody/convert/storage conversion endpoint (7. Data and OCSF 1.9.0 mapping)
- Confluence Data Center: create and update examples with version 2 (8. Write actions, risk, and idempotency)
- Confluence Data Center: X-Atlassian-Token no-check header for attachment uploads (8. Write actions, risk, and idempotency)
- Confluence Data Center: no vendor-official Data Center MCP server identified (9. Vendor MCP server and SDKs)
- Confluence Data Center: official general-purpose Python REST SDK not asserted (9. Vendor MCP server and SDKs)
- Confluence Data Center: Backstage multi-instance and caching details (10. Comparable open-source integrations)
- Confluence Data Center: DefectDojo Confluence publisher and Port Ocean Confluence integration not claimed (10. Comparable open-source integrations)
- Confluence Data Center: server info endpoint path not sourced (Proposed ICUHUB connector: Confluence Data Center)
- Confluence Data Center: audit_records source record ID and AssetRef form not sourced (Proposed ICUHUB connector: Confluence Data Center)
- Kubernetes: `scale_workload` idempotency not sourced; pack gives only resourceVersion-conditional patch (Kubernetes > 8. Write actions, risk, and idempotency)
- Kubernetes: `delete_pod` idempotency not sourced; pack gives no idempotency contract for deletion (Kubernetes > 8. Write actions, risk, and idempotency)
- Kubernetes: webhook replay protection not sourced beyond dedupe on `API source + auditID + stage` (Kubernetes > 6. Webhooks and push delivery)
- OpenShift: `update_route_tls` idempotency not sourced (OpenShift > 8. Write actions, risk, and idempotency)
- OpenShift: `update_scc` idempotency not sourced (OpenShift > 8. Write actions, risk, and idempotency)
- OpenShift: `get_cluster_version` endpoint not sourced; pack names the operation only as "when authorized" (OpenShift > Proposed ICUHUB connector)
- OpenShift: webhook replay protection not sourced beyond dedupe on `API source + auditID + stage` (OpenShift > 6. Webhooks and push delivery)
- Prisma Cloud: exact minimum CSPM custom-role permission names are tenant/release dependent [UNVERIFIED] (2. Authentication options and required roles)
- Prisma Cloud: SSO-only Compute local-user noninteractive credential behavior [UNVERIFIED] (2. Authentication options and required roles)
- Prisma Cloud: CSPM alert webhook signature algorithm, retry schedule, and delivery-ID header [UNVERIFIED] (6. Webhooks and push delivery)
- Prisma Cloud: Compute generic webhook HMAC, raw-byte signing, retry, and delivery-ID semantics [UNVERIFIED] (6. Webhooks and push delivery)
- Prisma Cloud: precise behavior of every IdP configuration [UNVERIFIED] (11. Gotchas and operational risks)
- Prisma Cloud: sunset dates for CSPM and Compute API versions: not sourced (1. Product editions and API versions)
- Prisma Cloud: maximum V2 alert page size: not sourced (4. Rate limits and pagination)
- Prisma Cloud: `list_alert_filters` endpoint: not sourced (Proposed ICUHUB connector)
- Prisma Cloud: `get_alert_export_status` endpoint: not sourced (Proposed ICUHUB connector)
- Prisma Cloud: `download_alert_export` endpoint: not sourced (Proposed ICUHUB connector)
- Fortify SSC: 26.2.x listing not confirmed [UNVERIFIED] (Fortify Software Security Center (SSC) / 1. Product editions and API versions in scope)
- Fortify SSC: exact permission names vary by SSC role configuration and release [UNVERIFIED] (Fortify Software Security Center (SSC) / 2. Authentication options and required permissions)
- Fortify SSC: no universal numeric rate limit, Retry-After, or X-RateLimit contract found [UNVERIFIED] (Fortify Software Security Center (SSC) / 4. Rate limits and pagination)
- Fortify SSC: automatic retry count/backoff and unique delivery header not found [UNVERIFIED] (Fortify Software Security Center (SSC) / 6. Webhooks and push delivery)
- Fortify SSC: get_project_version endpoint not sourced (Proposed ICUHUB connector)
- Fortify SSC: get_issue endpoint not sourced (Proposed ICUHUB connector)
- Fortify SSC: get_issue_details endpoint not sourced (Proposed ICUHUB connector)
- Fortify SSC: list_issue_audit endpoint not sourced (Proposed ICUHUB connector)
- Fortify SSC: list_comments endpoint not sourced (Proposed ICUHUB connector)
- Fortify SSC: get_artifact endpoint not sourced (Proposed ICUHUB connector)
- Fortify SSC: get_webhook_delivery endpoint not sourced (Proposed ICUHUB connector)
- Fortify SSC: artifacts stream fingerprint inputs not sourced (Proposed ICUHUB connector)
- Fortify SSC: activity stream fingerprint inputs not sourced (Proposed ICUHUB connector)
- Fortify on Demand: regions and hostnames other than the two verified API hosts [UNVERIFIED] (Fortify on Demand (FoD) / 3. Base URLs, regional hosts, and tenant paths)
- Fortify on Demand: no universal requests-per-minute quota or standard limit headers found [UNVERIFIED] (Fortify on Demand (FoD) / 4. Rate limits and pagination)
- Fortify on Demand: webhook event types, signature algorithm and header, delivery ID, and retry behavior [UNVERIFIED]; portal content not accessible as static text (Fortify on Demand (FoD) / 6. Webhooks and push delivery)
- Fortify on Demand: no documented ETag/revision or client idempotency key [UNVERIFIED] (Fortify on Demand (FoD) / 8. Useful actions and idempotency hooks)
- Fortify on Demand: no general-purpose official Python SDK identified [UNVERIFIED] (Fortify on Demand (FoD) / 9. Vendor MCP server and official SDKs)
- Fortify on Demand: OAuth scope name for starting scans not sourced (Fortify on Demand (FoD) / 2. Authentication options and required scopes)
- Fortify on Demand: cancel_scan classification (write or destructive) is ambiguous in pack; chunk uses destructive (Fortify on Demand (FoD) / 8. Useful actions and idempotency hooks)
- Fortify on Demand: get_release endpoint not sourced (Proposed ICUHUB connector)
- Fortify on Demand: get_issue endpoint not sourced (Proposed ICUHUB connector)
- Fortify on Demand: get_issue_details endpoint not sourced (Proposed ICUHUB connector)
- Fortify on Demand: get_issue_history endpoint not sourced (Proposed ICUHUB connector)
- Fortify on Demand: get_recommendations endpoint not sourced (Proposed ICUHUB connector)
- Fortify on Demand: list_scans endpoint not sourced (Proposed ICUHUB connector)
- Fortify on Demand: get_scan endpoint not sourced (Proposed ICUHUB connector)
- Fortify on Demand: download_fpr endpoint not sourced (Proposed ICUHUB connector)
- Fortify on Demand: get_report endpoint not sourced (Proposed ICUHUB connector)
- Fortify on Demand: data_exports source record ID, fingerprint inputs, and AssetRef form not sourced (Proposed ICUHUB connector)
- Fortify on Demand: scans stream fingerprint inputs not sourced (Proposed ICUHUB connector)
- Invicti Enterprise: Release-note content for On-Demand, On-Premises, and Standard not reviewed in detail (1. Product editions and API versions in scope)
- Invicti Enterprise: Newer releases adding PATCH semantics for scan profile/policy endpoints (1. Product editions and API versions in scope)
- Invicti Enterprise: Per-role bundles for every endpoint (2. Authentication options and required permissions)
- Invicti Enterprise: On-prem reverse-proxy path-prefix variations (3. Base URLs, regional hosts, and on-prem paths)
- Invicti Enterprise: Retry-After and X-RateLimit header behavior (4. Rate limits and pagination)
- Invicti Enterprise: Triage-only edits may not advance lastSeenDate (5. Incremental sync, exports, and deletion signals)
- Invicti Enterprise: Built-in HMAC, signed timestamp, delivery ID, and retry schedule for webhooks (6. Webhooks and push delivery)
- Invicti Enterprise: No vendor-official public MCP server or general Enterprise SDK identified (9. Vendor MCP server and official SDKs)
- Invicti Enterprise: Scan creation has no documented idempotency key (8. Useful actions and idempotency hooks)
- Invicti Enterprise: get_website endpoint not sourced (3. Base URLs, regional hosts, and on-prem paths)
- Invicti Enterprise: get_issue endpoint not sourced (8. Useful actions and idempotency hooks)
- Invicti Enterprise: get_issue_history endpoint not sourced (8. Useful actions and idempotency hooks)
- Invicti Enterprise: get_scan endpoint not sourced (8. Useful actions and idempotency hooks)
- Invicti Enterprise: list_notifications endpoint not sourced (8. Useful actions and idempotency hooks)
- Invicti Enterprise: scans fingerprint inputs not sourced (7. Data and natural OCSF 1.9.0 mapping)
- Invicti Enterprise: scan_results source record ID not sourced (7. Data and natural OCSF 1.9.0 mapping)
- Invicti Enterprise: scan_results fingerprint inputs not sourced (7. Data and natural OCSF 1.9.0 mapping)
- Invicti Standard: Release-note content not reviewed in detail (1. Product editions and API versions in scope)
- Invicti Standard: No Standard REST compatibility inferred (1. Product editions and API versions in scope)
- Invicti Standard: Rate limits and pagination not sourced (4. Rate limits and pagination)
- Invicti Standard: Built-in HMAC, signed timestamp, delivery ID, and retry schedule not documented (6. Webhooks and push delivery)
- Invicti Standard: No vendor-official public MCP server identified (9. Vendor MCP server and official SDKs)
- Invicti Standard: Standard SDK not sourced (9. Vendor MCP server and official SDKs)
- Invicti Standard: webhook_issues cursor kind not sourced (6. Webhooks and push delivery)
- Invicti Standard: webhook_issues source record ID not sourced (6. Webhooks and push delivery)
- Invicti Standard: Exact issue identity field for report_issues source record ID not sourced (7. Data and natural OCSF 1.9.0 mapping)
- Invicti Standard: Integration ID and issue ID not sourced for webhook dedupe key (6. Webhooks and push delivery)
- Mend SCA: Exact per-endpoint role mapping for every role (2. Authentication options and required permissions)
- Mend SCA: Universal numeric request quota, 429 declarations, and rate-limit header contract (4. Rate limits and pagination)
- Mend SCA: Generic signed Automation Workflow webhook not identified (6. Webhooks and push delivery)
- Mend SCA: No vendor-official public MCP server identified (9. Vendor MCP server and official SDKs)
- Mend SCA: No universal ETag or idempotency header (8. Useful actions and idempotency hooks)
- Mend SCA: get_project endpoint not sourced (8. Useful actions and idempotency hooks)
- Mend SCA: get_finding endpoint not sourced (8. Useful actions and idempotency hooks)
- Mend SCA: get_library endpoint not sourced (8. Useful actions and idempotency hooks)
- Mend SCA: get_dependency_paths endpoint not sourced (8. Useful actions and idempotency hooks)
- Mend SCA: get_vulnerability_profile endpoint not sourced (8. Useful actions and idempotency hooks)
- Mend SCA: get_remediation endpoint not sourced (8. Useful actions and idempotency hooks)
- Mend SCA: get_policy endpoint not sourced (8. Useful actions and idempotency hooks)
- Mend SCA: download_report endpoint not sourced (8. Useful actions and idempotency hooks)
- Mend SCA: list_security_alerts (2.0) endpoint path not sourced (5. Incremental sync, exports, and deletion signals)
- Mend SCA: list_security_findings (3.0) endpoint path not sourced (5. Incremental sync, exports, and deletion signals)
- Mend SCA: legal_violations (3.0) source record ID not sourced (7. Data and natural OCSF 1.9.0 mapping)
- Mend SCA: legal_violations algorithm version not sourced (7. Data and natural OCSF 1.9.0 mapping)
- Mend SCA: legal_alerts algorithm version not sourced (7. Data and natural OCSF 1.9.0 mapping)
- Mend SCA: create_project endpoint path not sourced (8. Useful actions and idempotency hooks)
- Mend SCA: update_project_metadata endpoint path not sourced (8. Useful actions and idempotency hooks)
- Qualys: VMRS JSON HLD general availability in the target subscription (Qualys (VMDR, KnowledgeBase, WAS, asset inventory) / 1. Product editions and API versions in scope)
- Qualys: newer CSAM 2.x changes after v2.9 (Qualys (VMDR, KnowledgeBase, WAS, asset inventory) / 1. Product editions and API versions in scope)
- Qualys: VM/PA session and JWT mechanics (Qualys (VMDR, KnowledgeBase, WAS, asset inventory) / 2. Auth options and required permissions)
- Qualys: role-to-scope mapping for business unit, tag, and asset group visibility (Qualys (VMDR, KnowledgeBase, WAS, asset inventory) / 2. Auth options and required permissions)
- Qualys: WAS ignore and activate permission names (Qualys (VMDR, KnowledgeBase, WAS, asset inventory) / 2. Auth options and required permissions)
- Qualys: full public platform region list (Qualys (VMDR, KnowledgeBase, WAS, asset inventory) / 3. Base URL patterns and tenant hosts)
- Qualys: current tenant rate limits; the 2018 limits document is the only published source (Qualys (VMDR, KnowledgeBase, WAS, asset inventory) / 4. Rate limits, concurrency, and pagination)
- Qualys: CSAM maximum page size (Qualys (VMDR, KnowledgeBase, WAS, asset inventory) / 4. Rate limits, concurrency, and pagination)
- Qualys: HLD detection-update filter names and status-default behavior (Qualys (VMDR, KnowledgeBase, WAS, asset inventory) / 5. Incremental sync and deletion signals)
- Qualys: KnowledgeBase modification-date parameter names (Qualys (VMDR, KnowledgeBase, WAS, asset inventory) / 5. Incremental sync and deletion signals)
- Qualys: CSAM deleted-asset change feed (Qualys (VMDR, KnowledgeBase, WAS, asset inventory) / 5. Incremental sync and deletion signals)
- Qualys: webhook event types, signature scheme, retry behavior, and delivery IDs (Qualys (VMDR, KnowledgeBase, WAS, asset inventory) / 6. Webhooks and push delivery)
- Qualys: exact uniqueness statement for the unique vulnerability ID across QIDs and assets (Qualys (VMDR, KnowledgeBase, WAS, asset inventory) / 7. Data and natural OCSF 1.9.0 mapping)
- Qualys: absence of a vendor-official general MCP server (Qualys (VMDR, KnowledgeBase, WAS, asset inventory) / 9. Vendor MCP and official SDKs)
- Qualys: license of the official sample repository (Qualys (VMDR, KnowledgeBase, WAS, asset inventory) / 9. Vendor MCP and official SDKs)
- Qualys: endpoint for the `was.get_finding` read operation is not sourced (Qualys (VMDR, KnowledgeBase, WAS, asset inventory) / Proposed ICUHUB connector)
- Qualys: endpoint for the `vmdr.get_api_usage` read operation is not sourced (Qualys (VMDR, KnowledgeBase, WAS, asset inventory) / Proposed ICUHUB connector)
- Qualys: fingerprint inputs for the `vmdr.assets` stream are not sourced (Qualys (VMDR, KnowledgeBase, WAS, asset inventory) / Proposed ICUHUB connector)
- Qualys: fingerprint inputs for the `vmdr.knowledgebase` stream are not sourced (Qualys (VMDR, KnowledgeBase, WAS, asset inventory) / Proposed ICUHUB connector)
- Tenable VM: regional cloud hosts beyond https://cloud.tenable.com (Tenable Vulnerability Management (cloud) / 3. Base URL patterns and tenant hosts)
- Tenable VM: full role matrix beyond Basic [16] and the export privilege (Tenable Vulnerability Management (cloud) / 2. Auth options and required permissions)
- Tenable VM: OAuth or service-account authentication options (Tenable Vulnerability Management (cloud) / 2. Auth options and required permissions)
- Tenable VM: vulnerability chunk expiry conflict between 24 hours and three days; design uses 24 hours and re-checks per tenant (Tenable Vulnerability Management (cloud) / 5. Incremental sync and deletion signals)
- Tenable VM: exact path for the cancel export operation (Tenable Vulnerability Management (cloud) / 5. Incremental sync and deletion signals)
- Tenable VM: absence of a native webhook or signed push contract (Tenable Vulnerability Management (cloud) / 6. Webhooks and push delivery)
- Tenable VM: tag natural key (category and value) as a future write idempotency anchor (Tenable Vulnerability Management (cloud) / 8. Useful write actions, risk, and idempotency)
- Tenable VM: repository URL of the community MCP server is not verified (Tenable Vulnerability Management (cloud) / 9. Vendor MCP and official SDKs)
- Tenable VM: no other API-sync open-source comparable verified (Tenable Vulnerability Management (cloud) / 10. Comparable open-source integrations)
- Tenable VM: fingerprint inputs for the `asset_export` stream are not sourced (Tenable Vulnerability Management (cloud) / Proposed ICUHUB connector)
- Tenable SC: token and session login mechanics; the Token and Session reference URLs returned 404 during research (Tenable Security Center (on-prem) / 2. Auth options and required permissions)
- Tenable SC: role and data-scope mapping for the API user (Tenable Security Center (on-prem) / 2. Auth options and required permissions)
- Tenable SC: exact role for analysis read on the intended repositories (Tenable Security Center (on-prem) / Proposed ICUHUB connector)
- Tenable SC: port and certificate defaults (Tenable Security Center (on-prem) / 3. Base URL patterns and tenant hosts)
- Tenable SC: numeric rate limits, none found in the consulted pages (Tenable Security Center (on-prem) / 4. Rate limits, concurrency, and pagination)
- Tenable SC: syslog alert signing and format (Tenable Security Center (on-prem) / 6. Webhooks and push delivery)
- Tenable SC: source record ID, fingerprint inputs, and AssetRef for the notifications stream are not sourced (Tenable Security Center (on-prem) / Proposed ICUHUB connector)
- Nessus: API Keys tab availability for Professional and Expert depends on license (Nessus (scan export and .nessus file format) / 1. Product editions and API versions in scope)
- Nessus: standalone Nessus API key header (Nessus (scan export and .nessus file format) / 2. Auth options and required permissions)
- Nessus: read-only export scope on standalone Nessus beyond the key-guide restriction (Nessus (scan export and .nessus file format) / 2. Auth options and required permissions)
- Nessus: default port of the Nessus host (Nessus (scan export and .nessus file format) / 3. Base URL patterns and tenant hosts)
- Nessus: rate limits; none recorded (Nessus (scan export and .nessus file format) / 4. Rate limits, concurrency, and pagination)
- Nessus: official schema documentation URL for the .nessus format; structure taken from DefectDojo (Nessus (scan export and .nessus file format) / 7. Data and natural OCSF 1.9.0 mapping)
- Nessus: fingerprint inputs for the `scan_runs` stream are not sourced (Nessus (scan export and .nessus file format) / Proposed ICUHUB connector)
- Nessus: OCSF class for scan-run records is not sourced; classified non-finding by ICUHUB rule (Nessus (scan export and .nessus file format) / Proposed ICUHUB connector)
- Archer: SaaS personal access token endpoint, header, expiry, and backward compatibility (Archer GRC / Facts, Authentication and scopes)
- Archer: universal API sunset dates and mapping of release trains to REST, Content API, and SOAP behavior (Archer GRC / Facts, Editions)
- Archer: numeric rate limits and a standard `Retry-After` contract (Archer GRC / Facts, Rate limits and pagination)
- Archer: generic signed outbound notification schema, HMAC header, delivery ID, and retry schedule (Archer GRC / Facts, Webhooks)
- Archer: official MCP server (Archer GRC / Facts, MCP server and SDKs)
- Archer: source license of the NuGet `RSA.Archer.Api.Client` package and of the community `rsa_archer` package (Archer GRC / Facts, MCP server and SDKs)
- Archer: custom role names that grant each read and write probe in the scope table, which vary by release and tenant (Archer GRC / Capability scopes)
- Archer: whether the `history` endpoint exposes a monotonic history ID across installations (Archer GRC / Connector spec)

## 10. Archer GRC

Archer GRC (RSA Archer; Archer Integrated Risk Management) runs on-premises and as SaaS. Its applications, levels, fields, and values lists are configured per installation, so this subsection defines `archer` as a metadata-driven connector: numeric IDs are resolved at runtime and never hardcoded. The subsection defines native REST synchronization with a SOAP search fallback, attachments as evidence, and plan/apply writes with explicit preconditions.

### Archer GRC

#### Facts

| Topic | Fact |
|---|---|
| Editions and API versions and sunsets | Archer documents separate on-premises and SaaS release trains. The 2024.11 on-premises notes say updates are cumulative and describe the 6.x upgrade lineage. The 2025 SaaS notes show separate non-production and production rollouts. The REST base changed from `/api/` to `/platformapi/` in release 6.5. This subsection uses the 2025.04 REST, Content API, SOAP, and data-feed documentation as a baseline, with target-version probing rather than assuming feature parity. Universal API sunset dates were not found `[UNVERIFIED]`. [On-premises releases](https://help.archerirm.cloud/archerreleasenotes/content/rnhome/2024/2024_11_onprem.htm), [SaaS releases](https://help.archerirm.cloud/archerreleasenotes/content/rnhome/2025/archer_releases_saas_2025.htm), [REST usage](https://help.archerirm.cloud/api_2025_04/content/api/restfulapi/starting.htm). |
| Authentication and scopes | Baseline REST login is `POST /platformapi/core/security/login` with instance, username, domain where needed, and password. The response contains `RequestedObject.SessionToken`; later calls use `Authorization: Archer session-id="<token>"`. Refresh with single-flight locking and retry a safe read once after 401. SOAP uses `CreateUserSessionFromInstance` or the domain variant on `/ws/general.asmx`; `CreateUserSession` is disabled. Archer SaaS 2025.10 introduced PATs, but the PAT endpoint, header, expiry, and backwards compatibility are `[UNVERIFIED]`, so PATs do not replace the baseline flow. Use a dedicated identity because the official API test-tool notes warn that simultaneous login by the same user can terminate an existing session. [REST authentication](https://help.archerirm.cloud/api_2025_04/content/api/restfulapi/segmentsresources/authentication.htm), [supported SOAP login](https://help.archerirm.cloud/api_2025_04/content/api/webapi/createusersessionfrominstance.htm), [disabled SOAP login](https://help.archerirm.cloud/api_2025_04/content/api/webapi/createusersession.htm), [API test utility](https://help.archerirm.cloud/exchange/content/exchange/tools_utilities/api_testing.htm). |
| Base URLs | Configure the Archer application root supplied by the operator. REST paths are `/platformapi/core/...`, Content API paths are `/contentapi/...`, and SOAP services are `/ws/<service>.asmx`. Do not hardcode `/RSAArcher`, an instance name, or a SaaS region into every installation. Content API discovery at `/contentapi/` returns permission-filtered level and cross-reference entity sets. [API overview](https://help.archerirm.cloud/platform_2025_04/en-us/content/api/archer_apis_platform.htm), [Content API discovery](https://help.archerirm.cloud/api_2024_06/en-us/content/api/contentapi/contentapi_get_endpoints.htm), [SOAP access](https://help.archerirm.cloud/api_2025_04/content/api/webapi/access_web_services_api.htm). |
| Rate limits and pagination | Many REST reads are `POST` with `X-Http-Method-Override: GET`; this does not make real POST writes idempotent. OData queries are passed in the request body and use `$top`, `$skip`, `$select`, and `$orderby`. A configurable server-side maximum page size can cap the requested `$top`. No universal numeric API rate limit or standard `Retry-After` contract was established `[UNVERIFIED]`. Use bounded pages, low initial concurrency, and adaptive backoff. [OData](https://help.archerirm.cloud/api_2025_04/content/api/restfulapi/odata.htm). |
| Incremental support | Use a configured Date or Last Updated field plus `Content.Id` as the durable `time_id` tie-breaker, ascending, with bounded overlap. SOAP `ExecuteSearch` supports search XML, `PageSize`, and a separate `pageNumber`; these are request state only. Full snapshots per application/level are required for absence closure. The source does not provide a universal signed change feed. XSOAR demonstrates timestamp polling, but its request hardcodes `PageNumber` 1 and `MaxRecordCount`, so its fetch is not a complete-pagination model to copy. [ExecuteSearch](https://help.archerirm.cloud/api_2025_04/content/api/webapi/executesearch.htm), [XSOAR implementation](https://raw.githubusercontent.com/demisto/content/master/Packs/ArcherRSA/Integrations/ArcherV2/ArcherV2.py). |
| Webhooks (header, algorithm) | Initial declaration is `none`. Archer notifications can be queued on record save, schedules, workflow stage changes, or filtered record searches and delivered through configured channels. No generic signed outbound JSON webhook, HMAC header, delivery ID, or retry contract was established `[UNVERIFIED]`. A notification integration may trigger a targeted poll, never direct finding acceptance or closure. [Notifications](https://help.archerirm.cloud/platform_2025_04/en-us/content/platform/notifications/note_basics.htm). |
| MCP server and SDKs | No official Archer MCP server was confirmed `[UNVERIFIED]`. Do not make an unreviewed community MCP server a synchronization dependency. The NuGet `RSA.Archer.Api.Client` package was located, but no source or license was established `[UNVERIFIED]`, so it is not a reuse baseline. The useful opened implementations are XSOAR ArcherV2 (MIT), pyarcher (MIT), and Splunk SOAR Archer (Apache-2.0). The community `rsa_archer` package ([repository](https://github.com/aleksei-aikashev/rsa_archer)) was located and its repository page opened, but its LICENSE text was not confirmed; package metadata reports MIT `[UNVERIFIED for source text]`, and it is not a reuse baseline. Native HTTP remains authoritative. |
| Comparable open-source integrations | [XSOAR ArcherV2](https://raw.githubusercontent.com/demisto/content/master/Packs/ArcherRSA/Integrations/ArcherV2/ArcherV2.py) caches level/field/value-list metadata, refreshes REST sessions after 401, regenerates SOAP tokens after bounded 500 responses, maps numeric field IDs to names, and polls a configured date field. [pyarcher](https://raw.githubusercontent.com/kylecribbs/pyarcher/master/pyarcher/base.py) shows `/api`, `/platformapi`, and `/contentapi` URL separation, but has incomplete methods and no robust refresh loop. [Splunk SOAR Archer](https://raw.githubusercontent.com/splunk-soar-connectors/archer/main/archer_connector.py) provides another polling and action surface. Copy the metadata and reconciliation ideas, not unbounded recursion, empty-on-error behavior, or timestamp-only checkpoints. |
| Gotchas | Application, level, field, values-list, and cross-reference IDs are installation-specific. `FieldContents` is keyed by numeric field ID and typed by field metadata. `PUT /platformapi/core/content` requires the current `Version` for optimistic concurrency. Creating an existing record or updating a nonexistent record can return 403. Content API rejects a no-change update with HTTP 400. REST, SOAP, and data feeds can modify records locked in the UI. REST writes and workflow can have side effects beyond the submitted fields. [Content and attachments](https://help.archerirm.cloud/api_2025_04/content/api/restfulapi/segmentsresources/content.htm), [Content API behavior](https://help.archerirm.cloud/platform_2025_04/en-us/content/api/contentapi/contentapi_get_endpoints.htm). |

#### Domain mapping

Use configured application aliases, then resolve actual module, level, field, values-list, and cross-reference IDs at runtime. Cache by Archer instance plus application/level identity and refresh on schema drift or unknown IDs.

- IT Security Vulnerabilities: Vulnerability Scan Results, Vulnerability Tickets, Devices, Applications, Vulnerability Library, Findings, Exception Requests, Remediation Plans, and Vulnerability Historical Data. A Vulnerability Scan Result maps to Vulnerability Finding 2002 only when configured fields contain actual vulnerability evidence. Assessment Findings map to Compliance Finding 2003. [Application model](https://help.archerirm.cloud/itsecrisk_itsecvuln_692/en-us/Content/Solutions/ITSecRisk/itsrm_vulnmgt_design.htm).
- Issues Management: Finding, Remediation Plan, Remediation Plan Status Update, and Exception Request remain distinct records. Do not collapse an exception or remediation ticket into the finding itself. [Issues model](https://help.archerirm.cloud/archersolutions/en-us/Content/ArcherSolutions/issues_management.htm).
- Risk Management: Risks, Controls, Risk Hierarchy, Risk Snapshot, Loss Events, Metrics, and Metric Results remain typed GRC or metrics records. They are not automatically OCSF findings. [Risk model](https://help.archerirm.cloud/archersolutions/en-us/Content/ArcherSolutions/risk%5Fmanagement.htm).
- ITSRM integration guidance recommends summary metrics, threshold signals, and control-effectiveness evidence over copying every raw vulnerability into Archer. ICUHUB should ingest configured detail where needed but should offer aggregate metrics as a first-class outbound pattern. [Integration guidance](https://help.archerirm.cloud/archersolutions/en-us/Content/ArcherSolutions/itsrm_integration_guide.htm).

#### Connection configuration

| Field | Type | Rule |
|---|---|---|
| `base_url` | URL | Operator-supplied application root; HTTPS; CA configuration without skip-verify defaults |
| `instance_name` | string | Required for session login and SOAP `CreateUserSessionFromInstance` |
| `auth_mode` | enum | `session` (REST `security/login`) or `domain_session` (SOAP domain variant) |
| `user` | string | Dedicated identity; simultaneous login by the same user is not assumed safe |
| `password` | SecretRef | Never stored in plain config |
| `user_domain` | string, optional | Required when the instance authenticates by domain |
| `record_type_map` | per connection | Application IDs, level IDs, and field IDs per logical type, resolved and verified at connection probe |
| `write_enabled` | bool | Default `false`; enables `create`, `update`, `upload`, and `execute` actions |
| `destructive_enabled` | bool | Default `false`; enables `delete_content` only |

#### Connector spec

| Stream | OCSF class or record type | Cursor kind | Modes | Source record ID | Fingerprint inputs | AssetRef form |
|---|---|---|---|---|---|---|
| `vulnerability_scan_results` | Vulnerability Finding (2002) | `time_id` incremental; `snapshot` full | `incremental`, `full` | `Content.Id`; retain `LevelId`, `Version`, `LastUpdated` | Mapping version + application/level + vulnerability/library/CVE key + device or application + port/plugin/source key; exclude severity, status, Version | Related Device or Application content identity; fallback `archer_content:<connection>/<level-id>/<content-id>` |
| `assessment_findings` | Compliance Finding (2003) | `time_id`; `snapshot` | `incremental`, `full` | `Content.Id` | Mapping version + assessment/control/rule identity + assessed target + source native key; exclude workflow state | Assessed system, control, application, or device reference |
| `risks` | Non-finding GRC risk | `time_id`; `snapshot` | `incremental`, `full` | `Content.Id` | Not fingerprint-sourced | Risk content plus related business unit, system, and controls |
| `exception_requests` | Non-finding exception/workflow | `time_id`; `snapshot` | `incremental`, `full` | `Content.Id` | Not fingerprint-sourced; link to finding by cross-reference IDs | Exception content and linked finding/assets |
| `remediation_plans` | Non-finding remediation/work item | `time_id`; `snapshot` | `incremental`, `full` | `Content.Id` | Not fingerprint-sourced; status updates remain child records | Remediation content and linked findings |
| `applications_devices` | Non-finding inventory | `time_id`; `snapshot` | `incremental`, `full` | `Content.Id` | Not fingerprint-sourced | Application or Device content identity plus configured external asset key |
| `vulnerability_library` | Non-finding vulnerability intelligence | `time_id`; `snapshot` | `incremental`, `full` | `Content.Id` | Not finding fingerprint input by itself | CVE/plugin/reference identity and linked technologies |
| `attachments` | Non-finding evidence | `snapshot`; parent `time_id` for discovery | `full`, targeted read | Attachment ID and owning `Content.Id` | Not fingerprint-sourced; hash bytes for evidence identity | Owning content record; evidence SHA-256 |
| `history` | Non-finding audit/history | `snapshot`; optional parent `time_id` | `full`, targeted read | Parent content ID plus history entry identity supplied by the target | Not fingerprint-sourced | Parent content identity; no universal monotonic history ID assumed |
| `data_feed_runs` | Non-finding integration execution | `snapshot` | `full`, targeted read | Data-feed history ID and DataFeedGuid | Not fingerprint-sourced | DataFeedGuid and history ID |

Cursor rules:

- Partition each stream by connection, configured application, level, saved-search/filter, and any record-permission scope. Persist the selected date-field ID and ascending content-ID tie-breaker with `time_id`. Re-read an overlap and dedupe on `(Content.Id, Version)` while retaining every changed version required by the event model.
- A full snapshot enumerates every page for every configured level/filter. `$skip` or SOAP `pageNumber` stays inside that snapshot. Any inaccessible record, failed values-list expansion, or page error makes only the affected partition incomplete, but never treats it as empty.
- Attachments are bounded evidence downloads linked to a successfully committed parent record. Do not let a large or failed attachment invalidate already committed finding identity; mark its evidence incomplete and keep snapshot closure disabled until the declared evidence policy is satisfied.

#### Read operations

| Operation | Endpoint | Notes |
|---|---|---|
| `get_version` | `POST /platformapi/core/system/applicationinfo/version` with `X-Http-Method-Override: GET` | Record target release before selecting API behavior |
| `list_applications` | `POST /platformapi/core/system/application` with override GET | Resolve configured application aliases to module IDs and GUIDs |
| `list_levels` | `POST /platformapi/core/system/level/module/{applicationId}` with override GET | Discover levels and do not assume the first level is the intended one |
| `list_fields` | `POST /platformapi/core/system/fielddefinition/level/{levelId}` with override GET | Cache numeric IDs, names, aliases, types, required flags, and related values-list IDs |
| `list_values` | `POST /platformapi/core/system/valueslistvalue/valueslist/{valuesListId}` with override GET | Preserve hierarchy, selectable state, ID, and display name; cache by field and depth |
| `discover_content_api` | `GET /contentapi/` | Optional permission-filtered level and cross-reference discovery |
| `search_content` | `POST /ws/search.asmx`, `ExecuteSearch` | Supported Read privilege; XML search plus `PageSize` and `pageNumber`; sort by configured date field and content ID where supported |
| `get_content` | `POST /platformapi/core/content/contentid?id=<contentId>` with override GET | Read typed fields, `Version`, `LastUpdated`, and identity locators |
| `get_record_soap` | `POST /ws/record.asmx`, `GetRecordById` | Fallback when a target workflow requires record XML; parse with hardened XML limits |
| `get_history` | `POST /platformapi/core/content/history/{contentId}` with override GET | Optional history/audit enrichment; no global sequence assumed |
| `get_attachment` | `POST /platformapi/core/content/attachment/{attachmentId}` with override GET | Stream bytes with size limits and SHA-256; do not log contents |
| `get_data_feed_history` | `POST /platformapi/core/datafeed/history` with override GET | Reconcile run status, created/updated/deleted counts, and history messages |

Primary references for these operations: [applications and version](https://help.archerirm.cloud/api_2025_04/content/api/restfulapi/segmentsresources/metadata_application.htm), [levels](https://help.archerirm.cloud/api_2025_04/content/api/restfulapi/segmentsresources/metadata_level.htm), [fields](https://help.archerirm.cloud/api_2025_04/content/api/restfulapi/segmentsresources/metadata_field.htm), [values lists](https://help.archerirm.cloud/api_2025_04/content/api/restfulapi/segmentsresources/metadata_values_list.htm), [content](https://help.archerirm.cloud/api_2025_04/content/api/restfulapi/segmentsresources/content.htm), [record XML](https://help.archerirm.cloud/api_2025_04/content/api/webapi/getrecordbyid.htm), and [data feeds](https://help.archerirm.cloud/api_2025_04/content/api/restfulapi/segmentsresources/data_feed.htm).

#### Actions

| Action | Classification | Idempotency | Precondition and reconciliation |
|---|---|---|---|
| `create_finding_or_exception` | write | `natural_key`: connection + level + configured external correlation field value | Resolve required fields and values-list IDs; search for an existing natural key before `POST /platformapi/core/content`; read back the created content. Timeout becomes `outcome_unknown` and repeats the natural-key search before any retry. |
| `update_finding_or_exception` | write | `natural_key`: content ID + expected Version + exact typed field-diff hash | Plan from current content. `PUT /platformapi/core/content` carries `Content.Id`, `LevelId`, only intended `FieldContents`, and current `Version`; 409/403 or a changed version becomes `stale_plan`. No-change plans do not call the API. Read back every mapped field. |
| `upload_attachment` | write | `natural_key`: content ID + field ID + evidence SHA-256 | Upload through `/content/attachment` or `/content/multipartattachment`, then associate the returned attachment ID through a versioned content update. Preserve existing attachment IDs, verify the association and downloadable hash, and reconcile an orphaned upload explicitly. |
| `execute_data_feed` | write | `natural_key`: DataFeedGuid + approved plan hash; no native idempotency assumed | `POST /platformapi/core/datafeed/execution` with `DataFeedGuid` and explicit `IsReferenceFeedsIncluded`. Persist before send, never blind-retry, and reconcile through recent/run history and history messages. |
| `delete_content` | destructive | none | Read current content, require explicit approval and expected identity/version at planning and immediately before deletion. The delete API has no documented generic idempotency token. Never retry an ambiguous delete; reconcile by content ID and report `outcome_unknown` until absence is proven. |

#### Notifications

| Field | Value |
|---|---|
| scheme | `none` initially |
| header | `none`; no generic signed notification header was established |
| dedupe key | Not applicable initially; a later notification adapter uses connection + raw-body digest + notification timestamp only as a wake-up hint |
| replay protection | Not applicable initially; durable poll checkpoints and content versions provide reconciliation |
| known gaps | Generic outbound JSON schema, HMAC, delivery ID, retry schedule, and notification completeness `[UNVERIFIED]` |

#### Capability scopes

| Capability | Scope or permission and probe |
|---|---|
| Version and application discovery | Independent probe of version, application, level, and field metadata reads |
| Content reads | Read privilege per configured application/level and record-permission scope; verify saved-search and direct content read separately |
| Values-list and cross-reference reads | Separate metadata probes; a denied expansion degrades mapping rather than dropping the value |
| Attachment evidence | Attachment read permission and a bounded test download, separately from content read |
| Finding/exception create and update | Separate create and update probes on write-enabled connections; do not infer one from the other |
| Attachment upload and association | Attachment create plus content update, with a non-production test record |
| Data-feed execution and history | Data-feed run permission plus independent history-read permission |
| Delete content | Delete permission only on explicitly destructive-enabled connections |

#### Top risks

- Hardcoded example field or level IDs silently map the wrong data. Dynamic metadata and typed contract tests are mandatory.
- Timestamp-only polling can skip records sharing a timestamp or records beyond a capped first page. Use ID tie-breakers, overlap, and complete pagination.
- Partial record permissions can look like an empty application. A 403 or omitted permission-filtered entity is degraded coverage, never closure.
- UI locks do not prevent API writes. Optimistic `Version`, exact diffs, and read-back are the defense against lost updates and workflow side effects.
- SOAP XML and attachment bodies require parser and size limits. Do not copy legacy unbounded retry or insecure XML patterns.
- Data feeds and content saves can trigger workflows and referenced feeds. The plan must disclose those effects and reconcile history.
- Session refresh storms can terminate other sessions for the same identity. Use a dedicated account and single-flight refresh.

#### Recommended ICUHUB recipe

| Area | Required implementation |
|---|---|
| Connector and authentication | `archer`, operator-supplied base URL, REST session login with single-flight 401 refresh, optional SOAP `CreateUserSessionFromInstance`, dedicated identity, and CA configuration without skip-verify defaults. |
| Streams and cursors | Enable `vulnerability_scan_results` 2002, `assessment_findings` 2003, `risks`, `exception_requests`, `remediation_plans`, `applications_devices`, `attachments`, and optional `vulnerability_library`, `history`, and `data_feed_runs`. Use configured Last Updated + Content.Id `time_id` with overlap for discovery and per-level `snapshot` runs for closure. |
| Read operations | Implement version, applications, levels, fields, values lists, content search/get, attachment get, optional history, and data-feed history before enabling any write. |
| Actions | Start with `create_finding_or_exception`, `update_finding_or_exception`, and `upload_attachment` as `write`; add `execute_data_feed` only with run-history reconciliation; keep `delete_content` `destructive` and disabled by default. |
| Scopes | Probe application/level read, content read, create, update, attachment read, attachment write, data-feed run, and delete independently. Missing permission produces `not_evaluated` for that capability. |
| Notifications | Declare `none`. Optionally accept a separately authenticated notification as a wake-up signal for targeted search, never as a complete feed. |
| Principal risks | Metadata drift, partial record permissions, capped or skipped SOAP pages, timestamp ties, UI-locked record writes, workflow side effects, session refresh races, and large evidence. |
| Build order | First metadata discovery and read-only mappings, then full snapshot closure and HTTP cassettes, then versioned writes and attachments, and only then data-feed execution or destructive actions. |

Fixtures and reusable evidence:

| Fixture or code source | Use | License |
|---|---|---|
| [XSOAR ArcherV2 tests](https://raw.githubusercontent.com/demisto/content/master/Packs/ArcherRSA/Integrations/ArcherV2/ArcherV2_test.py) | Inline login, level/field, nested values-list, SOAP token, search, and attachment-association cases. Add new cases for SOAP fault bodies, page 2, equal timestamps, version conflict, and partial permissions. | MIT, [license](https://raw.githubusercontent.com/demisto/content/master/LICENSE) |
| [Official get-content JSON](https://help.archerirm.cloud/api_2025_04/content/api/restfulapi/segmentsresources/json_examples/get-content-by-id.txt) | Vendor-shaped `FieldContents`, `LastUpdated`, `Version`, identity, and update metadata reference. Replace all example IDs with synthetic connection-local mappings. | Vendor documentation, no open-source reuse license established; schema reference only |
| [Official create-content JSON](https://help.archerirm.cloud/api_2025_04/content/api/restfulapi/segmentsresources/json_examples/post_content_request_body.txt) | Request-shape reference only. The opened example contains malformed quoting/commas; correct and sanitize it before JSON use and record that provenance. | Vendor documentation, no open-source reuse license established; do not treat the malformed sample as a golden without repair |
| [pyarcher client](https://raw.githubusercontent.com/kylecribbs/pyarcher/master/pyarcher/base.py) | URL-family and metadata ideas only; do not inherit its incomplete refresh, unchecked login, or legacy defaults. | MIT, [license](https://raw.githubusercontent.com/kylecribbs/pyarcher/master/LICENSE) |
| [Splunk SOAR Archer connector](https://raw.githubusercontent.com/splunk-soar-connectors/archer/main/archer_connector.py) | Additional action and polling contract cases; bound all retries in ICUHUB. | Apache-2.0, [license](https://raw.githubusercontent.com/splunk-soar-connectors/archer/main/LICENSE) |
