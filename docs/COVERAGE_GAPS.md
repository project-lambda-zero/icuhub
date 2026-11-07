# ICUHUB connector coverage gaps

| Field | Value |
|---|---|
| Document | COVERAGE_GAPS.md |
| Status | v0.1 |
| Date | 2026-11-07 |
| Inputs | `VENDOR_CONNECTORS.md`; `CONNECTOR_FRAMEWORK.md`; SCM, Atlassian, container-platform, AppSec, and vulnerability-management artifact comparisons researched 2026-11-07 |
| Feeds | `VENDOR_CONNECTORS.md`; ROADMAP P5, P8, P10 |

This document compares the connector specifications with inspected open-source and source-available integration artifacts. It identifies missing specification coverage; it does not describe runtime implementation, because the connectors are not yet implemented. `Y` means covered by the inspected artifact or ICUHUB specification, `P` means partial or adjacent coverage, and `N` means absent from that artifact or specification. `N` is not a claim that the vendor API or an entire platform lacks the capability.

Waves are the connector delivery waves in `VENDOR_CONNECTORS.md`. Wave 4 and Later items are recorded but are outside the current three-wave roadmap. In gap tables, read operations have classification `read` and idempotency `none`; write and destructive actions use plan/apply, with idempotency shown as `key` or `natural_key`. Existing connector auth applies unless another auth mode is stated. Shared GitHub and GitLab family gaps are defined once, counted for both edition kinds in section 2, and must be specialized by edition fixtures rather than copied blindly.

## 1. Platforms compared

| Platform | Integration unit | Vendors covered, of ICUHUB's set | License of the artifacts read | Reuse in ICUHUB |
|---|---|---|---|---|
| Airbyte | Declarative source manifests | GitHub, GitLab, Jira Cloud, Confluence Cloud | ELv2 | Ideas only |
| Steampipe | SQL table plugins | GitHub, GitLab, Bitbucket Cloud, Jira, Kubernetes, OpenShift | Apache-2.0 | Code with notice |
| Port Ocean and K8s Exporter | Resync handlers, actions, webhook processors, informers | GitHub, GitLab, Bitbucket, Jira Cloud, Mend SCA, Kubernetes | Apache-2.0 | Code with notice |
| n8n | Workflow nodes and triggers | GitHub, GitLab, Bitbucket Cloud, Jira, Confluence Cloud | Sustainable Use License 1.0 | Ideas only |
| StackStorm Exchange | Action and sensor packs | GitHub, GitLab, Bitbucket, Jira, Qualys | Apache-2.0 | Code with notice |
| Backstage | Catalog providers, scaffolder actions, search collators, Kubernetes backend | Bitbucket, Confluence, Kubernetes | Apache-2.0 | Code with notice |
| Activepieces | Community pieces | GitLab, Jira Cloud, Confluence Cloud | MIT Expat for inspected community paths | Code with notice |
| MeltanoLabs | Singer `tap-gitlab` | GitLab | AGPL-3.0 | Code only with copyleft compliance; otherwise ideas |
| Singer taps | Stream-based extractors | Jira, Bitbucket Cloud | `tap-jira` AGPL-3.0; HumbleBeck `tap-bitbucket` Apache-2.0 | Artifact-specific code reuse with license obligations |
| XSOAR `demisto/content` | Integration packs, commands, mirroring, event collectors | GitLab, Bitbucket, Jira, Prisma Cloud, Qualys, Tenable VM, Tenable SC | MIT for content artifacts | Code with notice; no commercial-platform code implied |
| Elastic Integrations | Agent input and CEL data streams | Bitbucket DC, Jira, Confluence, Kubernetes, Prisma Cloud, Qualys, Tenable VM | Elastic License 2.0 by repository default | Ideas only |
| Faros and Musixmatch Airbyte connectors | Airbyte source specification | Bitbucket Data Center | Apache-2.0 | Code with notice |
| CloudQuery | Provider resource map | Kubernetes | MPL-2.0 for inspected legacy provider | Code with file-level license obligations |
| Nango | Sync and action templates | Jira Cloud, Confluence Cloud | ELv2 | Ideas only |
| Tracecat | Git synchronization workflow | Bitbucket Cloud | AGPL-3.0 community edition; enterprise terms [UNVERIFIED] | Code only with copyleft compliance; otherwise ideas |
| DefectDojo | File parsers and Jira finding synchronization | Jira, Prisma Compute, Fortify, Invicti, Mend, Qualys, Tenable, Nessus | BSD-3-Clause | Code with notice |
| Prowler | Kubernetes provider and posture checks | Kubernetes | Apache-2.0 | Code with notice |
| Kestra | Kubernetes task plugin | Kubernetes and generic OpenShift API operations | Apache-2.0 | Code with notice |
| Faraday plugins | Repository report parsers | Fortify, Invicti, Qualys, Tenable, Nessus | GPL-3.0 | Code only with copyleft compliance; otherwise ideas |
| Cortex Analyzers | Nessus analyzer | Nessus | AGPL-3.0 | Code only with copyleft compliance; otherwise ideas |
| OpenCTI | External import and enrichment connectors | Qualys, Tenable VM | Repository Apache-2.0; Qualys connector manifest says Commercial and `verified=false` | Ideas only until artifact licensing is reconciled |
| Jenkins Qualys WAS plugin | Build-task scan integration | Qualys WAS | [UNVERIFIED] in this comparison | Ideas only |
| Qualys GitHub Action | WAS scan action | Qualys WAS | [UNVERIFIED]; no license verified | Ideas only |
| Qualys community samples | WAS CSV bootstrap scripts | Qualys WAS | GPL-3.0-only | Code only with copyleft compliance; otherwise ideas |
| Wazuh ruleset | Legacy QualysGuard ticket-log decoder | Qualys | GPL-2.0-only | Code only with copyleft compliance; otherwise ideas |

Dependency-Track, SecObserve, Shuffle, Windmill, and the other empty repository paths recorded in the slice inputs supplied no confirmed artifact for the assigned vendors; those bounded checks do not establish universal absence. Port Ocean Confluence, StackStorm Confluence, and the platform-specific empty checks likewise add no matrix claims.

## 2. Coverage overview

Counts below are specification gaps, not implementation effort estimates. Shared family counts refer to the same unique IDs defined under GitHub and GitLab; they are counted for each applicable kind but are not duplicated in the document.

| ICUHUB kind | Must | Should | Could | Deepest compared coverage |
|---|---:|---:|---:|---|
| `github` | 4 | 7 | 2 | Steampipe reads; Port events/actions; n8n and StackStorm writes |
| `github_enterprise_server` | 4 shared | 7 shared | 2 shared | Same family artifacts; GHES-specific fixtures remain ICUHUB-owned |
| `gitlab` | 5 | 7 | 1 | Airbyte and Activepieces; Port events; n8n writes |
| `gitlab_self_managed` | 5 shared | 7 shared | 1 shared | Same family artifacts; self-managed tier and host behavior need separate probes |
| `bitbucket_cloud` | 2 | 5 | 1 | Steampipe, Backstage, Singer, XSOAR, Port |
| `bitbucket_data_center` | 4 | 2 | 1 | Backstage, Port, Faros Airbyte, Elastic, StackStorm |
| `jira_cloud` | 4 | 8 | 4 | Airbyte, Port, Steampipe, Singer, Nango, n8n, XSOAR |
| `jira_dc` | 4 | 7 | 1 | XSOAR, Steampipe, Singer, n8n, Elastic |
| `confluence_cloud` | 4 | 5 | 2 | Nango, n8n, Activepieces, Airbyte, Backstage |
| `confluence_dc` | 3 | 5 | 1 | Backstage and Elastic; Cloud artifacts used only as porting evidence |
| `kubernetes` | 3 | 5 | 4 | Prowler posture; Elastic telemetry; Kestra writes; Steampipe inventory |
| `openshift` | 1 | 3 | 1 | Steampipe OpenShift; generic Kubernetes artifacts |
| `prisma_cloud` | 9 | 14 | 8 | XSOAR CSPM and Compute; Elastic CSPM and Compute; DefectDojo files |
| `fortify_ssc` | 2 | 1 | 0 | DefectDojo and Faraday file parsers |
| `fortify_fod` | 0 | 1 | 1 | DefectDojo and Faraday file parsers only |
| `invicti_enterprise` | 1 | 3 | 0 | DefectDojo and Faraday file parsers |
| `invicti_standard` | 2 | 2 | 0 | DefectDojo and Faraday file parsers |
| `mend_sca` | 3 | 2 | 0 | Port Ocean live reads; DefectDojo file parser |
| `qualys_enterprise` | 1 | 6 | 5 | XSOAR administration; Elastic collection; DefectDojo and Faraday files |
| `tenable_vm` | 1 | 4 | 2 | XSOAR and Elastic live reads; OpenCTI import; file parsers |
| `tenable_sc` | 2 | 7 | 2 | XSOAR live API; DefectDojo and Faraday files |
| `nessus` | 3 | 3 | 1 | Cortex live scan flow; DefectDojo and Faraday files |

## 3. Source control management

### 3.1 GitHub and GitHub Enterprise Server

Applies to `github` and `github_enterprise_server`. The GHES kind must apply every addition through its configured host, private-CA handling, release feature probes, and separate fixtures.

| Object or operation | Airbyte | Steampipe | Port | n8n / StackStorm | ICUHUB |
|---|---:|---:|---:|---:|---:|
| Repository, organization, team, user inventory | Y | Y | Y | P | N |
| Branches, tags, commits, files | P | Y | P | P | N |
| PRs, reviews, comments | P | Y | P | Y | Y |
| Actions workflows, runs, jobs, artifacts, runners | P | Y | P | P | N |
| Deployments, environments, releases, packages | Y | Y | Y | P | N |
| Security alerts, branch protection, enterprise audit | N | P | Y | N | Y |
| Commit status and check-run writes | N | N | P | Y | N |
| Repository file and release writes | N | N | N | Y | N |
| Webhook registration and broad event catalog | N | N | Y | Y | P |
| App, PAT, OAuth user token | P | Y | Y | Y | P: no OAuth user token |

| ID | Missing item | Implemented by | Why it matters | Proposed ICUHUB addition | Priority | Wave |
|---|---|---|---|---|---|---|
| GAP-GITHUB-01 | Repository and identity inventory | [Airbyte][AB-GH], [Steampipe][SP-GH] | Findings need asset ownership, membership, permission, and reachability context. | Add full-snapshot non-finding `repositories`, `organizations`, `users`, `teams`, `team_members`, `team_repositories`, `collaborators`, and `organization_external_identities`; `snapshot` cursor; App/PAT metadata and administration reads. | must | 1 |
| GAP-GITHUB-02 | Branches, tags, commits, trees, and files | [Steampipe][SP-GH], [Port][PO-GH] | SARIF and remediation must resolve to exact commit and path identity. | Add `branches`, `tags`, and `commits` with `time_id` or `snapshot` as supported; bounded `repository_files` snapshot and `get_file` read; immutable repository IDs and commit SHAs. | must | 1 |
| GAP-GITHUB-03 | Actions CI evidence | [Steampipe][SP-GH], [Port][PO-GH] | Build provenance, failed checks, artifacts, and runner exposure are security evidence. | Add `workflows`, `workflow_runs`, and `workflow_jobs` with `time_id`; `workflow_artifacts`, `actions_caches`, and `actions_runners` with `snapshot`; bounded log/artifact reads with secret controls. | must | 1 |
| GAP-GITHUB-04 | Commit statuses and check runs | [StackStorm][ST2-GH-ACT], [n8n trigger][N8-GH-TRIG] | Scan outcomes must attach to the exact commit and consume native gate results. | Add `commit_statuses` and `check_runs` reads; `create_commit_status` write/natural_key and `create_or_update_check_run` write/key; map status, check, and workflow webhooks and read back. | must | 1 |
| GAP-GITHUB-05 | Issues and planning records | [Airbyte][AB-GH], [n8n][N8-GH] | Native remediation tracking is needed when no external tracker exists. | Add `issues`, `issue_comments`, `labels`, `milestones`, and `issue_events` non-finding streams with `time_id`; issue create/update/comment/lock write actions, key or natural_key, with echo suppression. | should | 2 |
| GAP-GITHUB-06 | PR diff, patch, update, close, and reopen | [n8n PR operations][N8-GH-PR] | Fix automation needs exact changed lines and stale-PR lifecycle control. | Add `get_pr_diff`, `get_pr_patch`, and `list_pr_commits` reads; update/close/reopen write/natural_key with head-SHA and current-state preconditions. | should | 2 |
| GAP-GITHUB-07 | Deployments, environments, releases, and packages | [Steampipe][SP-GH], [Port][PO-GH], [StackStorm][ST2-GH-ACT] | Exposure priority depends on what shipped and where it deployed. | Add non-finding `deployments`, `deployment_statuses`, `environments`, `releases`, and `packages` streams with `time_id` or `snapshot`; deployment/status and release write/natural_key actions. | should | 2 |
| GAP-GITHUB-08 | Repository file and release mutation | [n8n][N8-GH], [StackStorm][ST2-GH-ACT] | Fix branches require content writes, not only empty PR creation. | Add `create_or_update_file` write/key and `delete_file` destructive/key with expected blob/head SHA and bounded content; branch create write/natural_key; release update write and release delete destructive. | should | 2 |
| GAP-GITHUB-09 | Workflow dispatch and lifecycle | [Port actions][PO-GH-ACT], [n8n][N8-GH] | On-demand scans and remediation pipelines are standard hub operations. | Add `dispatch_workflow` write/key with typed inputs and asynchronous run reconciliation; optional enable/disable write/natural_key guarded by current state. | should | 2 |
| GAP-GITHUB-10 | Repository custom properties | [Port actions][PO-GH-ACT] | Security tier, ownership, and policy metadata can be reconciled in the SCM catalog. | Add `repository_custom_properties` non-finding snapshot; bulk update write/key and delete destructive/key with per-property preconditions. | could | 3 |
| GAP-GITHUB-11 | Webhook subscription lifecycle and event breadth | [n8n trigger][N8-GH-TRIG], [Port][PO-GH] | Receive-only configuration cannot detect subscription drift or disabled hooks. | Add list/test reads and create/update write/natural_key plus delete destructive/key for hooks; health checks and explicit security, push, PR, issue, check, workflow, deployment, repository, and installation mappings. | should | 1 |
| GAP-GITHUB-12 | OAuth user-token authentication | [n8n][N8-GH] | Some interactive and legacy enterprise deployments cannot use installation tokens. | Add OAuth user-token auth beside App installation and PAT, retaining scope probes and preferring App auth for automation. | should | 1 |
| GAP-GITHUB-13 | Credential pools and installation discovery | [Airbyte][AB-GH], [Port][PO-GH] | Large installations need isolation and throughput without one global quota bucket. | Add optional credential-pool config, App-installation discovery reads, per-token health/quota state, and deterministic target ownership; auth remains App/PAT/OAuth. | could | 2 |

ICUHUB differentiator: no compared GitHub artifact combines asynchronous SARIF reconciliation, alert-state writes, audit destination-file ingestion, secret-value non-persistence, and approval-bound plan/apply merges with edition-specific GHES probes.

### 3.2 GitLab and GitLab Self-Managed

Applies to `gitlab` and `gitlab_self_managed`. Self-managed and Dedicated additions require per-host version, tier, and feature probes; GitLab.com-only batched audit behavior must not leak into those kinds.

| Object or operation | Airbyte | Activepieces | Port | n8n | ICUHUB |
|---|---:|---:|---:|---:|---:|
| Projects, groups, members, labels, milestones | Y | Y | Y | P | P |
| Branches, tags, commits, repository files | P | Y | P | P | N |
| Pipelines, jobs, bridges, artifacts | P | Y | P | N | N |
| MR diffs, discussions, approvals | P | Y | P | N | P |
| Issues, epics, boards | Y | Y | P | P | N |
| Releases and deployments | Y | P | N | P | N |
| Vulnerability findings and audit | N | N | N | N | Y |
| Branch, file, commit, and pipeline writes | N | Y | N | P | N |
| Webhook lifecycle and event breadth | N | P | Y | Y | P |

| ID | Missing item | Implemented by | Why it matters | Proposed ICUHUB addition | Priority | Wave |
|---|---|---|---|---|---|---|
| GAP-GITLAB-01 | Project, group, and membership inventory | [Airbyte][AB-GL], [Port][PO-GL] | Ownership, inherited access, and group scope are required for audit and least privilege. | Add full-snapshot non-finding `projects`, `groups`, `group_members`, `project_members`, `labels`, and `milestones`; stable numeric IDs, mutable full paths, existing token/OAuth. | must | 1 |
| GAP-GITLAB-02 | Branches, commits, tags, and repository files | [Activepieces][AP-GL], [Airbyte][AB-GL] | Findings and fixes must resolve to commit, path, and branch after project moves. | Add `branches`, `tags`, `commits`, `commit_diffs`, `repository_files`, `file_blame`, and `repository_tree` reads/streams with `time_id` or `snapshot`; numeric project identity. | must | 1 |
| GAP-GITLAB-03 | Pipeline, job, and artifact evidence | [Airbyte][AB-GL], [Activepieces][AP-GL] | Security report lineage and failed ingestion cannot be inferred from MR metadata. | Add `pipelines`, `pipeline_bridges`, `jobs`, and `pipeline_test_reports` with `time_id`; bounded `job_logs`, `job_artifacts`, and metadata-only `pipeline_variables` reads with size and secret controls. | must | 1 |
| GAP-GITLAB-04 | MR diffs, versions, and approval state | [Activepieces][AP-GL], [Airbyte][AB-GL] | Inline review and merge safety require base/head/start SHAs and actual approvals. | Add `mr_diffs`, `mr_versions`, `mr_commits`, `mr_pipelines`, `mr_approval_rules`, and `mr_approval_state` reads; diff-version SHAs anchor discussions. | must | 1 |
| GAP-GITLAB-05 | SARIF and native report-artifact publication | [Activepieces][AP-GL], [GitLab artifact contract][GL-SARIF-CI] | GitLab uses CI report artifacts, not GitHub-style direct SARIF upload. | Add `publish_security_report_artifact` write/key to create/run a CI job emitting bounded SARIF; reconcile job and vulnerability ingestion; require Ultimate and successful-job preconditions. | must | 2 |
| GAP-GITLAB-06 | MR update, unapprove, resolve, rebase, and delete | [Activepieces][AP-GL] | Long-lived remediation MRs need complete lifecycle management. | Add update, unapprove, reset approvals, resolve discussion, rebase, and cancel auto-merge write/natural_key; delete MR destructive/natural_key; use head SHA and state preconditions. | should | 1 |
| GAP-GITLAB-07 | Issues, epics, and boards | [Airbyte][AB-GL], [Activepieces][AP-GL] | Native remediation tracking should not require an external ticket product. | Add non-finding `issues`, `epics`, `epic_issues`, `boards`, and issue notes with `time_id`; create/update/comment write/key or natural_key. | should | 2 |
| GAP-GITLAB-08 | Branch, file, multi-file commit, and status writes | [Activepieces][AP-GL], [n8n][N8-GL] | Fix delivery and verification need tested content and commit status. | Add create branch and file/commit/status write/key with `last_commit_id`; delete branch/file destructive/key; no history-force option. | should | 2 |
| GAP-GITLAB-09 | Pipeline and job control | [Activepieces][AP-GL], [StackStorm][ST2-GL-PIPE] | The hub needs on-demand report production and recovery from failed jobs. | Add trigger/retry/cancel pipeline and retry/play/cancel job write/natural_key with accepted-async reconciliation; erase job destructive/natural_key and default-off. | should | 2 |
| GAP-GITLAB-10 | Releases, deployments, and environments | [Airbyte][AB-GL], [n8n][N8-GL] | Release and environment context determines exposure and remediation priority. | Add non-finding `releases`, `deployments`, and `environments` streams with `time_id`; optional release create/update write/natural_key and delete destructive/natural_key. | should | 2 |
| GAP-GITLAB-11 | Webhook lifecycle, resend, and event breadth | [Activepieces][AP-GL], [n8n trigger][N8-GL-TRIG] | Disabled hooks and unhandled event families become silent synchronization gaps. | Add list/test reads, create/update write/natural_key, resend write/key, and delete destructive/key for project/group hooks; map development, CI, member, release, and vulnerability events; surface disabled hooks in `check`. | should | 1 |
| GAP-GITLAB-12 | Audit keyset pagination | [XSOAR][XS-GL-AUDIT], [GitLab audit contract][GL-AUDIT] | Offset pagination over changing audit data can skip or duplicate events. | Change `audit_events` to `page_token` containing `created_at` plus ID; retain overlap and event-ID dedupe across instance, group, and project reads. | should | 1 |
| GAP-GITLAB-13 | Sensitive CI and protection configuration | [Steampipe catalog][SP-GL], [Meltano][ML-GL] | Posture includes variables and protection rules, but variable values are sensitive. | Add metadata-only full-snapshot `ci_variables`, `protected_branches`, `protected_tags`, and `webhook_configs`; never ingest variable values; expose masked/protected/raw status. | could | 3 |

ICUHUB differentiator: no compared GitLab artifact combines Ultimate asynchronous vulnerability exports and state writes, audit destination-object ingestion, Standard Webhooks verification, and head-SHA/approval-bound merge handling across cloud and self-managed edition contracts.

### 3.3 Bitbucket Cloud

| Object or operation | Steampipe | Backstage | Singer / XSOAR | Port / n8n | ICUHUB |
|---|---:|---:|---:|---:|---:|
| Workspaces, projects, repositories, members | Y | P | P | P | N |
| Branches, tags, commits, source files | P | P | P | P | N |
| PRs, comments, activity, diffs | P | N | P | P | Y |
| Pipelines and deployments | N | P | Y | N | N |
| Code Insights reports and annotations | N | N | N | N | Y |
| Repository, branch, PR, and file writes | N | P | Y | N | P |
| Default reviewers and branch restrictions | Y | P | N | N | P |
| Webhook registration and event catalog | N | P | N | Y | P |

| ID | Missing item | Implemented by | Why it matters | Proposed ICUHUB addition | Priority | Wave |
|---|---|---|---|---|---|---|
| GAP-BBCLOUD-01 | Workspace, project, repository, and membership inventory | [Steampipe][SP-BB], [Backstage][BS-BBC], [Singer][SG-BBC] | PRs and insights need stable UUID ownership and permission context. | Add full-snapshot non-finding `workspaces`, `projects`, `repositories`, `workspace_members`, and `repository_permissions`; immutable UUIDs; existing OAuth/API token. | must | 3 |
| GAP-BBCLOUD-02 | Branches, tags, commits, and source files | [Steampipe][SP-BB], [Port][PO-BBC], [Singer][SG-BBC] | Commit-scoped Code Insights needs exact revision and changed-path context. | Add `branches`, `tags`, `commits`, `commit_diffs`, `commit_diffstats`, `source_files`, and `file_history` with `time_id` or `snapshot`; bounded file reads. | must | 3 |
| GAP-BBCLOUD-03 | Pipelines and deployments | [Singer][SG-BBC], [Backstage actions][BS-BBC-ACT] | Build and deployment state are required for exposure and remediation gates. | Add non-finding `pipelines`, `pipeline_steps`, `deployments`, and `environments` with `time_id`; bounded pipeline logs; `run_pipeline` write/key with async step reconciliation. | should | 3 |
| GAP-BBCLOUD-04 | Repository, branch, and file writes | [Backstage actions][BS-BBC-ACT], [XSOAR][XS-BBC], [Tracecat][TC-GIT-SYNC] | Fix delivery requires content and commits, not only empty PRs. | Add create repository/branch and create/update file or atomic commit write/key with base-commit preconditions and non-fast-forward protection; repository deletion remains out of scope. | should | 3 |
| GAP-BBCLOUD-05 | PR update and comment correction | [XSOAR][XS-BBC] | Automated comments must be correctable and stale fix PRs need updates. | Add `update_pull_request` and `edit_comment` write/natural_key with current revision/state; `delete_comment` destructive/natural_key and default-off. | should | 3 |
| GAP-BBCLOUD-06 | Default reviewers | [Steampipe][SP-BB-REPO] | Review routing and required ownership affect remediation SLAs. | Add `default_reviewers` and `effective_default_reviewers` full-snapshot non-finding reads; optional assignment write/natural_key with membership preconditions. | should | 3 |
| GAP-BBCLOUD-07 | Webhook registration and event catalog | [Port][PO-BBC-WH], [n8n][N8-BBC] | Hook drift and repository transfer/deletion otherwise leave stale assets and missed PR changes. | Add hook list and `hook_events` reads; create/update write/natural_key and delete destructive/key; map PR, push, status, repository update/transfer/delete hints followed by REST reconciliation. | should | 3 |
| GAP-BBCLOUD-08 | Legacy issues | [Steampipe][SP-BB], [XSOAR][XS-BBC] | Native issue tracking could help, but the inspected XSOAR notes describe retirement of this surface. | Do not add a stream now. Re-evaluate only after a supported replacement API is confirmed; any future read would be non-finding with `time_id`. | could | Later |

ICUHUB differentiator: commit-scoped Code Insights, full PR decision/merge task reconciliation, and fail-closed HMAC with durable dedupe are not present together in the compared artifacts; unsigned or UUID-only receiver behavior must not be copied.

### 3.4 Bitbucket Data Center

| Object or operation | Backstage | Port | Faros Airbyte | Elastic / StackStorm | ICUHUB |
|---|---:|---:|---:|---:|---:|
| Projects, repositories, users, project users | P | Y | Y | N | P |
| Default branch, branches, commits, tags, raw files | P | N | P | P | N |
| PR detail, activities, diffs, comments | P | P | Y | N | P |
| PR create, approve, merge, review writes | P | N | N | N | Y |
| Code Insights and branch restrictions | N | N | N | N | Y |
| Audit REST events | N | N | N | Y | N |
| Node-local audit files | N | N | N | Y | Y |
| Repository create and LFS enable | Y | N | N | N | N |
| Webhook lifecycle and version probe | P | Y | N | P | P |

| ID | Missing item | Implemented by | Why it matters | Proposed ICUHUB addition | Priority | Wave |
|---|---|---|---|---|---|---|
| GAP-BBDC-01 | Users and project users | [Port][PO-BBD-CLI], Faros | Audit, review, and permission records need stable actors and owners. | Add full-snapshot non-finding `users` and `project_users` with project/repository permission scope and minimal profile data; existing token/Basic auth. | must | 3 |
| GAP-BBDC-02 | Default branch, raw files, commits, and tags | [Backstage][BS-BBD-CLI], Faros, [StackStorm][ST2-BBD] | PR diffs and Code Insights need exact revisions and changed paths. | Add `default_branch`, `branches`, `tags`, `commits`, and `commit_changes` with `time_id` or `snapshot`; `get_raw_file` read; version-gated merge-base behavior. | must | 3 |
| GAP-BBDC-03 | PR activities and diffs | Faros | PR metadata alone cannot reconstruct review history or exact remediation changes. | Add `pr_activities`, `pr_changes`, and `pr_diffs` with `time_id` using `updatedDate` overlap plus PR-ID/version dedupe; associated commit reads. | must | 3 |
| GAP-BBDC-04 | Audit REST collection | Elastic | Node-local files are unavailable to many hub deployments. | Add `audit_events` OCSF 6003 beside `audit_log_files`; `page_token` or time-plus-ID cursor with next-page links, timestamp+ID dedupe, and node/instance identity. | must | 3 |
| GAP-BBDC-05 | Application-properties version probe | [Port][PO-BBD-CLI] | Merge-base, webhook, token, and audit behavior vary by DC release. | Add `get_application_properties` read feeding `check`; gate capabilities and fixtures by parsed DC version and license tier. | should | 3 |
| GAP-BBDC-06 | Webhook lifecycle and explicit event mappings | Port, [Backstage][BS-BBD-EVENT] | Plugin disablement, drift, and renames otherwise break inventory continuity. | Add project/repository hook list reads, create/update write/natural_key, delete destructive/key, and health; map refs, PR, reviewer, comment, and `repo:modified` events with rename-as-move semantics. | should | 3 |
| GAP-BBDC-07 | Repository create and Git LFS enable | [Backstage][BS-BBD-SCAF] | Remediation or mirror repositories need an administrative bootstrap path. | Add `create_repository` write/natural_key and optional `enable_git_lfs` write/natural_key with project permission and current-state preconditions; not sync prerequisites. | could | 3 |

ICUHUB differentiator: creator-aware Code Insights, PR approval/merge/restriction plan-apply actions, rotation-aware audit checkpoints, and fail-closed HMAC coexist only in the ICUHUB specification.

## 4. Atlassian

### 4.1 Jira Cloud

| Object or operation | Airbyte / Singer | Port / Steampipe | n8n / Activepieces | XSOAR / Nango | ICUHUB |
|---|---:|---:|---:|---:|---:|
| Issues, projects, comments | Y | Y | Y | Y | Y |
| Audit records | N | N | N | N | Y |
| Users, groups, teams, roles | Y | Y | P | P | N |
| Attachments | P | N | Y | Y | N |
| Changelogs and worklogs | Y | Y | P | Y | P: detail only |
| Agile, versions, components | Y | Y | P | P | N |
| Configuration, dashboards, filters | Y | P | P | P | P |
| Core issue writes | N | Y | Y | Y | Y |
| Comment, attachment, worklog lifecycle | N | N | Y | Y | P |
| Webhook event and registration lifecycle | N | Y | Y | N | P |

| ID | Missing item | Implemented by | Why it matters | Proposed ICUHUB addition | Priority | Wave |
|---|---|---|---|---|---|---|
| GAP-JIRACLOUD-01 | Attachment inventory and content | [XSOAR][XS-JIRA-YML], [Activepieces][AP-JIRA] | Screenshots, logs, and exports are often the only reproduction evidence. | Add `attachments` non-finding EvidenceRecord with parent `time_id` and full `snapshot`; `download_attachment` read; upload write/key and delete destructive/natural_key using issue scopes. | must | 1 |
| GAP-JIRACLOUD-02 | Identity and ownership | [Airbyte][AB-JIRA], [Port kinds][PO-JIRA-KINDS], [Steampipe][SP-JIRA] | Routing and permission review need assignee, group, team, and role context. | Add full-snapshot non-finding `users`, `groups`, `group_members`, `teams`, and `project_roles`; IdentityRecord/AccessRecord; organization scopes only where required. | should | 2 |
| GAP-JIRACLOUD-03 | Issue changelog history | [Singer][SG-JIRA], [Airbyte][AB-JIRA] | Current issues cannot prove who changed severity or status. | Add `issue_changelogs` OCSF 6003 with issue/window `time_id` and full backfill; overlap and entry-ID dedupe; existing issue-read scope. | must | 1 |
| GAP-JIRACLOUD-04 | Worklog history | [Singer][SG-JIRA], [Port][PO-JIRA] | Remediation effort and investigation history are otherwise invisible. | Add `issue_worklogs` non-finding WorklogRecord with issue/window `time_id` and full backfill; `list_worklogs` read. | should | 2 |
| GAP-JIRACLOUD-05 | Agile delivery graph | [Port kinds][PO-JIRA-KINDS], [XSOAR][XS-JIRA] | Boards, sprints, epics, and backlog connect findings to remediation plans. | Add non-finding `boards`, `sprints`, `epics`, and `backlog_issues` with full/scoped `snapshot`; sprint and issue-move write/natural_key with membership preconditions. | should | 2 |
| GAP-JIRACLOUD-06 | Versions and components | [Nango][NG-JIRA-SYNCS], [Singer][SG-JIRA] | Fix versions and components support release verification and ownership. | Add full-snapshot `project_versions` and `project_components` non-finding records plus reads. | should | 2 |
| GAP-JIRACLOUD-07 | Watchers and votes | [Airbyte][AB-JIRA], [Activepieces][AP-JIRA] | Notification coverage and remediation demand are not recoverable from issue fields alone. | Add scoped non-finding `issue_watchers` and `issue_votes`; add/remove watcher write/natural_key with read-back. | could | 3 |
| GAP-JIRACLOUD-08 | Configuration and workflow catalog | [Airbyte][AB-JIRA], [Steampipe][SP-JIRA] | Safe custom-field mapping and transitions require installation-specific metadata. | Add full-snapshot non-finding fields, issue types, priorities, resolutions, statuses, workflows, screens, permission schemes, and issue-security schemes with per-scope probes. | should | 2 |
| GAP-JIRACLOUD-09 | Dashboards and filters | [Airbyte][AB-JIRA], [StackStorm][ST2-JIRA] | Saved filters define security queues and reproducible reporting. | Add full-snapshot `dashboards`, `filters`, and `filter_sharing`; reads first, optional write/natural_key later. | could | 3 |
| GAP-JIRACLOUD-10 | Comment correction and removal | [Nango actions][NG-JIRA-ACTIONS], [XSOAR][XS-JIRA] | Add-only comments cannot correct stale or sensitive automated text. | Add `update_comment` write/natural_key keyed by comment ID and revision; `delete_comment` destructive/natural_key, default-off, with read-back. | must | 1 |
| GAP-JIRACLOUD-11 | Worklog writes | [Nango worklog action][NG-JIRA-WORKLOG] [UNVERIFIED] | Automation may need to record or correct investigation effort. | Add add worklog write/natural_key, update write/natural_key with ID/revision, and delete destructive/natural_key. | should | 2 |
| GAP-JIRACLOUD-12 | Issue properties and remote-link lifecycle | [Airbyte][AB-JIRA], [Activepieces][AP-JIRA] | ICUHUB relies on properties for idempotency but cannot inspect or repair them. | Add scoped property/remote-link reads or streams; set/update write/natural_key with version; property/link delete destructive/natural_key. | should | 2 |
| GAP-JIRACLOUD-13 | Issue forms | [XSOAR][XS-JIRA] | Security intake responses may exist only in ProForma forms. | Add `get_issue_forms` read and optional non-finding `issue_forms` full/scoped stream with privacy controls and raw residue. | could | 3 |
| GAP-JIRACLOUD-14 | Notifications and user administration | [Activepieces][AP-JIRA], [n8n issue operations][N8-JIRA-ISSUE] [UNVERIFIED] | Escalation and service-account provisioning are occasionally required but high risk. | Add notification write/key with recipient allowlist; create user write/natural_key and delete user destructive/natural_key under separate default-off administration scope. | could | 3 |
| GAP-JIRACLOUD-15 | Event coverage and webhook lifecycle | [n8n trigger][N8-JIRA-TRIG], [Port][PO-JIRA] | Dynamic registrations expire and issue-only events omit security-relevant changes. | Add typed event sets, list reads, create write/natural_key, delete destructive/key, expiry checkpoint, refresh scheduler, read-back, and dead-letter reconciliation; `manage:jira-webhook`. | must | 1 |
| GAP-JIRACLOUD-16 | Security publication policy | [DefectDojo][DD-JIRA] | Generic issue creation lacks verified-only filters, grouping, ownership, and close/reopen policy. | Add versioned per-target `ticket_policy` consumed by create/transition write actions with dry-run rendering and natural-key reconciliation; `write:jira-work`. | should | 2 |

ICUHUB differentiator: Cloud `cloudId` and granular scopes, route-key reconciliation, `outcome_unknown`, permission-aware absence closure, and explicit JQL eventual-consistency handling are not combined in the inspected platforms.

### 4.2 Jira Data Center

| Object or operation | Singer / Steampipe | n8n / XSOAR | Elastic | DefectDojo / StackStorm | ICUHUB |
|---|---:|---:|---:|---:|---:|
| Issues, projects, comments | Y | Y | N | P | Y |
| Audit REST and node-local files | N | P: files | Y | N | P: REST only |
| Users, groups, project roles | Y | P | N | P | N |
| Attachments | N | Y | N | P | P: writes only |
| Changelogs and worklogs | Y | P | N | P | P: detail only |
| Agile, versions, components | Y | P | N | P | N |
| Configuration and dashboards | Y | P | N | P | P |
| Core issue and attachment writes | N | Y | N | Y | Y |
| Comment update and agile writes | N | Y | N | P | N |
| PAT and signed webhooks | P | Y | Y | P | Y |

| ID | Missing item | Implemented by | Why it matters | Proposed ICUHUB addition | Priority | Wave |
|---|---|---|---|---|---|---|
| GAP-JIRADC-01 | Node-local audit files | [Elastic][EL-JIRA-AUDIT], [XSOAR DC pack][XS-JIRADC] | API retention and permissions can omit administrative evidence held on each node. | Add `audit_log_files` OCSF 6003 with per-node file identity and `sequence` offset/fingerprint, rotation/truncation handling, and separate TLS file-collector auth. | must | 1 |
| GAP-JIRADC-02 | Attachment reads | [XSOAR][XS-JIRA], [StackStorm][ST2-JIRA] | Existing upload/delete cannot ingest or download evidence. | Add `attachments` EvidenceRecord full/parent-incremental stream and `download_attachment` read using PAT visibility; retain existing guarded writes. | must | 1 |
| GAP-JIRADC-03 | Issue changelog history | [Singer][SG-JIRA], [Steampipe][SP-JIRA] | Long-lived queues need attributable triage history. | Add `issue_changelogs` OCSF 6003 with `time_id`, overlap, tie-overflow guards, and PAT auth. | must | 1 |
| GAP-JIRADC-04 | Worklog history and writes | [Singer][SG-JIRA], [Steampipe][SP-JIRA] | Remediation effort and corrections are not represented in issue snapshots. | Add non-finding `issue_worklogs` with `time_id`; read plus add/update write/natural_key and delete destructive/natural_key. | should | 2 |
| GAP-JIRADC-05 | Users, groups, and project roles | [Steampipe][SP-JIRA], [Singer][SG-JIRA] | Local groups and plugin customization make ownership and drift review essential. | Add full-snapshot `users`, `project_roles`, and version-gated `groups/group_members`; never reuse Cloud-only group endpoints. | should | 2 |
| GAP-JIRADC-06 | Agile objects and writes | [Steampipe][SP-JIRA], [XSOAR][XS-JIRA] | DC remediation is planned in boards, sprints, and epics. | Add version-gated non-finding agile streams with `snapshot`; move to sprint/backlog/epic write/natural_key with board/issue preconditions. | should | 2 |
| GAP-JIRADC-07 | Versions and components | [Singer][SG-JIRA] | Affected-version and fix-release traceability requires native records. | Add full-snapshot `project_versions` and `project_components` non-finding streams and reads. | should | 2 |
| GAP-JIRADC-08 | Configuration schema | [Steampipe][SP-JIRA] | DC fields and workflows vary by installation and plugin set. | Add full-snapshot workflows, issue types, fields, priorities, resolutions, and project roles as non-finding configuration records. | should | 2 |
| GAP-JIRADC-09 | Dashboards and filters | [Steampipe][SP-JIRA], [StackStorm][ST2-JIRA] | Saved operational queues are otherwise unreproducible. | Add full-snapshot `dashboards` and `filters`; optional writes are default-off write/natural_key. | could | 3 |
| GAP-JIRADC-10 | Comment update | [n8n][N8-JIRA-COMMENT] [UNVERIFIED], [XSOAR][XS-JIRA] | Delete-only lifecycle cannot correct stale or sensitive text. | Add `update_comment` write/natural_key with current body/revision precondition and read-back. | should | 1 |
| GAP-JIRADC-11 | Webhook catalog and registration | [n8n trigger][N8-JIRA-TRIG] | Issue-only push misses comments, links, worklogs, and projects. | Add typed event declarations, hook list reads, create write/natural_key, delete destructive/key, registration health, Jira 10 async fixtures, and digest dedupe. | must | 1 |
| GAP-JIRADC-12 | Security publication policy | [DefectDojo][DD-JIRA] | DC installations need local issue type, field, workflow, severity, and epic maps. | Add versioned per-target `ticket_policy` discovered from DC metadata; dry-run plan and natural-key ticket writes under PAT. | should | 2 |

ICUHUB differentiator: PAT-only new connections, legacy Basic rejection, context-path/private-CA support, destructive-action approval, and timestamp-tie/complete-project closure semantics distinguish the DC specification.

### 4.3 Confluence Cloud

| Object or operation | Airbyte | Nango | n8n / Activepieces | Backstage | ICUHUB |
|---|---:|---:|---:|---:|---:|
| Spaces and pages | Y | Y | Y | Y | Y |
| Blog posts | Y | Y | P | Y | N |
| Inline and footer comments | P | Y | Y | P | P: one stream |
| Attachment metadata and content | N | Y | Y | P | P |
| Groups and users | Y | N | P | N | N |
| Content history and restrictions | Y | P | P | P | P |
| Content properties and labels | N | Y | Y | N | P |
| Page writes | N | Y | Y | N | Y |
| Blog, comment, attachment lifecycle | N | Y | Y | N | N |
| Move, draft, append, template, subtree | N | N | Y | P | N |

| ID | Missing item | Implemented by | Why it matters | Proposed ICUHUB addition | Priority | Wave |
|---|---|---|---|---|---|---|
| GAP-CONFCLOUD-01 | Blog posts | [Airbyte][AB-CONF], [Nango][NG-CONF], [Backstage][BS-CONF] | Advisories and incident timelines are often blog posts rather than pages. | Add `blog_posts` DocumentRecord with `time_id`, full and event modes; create/update write/natural_key and delete destructive/natural_key using content scopes. | should | 2 |
| GAP-CONFCLOUD-02 | Attachment sync and lifecycle | [Nango attachments][NG-CONF-ATTACH], [n8n][N8-CONF], [Activepieces][AP-CONF] | Diagrams, scan exports, and evidence need reconciliation and safe removal. | Add `attachments` EvidenceRecord with resumable `snapshot` and parent-content incremental hints; download read; delete destructive/natural_key; retain upload hash key. | must | 2 |
| GAP-CONFCLOUD-03 | Inline and footer comment semantics | [Nango][NG-CONF-ACTIONS], [n8n][N8-CONF-PAGE] [UNVERIFIED] | Inline resolution and selected text need workflows distinct from footer discussion. | Split `inline_comments` and `footer_comments` CommentRecord streams with `time_id`; reply/update write/natural_key and delete destructive/natural_key using IDs and versions. | must | 2 |
| GAP-CONFCLOUD-04 | Groups and users | [Airbyte][AB-CONF], [Activepieces][AP-CONF] | Authors, restrictions, and ownership need identity resolution. | Add full-snapshot `groups`, `group_members`, and `users` IdentityRecord streams plus `find_user` read; isolate organization-admin scopes and denied results. | should | 2 |
| GAP-CONFCLOUD-05 | Version history | [Airbyte][AB-CONF], [Backstage][BS-CONF] | Current content cannot show who removed a mitigation or changed evidence. | Add `content_versions` DocumentVersionRecord or OCSF 6003 for audit-worthy changes; per-content `snapshot` and version-number incremental identity. | should | 2 |
| GAP-CONFCLOUD-06 | Queryable permissions and restrictions | [Airbyte][AB-CONF] | Restriction drift affects confidentiality and snapshot completeness. | Add full/scoped `space_permissions` and `content_restrictions` AccessRecord streams with `snapshot`; denied admin visibility is `not_evaluated`; existing change action remains destructive. | must | 2 |
| GAP-CONFCLOUD-07 | Content property lifecycle | [Nango property update][NG-CONF-PROPERTY], [Nango actions][NG-CONF-ACTIONS] | Report idempotency state cannot be inspected or repaired. | Add property reads or scoped stream; create/update write/natural_key with property version and delete destructive/natural_key. | must | 2 |
| GAP-CONFCLOUD-08 | Label reads and removal | [n8n][N8-CONF-PAGE] [UNVERIFIED], [Activepieces][AP-CONF] | Add-only labels accumulate stale report classifications. | Add `content_labels` scoped non-finding stream and label-query read; `remove_label` write/natural_key with current-label precondition. | should | 2 |
| GAP-CONFCLOUD-09 | Move, draft publication, and append | [Activepieces][AP-CONF], [n8n][N8-CONF] | Controlled report lifecycle requires moves, reviewed publication, and non-destructive updates. | Add `publish_draft` and `append_page` write/natural_key with version/body-hash plans; `move_page` destructive/natural_key with destination permission checks. | should | 2 |
| GAP-CONFCLOUD-10 | Template-based publishing | [Activepieces template action][AP-CONF-TEMPLATE] | Standard security templates reduce omitted fields and inconsistent reports. | Add template list/get reads and `create_page_from_template` write/key with escaped variables, deterministic title, and report-key property. | could | 3 |
| GAP-CONFCLOUD-11 | Page subtree retrieval | [n8n][N8-CONF-PAGE] [UNVERIFIED], [Backstage][BS-CONF] | Hierarchical runbooks need complete context and safe move impact analysis. | Add `get_page_subtree` read with depth/count bounds and ancestor/descendant references in DocumentRecord. | could | 3 |

ICUHUB differentiator: combined v1/v2 CQL reconciliation, deterministic report properties, plan hashes, high-risk destructive-action defaults, and optional Connect/Forge verification are broader than the compared content sync artifacts.

### 4.4 Confluence Data Center

Only Backstage and Elastic supplied confirmed DC-relevant artifacts. Cloud-only Nango, n8n, Activepieces, and Airbyte features below are porting evidence, not claims of DC implementation.

| Object or operation | Backstage | Elastic | Cloud porting evidence | ICUHUB |
|---|---:|---:|---:|---:|
| Spaces and pages | Y | N | Y | Y |
| Blog posts and generic comments | Y | N | Y | P |
| Attachments | P | N | Y | P |
| Content versions and ancestors | Y | N | Y | P |
| Audit REST and node-local files | N | Y | P | P: REST only |
| Page, comment, label, property writes | N | N | Y | P |
| Signed webhooks with rotation | N | N | N | Y |
| Restrictions and identity catalog | N | N | Y | P |

| ID | Missing item | Implemented by | Why it matters | Proposed ICUHUB addition | Priority | Wave |
|---|---|---|---|---|---|---|
| GAP-CONFDC-01 | Node-local audit files | [Elastic][EL-CONF-AUDIT] | Administrative evidence is distributed across nodes and may exceed REST visibility. | Add `audit_log_files` OCSF 6003 with per-node filename/offset/fingerprint `sequence`, rotation handling, raw-event preservation, and separate file-collector auth. | must | 3 |
| GAP-CONFDC-02 | Blog posts | [Backstage][BS-CONF], [Nango Cloud action][NG-CONF-BLOG] [UNVERIFIED] | Page-only CQL omits a distinct authoritative content type. | Add version-gated `blog_posts` DocumentRecord via DC content/CQL with `time_id`; create/update/delete actions only after fixtures, write or destructive with natural_key. | should | 3 |
| GAP-CONFDC-03 | Attachment inventory, download, and delete | [Backstage][BS-CONF], [Nango Cloud attachments][NG-CONF-ATTACH] | Related-read/upload cannot reconcile evidence or remove unsafe files. | Add `attachments` EvidenceRecord with content/parent `snapshot`; download read with anti-XSSI/version fixtures; delete destructive/natural_key. | must | 3 |
| GAP-CONFDC-04 | Full content history | [Backstage][BS-CONF], [Airbyte Cloud][AB-CONF] | Tamper review and conflict investigation need version history. | Add `content_versions` DocumentVersionRecord full/scoped `snapshot` with version and author; retain storage bodies only under configured limits. | should | 3 |
| GAP-CONFDC-05 | Comment lifecycle | [Nango Cloud actions][NG-CONF-ACTIONS], [n8n Cloud][N8-CONF-PAGE] [UNVERIFIED] | Add-only comments cannot correct sensitive or obsolete guidance. | Add reply/update write/natural_key and delete destructive/natural_key on v1 comments; separate inline stream only for confirmed DC versions. | should | 3 |
| GAP-CONFDC-06 | Content property lifecycle | [Nango Cloud property action][NG-CONF-PROPERTY] | The connector cannot reconcile the report idempotency state it owns. | Add list/get reads, update write/natural_key with version, delete destructive/natural_key, and optional scoped property stream. | must | 3 |
| GAP-CONFDC-07 | Label inventory and removal | [n8n Cloud][N8-CONF-PAGE] [UNVERIFIED], [Activepieces Cloud][AP-CONF] | Report classification and retention labels currently cannot be reconciled. | Add `content_labels` scoped stream and label-query read; remove write/natural_key with current-label precondition. | should | 3 |
| GAP-CONFDC-08 | Queryable restrictions and space permissions | [Airbyte Cloud][AB-CONF] | Restriction drift affects confidentiality and snapshot completeness. | Add full/scoped `space_permissions` and `content_restrictions` AccessRecord streams using v1 expansions; denied visibility is `not_evaluated`. | should | 3 |
| GAP-CONFDC-09 | Identity catalog | [Airbyte Cloud][AB-CONF] | Restriction and audit identities need local directory resolution. | Add version-gated full-snapshot `users`, `groups`, and `group_members` only after DC fixtures; never reuse Cloud `/wiki` group APIs. | could | 3 |

ICUHUB differentiator: signed admin webhooks with rotation, deterministic report keys, full publishing/destructive lifecycle, `/rest/api/content/scan` snapshots, and explicit rejection of Cloud-only v2/OAuth/ADF assumptions are unique in this comparison.

## 5. Container platforms and cloud posture

This section compares ICUHUB with inspected Kubernetes, OpenShift, Prisma Cloud CSPM, and Prisma Cloud Compute integrations. Coverage values are `Y` (implemented), `P` (partial, indirect, read-only subset, or generic API only), and `N` (not present in the inspected artifact). Elastic License 2.0 is source-available, not an OSI open-source license.

### 5.1 Kubernetes

#### Coverage matrix

| Object or operation | SP | CQ | Port | BS | PR | EL | KE | ICUHUB |
|---|---|---|---|---|---|---|---|---|
| Pods and workload controllers | Y | Y | Y | Y | P | P | Y | Y |
| Roles, bindings, and ServiceAccounts | Y | P | Y | P | Y | N | P | P |
| Secret metadata and workload secret usage | Y | N | P | P | Y | N | P | P |
| Helm charts, releases, templates, and values | Y | N | N | N | N | N | N | N |
| Dynamic CRDs and custom resources | Y | N | Y | Y | N | N | P | Y |
| Core Kubernetes Events | Y | N | P | N | N | Y | N | N |
| Container logs | N | N | N | N | N | Y | P | N |
| Kubelet, workload-state, and control-plane metrics | N | N | N | P | N | Y | N | N |
| API audit from node files | N | N | N | N | N | Y | N | Y |
| EKS, AKS, and GKE managed audit ingestion | N | N | N | N | N | Y | N | N |
| Native workload security posture checks | N | N | N | N | Y | N | N | P |
| Native RBAC privilege and wildcard checks | N | N | N | N | Y | N | N | N |
| Control-plane and node configuration checks | N | N | N | N | Y | P | N | N |
| Live synchronization and stale-entity cleanup | P | P | Y | P | P | P | P | Y |
| Generic apply, patch, restart, and deletion | N | N | N | N | N | N | Y | P |

#### Gaps

| ID | Missing item | Implemented by | Why it matters | Proposed ICUHUB addition | Priority | Wave |
|---|---|---|---|---|---|---|
| GAP-K8S-01 | Native workload posture | [Prowler core checks](https://github.com/prowler-cloud/prowler/tree/master/prowler/providers/kubernetes/services/core) | Kyverno and Gatekeeper evidence covers only clusters running those engines. Direct checks are needed for CIS-like workload misconfiguration evidence. | `workload_assessment_changes`, `workload_assessment_snapshot`; OCSF 2003; cursor: resourceVersion/watch and snapshot; read; idempotency: none. | must | 2 |
| GAP-K8S-02 | RBAC assessment | [Prowler RBAC checks](https://github.com/prowler-cloud/prowler/tree/master/prowler/providers/kubernetes/services/rbac) | Inventory alone does not expose privilege-escalation paths, wildcard permissions, or excessive secret and certificate access. | `rbac_assessment_changes`, `rbac_assessment_snapshot`, optional authorized `get_subject_access_review`; OCSF 2003; cursor: resourceVersion/watch and snapshot; read; idempotency: none. | must | 2 |
| GAP-K8S-03 | Control-plane and node posture | [Prowler service catalog](https://github.com/prowler-cloud/prowler/tree/master/prowler/providers/kubernetes/services), [API-server checks](https://github.com/prowler-cloud/prowler/tree/master/prowler/providers/kubernetes/services/apiserver) | Audit activity and workload policy do not establish secure API-server, etcd, kubelet, controller-manager, or scheduler configuration. | `control_plane_assessment_snapshot`; OCSF 2003; cursor: snapshot; read; idempotency: none; auth: node/config/file probe access where required; use `not_evaluated` for hidden managed flags. | should | 2 |
| GAP-K8S-04 | Managed audit transports | [Elastic Kubernetes manifest](https://raw.githubusercontent.com/elastic/integrations/main/packages/kubernetes/manifest.yml) | Managed clusters commonly hide control-plane nodes, so file and webhook ingestion alone leaves an audit blind spot. | `audit_events` adapters for CloudWatch, Event Hub, and Pub/Sub; record: API audit event; cursor: per-source sequence; read; idempotency: none; auth: cloud-provider credentials; retain API source, auditID, and stage dedupe. | must | 2 |
| GAP-K8S-05 | Core Events | [Steampipe registry](https://raw.githubusercontent.com/turbot/steampipe-plugin-kubernetes/main/kubernetes/plugin.go), [Elastic manifest](https://raw.githubusercontent.com/elastic/integrations/main/packages/kubernetes/manifest.yml) | Scheduling, image-pull, probe, and workload failures explain operational and security incidents but are not API audit records. | `core_events`; record: operational event; cursor: watch plus relist; read; idempotency: none; retain involved-object UID, reason, source, count, and first/last timestamps. | should | 3 |
| GAP-K8S-06 | Container logs | [Elastic manifest](https://raw.githubusercontent.com/elastic/integrations/main/packages/kubernetes/manifest.yml), [Kestra PodCreate](https://raw.githubusercontent.com/kestra-io/plugin-kubernetes/main/src/main/java/io/kestra/plugin/kubernetes/core/PodCreate.java) | Runtime troubleshooting and detection triage need application evidence unavailable from resource state and API audit. | `container_logs`; record: container log; cursor: byte/sequence checkpoint with container restart identity; read; idempotency: none; auth: existing plus explicit `pods/log` authorization when used; apply bounds and secret redaction. | should | 3 |
| GAP-K8S-07 | Cluster telemetry | [Elastic manifest](https://raw.githubusercontent.com/elastic/integrations/main/packages/kubernetes/manifest.yml), [Backstage fetcher](https://raw.githubusercontent.com/backstage/backstage/master/plugins/kubernetes-backend/src/service/KubernetesFanOutHandler.ts) | Resource pressure, unavailable workloads, and control-plane health distinguish connector failure from cluster failure and help prioritize remediation. | `cluster_metrics`, `workload_metrics`; record: metric; cursor: metric timestamp and labels; read; idempotency: none; sources: Kubelet/kube-state-metrics and optional metrics.k8s.io. | could | 3 |
| GAP-K8S-08 | Helm inventory and offline evidence | [Steampipe registry](https://raw.githubusercontent.com/turbot/steampipe-plugin-kubernetes/main/kubernetes/plugin.go), [Steampipe configuration](https://raw.githubusercontent.com/turbot/steampipe-plugin-kubernetes/main/kubernetes/connection_config.go) | Release lineage links deployed resources to chart, version, and values. Rendered manifests also support disconnected and pre-deployment assessment. | `helm_releases`, `manifest_assessments`; records: HelmRelease and OCSF 2003; cursor: release snapshot and file replay; read; idempotency: none; redact values and secrets. | could | 3 |
| GAP-K8S-09 | Generic guarded apply and patch | [Kestra Apply](https://raw.githubusercontent.com/kestra-io/plugin-kubernetes/main/src/main/java/io/kestra/plugin/kubernetes/kubectl/Apply.java), [Kestra Patch](https://raw.githubusercontent.com/kestra-io/plugin-kubernetes/main/src/main/java/io/kestra/plugin/kubernetes/kubectl/Patch.java) | Annotation-only writes cannot implement most remediations, policy fixes, or GitOps-adjacent workflows. | `apply_manifest`, `patch_resource`; record: action outcome; cursor: n/a; write; idempotency: key; enforce GVK policy, resourceVersion/dry-run preconditions, redacted diff, read-back, and bounded readiness. | should | 3 |
| GAP-K8S-10 | Rolling restart | [Kestra Restart](https://raw.githubusercontent.com/kestra-io/plugin-kubernetes/main/src/main/java/io/kestra/plugin/kubernetes/kubectl/Restart.java) | Restart is a common remediation after secret rotation, policy correction, or workload containment. | `restart_workload`; record: action outcome; cursor: n/a; write; idempotency: key; require availability approval, expected resourceVersion and Pod-template hash, rollout read-back, and no blind retry. | should | 3 |
| GAP-K8S-11 | Generic deletion | [Kestra Delete](https://raw.githubusercontent.com/kestra-io/plugin-kubernetes/main/src/main/java/io/kestra/plugin/kubernetes/kubectl/Delete.java) | Pod-only deletion cannot quarantine a malicious Service, Ingress, Job, or custom resource. | `delete_resource`; record: action outcome; cursor: n/a; destructive; idempotency: key; disabled by default with GVK allowlist, UID/resourceVersion precondition, approval, and deletion read-back. | could | 3 |
| GAP-K8S-12 | Pod execution lifecycle | [Kestra PodCreate](https://raw.githubusercontent.com/kestra-io/plugin-kubernetes/main/src/main/java/io/kestra/plugin/kubernetes/core/PodCreate.java) | Controlled one-shot scanners and collectors are useful, but execution and file transfer create a large security boundary. | `run_pod_job`; record: action outcome; cursor: task-run resume state; destructive; idempotency: natural_key; fixed image/command policy, no arbitrary exec by default, bounded artifacts, and cleanup compensation. | could | 4 |

ICUHUB differentiator: ICUHUB uniquely combines normalized incremental/full Kyverno, OpenReports, and Gatekeeper findings with truncation and absence-closure safety; authenticated audit webhook and file ingestion with multi-source dedupe; typed resourceVersion-gated plan/apply outcomes; and OCSF finding, inventory, and API Activity separation with raw evidence, mapper versions, and host-owned checkpoints.

### 5.2 OpenShift

#### Coverage matrix

| Object or operation | OSP | SP/CQ/Port/BS/PR generic | KE generic | ICUHUB |
|---|---|---|---|---|
| Routes and TLS/ingress status | Y | P | P | Y |
| SecurityContextConstraints | N | N | P | Y |
| Builds and BuildConfigs | Y | P | P | Y |
| ImageStreams and tag/digest history | Y | P | P | Y |
| DeploymentConfigs, rollout state, and triggers | Y | N | P | N |
| Projects as tenancy objects | Y | P | P | N |
| Users, identities, and group memberships | Y | N | P | N |
| OAuthAccessToken metadata | Y | N | P | N |
| ClusterVersion read | N | N | P | Y |
| Kyverno/OpenReports policy evidence | N | P | P | Y |
| Multi-source API audit from files and webhook | N | N | N | Y |
| Generic manifest apply and patch | N | N | P | P |
| Rolling workload restart | N | N | P | N |
| Kubeconfig, OAuth token, and certificate auth | P | P | P | Y |
| Explicit OpenShift and managed-offering handling | Y | N | N | Y |

#### Gaps

| ID | Missing item | Implemented by | Why it matters | Proposed ICUHUB addition | Priority | Wave |
|---|---|---|---|---|---|---|
| GAP-OSHIFT-01 | Projects | [Steampipe Project table](https://raw.githubusercontent.com/turbot/steampipe-plugin-openshift/main/openshift/table_openshift_project.go) | Project is the OpenShift tenancy and RBAC boundary. Treating Namespace as equivalent loses lifecycle and API identity and weakens target scoping. | `projects_changes`, `projects_snapshot`, `get_project`; record: Project; cursor: project UID/resourceVersion watch and snapshot; read; idempotency: none. | must | 2 |
| GAP-OSHIFT-02 | DeploymentConfigs | [Steampipe DeploymentConfig table](https://raw.githubusercontent.com/turbot/steampipe-plugin-openshift/main/openshift/table_openshift_deployment_config.go) | Existing estates still use DeploymentConfigs. Deployments alone miss their rollout lineage, triggers, revision history, and availability. | Add DeploymentConfig to `openshift_inventory_*` and add `get_deploymentconfig`; record: inventory; cursor: resourceVersion/watch and snapshot; read; idempotency: none; preserve digest and template identity. | should | 3 |
| GAP-OSHIFT-03 | Users and identity mappings | [Steampipe User table](https://raw.githubusercontent.com/turbot/steampipe-plugin-openshift/main/openshift/table_openshift_user.go) | SCC and RBAC findings need subject identity for privilege analysis, offboarding, and access review. | `users_identities_changes`, `users_identities_snapshot`, `get_user`; record: identity; cursor: resourceVersion/watch and snapshot; read; idempotency: none; auth: user.openshift.io read permission. | should | 3 |
| GAP-OSHIFT-04 | OAuth token metadata | [Steampipe OAuthAccessToken table](https://raw.githubusercontent.com/turbot/steampipe-plugin-openshift/main/openshift/table_openshift_oauth_access_token.go) | Long-lived or broadly scoped tokens are attack paths, while raw token values are credentials and must not become evidence. | `oauth_access_token_metadata_snapshot`; record: token metadata; cursor: snapshot; read; idempotency: none; auth: privileged read; drop token material and retain client, user, scope, and expiry. | could | 3 |
| GAP-OSHIFT-05 | Generic guarded writes and restart | [Kestra Apply](https://raw.githubusercontent.com/kestra-io/plugin-kubernetes/main/src/main/java/io/kestra/plugin/kubernetes/kubectl/Apply.java), [Kestra Restart](https://raw.githubusercontent.com/kestra-io/plugin-kubernetes/main/src/main/java/io/kestra/plugin/kubernetes/kubectl/Restart.java) | Route-only patching cannot remediate BuildConfigs, DeploymentConfigs, or other discovered custom resources. | Reuse `apply_manifest`, `patch_resource`, `restart_workload`; record: action outcome; cursor: n/a; write; idempotency: key; OpenShift GVK allowlists, SCC/Route secret redaction, resourceVersion and approval gates. | should | 3 |

ICUHUB differentiator: ICUHUB provides native SCC assessment and guarded update, Route assessment and TLS update, BuildConfig instantiation with outcome-unknown handling, multi-source audit checkpoints, closure-safe incremental/full policy findings, and explicit OpenShift version, managed-audit, mutable-tag, and private-CA handling in one contract.

### 5.3 Prisma Cloud CSPM

#### Coverage matrix

| Object or operation | XSOAR | EL | ICUHUB |
|---|---|---|---|
| V2 alert polling, detail, dismiss, and reopen | Y | P | Y |
| Alert snooze | P | N | Y |
| Alert remediation and command preview | Y | N | P |
| CSPM management audit log | P | Y | N |
| Resource, event, and network RQL search | Y | P | N |
| Resource-level misconfiguration scan info | P | Y | P |
| Full vulnerability search and download | P | Y | P |
| Resource get and resource-list reads | Y | P | N |
| Unified asset details and relationships | Y | P | N |
| Cloud accounts, status, and owners | Y | N | N |
| Users, roles, and permission queries | Y | N | N |
| External host findings | Y | N | N |
| Access-key metadata and lifecycle | Y | N | N |
| Code Security issues and scan trigger | Y | N | N |
| Async alert export and aggregate posture metrics | N | N | Y |

#### Gaps

| ID | Missing item | Implemented by | Why it matters | Proposed ICUHUB addition | Priority | Wave |
|---|---|---|---|---|---|---|
| GAP-PCSPM-01 | CSPM audit events | [Elastic audit input](https://raw.githubusercontent.com/elastic/integrations/main/packages/prisma_cloud/data_stream/audit/agent/stream/input.yml.hbs) | Administrative and configuration activity is essential for investigating who changed posture, policies, accounts, or credentials. | `cspm_audit_events`; OCSF 6003; cursor: time_id with overlap and event-ID dedupe; read; idempotency: none; auth: CSPM JWT with separate audit-read probe. | must | 2 |
| GAP-PCSPM-02 | Resource inventory and misconfiguration | [XSOAR requests](https://raw.githubusercontent.com/demisto/content/master/Packs/PrismaCloud/Integrations/PrismaCloudV2/PrismaCloudV2.py), [Elastic misconfiguration input](https://raw.githubusercontent.com/elastic/integrations/main/packages/prisma_cloud/data_stream/misconfiguration/agent/stream/cel.yml.hbs) | Alerts are filtered findings, not a complete asset and configuration inventory. Resource-level evidence supports relationship mapping and posture reconciliation. | `cspm_resources_snapshot`, `cspm_resource_misconfigurations_snapshot`, `get_resource`, `list_resources`; records: Resource and OCSF 2003; cursor: snapshot and pageToken; read; idempotency: none. | must | 2 |
| GAP-PCSPM-03 | Full vulnerability export | [Elastic vulnerability input](https://raw.githubusercontent.com/elastic/integrations/main/packages/prisma_cloud/data_stream/vulnerability/agent/stream/cel.yml.hbs) | Alert-only ingestion can omit vulnerabilities without a matching alert policy or current alert. | `cspm_vulnerability_export`; OCSF 2002; cursor: snapshot with download digest and row identity; read; idempotency: none; handle expiry and full completeness. | must | 2 |
| GAP-PCSPM-04 | RQL investigation reads | [XSOAR request code](https://raw.githubusercontent.com/demisto/content/master/Packs/PrismaCloud/Integrations/PrismaCloudV2/PrismaCloudV2.py) | Analysts and automated triage need ad hoc blast-radius, network-path, and cloud-event queries, not only predetermined streams. | `search_config`, `search_event`, `search_network`; record: query result; cursor: pageToken; read; idempotency: none; auth: read-only CSPM scopes; bound query, time, and page inputs. | should | 2 |
| GAP-PCSPM-05 | Unified asset context | [XSOAR asset request and dispatcher](https://raw.githubusercontent.com/demisto/content/master/Packs/PrismaCloud/Integrations/PrismaCloudV2/PrismaCloudV2.py) | Relationships and network context turn an isolated alert into an attack-path and ownership investigation. | `get_asset`, `get_asset_findings`, `get_asset_relationships`, `get_asset_network`, optional `cspm_asset_relationships_snapshot`; records: Asset and relationship edge; cursor: pageToken and snapshot; read; idempotency: none. | should | 2 |
| GAP-PCSPM-06 | Cloud-account discovery and health | [XSOAR request code](https://raw.githubusercontent.com/demisto/content/master/Packs/PrismaCloud/Integrations/PrismaCloudV2/PrismaCloudV2.py) | Account scope determines whether sync is complete and who owns remediation. Empty results can otherwise hide unmonitored accounts. | `cspm_accounts_snapshot`, `get_account_status`, `list_account_owners`; records: Target and Account; cursor: snapshot; read; idempotency: none; drive target discovery and `not_evaluated` health. | must | 2 |
| GAP-PCSPM-07 | External host findings | [XSOAR request code](https://raw.githubusercontent.com/demisto/content/master/Packs/PrismaCloud/Integrations/PrismaCloudV2/PrismaCloudV2.py) | GuardDuty, Inspector, CIS, and host-CVE evidence may not fit the current alert mapping. | `cspm_external_host_findings`; OCSF 2002 for CVE, 2003 for compliance, and 2004 for detection only by explicit type; cursor: snapshot; read; idempotency: none. | should | 2 |
| GAP-PCSPM-08 | Users, roles, and effective permissions | [XSOAR request code](https://raw.githubusercontent.com/demisto/content/master/Packs/PrismaCloud/Integrations/PrismaCloudV2/PrismaCloudV2.py) | IAM excess and alert ownership are core cloud posture context. | `cspm_identities_snapshot`, `list_permissions`; records: identity and permission; cursor: snapshot and pageToken; read; idempotency: none; auth: separate privileged IAM-read probe. | should | 3 |
| GAP-PCSPM-09 | Access-key inventory | [XSOAR request code](https://raw.githubusercontent.com/demisto/content/master/Packs/PrismaCloud/Integrations/PrismaCloudV2/PrismaCloudV2.py) | Stale, excessive, or disabled-but-present keys are credential risks. Metadata review is useful without automating credential creation. | `cspm_access_keys_snapshot`, `list_access_keys`; record: access-key metadata; cursor: snapshot; read; idempotency: none; exclude secret material. | should | 3 |
| GAP-PCSPM-10 | Access-key lifecycle actions | [XSOAR request code](https://raw.githubusercontent.com/demisto/content/master/Packs/PrismaCloud/Integrations/PrismaCloudV2/PrismaCloudV2.py) | Break-glass revocation can contain compromise. Creation and deletion are high impact and are not required for ingestion. | `set_access_key_enabled` write and `create_access_key`, `delete_access_key` destructive; record: action outcome; cursor: n/a; idempotency: key; current-state precondition, disabled by default, one-time secret handling, and explicit approval. | could | 4 |
| GAP-PCSPM-11 | Code Security issues and scan trigger | [XSOAR request code](https://raw.githubusercontent.com/demisto/content/master/Packs/PrismaCloud/Integrations/PrismaCloudV2/PrismaCloudV2.py) | IaC, secrets, licenses, and code vulnerabilities are distinct from cloud-resource alerts and valuable to a DevSecOps hub. | Separate `code_security` profile: `code_issues_snapshot` with OCSF 2002/2003/2004 by type, cursor: snapshot, read, idempotency: none; `trigger_integration_scan`, record: action outcome, cursor: n/a, write, idempotency: key, with integration-state reconciliation. | could | 3 |
| GAP-PCSPM-12 | Remediation preview | [XSOAR dispatcher](https://raw.githubusercontent.com/demisto/content/master/Packs/PrismaCloud/Integrations/PrismaCloudV2/PrismaCloudV2.py) | The remediation command is the safest available precondition for an irreversible cloud change. | `get_alert_remediation`; record: remediation command; cursor: n/a; read; idempotency: none. Require its command/diff in existing `remediate_alert` write plans with idempotency: key and alert status/policy preconditions. | must | 2 |

ICUHUB differentiator: ICUHUB adds async alert export submission, polling, and download; distinct aggregate compliance posture metrics; first-class snooze and plan/apply remediation; complete-snapshot closure; explicit OCSF configuration, vulnerability, and detection separation; and per-endpoint rate-budget and export-job semantics.

### 5.4 Prisma Cloud Compute

#### Coverage matrix

| Object or operation | XSOAR | EL | DD | ICUHUB |
|---|---|---|---|---|
| Image vulnerabilities and compliance | Y | N | Y | Y |
| Host vulnerabilities and compliance | Y | Y | P | Y |
| Registry image read and on-demand scan | P | N | N | Y |
| Container vulnerability scan results | Y | N | P | P |
| CI scan results | Y | N | P | N |
| Runtime incidents | Y | Y | N | Y |
| Runtime container and host audit events | Y | P | N | P |
| WAAS/firewall and file-integrity events | Y | N | N | N |
| Host runtime profiles | Y | Y | N | N |
| Container profiles and container/host forensics | Y | N | N | N |
| CVE details and impacted resources | Y | N | P | N |
| Defenders, settings, and Defender logs | Y | N | N | N |
| Policies, feeds, alert profiles, namespaces, and backups | Y | N | N | N |
| Syslog/TCP/UDP push inputs | N | P | N | N |
| Offline JSON/CSV import | N | N | Y | N |

#### Gaps

| ID | Missing item | Implemented by | Why it matters | Proposed ICUHUB addition | Priority | Wave |
|---|---|---|---|---|---|---|
| GAP-PCCOMP-01 | Container vulnerabilities | [XSOAR Compute dispatcher](https://raw.githubusercontent.com/demisto/content/master/Packs/PrismaCloudCompute/Integrations/PaloAltoNetworks_PrismaCloudCompute/PaloAltoNetworks_PrismaCloudCompute.py) | Running containers have distinct CVE and compliance exposure from stored images and hosts. | `compute_container_vulnerabilities`; OCSF 2002; cursor: snapshot by Console, project, collection, container, CVE, and package; read; idempotency: none; include complete acknowledgment-state reads. | must | 2 |
| GAP-PCCOMP-02 | CI scan results | [XSOAR Compute requests](https://raw.githubusercontent.com/demisto/content/master/Packs/PrismaCloudCompute/Integrations/PaloAltoNetworks_PrismaCloudCompute/PaloAltoNetworks_PrismaCloudCompute.py), [DefectDojo parser](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/tools/twistlock/parser.py) | Build-time findings provide shift-left lineage and may never appear as running-image or host scans. | `compute_ci_scans_snapshot`, `compute_ci_vulnerabilities`, `compute_ci_compliance`; records: scan run, OCSF 2002, and OCSF 2003; cursor: snapshot; read; idempotency: none; retain build, job, and image identity. | should | 2 |
| GAP-PCCOMP-03 | Runtime container and host audits | [XSOAR Compute dispatcher](https://raw.githubusercontent.com/demisto/content/master/Packs/PrismaCloudCompute/Integrations/PaloAltoNetworks_PrismaCloudCompute/PaloAltoNetworks_PrismaCloudCompute.py) | Process, network, and runtime-defense events are detections, not interchangeable with the incident summary stream. | `compute_runtime_container_audits`, `compute_runtime_host_audits`; OCSF 2004; cursor: time_id plus audit ID and acknowledgment-state partitioning; read; idempotency: none. | must | 2 |
| GAP-PCCOMP-04 | WAAS and firewall alerts | [XSOAR request code](https://raw.githubusercontent.com/demisto/content/master/Packs/PrismaCloudCompute/Integrations/PaloAltoNetworks_PrismaCloudCompute/PaloAltoNetworks_PrismaCloudCompute.py) | Web-layer attacks are a major Compute detection class currently absent from ICUHUB. | `compute_waas_alerts`; OCSF 2004; cursor: time_id plus stable audit ID; read; idempotency: none; auth: runtime/WAAS read permission; support image, time, limit, and audit-type filters. | must | 2 |
| GAP-PCCOMP-05 | File-integrity events | [XSOAR request code](https://raw.githubusercontent.com/demisto/content/master/Packs/PrismaCloudCompute/Integrations/PaloAltoNetworks_PrismaCloudCompute/PaloAltoNetworks_PrismaCloudCompute.py) | Unauthorized binary and configuration changes are high-value runtime evidence. | `compute_file_integrity_events`; OCSF 2004; cursor: host, time, and event ID; read; idempotency: none; bound message and path evidence. | should | 2 |
| GAP-PCCOMP-06 | Incident acknowledgment | [XSOAR request code](https://raw.githubusercontent.com/demisto/content/master/Packs/PrismaCloudCompute/Integrations/PaloAltoNetworks_PrismaCloudCompute/PaloAltoNetworks_PrismaCloudCompute.py) | A security hub needs triage-state synchronization, not only read-only incidents and collection administration. | `acknowledge_incident`, `unacknowledge_incident`; record: action outcome; cursor: n/a; write; idempotency: natural_key; key on incident ID and target state with current-state precondition and read-back. | must | 2 |
| GAP-PCCOMP-07 | CVE intelligence and blast radius | [XSOAR Compute client](https://raw.githubusercontent.com/demisto/content/master/Packs/PrismaCloudCompute/Integrations/PaloAltoNetworks_PrismaCloudCompute/PaloAltoNetworks_PrismaCloudCompute.py) | Analysts need every affected image and host for a CVE plus vendor context independent of one scan snapshot. | `get_cve`, `list_cve_impacted_resources`, optional `compute_cve_impact_snapshot`; records: CVE and impact edge; cursor: pageToken and snapshot; read; idempotency: none. | should | 2 |
| GAP-PCCOMP-08 | Runtime profiles and forensics | [XSOAR client](https://raw.githubusercontent.com/demisto/content/master/Packs/PrismaCloudCompute/Integrations/PaloAltoNetworks_PrismaCloudCompute/PaloAltoNetworks_PrismaCloudCompute.py), [Elastic host-profile input](https://raw.githubusercontent.com/elastic/integrations/main/packages/prisma_cloud/data_stream/host_profile/agent/stream/input.yml.hbs) | Learned process, port, SSH, and runtime behavior supplies baselines and forensic context behind an incident. | `compute_host_profiles`, `compute_container_profiles`, `get_container_forensics`, `get_host_forensics`; records: runtime profile and forensic record; cursor: snapshot and pageToken; read; idempotency: none. | should | 3 |
| GAP-PCCOMP-09 | Defender health and logs | [XSOAR request code](https://raw.githubusercontent.com/demisto/content/master/Packs/PrismaCloudCompute/Integrations/PaloAltoNetworks_PrismaCloudCompute/PaloAltoNetworks_PrismaCloudCompute.py) | Missing or stale Defenders create coverage blind spots that a clean API response cannot reveal. | `compute_defenders_snapshot`, `get_defender_settings`, `get_defender_logs`, `download_defender_logs`; records: Defender health and log; cursor: snapshot and pageToken; read; idempotency: none; enforce size and redaction limits. | should | 3 |
| GAP-PCCOMP-10 | Console version operation | [XSOAR Compute dispatcher](https://raw.githubusercontent.com/demisto/content/master/Packs/PrismaCloudCompute/Integrations/PaloAltoNetworks_PrismaCloudCompute/PaloAltoNetworks_PrismaCloudCompute.py) | Compute paths embed Console version, making version discovery central to contract health and fixture selection. | `get_console_version`; record: health metadata; cursor: n/a; read; idempotency: none; auth: existing Compute auth unless the vendor explicitly permits unauthenticated access. | should | 2 |
| GAP-PCCOMP-11 | Runtime policy reads | [XSOAR Compute dispatcher](https://raw.githubusercontent.com/demisto/content/master/Packs/PrismaCloudCompute/Integrations/PaloAltoNetworks_PrismaCloudCompute/PaloAltoNetworks_PrismaCloudCompute.py) | Detection findings need the policy and rule version that produced them, and policy drift must be visible. | `compute_runtime_policies_snapshot`; record: runtime policy; cursor: snapshot; read; idempotency: none; auth: read-only runtime-policy permission; retain owner, modified, and rule identity. | should | 3 |
| GAP-PCCOMP-12 | WAAS policy read and update | [XSOAR request code](https://raw.githubusercontent.com/demisto/content/master/Packs/PrismaCloudCompute/Integrations/PaloAltoNetworks_PrismaCloudCompute/PaloAltoNetworks_PrismaCloudCompute.py) | WAAS alert triage often requires rule correction or emergency blocking. | `compute_waas_policies_snapshot`, cursor: snapshot, read, idempotency: none; `update_waas_policy`, record: action outcome, cursor: n/a, destructive, idempotency: key, with full-policy revision precondition, redacted diff, approval, and read-back. | should | 3 |
| GAP-PCCOMP-13 | Trusted-image rules | [XSOAR request code](https://raw.githubusercontent.com/demisto/content/master/Packs/PrismaCloudCompute/Integrations/PaloAltoNetworks_PrismaCloudCompute/PaloAltoNetworks_PrismaCloudCompute.py) | Trust rules directly change image admission and scanning security and require auditable drift and controlled remediation. | `compute_trusted_images_snapshot`, record: trust policy, cursor: snapshot, read, idempotency: none; `update_trusted_images`, record: action outcome, cursor: n/a, destructive, idempotency: key, with document-hash precondition and impact plan. | should | 3 |
| GAP-PCCOMP-14 | Custom IP and malware feeds | [XSOAR Compute dispatcher](https://raw.githubusercontent.com/demisto/content/master/Packs/PrismaCloudCompute/Integrations/PaloAltoNetworks_PrismaCloudCompute/PaloAltoNetworks_PrismaCloudCompute.py) | Threat-intelligence feeds drive runtime blocking and detection, so drift and emergency IOC updates matter to a response hub. | `compute_custom_feeds_snapshot`, record: feed configuration, cursor: snapshot, read, idempotency: none; `replace_custom_ip_feeds`, `replace_custom_malware_feeds`, record: action outcome, cursor: n/a, destructive, idempotency: key, with full-list precondition, validation, approval, and read-back. | could | 3 |
| GAP-PCCOMP-15 | Alert profiles | [XSOAR request code](https://raw.githubusercontent.com/demisto/content/master/Packs/PrismaCloudCompute/Integrations/PaloAltoNetworks_PrismaCloudCompute/PaloAltoNetworks_PrismaCloudCompute.py) | The profile is the prerequisite for reliable provider push configuration and destination-specific verification. | `compute_alert_profiles_snapshot`, `get_alert_profile`; record: alert profile; cursor: snapshot and pageToken; read; idempotency: none; defer writes until delivery verification contracts are proven. | could | 3 |
| GAP-PCCOMP-16 | Syslog/TCP/UDP profile ingestion | [Elastic host stream catalog](https://github.com/elastic/integrations/tree/main/packages/prisma_cloud/data_stream/host/agent/stream), [Elastic host-profile stream catalog](https://github.com/elastic/integrations/tree/main/packages/prisma_cloud/data_stream/host_profile/agent/stream) | Push reduces polling lag for runtime evidence where a supported provider contract exists. | Optional `compute_syslog`; record: host/profile event; cursor: delivery dedupe plus authoritative API reconciliation; read; idempotency: none; auth: TLS and source allowlist; define message framing. | could | 3 |
| GAP-PCCOMP-17 | Offline Twistlock JSON/CSV import | [DefectDojo parser](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/tools/twistlock/parser.py) | Disconnected Consoles, CI artifacts, and historical evidence cannot always be reached through live API sync. | `compute_scan_file_import`; OCSF 2002/2003; cursor: file/replay offset; read; idempotency: none; detect JSON/CSV, version fixtures, declare snapshot completeness, and reuse Compute mappers. | could | 3 |
| GAP-PCCOMP-18 | Radar namespaces | [XSOAR Compute client](https://raw.githubusercontent.com/demisto/content/master/Packs/PrismaCloudCompute/Integrations/PaloAltoNetworks_PrismaCloudCompute/PaloAltoNetworks_PrismaCloudCompute.py) | Namespace inventory improves collection scoping and detects uncovered cluster segments. | `compute_namespaces_snapshot`; record: inventory; cursor: snapshot keyed by Console, project, cluster, and namespace; read; idempotency: none. | could | 3 |
| GAP-PCCOMP-19 | Backup inventory | [XSOAR request code](https://raw.githubusercontent.com/demisto/content/master/Packs/PrismaCloudCompute/Integrations/PaloAltoNetworks_PrismaCloudCompute/PaloAltoNetworks_PrismaCloudCompute.py) | Backup presence and age affect recoverability after Console compromise or failure. | `compute_backups_snapshot`; record: operational inventory; cursor: snapshot; read; idempotency: none; exclude backup contents and secrets. | could | 4 |

ICUHUB differentiator: ICUHUB combines registry-scan submission with warning and result reconciliation, collection plan/apply including impact-planned destructive deletion, explicit snapshot completeness by Console, project, collection, asset type, and acknowledgment state, and one OCSF 2002/2003/2004 mapping contract with typed plan hashes, preconditions, and outcome-unknown handling.
## 6. Application security testing

This section compares the ICUHUB connector specifications with inspected DefectDojo file parsers, Faraday report plugins, and the Port Ocean Mend integration. Matrix values are `yes`, `partial`, and `no`; `no` means absent from the inspected artifact, not absent from the vendor API. DefectDojo's Pro-audience Fortify, Acunetix 360, and Mend connector references are documentation only and are not counted as open-source implementations. Source licenses are DefectDojo BSD-3-Clause, Faraday GPL-3.0, and Port Ocean Apache-2.0.

### 6.1 Fortify Software Security Center

#### Coverage matrix

| Object or operation | DefectDojo | Faraday | ICUHUB |
|---|---|---|---|
| Live issues, delta export, artifacts, and activity | no | no | yes |
| Revision-checked triage and comments | no | no | yes |
| FPR upload/download and artifact lifecycle | no | no | yes |
| Offline FPR SAST findings | yes | yes | no |
| Standalone Fortify XML across versions | yes | no | no |
| Embedded WebInspect DAST evidence | partial | yes | no |
| FPR suppression and threaded comments | yes | partial | no |
| Explicit FPR line-location semantics | yes | no | no |
| Signed webhooks and reconciliation | no | no | yes |

#### Gaps

| ID | Missing item | Implemented by | Why it matters | Proposed ICUHUB addition | Priority | Wave |
|---|---|---|---|---|---|---|
| GAP-SSC-01 | Offline FPR finding ingestion | [DefectDojo FPR](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/tools/fortify/fpr_parser.py), [Faraday Fortify](https://raw.githubusercontent.com/infobyte/faraday_plugins/master/faraday_plugins/plugins/repo/fortify/plugin.py) | Historical and CI-produced FPRs can predate or outlive SSC access. Direct parsing preserves findings, suppression, comments, and evidence during migration or outage. | `fpr_issues` OCSF 2002 plus `parse_fpr`; artifact SHA-256 `snapshot` cursor; read; idempotency none; local-file auth. | must | 2 |
| GAP-SSC-02 | Versioned Fortify XML and WebInspect ingestion | [DefectDojo XML](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/tools/fortify/xml_parser.py), [Faraday Fortify](https://raw.githubusercontent.com/infobyte/faraday_plugins/master/faraday_plugins/plugins/repo/fortify/plugin.py) | Version sniffing avoids silent zero-finding imports, while WebInspect profiles retain DAST sessions and HTTP proof that SAST-only parsing loses. | `report_issues` OCSF 2002 with Fortify and WebInspect profiles; report-hash `snapshot` cursor; read; idempotency none; local-file auth. | must | 2 |
| GAP-SSC-03 | Stable FPR line-location semantics | [DefectDojo implementation](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/tools/fortify/fpr_parser.py), [format note](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/docs/content/supported_tools/parsers/file/fortify.md) | Snippet-start and source-location lines can differ. Changing modes without versioning splits finding identity and destroys triage continuity. | `fpr_location_semantics` on `fpr_issues` OCSF 2002, included in parser/fingerprint versions; artifact `snapshot` cursor; read; idempotency none; local-file auth. | should | 2 |

ICUHUB differentiator: Signed SSC webhooks, delta-export checkpoints, live activity/artifact streams, revision-preconditioned triage, reconciled FPR upload, webhook provisioning, and guarded purges exceed the compared file-only parsers.

### 6.2 Fortify on Demand

#### Coverage matrix

| Object or operation | DefectDojo | Faraday | ICUHUB |
|---|---|---|---|
| OAuth release issues, scan history, and exports | no | no | yes |
| Bulk audit, scan control/import, and reports | no | no | yes |
| Regional hosts and multiple OAuth grants | no | no | yes |
| Offline FPR SAST findings | yes | yes | no |
| Offline Fortify/WebInspect XML | yes | partial | no |
| FPR suppression and threaded comments | yes | partial | no |
| Explicit FPR line semantics | yes | no | no |
| Polling-only reconciliation | no | no | yes |

#### Gaps

| ID | Missing item | Implemented by | Why it matters | Proposed ICUHUB addition | Priority | Wave |
|---|---|---|---|---|---|---|
| GAP-FOD-01 | FoD-exported FPR replay with audit state | [DefectDojo](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/tools/fortify/fpr_parser.py), [Faraday](https://raw.githubusercontent.com/infobyte/faraday_plugins/master/faraday_plugins/plugins/repo/fortify/plugin.py) | Portable FPRs support backfill, tenant migration, and recovery when live deltas or asynchronous repository states are inconsistent. | `fpr_issues` OCSF 2002 plus `parse_fpr`; release plus artifact SHA-256 `snapshot` cursor; read; idempotency none; local-file auth or existing `view-issues` for download. | should | 2 |
| GAP-FOD-02 | Fortify XML/WebInspect replay and location mode | [DefectDojo XML](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/tools/fortify/xml_parser.py), [DefectDojo line modes](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/tools/fortify/fpr_parser.py), [Faraday](https://raw.githubusercontent.com/infobyte/faraday_plugins/master/faraday_plugins/plugins/repo/fortify/plugin.py) | DAST replay needs request/response and session context, and deterministic locations are required for cross-scan identity. | `fortify_xml` and `webinspect_xml` profiles on `report_issues` OCSF 2002 plus location mode; report-hash `snapshot` cursor; read; idempotency none; local-file auth. | could | 2 |

ICUHUB differentiator: FoD OAuth release synchronization, overlapping delta reconciliation, scan history, asynchronous exports, bulk audit, guarded scan operations, report lifecycle, and regional OAuth handling are absent from the compared file parsers.

### 6.3 Invicti Enterprise

#### Coverage matrix

| Object or operation | DefectDojo | Faraday | ICUHUB |
|---|---|---|---|
| Live issues, scans, results, and history | no | no | yes |
| Active scan lifecycle | no | no | yes |
| Website, agent, and notification management | no | no | yes |
| Authenticated issue-export webhook | no | no | yes |
| Invicti/Netsparker JSON | yes | no | partial |
| Invicti Enterprise XML | no | yes | no |
| Netsparker desktop/cloud XML | no | yes | no |
| Acunetix XML and JSON families | yes | yes | no |
| Accepted-risk and false-positive mapping | yes | no | no |
| Verification, proof, and classification fields | partial | yes | partial |
| Multiple locations and HTTP evidence per issue | yes | partial | no |

#### Gaps

| ID | Missing item | Implemented by | Why it matters | Proposed ICUHUB addition | Priority | Wave |
|---|---|---|---|---|---|---|
| GAP-IE-01 | Offline Invicti and Netsparker XML ingestion | [Invicti](https://raw.githubusercontent.com/infobyte/faraday_plugins/master/faraday_plugins/plugins/repo/invicti/plugin.py), [Netsparker](https://raw.githubusercontent.com/infobyte/faraday_plugins/master/faraday_plugins/plugins/repo/netsparker/plugin.py), [Netsparker Cloud](https://raw.githubusercontent.com/infobyte/faraday_plugins/master/faraday_plugins/plugins/repo/netsparkercloud/plugin.py) | XML remains an interchange path when API quotas, retention, or tenant access block live synchronization. Separate schemas must not be forced through JSON parsing. | `report_issues` OCSF 2002 and three XML `parse_report` profiles; report/scan ID plus file-hash `snapshot` cursor; read; idempotency none; local-file auth. | should | 3 |
| GAP-IE-02 | Acunetix legacy and current format profiles | [DefectDojo](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/tools/acunetix/parser.py), [Faraday 360](https://raw.githubusercontent.com/infobyte/faraday_plugins/master/faraday_plugins/plugins/repo/acunetix360/plugin.py), [Faraday export JSON](https://raw.githubusercontent.com/infobyte/faraday_plugins/master/faraday_plugins/plugins/repo/acunetix_json/plugin.py) | Acunetix exports persist in migrations and older integrations. The on-premises Standard/Premium live API is [UNVERIFIED] and must not inherit Invicti Enterprise endpoints or auth. | `acunetix_xml`, `acunetix_360_json`, and `acunetix_export_json` on `report_issues` OCSF 2002; file-hash `snapshot` cursor; read; idempotency none; local-file auth only. | should | 3 |
| GAP-IE-03 | Explicit DAST evidence, state, and classifications | [DefectDojo Netsparker](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/tools/netsparker/parser.py), [DefectDojo Acunetix](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/tools/acunetix/parse_acunetix360_json.py), [Faraday Invicti DTO](https://raw.githubusercontent.com/infobyte/faraday_plugins/master/faraday_plugins/plugins/repo/invicti/DTO.py), [Faraday Acunetix DTO](https://raw.githubusercontent.com/infobyte/faraday_plugins/master/faraday_plugins/plugins/repo/acunetix360/DTO.py) | Verification, accepted risk, false positives, proof, and compliance taxonomies drive prioritization, reproduction, governance, and safe dedupe. | Typed fields on `issues`, `scan_results`, and `report_issues` OCSF 2002; existing issue/scan cursors plus report `snapshot`; read; idempotency none; existing Basic or local-file auth. | must | 3 |
| GAP-IE-04 | One-to-many location and evidence cardinality | [DefectDojo Netsparker parser](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/tools/netsparker/parser.py) | One issue type can affect many endpoints. Title-only merging loses attack surface, while unconditional splitting destroys vendor triage identity. | `location_set` and stable `location_key` on OCSF 2002 findings; existing cursors; read; idempotency none; existing auth. | should | 3 |

ICUHUB differentiator: The live REST surface, rate-limit-aware issue windows, per-scan reconciliation, issue updates, active scan orchestration, management writes, and authenticated configurable issue-export webhooks exceed the compared upload-only parsers.

### 6.4 Invicti Standard

#### Coverage matrix

| Object or operation | DefectDojo | Faraday | ICUHUB |
|---|---|---|---|
| Invicti/Netsparker JSON report | yes | no | yes |
| Authenticated Send To Actions webhook | no | no | yes |
| Standard/Netsparker desktop XML | no | yes | no |
| Acunetix XML | yes | yes | no |
| Acunetix 360 and export JSON | partial | yes | no |
| Accepted-risk and false-positive state | yes | no | no |
| Verification, proof, and classifications | partial | yes | no |
| Multiple locations per repeated issue | yes | partial | no |
| Remote Enterprise scan actions | no | no | no |

#### Gaps

| ID | Missing item | Implemented by | Why it matters | Proposed ICUHUB addition | Priority | Wave |
|---|---|---|---|---|---|---|
| GAP-IS-01 | Standard and Netsparker XML parsing | [Invicti](https://raw.githubusercontent.com/infobyte/faraday_plugins/master/faraday_plugins/plugins/repo/invicti/plugin.py), [Netsparker](https://raw.githubusercontent.com/infobyte/faraday_plugins/master/faraday_plugins/plugins/repo/netsparker/plugin.py) | Desktop users and historical archives are not uniformly JSON. Native Standard reports should not require an Enterprise tenant. | `invicti_standard_xml` and `netsparker_desktop_xml` on `parse_report`/`report_issues` OCSF 2002; report hash plus scan/report ID `snapshot` cursor; read; idempotency none; local-file auth. | must | 3 |
| GAP-IS-02 | Acunetix XML and both JSON schemas | [DefectDojo Acunetix](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/tools/acunetix/parser.py), [Faraday Acunetix XML](https://raw.githubusercontent.com/infobyte/faraday_plugins/master/faraday_plugins/plugins/repo/acunetix/plugin.py), [Faraday 360 JSON](https://raw.githubusercontent.com/infobyte/faraday_plugins/master/faraday_plugins/plugins/repo/acunetix360/plugin.py), [Faraday export JSON](https://raw.githubusercontent.com/infobyte/faraday_plugins/master/faraday_plugins/plugins/repo/acunetix_json/plugin.py) | The JSON layouts have different roots and vulnerability-type resolution. One schema assumption silently rejects valid exports. | Three Acunetix profiles on `report_issues` OCSF 2002 with schema-specific parser versions; file-hash `snapshot` cursor; read; idempotency none; local-file auth only. | should | 3 |
| GAP-IS-03 | State, verification, evidence, and compliance mappings | [DefectDojo](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/tools/acunetix/parse_acunetix360_json.py), [Faraday DTO](https://raw.githubusercontent.com/infobyte/faraday_plugins/master/faraday_plugins/plugins/repo/acunetix360/DTO.py) | Without these fields, file and webhook records cannot reproduce scanner triage or proof and cannot support compliance workflows. | Typed fields on `report_issues` and `webhook_issues` OCSF 2002; report `snapshot` and webhook `delivery_id` cursors; read; idempotency none; local-file or existing webhook-secret auth. | must | 3 |
| GAP-IS-04 | Location-preserving dedupe | [DefectDojo Netsparker parser](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/tools/netsparker/parser.py) | Configurable reports can omit stable issue IDs, making title-only dedupe especially destructive. | `location_set`, `location_key`, and per-location evidence on OCSF 2002; existing report/webhook cursors; read; idempotency none; existing auth. | should | 3 |

ICUHUB differentiator: Authenticated Send To Actions, configuration-revision replay handling, static-header/Basic verification, full-snapshot closure protection, and deliberate isolation from Enterprise scan actions exceed the compared file parsers.

### 6.5 Mend SCA

#### Coverage matrix

| Object or operation | DefectDojo | Port Ocean | ICUHUB |
|---|---|---|---|
| API 3.0 security findings | partial | yes | yes |
| API 2.0 security/legal alerts | no | no | yes |
| Legal violations, libraries, and activity | partial | no | yes |
| Project summaries and severity rollups | no | yes | no |
| Reachability, exploitability, and suppression | partial | yes | no |
| Source locations, KEV, and fix enrichment | yes | partial | no |
| Offline Unified Agent/manual/API JSON | yes | no | no |
| Activation-key bundle and regional host derivation | no | yes | no |
| Email/user-key/org JWT login | no | yes | yes |
| Forced full reconciliation | no | yes | yes |
| Finding/project relationship | no | yes | partial |
| Triage, policy, SBOM, reports, and lifecycle writes | no | no | yes |

#### Gaps

| ID | Missing item | Implemented by | Why it matters | Proposed ICUHUB addition | Priority | Wave |
|---|---|---|---|---|---|---|
| GAP-MEND-01 | Project summaries and rollup metrics | [Port project exporter](https://raw.githubusercontent.com/port-labs/ocean/main/integrations/mend/mend/core/exporters/project_exporter.py), [Port mapping](https://raw.githubusercontent.com/port-labs/ocean/main/integrations/mend/.port/resources/port-app-config.yml) | Parent inventory relates findings to applications and distinguishes zero findings from stale or never-scanned projects. Rollups avoid repeated aggregation over every finding. | `projects` `ProjectRecord` with non-finding metrics plus `get_project_summary`; `snapshot` cursor; read; idempotency none; existing org JWT auth. | must | 2 |
| GAP-MEND-02 | Modern exploitability, reachability, and suppression fields | [Port blueprints](https://raw.githubusercontent.com/port-labs/ocean/main/integrations/mend/.port/resources/blueprints.json), [Port mapping](https://raw.githubusercontent.com/port-labs/ocean/main/integrations/mend/.port/resources/port-app-config.yml) | Reachability and exploitation evidence change remediation priority. Suppression metadata explains inactive findings and supports governance audit. | Typed risk, CVSS, timestamp, topFix, and suppression fields on `security_findings` OCSF 2002; existing incremental cursor; read; idempotency none; existing API 3.0 JWT auth. | must | 2 |
| GAP-MEND-03 | Offline Mend/WhiteSource JSON parser | [DefectDojo parser](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/tools/mend/parser.py), [format documentation](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/docs/content/supported_tools/parsers/file/mend.md) | CI reports and historical WhiteSource exports remain valuable when a tenant is inaccessible or ingestion has not occurred. | `report_findings` OCSF 2002 plus `parse_report` for four schemas; report SHA-256 plus project `snapshot` cursor; read; idempotency none; local-file auth. | must | 2 |
| GAP-MEND-04 | Source location and component-risk enrichment | [DefectDojo Mend parser](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/tools/mend/parser.py) | Dependency paths and source files locate remediation, while KEV, exploit, and fix metadata distinguish actionable exposure from theoretical risk. | Source, location, component, KEV, exploit, fix, and CVSS fields on `security_findings`/`report_findings` OCSF 2002; existing incremental and report `snapshot` cursors; read; idempotency none; existing JWT or local-file auth. | should | 2 |
| GAP-MEND-05 | Activation-key auth/configuration mode | [Port activation key](https://raw.githubusercontent.com/port-labs/ocean/main/integrations/mend/mend/auth/activation_key.py), [Port client initialization](https://raw.githubusercontent.com/port-labs/ocean/main/integrations/mend/mend/auth/authenticator.py) | A vendor-issued bundle reduces onboarding and regional-host mistakes. The activation-key item is an onboarding addition, not a correction, because ICUHUB already accepts the separate credentials and hosts. | `mend_activation_key` `SecretRef` applied to OCSF 2002 `security_findings`; existing cursors; read; idempotency none; decode in memory and derive existing JWT login without logging secrets. | should | 2 |

ICUHUB differentiator: Dual API 2.0/3.0 support, legal and library surfaces, activity, triage and policy writes, SBOM import, asynchronous reports, permission probes, lifecycle actions, and fail-closed permission handling exceed the compared parser and read-only resync.

## 7. Vulnerability management

This section compares ICUHUB with inspected XSOAR, StackStorm, DefectDojo, Faraday, Elastic, and Cortex artifacts. Matrix values are `yes`, `partial`, and `no`; file parsing is not represented as live API synchronization, and `no` is not a claim about the vendor API. Source/license key: XSOAR content is MIT; DefectDojo parsers are BSD-3-Clause; Faraday plugins are GPL-3.0; the StackStorm Qualys pack is Apache-2.0; Elastic `tenable_io` is Elastic License 2.0 and therefore ideas-only for ICUHUB; the Cortex Nessus analyzer is AGPL-3.0.

### 7.1 Qualys (VMDR, WAS, CSAM)

#### Coverage matrix

| Object or operation | XSOAR | StackStorm | DefectDojo | Faraday | Elastic | ICUHUB |
|---|---|---|---|---|---|---|
| VMDR live host detections | yes | no | no | no | yes | yes |
| Offline VMDR/WAS report ingestion | no | no | yes | yes | partial | no |
| KnowledgeBase/QID and CVE cross-reference | yes | no | partial | partial | yes | partial |
| WAS live QPS findings | no | no | no | no | yes | yes |
| CSAM asset search/count | no | no | no | no | yes | yes |
| User activity events | yes | no | no | no | yes | no |
| VM/PC/SCAP scan metadata and results | yes | partial | partial | partial | no | no |
| Scan freshness query | no | yes | no | no | no | no |
| VM/PC scan lifecycle | yes | partial | no | no | no | no |
| Scan schedules | yes | no | no | no | no | no |
| Report/templates catalog and download | yes | partial | no | no | no | no |
| Report generation and lifecycle | yes | no | no | no | no | no |
| Host/IP and asset-group administration | yes | partial | no | no | no | no |
| Asset tags | yes | no | no | no | no | no |
| Authentication records and virtualization mappings | yes | no | no | no | no | no |

#### Gaps

| ID | Missing item | Implemented by | Why it matters | Proposed ICUHUB addition | Priority | Wave |
|---|---|---|---|---|---|---|
| GAP-QUALYS-01 | VMDR/PC/SCAP scan and result metadata | [XSOAR scan commands](https://raw.githubusercontent.com/demisto/content/master/Packs/qualys/Integrations/Qualysv2/Qualysv2.yml), [StackStorm list scans](https://github.com/StackStorm-Exchange/stackstorm-qualys/tree/master/actions) | Findings need scan provenance, status, option profile, targets, and compliance context. | `vmdr.scans`, `vmdr.scan_results`, `vmdr.pc_scans`, `vmdr.scap_scans` `ScanRecord`; compliance evidence OCSF 2003; `snapshot` cursor; read; idempotency none. | must | 3 |
| GAP-QUALYS-02 | Activity and audit events | [XSOAR activity-log implementation](https://raw.githubusercontent.com/demisto/content/master/Packs/qualys/Integrations/Qualysv2/Qualysv2.py) | Audit explains detection, asset, tag, scan, and triage changes. | `activity_events` OCSF 6003; time plus offset/page-token cursor with dedupe; read; idempotency none. | should | 3 |
| GAP-QUALYS-03 | Scan freshness query | [StackStorm operation](https://raw.githubusercontent.com/StackStorm-Exchange/stackstorm-qualys/master/actions/list_hosts_not_scanned_since.yaml) | Assets can silently fall outside scanning coverage even when finding ingestion is healthy. | `vmdr.list_hosts_not_scanned_since` and optional `scan_coverage` `AssetRecord`; operation cursor none or stream `snapshot`; read; idempotency none. | should | 3 |
| GAP-QUALYS-04 | VM/PC scan lifecycle | [XSOAR lifecycle commands](https://raw.githubusercontent.com/demisto/content/master/Packs/qualys/Integrations/Qualysv2/Qualysv2.yml), [StackStorm launch](https://raw.githubusercontent.com/StackStorm-Exchange/stackstorm-qualys/master/actions/launch_scan.yaml) | Controlled rescans close the loop from exposure discovery to remediation verification. | `launch_vm_scan`, `launch_pc_scan`, `pause_resume_cancel_scan` `ScanRecord` write and `delete_scan` destructive; cursor n/a; idempotency key; approved target preconditions. | should | 4 |
| GAP-QUALYS-05 | Scan schedules | [XSOAR schedule commands](https://raw.githubusercontent.com/demisto/content/master/Packs/qualys/Integrations/Qualysv2/Qualysv2.yml) | Schedule drift creates persistent coverage gaps. | `scan_schedules` `ConfigRecord`; `snapshot` read with idempotency none; create/update write with natural_key and delete destructive with key. | could | 4 |
| GAP-QUALYS-06 | Report catalog, templates, and download | [XSOAR report commands](https://raw.githubusercontent.com/demisto/content/master/Packs/qualys/Integrations/Qualysv2/Qualysv2.yml), [StackStorm report catalog](https://github.com/StackStorm-Exchange/stackstorm-qualys/tree/master/actions) | Portable reports preserve evidence and interoperate with existing compliance workflows. | `reports`/`report_templates` `ReportRecord` plus bounded download operations; `snapshot` or operation cursor none; read; idempotency none. | should | 3 |
| GAP-QUALYS-07 | Report generation and lifecycle | [XSOAR](https://raw.githubusercontent.com/demisto/content/master/Packs/qualys/Integrations/Qualysv2/Qualysv2.yml) | Typed report generation supports existing assurance processes and asynchronous evidence production. | `launch_<type>_report` `ReportRecord` write, `cancel_report` write, `delete_report` destructive; cursor n/a; idempotency key; reconcile report ID and expiry. | could | 4 |
| GAP-QUALYS-08 | Host/IP and asset-group administration | [XSOAR host/IP/group commands](https://raw.githubusercontent.com/demisto/content/master/Packs/qualys/Integrations/Qualysv2/Qualysv2.yml), [StackStorm add host](https://raw.githubusercontent.com/StackStorm-Exchange/stackstorm-qualys/master/actions/add_host.yaml) | Scan scope must stay aligned with asset inventory and ownership boundaries. | `ip_assets`, `asset_groups`, `excluded_ips`, `restricted_ips`, `virtual_hosts` `AssetRecord`/`ConfigRecord`; `snapshot` read with idempotency none; writes natural_key and purge/delete destructive key. | could | 4 |
| GAP-QUALYS-09 | Asset tags | [XSOAR tag implementation](https://raw.githubusercontent.com/demisto/content/master/Packs/qualys/Integrations/Qualysv2/Qualysv2.py) | Tags drive RBAC, scan scope, ownership, and routing, so losing them weakens downstream automation. | `asset_tags` `AssetTagRecord`; `snapshot` read with idempotency none; create/update write natural_key and delete destructive key. | should | 3 |
| GAP-QUALYS-10 | Authentication records and virtualization mappings | [XSOAR manifest](https://raw.githubusercontent.com/demisto/content/master/Packs/qualys/Integrations/Qualysv2/Qualysv2.yml) | Credentialed-scan failures otherwise look like absent vulnerabilities. | Metadata-only `authentication_records` and `vcenter_esxi_mappings` `ConfigRecord`; `snapshot` read with idempotency none; update/import write natural_key and purge destructive key; never ingest secrets. | could | 4 |
| GAP-QUALYS-11 | QID/CVE cross-reference and affected-asset query | [XSOAR commands](https://raw.githubusercontent.com/demisto/content/master/Packs/qualys/Integrations/Qualysv2/Qualysv2.yml) | Incident response often starts with a CVE and needs affected assets immediately. | `get_qids_by_cve` `VulnIntelRecord` and `get_assets_by_qid` `AssetRecord`; cursor none; read; idempotency none; existing detection scope checks. | should | 3 |
| GAP-QUALYS-12 | Offline VMDR and WAS report ingestion | [DefectDojo VMDR](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/tools/qualys/parser.py), [DefectDojo WAS](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/tools/qualys_webapp/parser.py), [Faraday VMDR](https://raw.githubusercontent.com/infobyte/faraday_plugins/master/faraday_plugins/plugins/repo/qualysguard/plugin.py), [Faraday WAS](https://raw.githubusercontent.com/infobyte/faraday_plugins/master/faraday_plugins/plugins/repo/qualyswebapp/plugin.py) | Portable reports support air-gapped evidence, migrations, and supplier findings without API credentials. | `vmdr.report_import` XML/CSV and `was.report_import` XML OCSF 2002; file-hash `snapshot` cursor; read; idempotency none; local-file auth. | could | 4 |

CSAM note: Elastic's `qualys_gav` package reads full CSAM asset snapshots paginated by `lastSeenAssetId`; its snapshot-only semantics and absence of writes are the comparison points, and no inspected implementation performs CSAM asset updates, purges, or reports.

ICUHUB differentiator: One connector joins VMDR detections, incremental KnowledgeBase, WAS QPS findings, and CSAM assets without mixing CSAM into finding identity; WAS triage has plan/apply and read-back, while CSAM adds separate hosts, sunset handling, scope-safe closure, and rate-limit health.

### 7.2 Tenable Vulnerability Management

#### Coverage matrix

| Object or operation | XSOAR | Elastic | DefectDojo | Faraday | ICUHUB |
|---|---|---|---|---|---|
| Async vulnerability export/chunks | yes | yes | no | no | yes |
| Async asset export/chunks | yes | yes | no | no | yes |
| Audit events with cursor pagination | yes | yes | no | no | no |
| Plugin catalog | no | yes | partial | partial | no |
| Scan list and details | yes | yes | no | no | no |
| Scan status and history | yes | partial | no | no | no |
| Per-scan report export | yes | no | partial | partial | no |
| Vulnerability details/by asset | yes | partial | partial | partial | partial |
| Asset details and custom attributes | yes | yes | partial | partial | partial |
| Scan filter metadata | yes | no | no | no | no |
| Scan launch/pause/resume | yes | no | no | no | no |
| Offline Nessus XML or Tenable CSV | no | no | yes | partial | no |

#### Gaps

| ID | Missing item | Implemented by | Why it matters | Proposed ICUHUB addition | Priority | Wave |
|---|---|---|---|---|---|---|
| GAP-TVM-01 | Audit events | [XSOAR audit client](https://raw.githubusercontent.com/demisto/content/master/Packs/Tenable_io/Integrations/Tenable_io/Tenable_io.py), [Elastic CEL stream](https://raw.githubusercontent.com/elastic/integrations/main/packages/tenable_io/data_stream/audit/agent/stream/cel.yml.hbs) | Audit explains asset, tag, scan, and export changes and supports compliance monitoring. | `audit_events` OCSF 6003; `time_id` plus vendor `next` cursor, overlap and event-ID dedupe; read; idempotency none. | must | 2 |
| GAP-TVM-02 | Plugin catalog | [Elastic plugin stream](https://raw.githubusercontent.com/elastic/integrations/main/packages/tenable_io/data_stream/plugin/agent/stream/cel.yml.hbs) | Central VulnIntel avoids inconsistent report glossaries and enables plugin-to-CVE/exploit queries. | `plugins` `VulnIntelRecord`; modification-time high-water mark plus page cursor; read; idempotency none. | should | 2 |
| GAP-TVM-03 | Scans, details, status, and history | [XSOAR commands](https://raw.githubusercontent.com/demisto/content/master/Packs/Tenable_io/Integrations/Tenable_io/Tenable_io.yml), [Elastic scan collector](https://raw.githubusercontent.com/elastic/integrations/main/packages/tenable_io/data_stream/scan/agent/stream/cel.yml.hbs) | Finding exports alone cannot reveal failed, running, archived, or missing scan coverage. | `scans`/`scan_runs` `ScanRecord` plus status/history/filter reads; `snapshot` or operation cursor none; read; idempotency none. | should | 2 |
| GAP-TVM-04 | Per-scan report export | [XSOAR export contract](https://raw.githubusercontent.com/demisto/content/master/Packs/Tenable_io/Integrations/Tenable_io/Tenable_io.yml) | Nessus, CSV, HTML, and PDF exports support analyst evidence and existing reporting workflows. | `create_scan_export`, `get_scan_export_status`, `download_scan_export` `EvidenceRecord`; vendor export-ID cursor; read; idempotency none; bounded evidence. | should | 3 |
| GAP-TVM-05 | Interactive asset and vulnerability reads | [XSOAR manifest](https://raw.githubusercontent.com/demisto/content/master/Packs/Tenable_io/Integrations/Tenable_io/Tenable_io.yml) | Incident investigation should not require a bulk export for one asset or vulnerability. | `get_vulnerability` OCSF 2002, `get_asset` `AssetRecord`, `list_asset_vulnerabilities` OCSF 2002; cursor none or bounded page token; read; idempotency none. | could | 3 |
| GAP-TVM-06 | Scan launch, pause, and resume | [XSOAR commands](https://raw.githubusercontent.com/demisto/content/master/Packs/Tenable_io/Integrations/Tenable_io/Tenable_io.yml) | Policy-controlled validation and remediation require on-demand rescans. | `launch_scan` and `pause_resume_scan` `ScanRecord` write; cursor n/a; idempotency key; status/target preconditions and asynchronous reconciliation. | should | 3 |
| GAP-TVM-07 | Offline report ingestion | [DefectDojo XML/CSV](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/tools/tenable/csv_format.py), [Faraday CSV](https://raw.githubusercontent.com/infobyte/faraday_plugins/master/faraday_plugins/plugins/repo/tenableio_csv/plugin.py) | Portable exports preserve state, severity, host, service, and plugin evidence for disconnected ingestion and migration. | `report_import` OCSF 2002 for Nessus XML and Tenable VM CSV; file-hash `snapshot` cursor; read; idempotency none; local-file auth. | could | 3 |

ICUHUB differentiator: Duplicate-filter 429 handling, conservative chunk expiry, out-of-order/failed chunk recovery, bounded plugin output, asset termination reconciliation, complete-scope closure, and stable finding/asset identity exceed the surveyed collectors.

### 7.3 Tenable Security Center

#### Coverage matrix

| Object or operation | XSOAR | DefectDojo | Faraday | ICUHUB |
|---|---|---|---|---|
| Cumulative/patched vulnerability analysis | yes | partial | partial | yes |
| Individual scan-result analysis | yes | partial | partial | partial |
| Analysis CSV download | partial | yes | yes | yes |
| Scans, status, reports, and results | yes | partial | partial | no |
| Repositories and zones | yes | no | no | no |
| Assets, groups, organizations, and devices | yes | partial | partial | no |
| Credential, policy, and report metadata | yes | no | no | no |
| Plugin intelligence and saved queries | yes | partial | partial | no |
| Alerts list/get | yes | no | no | partial |
| System licensing and health | yes | no | no | no |
| Scan and remediation orchestration | yes | no | no | no |
| Policy, asset, and user administration | yes | no | no | no |
| Username/password session auth | yes | no | no | no |
| Offline CSV import | no | yes | yes | no |

#### Gaps

| ID | Missing item | Implemented by | Why it matters | Proposed ICUHUB addition | Priority | Wave |
|---|---|---|---|---|---|---|
| GAP-TSC-01 | Username/password session auth | [XSOAR client](https://raw.githubusercontent.com/demisto/content/master/Packs/Tenable_sc/Integrations/Tenable_sc/Tenable_sc.py) | The confirmed token/cookie flow supports installations where API keys are not issued and resolves the auth mode ICUHUB leaves unverified. | `session` auth for OCSF 2002 analysis streams; existing cursors; read; idempotency none; broker-held credentials, single-flight refresh, one 403 retry, explicit logout. | must | 2 |
| GAP-TSC-02 | Repository, scan, and scan-result discovery | [XSOAR commands](https://raw.githubusercontent.com/demisto/content/master/Packs/Tenable_sc/Integrations/Tenable_sc/Tenable_sc.yml) | Discoverable repositories and scans are needed to scope analysis reads and detect failed imports or stale coverage. | `repositories`, `scans`, `scan_results` `RepositoryRecord`/`ScanRecord`; `snapshot` cursor; read; idempotency none. | must | 2 |
| GAP-TSC-03 | Individual analysis snapshots | [XSOAR vulnerability command](https://raw.githubusercontent.com/demisto/content/master/Packs/Tenable_sc/Integrations/Tenable_sc/Tenable_sc.yml) | Point-in-time evidence is needed for comparison with cumulative state. | `analysis_individual` OCSF 2002 keyed by repository, result, host, plugin, port/protocol; `snapshot` cursor; read; idempotency none; no cumulative absence closure. | should | 2 |
| GAP-TSC-04 | Assets, groups, organizations, zones, and devices | [XSOAR manifest](https://raw.githubusercontent.com/demisto/content/master/Packs/Tenable_sc/Integrations/Tenable_sc/Tenable_sc.yml) | Organization, group, and repository context is essential for scoped RBAC, ownership, and multi-tenant deployments. | `assets`, `groups`, `organizations`, `zones`, `devices` `AssetRecord`/`OrgRecord`; `snapshot` cursor; read; idempotency none. | should | 3 |
| GAP-TSC-05 | Plugin and saved-query intelligence | [XSOAR plugin/query commands](https://raw.githubusercontent.com/demisto/content/master/Packs/Tenable_sc/Integrations/Tenable_sc/Tenable_sc.yml) | Reusable queries and plugin metadata support investigation, reporting, and coverage explanation. | `plugin_families`, `plugins`, `saved_queries` `VulnIntelRecord`/`QueryRecord`; `snapshot` cursor; read; idempotency none. | should | 3 |
| GAP-TSC-06 | Credential, policy, and report-definition metadata | [XSOAR list commands](https://raw.githubusercontent.com/demisto/content/master/Packs/Tenable_sc/Integrations/Tenable_sc/Tenable_sc.yml) | Configuration metadata explains credentialed coverage and makes scan definitions reproducible. | `scan_policies`, `credential_metadata`, `report_definitions` `ConfigRecord`; `snapshot` cursor; read; idempotency none; exclude passwords and private keys. | should | 3 |
| GAP-TSC-07 | Get alert by ID | [XSOAR alert commands](https://raw.githubusercontent.com/demisto/content/master/Packs/Tenable_sc/Integrations/Tenable_sc/Tenable_sc.yml) | A list-only contract cannot inspect one alert for plan or incident context. | `get_alert` `AlertRecord`; cursor none; read; idempotency none; no execute/update side effect. | should | 2 |
| GAP-TSC-08 | System licensing and health | [XSOAR system commands](https://raw.githubusercontent.com/demisto/content/master/Packs/Tenable_sc/Integrations/Tenable_sc/Tenable_sc.yml) | License exhaustion and unhealthy services directly reduce vulnerability coverage. | `get_system_information` and `get_system_licensing` `HealthRecord`; cursor none; read; idempotency none; feed `check` and `not_evaluated` reasons. | should | 2 |
| GAP-TSC-09 | Scan and remediation orchestration | [XSOAR orchestration commands](https://raw.githubusercontent.com/demisto/content/master/Packs/Tenable_sc/Integrations/Tenable_sc/Tenable_sc.yml) | Controlled rescan and remediation verification require scan lifecycle operations. | `create_scan`, `create_remediation_scan`, `launch_scan` `ScanRecord` write and `delete_scan` destructive; cursor n/a; idempotency key; policy/repository/target preconditions. | should | 3 |
| GAP-TSC-10 | Policy, asset, and user administration | [XSOAR manifest](https://raw.githubusercontent.com/demisto/content/master/Packs/Tenable_sc/Integrations/Tenable_sc/Tenable_sc.yml) | Managed scanning and delegated administration need these high-privilege operations under explicit scope and approval. | Policy/asset `ConfigRecord`/`AssetRecord` writes and optional `UserRecord` administration; cursor n/a; create/update natural_key; deletes destructive key and disabled by default. | could | 4 |
| GAP-TSC-11 | Offline SC CSV ingestion | [DefectDojo CSV parser](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/tools/tenable/csv_format.py), [Faraday parser](https://raw.githubusercontent.com/infobyte/faraday_plugins/master/faraday_plugins/plugins/repo/nessus_sc/plugin.py) | Disconnected exports and historical evidence need a file ingestion path. | `analysis_report_import` OCSF 2002 with CSV column handling and explicit source type; file-hash `snapshot` cursor; read; idempotency none; local-file auth. | could | 3 |

ICUHUB differentiator: Remediation-aware cumulative/patched increments, SC 6.7 universal identity migration, side-effect-gated notification polling, explicit pagination and schema contracts, private-CA handling, and scope-safe closure exceed the surveyed artifacts.

### 7.4 Nessus

#### Coverage matrix

| Object or operation | DefectDojo | Faraday | Cortex | ICUHUB |
|---|---|---|---|---|
| `.nessus` XML findings | yes | yes | no | yes |
| Offline CSV findings | yes | partial | no | no |
| Host and service inventory | partial | yes | partial | no |
| Compliance checks as compliance violations | no | yes | no | no |
| Scan list/status polling | no | no | yes | yes |
| History enumeration and history export | no | no | no | yes |
| Direct JSON scan details/results | no | no | yes | no |
| Create and launch scan from policy | no | no | yes | no |
| Delete scan | no | no | yes | no |
| API-key auth | no | no | no | yes |
| Username/password session auth | no | no | yes | no |
| Custom CA bundle | no | no | yes | yes |
| Approved target network guard | no | no | yes | no |
| Async export and `TRUNCATED` handling | no | no | no | yes |

#### Gaps

| ID | Missing item | Implemented by | Why it matters | Proposed ICUHUB addition | Priority | Wave |
|---|---|---|---|---|---|---|
| GAP-NESSUS-01 | Compliance checks modeled as compliance | [Faraday parser](https://raw.githubusercontent.com/infobyte/faraday_plugins/master/faraday_plugins/plugins/repo/nessus/plugin.py) | Treating policy checks as ordinary CVE findings breaks posture reporting and remediation routing. | `compliance_findings` OCSF 2003 keyed by run/host/plugin/check with benchmark references and evidence; run `snapshot` cursor; read; idempotency none. | must | 2 |
| GAP-NESSUS-02 | Host and service inventory | [Faraday parser](https://raw.githubusercontent.com/infobyte/faraday_plugins/master/faraday_plugins/plugins/repo/nessus/plugin.py) | Inventory enables attack-surface and coverage correlation even where no vulnerability exists. | `host_inventory` and `service_inventory` `AssetRecord`/`ServiceRecord`; run `snapshot` cursor; read; idempotency none; shared finding AssetRefs. | should | 2 |
| GAP-NESSUS-03 | Direct scan details/results read | [Cortex analyzer](https://raw.githubusercontent.com/TheHive-Project/Cortex-Analyzers/master/analyzers/Nessus/nessus.py) | A lightweight current-state read avoids paying for a full asynchronous export for every inspection. | `get_scan_details` `ScanRecord` with bounded plugin output; cursor none; read; idempotency none; existing truncation and credential-field rules. | should | 2 |
| GAP-NESSUS-04 | Username/password session auth | [Cortex manifest](https://raw.githubusercontent.com/TheHive-Project/Cortex-Analyzers/master/analyzers/Nessus/Nessus.json), [Cortex source](https://raw.githubusercontent.com/TheHive-Project/Cortex-Analyzers/master/analyzers/Nessus/nessus.py) | This confirms a standalone Professional integration path distinct from API keys. | `username_password_session` for OCSF 2002 export findings; existing history/export cursor; read; idempotency none; version probe and token refresh without persisting credentials or tokens. | must | 2 |
| GAP-NESSUS-05 | Scan creation, launch, polling, and cleanup | [Cortex analyzer](https://raw.githubusercontent.com/TheHive-Project/Cortex-Analyzers/master/analyzers/Nessus/nessus.py) | On-demand verification needs a controlled create-to-results workflow and safe temporary-scan cleanup. | `create_scan_from_policy`/`launch_scan` `ScanRecord` write, `get_scan_status` read with idempotency none, `delete_scan` destructive; cursor n/a; writes idempotency key; cleanup after evidence commit. | should | 3 |
| GAP-NESSUS-06 | Target network egress guard | [Cortex analyzer](https://raw.githubusercontent.com/TheHive-Project/Cortex-Analyzers/master/analyzers/Nessus/nessus.py), [Cortex manifest](https://raw.githubusercontent.com/TheHive-Project/Cortex-Analyzers/master/analyzers/Nessus/Nessus.json) | A hub must not become an arbitrary scanner against unintended networks, including after DNS resolution. | `allowed_networks` target constraint on scan `ScanRecord` actions; cursor n/a; write; idempotency key; validate CIDR/domain and resolved addresses in plan and apply. | must | 3 |
| GAP-NESSUS-07 | Offline CSV ingestion | [DefectDojo CSV parser](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/tools/tenable/csv_format.py) | Supplied reports, historical migrations, and disconnected environments need CSV replay without assuming filtered files are complete. | `csv_report_import` OCSF 2002 with schema detection and source state/severity; file-hash `snapshot` cursor; read; idempotency none; local-file auth. | could | 3 |

ICUHUB differentiator: History-ID scan-run synchronization, one-complete-snapshot-per-history export, API keys and edition gating, archival windows, `exclude_rollover`, export status/download, `TRUNCATED` detection, source severity preservation, credential stripping, and safe replay/quarantine exceed the surveyed artifacts.
## 8. Platform-level gaps

The compared platforms expose framework features absent from the ICUHUB design. Each deduplicated row maps to the relevant section of `docs/CONNECTOR_FRAMEWORK.md`; features without an exact contract name the nearest section explicitly.

| ID | Missing framework feature | Implemented by | Why it matters | CONNECTOR_FRAMEWORK section | Proposed framework addition | Priority | Wave |
|---|---|---|---|---|---|---|---|
| GAP-PLAT-01 | Webhook desired-state subscription lifecycle | [Port GitHub](https://raw.githubusercontent.com/port-labs/ocean/main/integrations/github/main.py), [n8n GitHub trigger](https://raw.githubusercontent.com/n8n-io/n8n/master/packages/nodes-base/nodes/Github/GithubTrigger.node.ts), [Port Jira](https://raw.githubusercontent.com/port-labs/ocean/main/integrations/jira/main.py), [n8n Jira trigger](https://raw.githubusercontent.com/n8n-io/n8n/master/packages/nodes-base/nodes/Jira/JiraTrigger.node.ts) | Receive-only parsing cannot repair drift, expiry, disabled hooks, or missing event subscriptions. | section 8 Credentials and webhooks; section 4 Manifest | Add `webhooks[].registration` desired state, expiry and refresh metadata, drift and disabled-hook health in `check`; list/test reads with idempotency `none`, create/update write/`natural_key`, resend write/`key`, delete destructive/`key`; secrets remain `SecretRef`. | must | 1 |
| GAP-PLAT-02 | Bidirectional mirroring and link policy with echo suppression | [XSOAR PrismaCloudV2](https://raw.githubusercontent.com/demisto/content/master/Packs/PrismaCloud/Integrations/PrismaCloudV2/PrismaCloudV2.yml), [XSOAR JiraV3](https://raw.githubusercontent.com/demisto/content/master/Packs/Jira/Integrations/JiraV3/JiraV3.py) | Independent local and remote changes need field ownership, conflict rules, and loop prevention rather than connector-specific behavior. | section 7.3 Outbound sync (tickets) | Add host-level link policy for direction, origin markers, comment/attachment filters, close/reopen mapping, field ownership, last-remote revision, replay dedupe, and echo suppression; mirroring writes use `natural_key` and revision preconditions. | should | 2 |
| GAP-PLAT-03 | Finding publication profile and ticket policy | [DefectDojo Jira helper](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/dev/dojo/jira/helper.py) | Generic issue creation lacks verification and severity gates, grouping, ownership, field maps, and close/reopen policy. | section 7.3 Outbound sync (tickets) | Add reusable versioned `TrackerPolicy` with dry-run rendering and per-target overrides for filters, grouping, fields, assignee/component, epic, and closure; ticket writes use `natural_key`. | should | 2 |
| GAP-PLAT-04 | Custom authenticated vendor request operation | [Activepieces Jira](https://raw.githubusercontent.com/activepieces/activepieces/main/packages/pieces/community/jira-cloud/src/index.ts), [Activepieces Confluence](https://raw.githubusercontent.com/activepieces/activepieces/main/packages/pieces/community/confluence/src/index.ts) | A constrained extension point covers new vendor endpoints without waiting for a connector release. | No generic vendor-request section; nearest is section 3.1 Shape | Add default-off `vendor_request` restricted to the configured origin with method and body limits, no arbitrary redirects, full audit, explicit read/write/destructive classification, and idempotency `none` for reads or `key` for writes. | could | 3 |
| GAP-PLAT-05 | Per-stream selector schema with completeness propagation | [Port Mend selector](https://raw.githubusercontent.com/port-labs/ocean/main/integrations/mend/integration.py), [filter implementation](https://raw.githubusercontent.com/port-labs/ocean/main/integrations/mend/mend/core/exporters/sca_vulnerability_exporter.py) | Filters without host semantics can make a partial view appear complete and trigger unsafe absence closure. | section 4 Manifest; section 5.4 Deletion and closure | Add optional per-stream `selector_schema`; mark filtered runs partial/scoped, disable absence closure, report omitted ranges `not_evaluated`, and retain host-owned cursors. | could | -- |
| GAP-PLAT-06 | Run-scoped parent discovery reuse | [Port Mend project exporter](https://raw.githubusercontent.com/port-labs/ocean/main/integrations/mend/mend/core/exporters/project_exporter.py) | Repeated parent pagination wastes quota and lets parent and child streams observe inconsistent snapshots. | No discovery-cache section; nearest are section 3.3 SDK facade and section 5.1 Run modes | Add an optional tenant-isolated discovery snapshot to `StreamContext`, keyed by connection and discovery revision and reused only within one run; never advance checkpoints or hide permission failures. | could | -- |
| GAP-PLAT-07 | Location-set and cardinality policy for one-to-many findings | [DefectDojo Netsparker parser](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/tools/netsparker/parser.py) | Title-only merging loses affected endpoints, while unconditional splitting destroys vendor-level triage identity. | section 6.1 Parse, then map; section 6.2 Three identities | Add typed `LocationSet` and `EvidenceSet`, stable `location_key`, and declared `merge\|split_per_location` parser policy; keep source issue identity separate from emitted finding identity. | should | -- |
| GAP-PLAT-08 | Content-based report format detector | [Faraday framework](https://github.com/infobyte/faraday_plugins), [DefectDojo Fortify XML](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/tools/fortify/xml_parser.py), [DefectDojo Mend](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/tools/mend/parser.py) | Filename-only parser selection cannot handle aliases, schema versions, or ambiguous content safely. | section 6.1 Parse, then map; section 10 Testing kit | Add `ReportFormatDetector` returning vendor, edition-neutral profile, and schema version with bounded sniffing, safe XML/ZIP handling, explicit ambiguity errors, and golden fixtures. | should | -- |
| GAP-PLAT-09 | Async read-operation handles | [XSOAR Tenable export code](https://raw.githubusercontent.com/demisto/content/master/Packs/Tenable_io/Integrations/Tenable_io/Tenable_io.py), [Tenable SC manifest](https://raw.githubusercontent.com/demisto/content/master/Packs/Tenable_sc/Integrations/Tenable_sc/Tenable_sc.yml) | Long exports and scans need resumable reads without holding one HTTP request open. | No async read-handle section; nearest is section 3.2 Lifecycle | Add typed read handles with `submitted/polling/ready/failed/expired`, durable vendor job ID, poll interval/deadline, and resume operation; classification `read`, idempotency `none`, reusing stream export logic. | should | -- |
| GAP-PLAT-10 | Action target constraints with DNS-rebinding-safe checks | [Cortex Nessus manifest](https://raw.githubusercontent.com/TheHive-Project/Cortex-Analyzers/master/analyzers/Nessus/Nessus.json), [Cortex source](https://raw.githubusercontent.com/TheHive-Project/Cortex-Analyzers/master/analyzers/Nessus/nessus.py) | Plan/apply approval alone does not prevent scan egress to unauthorized networks. | section 7.1 Plan and apply | Add declarative CIDR/domain target constraints evaluated during both plan and apply, including post-DNS-resolution checks and plan-diff visibility; preserve the action's write/destructive classification and idempotency. | must | 3 |
| GAP-PLAT-11 | Adaptive page sizing | [XSOAR Qualys implementation](https://raw.githubusercontent.com/demisto/content/master/Packs/qualys/Integrations/Qualysv2/Qualysv2.py) | Oversized detections or evidence can fail repeatedly despite correct rate limits and run budgets. | section 5.5 Scheduling, fairness, limits | Add optional per-stream adaptive page sizing with min/max bounds, checkpoint-safe resume, and health telemetry; never reduce requested scope or completeness silently. | should | -- |
| GAP-PLAT-12 | Diagnostic trace lifecycle with redaction | [Elastic Tenable package](https://raw.githubusercontent.com/elastic/integrations/main/packages/tenable_io/manifest.yml), [CEL configuration](https://raw.githubusercontent.com/elastic/integrations/main/packages/tenable_io/data_stream/audit/agent/stream/cel.yml.hbs) | Request evidence aids diagnosis but can leak credentials and sensitive data without explicit retention controls. | section 11 Observability; section 8 Credentials and webhooks | Add an off-by-default diagnostic trace facility with short TTL, size/count bounds, declared secret redaction, tenant audit, and secure deletion on disable or expiry. | should | -- |
| GAP-PLAT-13 | Per-stream export-job tuning configuration | [Elastic asset stream](https://raw.githubusercontent.com/elastic/integrations/main/packages/tenable_io/data_stream/asset/manifest.yml), [Elastic vulnerability stream](https://raw.githubusercontent.com/elastic/integrations/main/packages/tenable_io/data_stream/vulnerability/manifest.yml) | Large exports need different backfill and expiry behavior from audit or plugin streams. | section 4 Manifest; section 5.5 Scheduling, fairness, limits | Standardize optional per-stream `initial_lookback`, `poll_interval`, `job_timeout`, and `job_poll_interval` while retaining host checkpoints, global fairness, and rate limits. | should | -- |
| GAP-PLAT-14 | Readiness and verification phase on action outcomes | [Kestra Apply](https://raw.githubusercontent.com/kestra-io/plugin-kubernetes/main/src/main/java/io/kestra/plugin/kubernetes/kubectl/Apply.java) | Read-back confirms a write, not necessarily rollout or workload readiness. | section 7.1 Plan and apply; section 7.2 Additional action states | Add bounded verification to applicable plans with ready/failed/timeout states and deadlines; never report ambiguous readiness as success. | should | -- |
| GAP-PLAT-15 | Resumable one-shot workload identity through idempotency-key labels | [Kestra PodCreate](https://raw.githubusercontent.com/kestra-io/plugin-kubernetes/main/src/main/java/io/kestra/plugin/kubernetes/core/PodCreate.java) | Retried operational workloads can duplicate scanners or collectors unless existing resources are reconciled. | section 7.2 Additional action states | Reuse the persisted action idempotency key as a vendor label/annotation and reconcile existing terminal and non-terminal resources before create; retain write classification and `key` idempotency. | should | -- |
| GAP-PLAT-16 | Sensitive configuration default-deny | [Meltano GitLab](https://github.com/MeltanoLabs/tap-gitlab), [Steampipe GitLab catalog](https://hub.steampipe.io/plugins/theapsgroup/gitlab/tables) | Variable values, secrets, logs, and artifacts require explicit policy rather than accidental bulk collection. | section 4 Manifest; section 8 Credentials and webhooks | Add manifest-level sensitive-data classification with default-deny for values and content while allowing explicitly declared metadata-only posture streams. | should | -- |
| GAP-PLAT-17 | Multi-transport source adapters sharing parser, mapper, and checkpoint contracts | [Elastic Kubernetes manifest](https://raw.githubusercontent.com/elastic/integrations/main/packages/kubernetes/manifest.yml), [Elastic Prisma manifest](https://raw.githubusercontent.com/elastic/integrations/main/packages/prisma_cloud/manifest.yml) | HTTP polling alone cannot cover managed control planes, files, or push-based runtime evidence. | No source-adapter section; nearest are section 3.1 Shape and section 5.1 Run modes | Add stream-source adapters for API, file, TCP/UDP, CloudWatch, Event Hub, and Pub/Sub that share parser, mapper, dedupe, health, and typed-checkpoint contracts instead of separate connectors. | should | -- |
| GAP-PLAT-18 | Offline and rendered replay source type | [Steampipe Kubernetes config](https://raw.githubusercontent.com/turbot/steampipe-plugin-kubernetes/main/kubernetes/connection_config.go), [DefectDojo Twistlock parser](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/tools/twistlock/parser.py) | Live APIs exclude disconnected environments, historical evidence, and pre-deployment assessment. | section 5.1 Run modes; section 6.1 Parse, then map | Add declared file/replay sources with source-path identity, format version, completeness declaration, `snapshot` cursor, and secret redaction; reuse existing parsers and mappers rather than implicit fallback. | should | -- |
| GAP-PLAT-19 | Relationship creation and dependent deletion policies | [Port controller](https://raw.githubusercontent.com/port-labs/port-k8s-exporter/main/pkg/k8s/controller.go), [Port Helm values](https://raw.githubusercontent.com/port-labs/helm-charts/main/charts/port-k8s-exporter/values.yaml) | Asset references alone do not define relationship completeness, dependent cleanup, or deletion safety. | section 6.3 Asset references; section 5.4 Deletion and closure | Add explicit mapping policies for create-missing-related entities, dependent deletion, diff-only updates, and tombstones with cycle guards and the complete-snapshot circuit breaker. | should | -- |
| GAP-PLAT-20 | Credential pools per connection with health | [Airbyte GitHub](https://raw.githubusercontent.com/airbytehq/airbyte/master/airbyte-integrations/connectors/source-github/manifest.yaml), [Port GitHub](https://raw.githubusercontent.com/port-labs/ocean/main/integrations/github/main.py) | Large installations need isolation and throughput without one global quota bucket. | section 8 Credentials and webhooks; section 5.5 Scheduling, fairness, limits | Add optional credential pools with per-credential quota and health, selection, exclusion after auth failure, and deterministic target ownership; retain existing auth strategies. | should | -- |
| GAP-PLAT-21 | Selectable file and folder ingestion with bounded selectors | [Port GitHub kinds](https://raw.githubusercontent.com/port-labs/ocean/main/integrations/github/github/helpers/utils.py), [Port GitLab kinds](https://raw.githubusercontent.com/port-labs/ocean/main/integrations/gitlab/gitlab_integration/utils.py), [Backstage Bitbucket Cloud](https://raw.githubusercontent.com/backstage/backstage/master/plugins/catalog-backend-module-bitbucket-cloud/src/providers/BitbucketCloudEntityProvider.ts) | Unbounded repository content collection risks cost and secret exposure, while no selector prevents targeted evidence sync. | section 4 Manifest; section 5.3 Cursor kinds provided by the kit | Add opt-in bounded `repository_files` capability with path/glob selectors, maximum files/bytes, binary filtering, commit-SHA `snapshot` checkpoints, and read idempotency `none`. | should | -- |
| GAP-PLAT-22 | Dynamic webhook event catalog diff | [n8n Bitbucket trigger](https://raw.githubusercontent.com/n8n-io/n8n/master/packages/nodes-base/nodes/Bitbucket/BitbucketTrigger.node.ts) | Static event lists miss vendor-added events and subscription incompatibilities. | section 8 Credentials and webhooks; section 3.2 Lifecycle | Add `hook_events` catalog reads with idempotency `none`; diff supported versus subscribed events during `check` and expose an operator-visible compatibility result. | should | -- |
| GAP-PLAT-23 | Scheduled full refresh with event-driven target repair | [Backstage Cloud events](https://raw.githubusercontent.com/backstage/backstage/master/plugins/catalog-backend-module-bitbucket-cloud/src/events/analyzeBitbucketCloudWebhookEvent.ts), [Backstage Server events](https://raw.githubusercontent.com/backstage/backstage/master/plugins/catalog-backend-module-bitbucket-server/src/events/analyzeBitbucketServerWebhookEvent.ts) | Push, rename, transfer, and deletion events need targeted reconciliation without corrupting stable asset identity. | section 5.1 Run modes; section 3.2 Lifecycle | Add target-repair event semantics to discovery and stream reconciliation, backed by scheduled full refresh; treat repository moves as identity-preserving and never create an asset solely because its slug changed. | should | -- |
| GAP-PLAT-24 | Manifest stream dependency validation | [Singer dependency validation](https://raw.githubusercontent.com/singer-io/tap-jira/master/tap_jira/streams.py) | Selecting child streams without required parents breaks relationships and reproducibility. | section 4 Manifest; section 3.2 Lifecycle | Add `requires: [stream:projects]` dependency edges and per-connection selected-stream validation; fail discovery/check with a structured dependency error before a run. | should | 1 |
| GAP-PLAT-25 | Per-source catalog selection and schema exposure | [Airbyte Jira metadata](https://raw.githubusercontent.com/airbytehq/airbyte/master/airbyte-integrations/connectors/source-jira/metadata.yaml), [Airbyte Jira manifest](https://raw.githubusercontent.com/airbytehq/airbyte/master/airbyte-integrations/connectors/source-jira/manifest.yaml) | Operators need explicit stream selection and effective schemas to reproduce and validate a source configuration. | section 4 Manifest; section 3.2 Lifecycle | Add selected streams and per-stream configuration to Connection, validate them against the generated manifest, expose effective schemas through discovery, and enforce dependency validation. | should | -- |

## 9. What this changes

Only `must` gaps are listed. Each row names the roadmap phase whose `VENDOR_CONNECTORS.md` spec (or `CONNECTOR_FRAMEWORK.md` change) should absorb the gap in its Write step. Research waves map to phases as follows: wave 1 is P5, waves 2 are P7 to P9, and wave 3 is P10. No `must` gap is assigned to wave 4 or `later`; those gaps stay in sections 3 to 8 with their own priority and are not scheduled by this document.

Totals: 58 kind-level `must` gaps (sections 3 to 7) and 2 framework-level `must` gaps (section 8). `GAP-GITHUB-*` and `GAP-GITLAB-*` also apply to `github_enterprise_server` and `gitlab_self_managed` respectively.

### 9.1 P5 (wave 1)

| Kind | Must gap IDs |
|---|---|
| `github` (and `github_enterprise_server`) | GAP-GITHUB-01, GAP-GITHUB-02, GAP-GITHUB-03, GAP-GITHUB-04 |
| `gitlab` (and `gitlab_self_managed`) | GAP-GITLAB-01, GAP-GITLAB-02, GAP-GITLAB-03, GAP-GITLAB-04 |
| `jira_cloud` | GAP-JIRACLOUD-01, GAP-JIRACLOUD-03, GAP-JIRACLOUD-10, GAP-JIRACLOUD-15 |
| `jira_dc` | GAP-JIRADC-01, GAP-JIRADC-02, GAP-JIRADC-03, GAP-JIRADC-11 |
| Framework (`CONNECTOR_FRAMEWORK.md`) | GAP-PLAT-01 (section 8 Credentials and webhooks; section 4 Manifest) |

### 9.2 P7 to P9 (wave 2)

| Kind | Must gap IDs |
|---|---|
| `gitlab` (and `gitlab_self_managed`) | GAP-GITLAB-05 |
| `confluence_cloud` | GAP-CONFCLOUD-02, GAP-CONFCLOUD-03, GAP-CONFCLOUD-06, GAP-CONFCLOUD-07 |
| `kubernetes` | GAP-K8S-01, GAP-K8S-02, GAP-K8S-04 |
| `openshift` | GAP-OSHIFT-01 |
| `prisma_cloud` (CSPM) | GAP-PCSPM-01, GAP-PCSPM-02, GAP-PCSPM-03, GAP-PCSPM-06, GAP-PCSPM-12 |
| `prisma_cloud` (Compute) | GAP-PCCOMP-01, GAP-PCCOMP-03, GAP-PCCOMP-04, GAP-PCCOMP-06 |
| `fortify_ssc` | GAP-SSC-01, GAP-SSC-02 |
| `mend_sca` | GAP-MEND-01, GAP-MEND-02, GAP-MEND-03 |
| `tenable_vm` | GAP-TVM-01 |
| `tenable_sc` | GAP-TSC-01, GAP-TSC-02 |
| `nessus` | GAP-NESSUS-01, GAP-NESSUS-04 |

### 9.3 P10 (wave 3)

| Kind | Must gap IDs |
|---|---|
| `bitbucket_cloud` | GAP-BBCLOUD-01, GAP-BBCLOUD-02 |
| `bitbucket_data_center` | GAP-BBDC-01, GAP-BBDC-02, GAP-BBDC-03, GAP-BBDC-04 |
| `confluence_dc` | GAP-CONFDC-01, GAP-CONFDC-03, GAP-CONFDC-06 |
| `invicti_enterprise` | GAP-IE-03 |
| `invicti_standard` | GAP-IS-01, GAP-IS-03 |
| `qualys_enterprise` | GAP-QUALYS-01 |
| `nessus` | GAP-NESSUS-06 |
| Framework (`CONNECTOR_FRAMEWORK.md`) | GAP-PLAT-10 (section 7.1 Plan and apply) |

### 9.4 Wave 4 and `later`

No `must` gap is assigned to wave 4 or `later`. Those rows remain in sections 3 to 8 with `should` or `could` priority.

### 9.5 Framework gaps outside the phase tables

GAP-PLAT-24 (manifest stream dependency validation) is `should` in wave 1. It is not a `must` and is therefore not listed in 9.1.

## 10. Unverified

Items below are not confirmed against a primary source in the research inputs, or have a known caveat. Each needs checking before the corresponding phase spec is written.

### 10.1 Marked `[UNVERIFIED]` in the body

| Line | Gap or row | Item |
|---|---|---|
| 33 | Tracecat (section 1) | Enterprise licensing terms |
| 40 | Jenkins Qualys WAS plugin (section 1) | License of the artifact |
| 41 | Qualys GitHub Action (section 1) | License of the artifact |
| 228 | GAP-JIRACLOUD-11 | Nango worklog write action |
| 231 | GAP-JIRACLOUD-14 | n8n issue operations |
| 263 | GAP-JIRADC-10 | n8n comment operation |
| 288 | GAP-CONFCLOUD-03 | n8n Confluence page operations |
| 293 | GAP-CONFCLOUD-08 | n8n Confluence page operations |
| 296 | GAP-CONFCLOUD-11 | n8n Confluence page operations |
| 318 | GAP-CONFDC-02 | Nango Cloud Confluence blog action |
| 321 | GAP-CONFDC-05 | n8n Cloud Confluence page operations |
| 323 | GAP-CONFDC-07 | n8n Cloud Confluence page operations |
| 573 | GAP-IE-02 | Acunetix legacy and current format profiles (live API behavior) |

### 10.2 Caveats stated in prose, not tagged

- Section 1, OpenCTI row (line 39): the Qualys connector manifest is marked Commercial and `verified=false`.
- GAP-PCCOMP-08 (line 482): priority `should`, wave `3`. The research line for this row was truncated; the wave value is unconfirmed.
- GAP-K8S generic apply, patch, restart, and delete matrix row (line 353): ICUHUB is condensed to `P`. The restart sub-row is `N` in the research output. Restart is tracked as GAP-K8S-10 (`should`, wave 3) and GAP-K8S-09.
- GAP-PLAT-01 wave: the research flagged the wave as ambiguous. The table keeps `1`.
- GAP-MEND-05 (line 633): the activation-key mode is an onboarding addition, not a correction to an existing Mend spec.

### 10.3 Matrix conflicts not re-verified against `VENDOR_CONNECTORS.md`

The research marked ICUHUB `Y` on several rows where the spec wording may read as `partial`. These were not re-checked against the spec text in this pass:

- GitHub: "PRs, reviews, comments" and "Security alerts, branch protection, enterprise audit".
- Bitbucket Cloud: "PRs, comments, activity, diffs".
- Bitbucket Data Center: "PR create, approve, merge, review writes".

### 10.4 Sources not used

- Wazuh ruleset (section 1, Qualys row): the research URL was truncated, so no link is cited.
- Empty-check platforms (Dependency-Track, SecObserve, Shuffle, Windmill, Port Ocean Confluence, StackStorm Confluence, Prowler, CloudQuery, Kestra non-Kubernetes): stated in the paragraph below the section 1 table; not repeated here.
- GitLab `artifacts_reports` documentation link: the research marked it defective; it is not cited anywhere in this document.
## References

[AB-CONF]: https://raw.githubusercontent.com/airbytehq/airbyte/master/airbyte-integrations/connectors/source-confluence/manifest.yaml
[AB-GH]: https://raw.githubusercontent.com/airbytehq/airbyte/master/airbyte-integrations/connectors/source-github/manifest.yaml
[AB-GL]: https://raw.githubusercontent.com/airbytehq/airbyte/master/airbyte-integrations/connectors/source-gitlab/manifest.yaml
[AB-JIRA]: https://raw.githubusercontent.com/airbytehq/airbyte/master/airbyte-integrations/connectors/source-jira/manifest.yaml
[AP-CONF]: https://raw.githubusercontent.com/activepieces/activepieces/main/packages/pieces/community/confluence/src/index.ts
[AP-CONF-TEMPLATE]: https://raw.githubusercontent.com/activepieces/activepieces/main/packages/pieces/community/confluence/src/lib/actions/create-page-from-template.ts
[AP-GL]: https://raw.githubusercontent.com/activepieces/activepieces/main/packages/pieces/community/gitlab/src/index.ts
[AP-JIRA]: https://raw.githubusercontent.com/activepieces/activepieces/main/packages/pieces/community/jira-cloud/src/index.ts
[BS-BBC]: https://raw.githubusercontent.com/backstage/backstage/master/plugins/catalog-backend-module-bitbucket-cloud/src/providers/BitbucketCloudEntityProvider.ts
[BS-BBC-ACT]: https://github.com/backstage/backstage/tree/master/plugins/scaffolder-backend-module-bitbucket-cloud/src/actions
[BS-BBD-CLI]: https://raw.githubusercontent.com/backstage/backstage/master/plugins/catalog-backend-module-bitbucket-server/src/lib/BitbucketServerClient.ts
[BS-BBD-EVENT]: https://raw.githubusercontent.com/backstage/backstage/master/plugins/catalog-backend-module-bitbucket-server/src/events/analyzeBitbucketServerWebhookEvent.ts
[BS-BBD-SCAF]: https://raw.githubusercontent.com/backstage/backstage/master/plugins/scaffolder-backend-module-bitbucket-server/src/actions/bitbucketServer.ts
[BS-CONF]: https://raw.githubusercontent.com/backstage/community-plugins/main/workspaces/confluence/plugins/search-backend-module-confluence-collator/src/collators/ConfluenceCollatorFactory.ts
[DD-JIRA]: https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/dev/dojo/jira/helper.py
[EL-CONF-AUDIT]: https://raw.githubusercontent.com/elastic/integrations/main/packages/atlassian_confluence/data_stream/audit/manifest.yml
[EL-JIRA-AUDIT]: https://raw.githubusercontent.com/elastic/integrations/main/packages/atlassian_jira/data_stream/audit/manifest.yml
[GL-AUDIT]: https://docs.gitlab.com/api/audit_events/
[GL-SARIF-CI]: https://docs.gitlab.com/ci/yaml/artifacts_reports/
[ML-GL]: https://github.com/MeltanoLabs/tap-gitlab
[N8-BBC]: https://raw.githubusercontent.com/n8n-io/n8n/master/packages/nodes-base/nodes/Bitbucket/BitbucketTrigger.node.ts
[N8-CONF]: https://raw.githubusercontent.com/n8n-io/n8n/master/packages/nodes-base/nodes/Confluence/actions/router.ts
[N8-CONF-PAGE]: https://raw.githubusercontent.com/n8n-io/n8n/master/packages/nodes-base/nodes/Confluence/actions/page/index.ts
[N8-GH]: https://raw.githubusercontent.com/n8n-io/n8n/master/packages/nodes-base/nodes/Github/Github.node.ts
[N8-GH-PR]: https://raw.githubusercontent.com/n8n-io/n8n/master/packages/nodes-base/nodes/Github/descriptions/PullRequestDescription.ts
[N8-GH-TRIG]: https://raw.githubusercontent.com/n8n-io/n8n/master/packages/nodes-base/nodes/Github/GithubTrigger.node.ts
[N8-GL]: https://raw.githubusercontent.com/n8n-io/n8n/master/packages/nodes-base/nodes/Gitlab/Gitlab.node.ts
[N8-GL-TRIG]: https://raw.githubusercontent.com/n8n-io/n8n/master/packages/nodes-base/nodes/Gitlab/GitlabTrigger.node.ts
[N8-JIRA-COMMENT]: https://raw.githubusercontent.com/n8n-io/n8n/master/packages/nodes-base/nodes/Jira/IssueCommentDescription.ts
[N8-JIRA-ISSUE]: https://raw.githubusercontent.com/n8n-io/n8n/master/packages/nodes-base/nodes/Jira/IssueDescription.ts
[N8-JIRA-TRIG]: https://raw.githubusercontent.com/n8n-io/n8n/master/packages/nodes-base/nodes/Jira/JiraTrigger.node.ts
[NG-CONF]: https://github.com/NangoHQ/integration-templates/tree/main/integrations/confluence
[NG-CONF-ACTIONS]: https://github.com/NangoHQ/integration-templates/tree/main/integrations/confluence/actions
[NG-CONF-ATTACH]: https://raw.githubusercontent.com/NangoHQ/integration-templates/main/integrations/confluence/syncs/attachments.ts
[NG-CONF-BLOG]: https://raw.githubusercontent.com/NangoHQ/integration-templates/main/integrations/confluence/actions/create-blog-post.ts
[NG-CONF-PROPERTY]: https://raw.githubusercontent.com/NangoHQ/integration-templates/main/integrations/confluence/actions/update-page-property.ts
[NG-JIRA-ACTIONS]: https://github.com/NangoHQ/integration-templates/tree/main/integrations/jira/actions
[NG-JIRA-SYNCS]: https://github.com/NangoHQ/integration-templates/tree/main/integrations/jira/syncs
[NG-JIRA-WORKLOG]: https://raw.githubusercontent.com/NangoHQ/integration-templates/main/integrations/jira/actions/update-worklog.ts
[PO-BBC]: https://raw.githubusercontent.com/port-labs/ocean/main/integrations/bitbucket-cloud/.port/resources/port-app-config.yml
[PO-BBC-WH]: https://raw.githubusercontent.com/port-labs/ocean/main/integrations/bitbucket-cloud/bitbucket_cloud/webhook_processors/webhook_client.py
[PO-BBD-CLI]: https://raw.githubusercontent.com/port-labs/ocean/main/integrations/bitbucket-server/client.py
[PO-GH]: https://raw.githubusercontent.com/port-labs/ocean/main/integrations/github/main.py
[PO-GH-ACT]: https://raw.githubusercontent.com/port-labs/ocean/main/integrations/github/github/actions/registry.py
[PO-GL]: https://raw.githubusercontent.com/port-labs/ocean/main/integrations/gitlab/gitlab_integration/ocean.py
[PO-JIRA]: https://raw.githubusercontent.com/port-labs/ocean/main/integrations/jira/main.py
[PO-JIRA-KINDS]: https://raw.githubusercontent.com/port-labs/ocean/main/integrations/jira/kinds.py
[SG-BBC]: https://raw.githubusercontent.com/HumbleBeck/tap-bitbucket/master/tap_bitbucket/streams.py
[SG-JIRA]: https://raw.githubusercontent.com/singer-io/tap-jira/master/tap_jira/streams.py
[SP-BB]: https://raw.githubusercontent.com/turbot/steampipe-plugin-bitbucket/main/bitbucket/plugin.go
[SP-BB-REPO]: https://raw.githubusercontent.com/turbot/steampipe-plugin-bitbucket/main/bitbucket/table_bitbucket_repository.go
[SP-GH]: https://raw.githubusercontent.com/turbot/steampipe-plugin-github/main/github/plugin.go
[SP-GL]: https://hub.steampipe.io/plugins/theapsgroup/gitlab/tables
[SP-JIRA]: https://raw.githubusercontent.com/turbot/steampipe-plugin-jira/main/jira/plugin.go
[ST2-BBD]: https://raw.githubusercontent.com/StackStorm-Exchange/stackstorm-bitbucket/master/sensors/repository_sensor.py
[ST2-GH-ACT]: https://github.com/StackStorm-Exchange/stackstorm-github/tree/master/actions
[ST2-GL-PIPE]: https://raw.githubusercontent.com/StackStorm-Exchange/stackstorm-gitlab/master/actions/pipeline_trigger.py
[ST2-JIRA]: https://github.com/StackStorm-Exchange/stackstorm-jira/tree/master/actions
[TC-GIT-SYNC]: https://docs.tracecat.com/manage-platform/git-sync
[XS-BBC]: https://xsoar.pan.dev/docs/reference/integrations/bitbucket
[XS-GL-AUDIT]: https://raw.githubusercontent.com/demisto/content/master/Packs/GitLab/Integrations/GitLabEventCollector/README.md
[XS-JIRA]: https://raw.githubusercontent.com/demisto/content/master/Packs/Jira/Integrations/JiraV3/JiraV3.py
[XS-JIRA-YML]: https://raw.githubusercontent.com/demisto/content/master/Packs/Jira/Integrations/JiraV3/JiraV3.yml
[XS-JIRADC]: https://github.com/demisto/content/tree/master/Packs/JiraDataCenter
