# ADR-0020 -- MVP scope: ten vendors, every specced edition, full hub runtime

- Status: Accepted
- Date: 2026-11-09
- Closes: D18, D19, D21
- Amends: ADR-0010 (wave 1 is extended; nothing is removed from it)

## Context

The operator defined the first release as an MVP in which ten vendors are fully
integrated into the hub: Jira, Fortify, Nessus, GitLab, GitHub, Mend, Invicti,
OpenShift, Archer GRC, and Prisma Cloud. Three questions followed from that directive:
which editions count (D18), how much of the hub runtime ships with them (D19), and what
happens to the earlier wave-1 list in ADR-0010 (D21). A persona review of the design
(`MVP.md` section 2) also found that "fully integrated" needs a per-vendor definition
of done, a cross-scanner correlation model, and an Archer specification.

## Decision

- D18: the MVP covers every edition that has a connector kind in `VENDOR_CONNECTORS.md`,
  plus a new `archer` kind for Archer GRC on premises and SaaS:
  `github`, `github_enterprise_server`, `gitlab`, `gitlab_self_managed`, `jira_cloud`,
  `jira_dc`, `fortify_ssc`, `fortify_fod`, `nessus`, `mend_sca`, `invicti_enterprise`,
  `invicti_standard`, `kubernetes`, `openshift`, `prisma_cloud` (profiles `cspm` and
  `compute`), and `archer`.
- D19: the MVP ships the full hub runtime: connector kit, PostgreSQL storage with
  row-level security, credential broker, typed policy, action state machine with
  approvals, hash-chained audit, job queue, sync engine, webhook ingress, report-file
  import, transactional outbox with the Kafka relay, REST `/v1`, MCP `/mcp`, ticket
  routing with cross-scanner correlation, and the SMTP notifier.
- D21: wave 1 keeps F5 BIG-IP, Google Threat Intelligence, and the SMTP notifier from
  ADR-0010 and adds the MVP kinds above.
- "Fully integrated" means the per-vendor definition of done in `MVP.md` section 4:
  every stream, read operation, action, webhook, report import, and auth mode in that
  kind's specification, proven by fixture tests, plus an operator-run live acceptance
  suite (`ICUHUB_ACC=1`).
- Live acceptance runs in the operator's private infrastructure; results are handed
  back and recorded per kind before a kind is released as `core`.

## Consequences

- The MVP phases M1..M7 (`MVP.md` section 5) replace the order of ROADMAP P2..P5 for
  these kinds; Fortify, Nessus, Mend, Invicti, OpenShift, Prisma Cloud, and Archer move
  from P8 and P10 into the MVP.
- Connector tests run offline against recorded vendor payloads. A kind is not released
  as `core` until its live acceptance result is recorded (FR-CNR-16).
- Cross-scanner correlation becomes a hub feature (FR-COR-01..05) because the finding
  fingerprint is per connector kind and cannot merge Fortify, Mend, and Nessus findings
  for one Jira ticket on its own.

## Requirements affected

BRD sections 11 and 18, FR-COR-01..05, FR-GRC-01..04; `MVP.md`; ROADMAP P2..P5, P8,
P10; `VENDOR_CONNECTORS.md` section 10 (Archer).
