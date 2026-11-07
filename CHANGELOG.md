# Changelog

All notable changes to ICUHUB are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Integration inventory of the existing consumer platforms with an ICUHUB disposition per integration (`docs/INTEGRATION_INVENTORY.md`).
- Technology options per design concern with licenses, air-gap fit, and sources (`docs/OPTIONS.md`).
- Delivery roadmap P0-P10; every phase runs as brainstorm, write, plan, implement, test (`docs/ROADMAP.md`).
- BRD v0.2: BR-16..27, NG8..13, FR-CNR-08..11, FR-ING-06, FR-AUD-05, FR-ADM-03..04, FR-TKT, FR-NTF, FR-DIR, FR-FET, FR-MCPG, FR-FEED, FR-MIG, NFR-13..16, R11..13; integration catalog waves updated.
- HLD capability protocols `Notifier`, `Directory`, `SbomSink`, `RiskRegister`, `VulnIntel`; extended `Tracker` operations.
- ADR-0004..0016 closing decisions D1-D14.
- `icuhub-schemas` 0.0.1 (`packages/icuhub-schemas`): OCSF 1.9.0 models for classes 2002-2007 and 6003 validated against the vendored official schemas, SARIF 2.1.0 codec with OCSF-to-SARIF conversion, CloudEvents 1.0 envelope, finding fingerprint (FR-NRM-01..06, FR-ING-05).
- Runtime dependency license check (`tools/license_check.py`) in CI (NFR-15).
- Prior-art survey of 51 comparable security, DevOps, and platform-engineering projects with cross-cutting lessons PA-01..PA-41 and anti-patterns AP-01..AP-18 (`docs/PRIOR_ART.md`).
- Connector framework design: connector contract, generated manifest, sync engine with transactional checkpoints, mapping and identity rules, plan/apply actions, testing kit (`docs/CONNECTOR_FRAMEWORK.md`).
- BRD v0.3: FR-CNR-12..19, FR-ING-07..13, FR-NRM-07..09, FR-CON-08..09, FR-TKT-09, FR-POL-09, NFR-18.
- Coverage gap analysis of the vendor connector specs against open-source integration platforms, with 192 vendor gaps and 25 platform-level gaps (`docs/COVERAGE_GAPS.md`).
- Per-vendor API facts and connector specifications for GitHub, GitLab, Bitbucket, Jira, Confluence, Kubernetes, OpenShift, Prisma Cloud, Fortify SSC and on Demand, Invicti, Mend, Qualys, Tenable, and Nessus (`docs/VENDOR_CONNECTORS.md`); `KnowledgeBase` capability and FR-KB-01..03; COMMATRIX F-122..123 and F-226..229.
- ADR-0017..0019 closing decisions D15-D17 (generated connector manifests, first-party in-process connectors, JMESPath extraction in mappers); `OPTIONS.md` section 17.

### Changed

- Decisions table in BRD section 18 records outcomes and ADR links; BR-15, FR-RX-01..10, NFR-17, and R10 are withdrawn (ADR-0011) with their IDs reserved.
- COMMATRIX event and secret flows describe Kafka and OpenBao Transit (ADR-0005, ADR-0006).
- CI installs `icuhub-schemas`, compiles `src`, `packages`, and `tools`, and runs the license check.
- HLD: ingestion capabilities are stream declarations driven by the sync engine; write and destructive operations are plan/apply actions; the `cursor` table is replaced by `stream_state`, with `target`, `sync_run`, `raw_batch`, `quarantine_item`, and `action_plan` added.
- ROADMAP P2, P3, P4, P5, and P10 carry the connector framework tasks and tests; connector guide checklist follows the framework.

## [0.0.1] - 2026-11-05 -- design documents and repository setup

### Added

- Business requirements (`docs/BRD.md`), high-level design (`docs/HLD.md`), and communication matrix (`docs/COMMATRIX.md`).
- Connector guide (`docs/CONNECTOR_GUIDE.md`) and architecture decision records 0001-0003.
- AI coding directives: `AGENTS.md` (canonical), `CLAUDE.md`, `GEMINI.md`, `.github/copilot-instructions.md`, `.cursor/rules/`, `.claude/commands/`, `.claude/rules/`, `llms.txt`.
- Python project configuration, CI (lint, compile, tests), issue and pull request templates.
