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

### Changed

- Decisions table in BRD section 18 records outcomes and ADR links; BR-15, FR-RX-01..10, NFR-17, and R10 are withdrawn (ADR-0011) with their IDs reserved.
- COMMATRIX event and secret flows describe Kafka and OpenBao Transit (ADR-0005, ADR-0006).
- CI installs `icuhub-schemas`, compiles `src`, `packages`, and `tools`, and runs the license check.

## [0.0.1] - 2026-11-05 -- design documents and repository setup

### Added

- Business requirements (`docs/BRD.md`), high-level design (`docs/HLD.md`), and communication matrix (`docs/COMMATRIX.md`).
- Connector guide (`docs/CONNECTOR_GUIDE.md`) and architecture decision records 0001-0003.
- AI coding directives: `AGENTS.md` (canonical), `CLAUDE.md`, `GEMINI.md`, `.github/copilot-instructions.md`, `.cursor/rules/`, `.claude/commands/`, `.claude/rules/`, `llms.txt`.
- Python project configuration, CI (lint, compile, tests), issue and pull request templates.
