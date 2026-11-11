# ADR-0008 -- OCSF 1.9.0 pinned, ICUHUB-owned models

- Status: Accepted
- Date: 2026-11-07
- Closes: D5, D6

## Context

ADR-0003 adopted OCSF and SARIF but left the OCSF version pin (D5) and the model source (D6) open. `OPTIONS.md` sections 5 and 16 compare ICUHUB-owned models with Prowler `py-ocsf-models`.

## Decision

- OCSF is pinned to 1.9.0.
- `icuhub-schemas` owns Pydantic v2 models for the classes ICUHUB maps and validates every produced document with `jsonschema` against the official OCSF 1.9.0 per-class JSON schemas, vendored in the package with a digest manifest.
- `py-ocsf-models` is not used.
- Phase 1 runtime dependencies of `icuhub-schemas`: `pydantic` 2.x and `jsonschema` 4.x.

## Consequences

- Validation needs no network at runtime.
- Moving to a later OCSF version is a new ADR, a new vendored schema set, and a minor version of `icuhub-schemas`.

## Requirements affected

BR-05, FR-NRM-01..06; HLD section 8; ROADMAP P1.
