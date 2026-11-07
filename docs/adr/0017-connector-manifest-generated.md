# ADR-0017 -- Connector manifests are generated from code and committed

- Status: Accepted
- Date: 2026-11-07
- Closes: D15

## Context

Every surveyed integration platform declares a manifest: identity, version, config
schema with secret flags, auth, capabilities, permissions, and compatibility
(`PRIOR_ART.md` PA-01, PA-02). Handwritten manifests duplicate what the connector code
already states; class attributes alone give reviewers nothing to diff and no schema
compatibility gate (PA-03).

## Decision

- `build_manifest(kind)` generates `manifest.json` from the connector class, its
  decorators, and its Pydantic models (`CONNECTOR_FRAMEWORK.md` section 4).
- The generated file is committed next to the connector. CI regenerates it and fails on
  any difference.
- A manifest diff tool classifies each change as additive or breaking; a breaking change
  requires a connector major version and a migration note.
- The manifest carries three versions: `format_version` (manifest schema), `sdk` (host
  contract range), and `version` (connector semver). The host refuses to register a
  connector whose `format_version` or `sdk` range it does not support.

## Consequences

- One source of truth; the manifest cannot drift from code.
- Reviewers and the admin surface read the manifest without reading Python.
- Manifest generation is part of P2 and must be deterministic (stable key order).

## Requirements affected

FR-CNR-12, FR-CNR-15, FR-CNR-19; `CONNECTOR_FRAMEWORK.md` sections 4, 9; ROADMAP P2.
