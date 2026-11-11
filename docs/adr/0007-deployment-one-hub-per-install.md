# ADR-0007 -- Deployment model: one ICUHUB per enterprise install

- Status: Accepted
- Date: 2026-11-07
- Closes: D4

## Context

ICUHUB can run as one instance per enterprise install, shared by every console of that install, or as a central hosted service for several installs.

## Decision

- One ICUHUB per enterprise install, shared by all consumers of that install.
- Tenancy inside the instance is enforced as designed (NFR-04): tenant on every row, row-level security, tenant from the caller token.

## Consequences

- Air-gapped installs are self-contained.
- A hosted multi-install offering is out of scope; it would need a new ADR.

## Requirements affected

BR-07, BR-08, NFR-04; HLD section 11.
