# ADR-0013 -- Policy engine: typed rules in PostgreSQL

- Status: Accepted
- Date: 2026-11-07
- Closes: D11

## Context

Every call needs a policy decision (FR-POL-01..08). `OPTIONS.md` section 9 compares OPA/Rego, Cedar, Cerbos, OpenFGA, Casbin, and typed rules.

## Decision

- Policy rules are typed records in PostgreSQL with a closed set of match fields and operators, evaluated in-process behind a `PolicyEvaluator` interface.
- Decisions are `allow`, `deny`, `require_approval`, or `preview`, with stable reason codes, the matched rule IDs, and the policy version digest.
- Evaluation fails closed on error.

## Consequences

- Rules are edited through the admin API without a bundle pipeline or sidecar.
- Adding custom predicates beyond the closed set would be a new ADR (OPA is the documented candidate).

## Requirements affected

FR-POL-01..08, FR-ADM-01, FR-ADM-03; HLD sections 6, 16.6.
