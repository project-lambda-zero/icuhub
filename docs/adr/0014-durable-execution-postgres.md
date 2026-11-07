# ADR-0014 -- Durable actions and approvals: PostgreSQL state machine and job queue

- Status: Accepted
- Date: 2026-11-07
- Closes: D12

## Context

Write and destructive actions pause for approval, expire, and execute once (FR-POL-04, FR-API-06). `OPTIONS.md` section 10 compares Temporal, DBOS, Hatchet, Restate, Prefect, Celery/ARQ, and an own state machine.

## Decision

- Actions follow the HLD 6.3 state machine stored in PostgreSQL, with an execution ledger keyed by `(tenant, idempotency_key)`.
- Work is claimed from PostgreSQL job rows with `FOR UPDATE SKIP LOCKED`; approval expiry runs as a sweeper.
- Policy is re-evaluated immediately before execution; an `uncertain` outcome is reconciled through a vendor lookup before any retry; non-idempotent destructive calls are never retried blindly.

## Consequences

- No workflow cluster to operate.
- Long multi-step workflows, if they enter scope, are a new ADR (Temporal is the documented candidate).

## Requirements affected

FR-POL-03, FR-POL-04, FR-API-06, NFR-06; HLD section 6.
