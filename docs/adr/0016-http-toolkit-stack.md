# ADR-0016 -- HTTP toolkit dependency set

- Status: Accepted
- Date: 2026-11-07
- Closes: D14

## Context

Connectors share one HTTP toolkit (HLD 5.5). `OPTIONS.md` section 2 compares httpx2, classic httpx, aiohttp, and requests stacks.

## Decision

- The connector kit uses `httpx2` (async client), `tenacity` (retries for idempotent operations), `aiolimiter` (per-process pacing), `Authlib` (OAuth 2.0), and `asyncpg` (PostgreSQL token bucket shared across replicas).
- Exact versions are pinned in the connector-kit package when P2 starts, after re-checking release and license status.

## Consequences

- Rate limits hold across replicas without Redis.
- Connectors never import the HTTP client directly; they use the toolkit.

## Requirements affected

FR-CNR-05, FR-CNR-09; HLD section 5.5; ROADMAP P2.
