# ADR-0009 -- Event envelope: CloudEvents 1.0

- Status: Accepted
- Date: 2026-11-07
- Closes: D7

## Context

Events need a stable envelope (FR-API-03) that consumers and tooling understand.

## Decision

- Every event is a CloudEvents 1.0 structured-mode JSON document; OCSF documents travel in `data` where applicable.
- ICUHUB extension attributes: `tenantid` and `correlationid`.
- Event types are named `icuhub.<resource>.<event>` (for example `icuhub.finding.upserted`).

## Consequences

- The envelope model lives in `icuhub-schemas` so consumers parse the same shape.

## Requirements affected

FR-API-03, NFR-11; HLD section 7.3.
