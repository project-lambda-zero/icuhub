# ADR-0015 -- Finding-to-ticket routing lives in ICUHUB

- Status: Accepted
- Date: 2026-11-07
- Closes: D13

## Context

Every consumer re-implements finding-to-ticket creation; none deduplicates reliably (INV-10..14).

## Decision

- ICUHUB implements routes, templates, field mapping, fingerprint-linked creation, fan-out with per-route results, and status synchronization (FR-TKT-02..07) on top of the `Tracker` primitives.
- Business prioritization (which findings deserve a ticket, deadlines) stays in consumers (FR-TKT-08).

## Consequences

- One dedupe rule for every consumer; a repeat request updates the linked ticket.
- Routing profiles are tenant data, reviewed against the non-goals so product logic does not move into ICUHUB (R13).

## Requirements affected

BR-16, FR-TKT-01..08, R13; ROADMAP P5.
