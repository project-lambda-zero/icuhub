# ADR-0011 -- Remote host execution stays in consumers

- Status: Accepted
- Date: 2026-11-07
- Closes: D9

## Context

The integration inventory shows SSH command execution and SFTP transfer in two consumers (INV-40..48). ICUHUB could own it as a `HostAccess` capability or leave it with the consumers.

## Decision

- ICUHUB does not execute commands or transfer files on managed hosts. Consumers keep their own SSH stacks.
- Results that consumers collect from hosts can still enter ICUHUB through result-file ingestion (FR-ING-06).
- BR-15, FR-RX-01..10, and NFR-17 are withdrawn; their IDs stay reserved.

## Consequences

- Host-key pinning, command approval, and audit for SSH remain consumer responsibilities; the inventory lists them as consumer hardening items.
- ROADMAP P7 covers only the scan platform's ticketing and result ingestion.

## Requirements affected

BR-15, FR-RX-*, NFR-17 (withdrawn), NG13; INTEGRATION_INVENTORY section 4.4; ROADMAP P7.
