# ADR-0010 -- First-wave connectors

- Status: Accepted
- Date: 2026-11-07
- Closes: D8
- Amended by: ADR-0020

## Context

Wave 1 must serve the first consumers and the approval path.

## Decision

- Wave 1: GitHub, GitLab, Jira (several instances per tenant), F5 BIG-IP, Google Threat Intelligence, and an SMTP notifier for approval notifications.

## Consequences

- The SMTP notifier is built with the entry points (ROADMAP P4) because approvals depend on it; the vendor connectors are built in P5.

## Requirements affected

BRD section 11; FR-NTF-01..04; ROADMAP P4, P5.
