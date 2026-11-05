# ADR-0002 -- Capability protocols and a plain dict connector registry

- Status: Accepted
- Date: 2026-11-05

## Context

Connectors for many vendors must be interchangeable where they share a purpose (GitHub,
GitLab, and Bitbucket all open change requests) without forcing a lowest-common-denominator
interface or factory hierarchies. PR-Agent (MIT) solves the SCM case with a `GitProvider`
ABC and a plain dictionary from provider id to class.

## Decision

- Small, separate capability protocols (`SourceControl`, `CodeScanningSink`,
  `FindingSource`, `TelemetrySource`, `Enforcer`, `Containment`, `Tracker`, `BuildSystem`,
  `ClusterOps`, `ThreatIntel`). A connector implements only what the vendor supports.
- Built-in connectors are registered in one plain dict `CONNECTORS: dict[str, type[Connector]]`.
  No reflection or entry-point discovery for the built-in set.
- Vendor-specific operations are exposed next to capability operations.
- The SCM providers port PR-Agent's provider approach with attribution, decoupled from
  PR-Agent's settings and request context, and add the write side PR-Agent lacks
  (`create_branch`, `commit_patch`, `open_change_request`, `set_check_status`,
  `upload_sarif`).

## Consequences

- Consumers never branch on vendor for shared capabilities.
- No `NotImplementedError` stubs: optional behaviour is a separate protocol.
- Adding a vendor is one class plus one dict entry.

## Requirements affected

FR-CNR-01, FR-CNR-02, FR-CNR-03, BR-09.
