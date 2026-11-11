# ADR-0018 -- Connectors are first-party and run in-process

- Status: Accepted
- Date: 2026-11-07
- Closes: D16

## Context

The survey shows two runtime models: in-process registries for trusted first-party
code, and process or container isolation for third-party code (`PRIOR_ART.md` PA-07).
Out-of-process runtimes add a host protocol, supervision, and packaging, and matter
only when code from outside the project is loaded.

## Decision

- Every connector is first-party code in this repository, registered in the plain
  `CONNECTORS` dictionary (ADR-0002).
- Connectors run in-process: sync, action, and webhook work in worker processes;
  synchronous read operations in the API or worker process.
- ICUHUB does not load connector packages from outside the repository: no entry points,
  no plugin directories, no subprocess or container connector runtime.
- Contributed connectors arrive as pull requests and pass the same review, conformance,
  and fixture gates as maintainer-written ones.

## Consequences

- No plugin protocol, supervisor, or connector packaging format to build or secure.
- All connectors share one dependency lock set; connectors use the kit HTTP client
  instead of vendor SDKs where a vendor SDK would add conflicting dependencies.
- A misbehaving connector shares a process with others; budgets, timeouts, and
  cancellation in the SDK facade bound its impact.
- Supporting externally packaged connectors later requires a new ADR.

## Requirements affected

FR-CNR-18; `CONNECTOR_FRAMEWORK.md` section 9.1; ROADMAP P2, P10.
