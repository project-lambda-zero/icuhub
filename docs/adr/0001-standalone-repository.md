# ADR-0001 -- ICUHUB is a standalone repository and service

- Status: Accepted
- Date: 2026-11-05

## Context

Several enterprise platforms need the same vendor integrations: the AI security platform
(AILA), a posture management console, and other hubs. Options considered:

| Option | Summary |
|---|---|
| A | Integrations inside the AILA platform package |
| B | Separate package inside the AILA repository with a strict import boundary |
| C | Separate repository and service |
| D | Buy a managed integration platform |

## Decision

Option C. ICUHUB is its own repository (`project-lambda-zero/icuhub`, AGPL-3.0) and its own
deployable service, not bound to the AILA codebase or brand. Consumers integrate through
REST, MCP, events, and webhooks only. AILA includes the repository as an optional git
submodule at `external/icuhub`.

## Consequences

- One implementation per vendor, one credential store, one policy and audit point for all
  consumers.
- Costs accepted: service-to-service auth, versioned contracts (REST, MCP tool names,
  events, schema package), a separate release train. Mitigations in `docs/BRD.md` R1-R2.
- Consumers must not call integrated vendors directly (`docs/COMMATRIX.md` X-01).

## Requirements affected

BR-01, BR-02, BR-03, BR-09; NFR-11.
