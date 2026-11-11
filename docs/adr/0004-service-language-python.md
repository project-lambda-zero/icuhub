# ADR-0004 -- Service language is Python 3.11+

- Status: Accepted
- Date: 2026-11-07
- Closes: D1

## Context

ICUHUB needs one implementation language for the service, the connector kit, and the shared schema package. The first consumers are Python services, and the prior art ICUHUB copies (PR-Agent provider registry, DefectDojo parsers) is Python.

## Decision

- The service, the connector kit, and `icuhub-schemas` are written in Python 3.11 or later.
- Consumers in other languages use the REST API, the MCP endpoint, or a generated client.

## Consequences

- Consumers in Python import `icuhub-schemas` directly and share one model of OCSF and SARIF.
- Throughput-critical collectors (P10) are measured before any second language is considered; that would be a new ADR.

## Requirements affected

BRD section 13, D1; HLD section 3.
