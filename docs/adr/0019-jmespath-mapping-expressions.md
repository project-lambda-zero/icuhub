# ADR-0019 -- JMESPath for declarative field extraction in mappers

- Status: Accepted
- Date: 2026-11-07
- Closes: D17

## Context

Mappers turn parsed vendor records into OCSF models. Most of that work is field
extraction from nested JSON. The survey shows declarative extraction reduces code,
and also shows expression or template mappings drifting into unreviewable pipelines
(`PRIOR_ART.md` PA-20).

## Decision

- Mappers use JMESPath expressions for field extraction, through the `jmespath` package
  (MIT, 1.1.0 current at decision time, Python >= 3.9; version re-checked and pinned
  when P2 starts).
- Kit helpers cover enum tables, timestamp parsing, and constants; any other logic is
  Python in the mapper.
- Expressions are compiled when the connector module loads; only built-in JMESPath
  functions are allowed; no custom function registry.
- Expressions only extract. Type coercion and validation happen in the Pydantic OCSF
  models, so a shape mismatch raises `VendorContractError`.
- An expression change bumps the mapper version and its golden fixtures.

## Consequences

- New runtime dependency `jmespath` for the connector kit; it passes the license check
  (NFR-15).
- Mapping stays reviewable: short expressions next to typed models and golden fixtures.
- No jq or template language in the mapping path.

## Requirements affected

FR-NRM-07; `CONNECTOR_FRAMEWORK.md` section 6.1; `OPTIONS.md` section 17; ROADMAP P2.
