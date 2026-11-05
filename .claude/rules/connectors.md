---
paths:
  - "src/icuhub/connectors/**"
  - "packages/icuhub-connector-kit/**"
  - "fixtures/**"
---

# Connector rules

- One class per vendor product; register in `CONNECTORS` (plain dict).
- Implement only the capability protocols the vendor supports; no `NotImplementedError`.
- Every operation: `@operation(...)` with name, classification, egress class, idempotency,
  input and output schema.
- Use the connector-kit HTTP toolkit for retries, rate limits, pagination, auth. Never call
  `httpx` directly from a connector.
- Never read credentials yourself: the credential broker injects auth.
- Fixtures are sanitized vendor-shaped payloads with an expected OCSF output. A mapping is
  live only after the fixture proof and prove gate pass.
- Vendor ports, headers, and paths you are unsure of: mark them for confirmation in the PR,
  do not guess silently.
