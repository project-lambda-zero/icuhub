# ICUHUB -- GitHub Copilot Instructions

The canonical instructions are in `AGENTS.md` at the repository root. Follow them.

Key rules:

- ICUHUB is an integration hub only: connectors, credentials, policy, approvals, audit,
  OCSF/SARIF normalization. No AI/LLM code, no consumer business logic.
- Never return, log, or audit credentials.
- Every external call goes through the single pipeline (auth, tenant-scoped connection,
  policy, approval, credential injection, connector, normalize, audit).
- Connectors: one class per vendor, registered in the plain dict `CONNECTORS`; small
  capability protocols; no `NotImplementedError` stubs; every operation declares
  classification (`read`/`write`/`destructive`) and egress class.
- Unknown values are `null` / "not measured", never `0`.
- Specific exception types, `__all__` in every package, migrations for schema changes.
- No new dependencies and no choice for open decisions D1-D8 without the operator.
- Use `--` instead of em-dashes in prose.
