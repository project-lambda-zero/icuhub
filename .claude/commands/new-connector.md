---
description: Add a new vendor connector following the ICUHUB connector checklist
argument-hint: <vendor-kind>
---

Add a connector for `$ARGUMENTS`.

1. Read `AGENTS.md` sections 5.2-5.4 and `docs/CONNECTOR_GUIDE.md` in full.
2. Confirm the connector is in the integration catalog (`docs/BRD.md` section 11). If not,
   stop and ask the operator to add it there first.
3. Confirm the network flows exist in `docs/COMMATRIX.md`. If not, add the flow rows (new
   `F-*` IDs, never renumber) and say so in your summary.
4. List the operations you will implement with classification, egress class, idempotency,
   and input/output schemas. Show the list before writing code.
5. Implement the connector class, register it in `CONNECTORS`, add sanitized fixtures and
   expected OCSF outputs, and the fixture proof (replay + prove gate).
6. Run `/verify`.
7. Summarize: operations added, flows touched, fixtures added, anything unverified against
   current vendor documentation.
