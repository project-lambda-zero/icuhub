---
description: Record an architecture decision
argument-hint: <title>
---

Record the decision "$ARGUMENTS".

1. Only proceed if the operator made the decision in the current conversation. Quote the
   decision in your summary (not in the ADR).
2. Create `docs/adr/NNNN-<kebab-title>.md` with the next number, using the format of the
   existing ADRs: Status, Date, Context, Decision, Consequences, Requirements affected.
3. If it closes an open decision (D1-D8), update `docs/BRD.md` section 18 (mark the row
   decided and link the ADR) and any `[decision Dx]` markers in `docs/HLD.md` and
   `docs/COMMATRIX.md`.
4. Add an entry to `CHANGELOG.md` under `Unreleased`.
