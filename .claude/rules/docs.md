---
paths:
  - "docs/**"
  - "*.md"
---

# Documentation rules

- Requirement IDs (`BR-*`, `FR-*`, `NFR-*`, `D*`, `R*`), flow IDs (`F-*`, `X-*`), and ADR
  numbers are stable. Never renumber; append new IDs.
- BRD, HLD, and COMMATRIX must stay consistent: a new operation or vendor that adds network
  traffic needs a COMMATRIX row; a new requirement referenced in HLD needs a BRD row.
- Mark unverified vendor facts as "confirm" and unmeasured numbers as "not measured".
- Neutral technical voice, `--` instead of em-dashes, no customer names or secrets.
