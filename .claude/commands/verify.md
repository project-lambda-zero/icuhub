---
description: Run the ICUHUB verification set
---

Run, in order, and report each result:

```bash
python -m ruff check .
python -m compileall -q src
python -m pytest -q
```

`pytest` exit code 5 (no tests collected) is acceptable only while the repository has no
runtime code. Any other failure must be fixed before yielding.
