---
description: Run the ICUHUB verification set
---

Run, in order, and report each result:

```bash
python -m pip install -e ".[dev]" -e packages/icuhub-schemas
python -m ruff check .
python -m compileall -q src packages tools
python -m pytest -q packages/icuhub-schemas/tests tests
python tools/license_check.py
```

Any failure must be fixed before yielding.
