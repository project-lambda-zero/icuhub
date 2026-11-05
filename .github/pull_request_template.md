## Summary

<!-- What changes and why. -->

## Requirements and flows

<!-- Cite IDs: BR-*, FR-*, NFR-*, F-*, ADR-NNNN. -->

## Checklist

- [ ] `python -m ruff check .`
- [ ] `python -m compileall -q src`
- [ ] `python -m pytest -q`
- [ ] No credentials in code, fixtures, logs, or tests
- [ ] Every new operation declares classification, egress class, idempotency, schemas
- [ ] New network traffic has `docs/COMMATRIX.md` rows
- [ ] No new dependency or open-decision choice without maintainer approval
- [ ] `CHANGELOG.md` updated under `Unreleased` (observable changes)

## Not verified

<!-- Vendor ports, headers, paths, API versions not checked against current vendor docs. -->
