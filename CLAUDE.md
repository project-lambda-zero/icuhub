# ICUHUB -- Claude Code Instructions

@AGENTS.md

The imported `AGENTS.md` is canonical. This file only adds Claude Code specifics.

## Claude Code specifics

- Slash commands in `.claude/commands/`:
  - `/new-connector <vendor>` -- walk the connector checklist in `docs/CONNECTOR_GUIDE.md`.
  - `/verify` -- run the full verification set from `AGENTS.md` section 7.
  - `/adr <title>` -- record a decision as a new ADR and update `docs/BRD.md` section 18.
- Path-scoped rules live in `.claude/rules/` and load for matching files.
- Before editing a design document, read the section you change and keep requirement IDs
  stable. Never renumber existing IDs; append new ones.
- Before adding a dependency or choosing an option for D1-D8, ask the operator.
- Use subagents for broad exploration; keep edits in the main session reviewable.
