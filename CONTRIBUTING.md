# Contributing to ICUHUB

1. Read `AGENTS.md`. Its rules apply to humans and AI agents alike.
2. Branch from `dev` (`feat/*`, `fix/*`, `docs/*`) and open the PR against `dev`.
3. Cite requirement and flow IDs (`FR-*`, `F-*`) in the PR description.
4. Run the verification set (`AGENTS.md` section 7) before opening the PR.
5. New connectors follow `docs/CONNECTOR_GUIDE.md` and start with a connector proposal
   issue.
6. New dependencies not named in an accepted ADR, and new decisions (D22 onward), need maintainer approval before code.
7. Add a `CHANGELOG.md` entry under `Unreleased` for observable changes.
