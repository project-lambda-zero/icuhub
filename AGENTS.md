# ICUHUB -- Agent Instructions (canonical)

This file is the single source of truth for every AI coding agent (Claude Code, Codex,
Copilot, Cursor, Gemini, others) and for humans. Tool-specific files (`CLAUDE.md`,
`GEMINI.md`, `.github/copilot-instructions.md`, `.cursor/rules/`) only point here and add
tool-specific notes. If they disagree with this file, this file wins.

## 1. What ICUHUB is

ICUHUB is a standalone integration service. It connects enterprise security,
engineering, and IT tools (SCM, CI/CD, SAST/SCA/DAST, vulnerability scanners, SIEM,
SOAR, EDR, WAF, DLP, CSPM/CNAPP, Kubernetes/OpenShift, ticketing, threat intelligence)
once, and exposes them to every internal platform (AILA, posture management console,
other hubs) through one governed, audited path.

Four entry points: REST API, MCP endpoint (for AI agents), event stream, webhook ingress.
Internal parts: connectors, connection store, credential broker, policy + approvals,
audit, OCSF/SARIF normalization.

## 2. What ICUHUB is NOT

- Not an AI system: no agents, prompts, LLM calls, or reasoning. Those belong to consumers.
- Not a SIEM, SOAR, data lake, or telemetry store.
- Not a product with branding work. It is an integration hub.
- Not a lowest-common-denominator "unified API": vendor-specific operations stay available.
- Not a place for consumer business logic.

## 3. Status

**Phase 1 (`docs/ROADMAP.md`).** Decisions D1-D17 are closed. The shared schema package
`packages/icuhub-schemas` (OCSF 1.9.0, SARIF 2.1.0, CloudEvents envelope, finding
fingerprint) and the CI license check exist. The service itself (`src/icuhub`) has no
runtime code yet. Do not describe features as implemented until they are.

| Document | Content | IDs to cite |
|---|---|---|
| `docs/BRD.md` | Business requirements, scope, risks, decisions | `BR-*`, `FR-*`, `NFR-*`, `NG*`, `D1`-`D17`, `R1`-`R13` |
| `docs/HLD.md` | Architecture, data model, APIs, MCP, events, connector framework, roadmap | section numbers |
| `docs/COMMATRIX.md` | Every network flow | `F-*`, `X-*` |
| `docs/INTEGRATION_INVENTORY.md` | Integrations found in existing consumers and their ICUHUB disposition | `INV-*` |
| `docs/OPTIONS.md` | Technology options per concern and the decision outcomes | section numbers |
| `docs/ROADMAP.md` | Delivery phases P0-P10, each run as brainstorm, write, plan, implement, test | `P*`, `R-*` |
| `docs/PRIOR_ART.md` | How comparable security, DevOps, and platform projects implement integrations; cross-cutting lessons | `PA-*`, `AP-*` |
| `docs/CONNECTOR_FRAMEWORK.md` | Connector contract, manifest, sync engine, mapping, identity, actions, testing kit | section numbers |
| `docs/VENDOR_CONNECTORS.md` | Per-vendor API facts and connector specs (SCM, Atlassian, Kubernetes/OpenShift, Prisma Cloud, Fortify, Invicti, Mend, Qualys, Tenable) | connector kind IDs |
| `docs/CONNECTOR_GUIDE.md` | How to add a connector | checklist |
| `docs/adr/` | Architecture decision records | `ADR-NNNN` |

Commit messages, PR descriptions, and code comments that implement a requirement cite its
ID (for example `FR-POL-03`, `F-100`).

## 4. Decisions: do not resolve them yourself

`docs/BRD.md` section 18 records decisions D1-D17, all closed by ADR-0004..0019. Any new
choice with real tradeoffs (a new dependency, a new engine, a scope change) is appended
there as D18 onward with options and a recommendation. An agent MUST NOT pick an option,
add a dependency that implies an option, or write code that assumes one. Ask the
operator. When a decision is made, record it as an ADR in `docs/adr/` and update BRD
section 18. A dependency named in an accepted ADR may be added when its phase starts.

## 5. Hard rules

### 5.1 Boundaries
1. ICUHUB never imports from any consumer codebase (`aila`, posture console, others).
2. ICUHUB contains no AI/LLM code.
3. Consumers never receive vendor credentials. Credentials are never returned by any API,
   never logged, never written to audit, events, errors, or traces.
4. Every external call goes through the one pipeline: authenticate -> resolve connection
   (tenant-scoped) -> policy -> approval if required -> credential injection -> connector
   -> normalize -> audit -> respond / publish. No side paths.
5. High-volume telemetry never flows through the REST API (stream only).

### 5.2 Connector design
1. One connector class per vendor product. Register it in the plain dict `CONNECTORS`.
   No reflection, entry-point scanning, or dynamic discovery for the built-in set.
2. Capability protocols are small and separate (`SourceControl`, `FindingSource`,
   `Enforcer`, `Tracker`, ...). A connector implements only what the vendor supports.
   Never write `raise NotImplementedError` stubs to satisfy a protocol.
3. Every operation declares: name, input schema, output schema, classification
   (`read` | `write` | `destructive`), egress class (`internal` | `vendor_tenant` |
   `third_party_shared`), idempotency.
4. Vendor-specific operations are welcome next to capability operations.
5. A mapping is live only after its fixture proof passes (replay produces expected OCSF;
   prove gate with the mapping reverted produces nothing). See `docs/CONNECTOR_GUIDE.md`.
6. MCP-backed connectors (upstream vendor MCP servers) must classify every upstream tool;
   unclassified tools stay hidden.

### 5.3 Policy and actions
1. Write and destructive operations execute automatically only when all three switches are
   on (deployment, tenant, rule). Defaults are off. Otherwise preview or approval.
2. Approvals are durable, expire with a recorded outcome, and can never be self-approved by
   the requesting service.
3. `mode=replay` can never execute a write or destructive operation.
4. Action state transitions are an explicit state machine (`docs/HLD.md` 6.3). No implicit
   flow through nested conditionals.

### 5.4 Data and normalization
1. All normalized output uses the shared schema package (OCSF; SARIF 2.1.0 for code
   findings). No ad-hoc output shapes.
2. Fields without a vendor source stay null and are listed as unmapped. Never invent
   defaults.
3. `actor.kind` and similar classification fields come from the vendor's documented field,
   never inferred.
4. Unknown or unmeasured values are reported as "not measured" / "unknown", never as `0`
   or `ok`.

### 5.5 Code quality
1. Python 3.11+, `ruff` clean, type hints on public functions.
2. Catch specific exception types. No bare `except Exception` that swallows errors.
3. Every package `__init__.py` and public module declares `__all__`. Underscore-prefixed
   private modules omit it.
4. Configuration through one settings module. No scattered `os.getenv` calls.
5. Schema changes only through migrations. No runtime `CREATE TABLE`, no
   `metadata.create_all()` outside tests.
6. No dead code, no compatibility shims, no alias fields. Clean cutover: when you replace
   something, migrate every caller and delete the old path.
7. No forwarding wrappers, fake managers, or string-mirroring constants.
8. No new third-party dependency without the operator's explicit approval in the current
   conversation. Never substitute a different library for one that was specified.

### 5.6 Tests
1. Tests cover behaviour: policy decisions, state transitions, boundaries, errors,
   normalization output, signature verification.
2. No tests that only check wiring, mock echoes, source text, or "does not throw".
3. Connector mappings are tested through fixtures, not by mocking the connector itself.

### 5.7 Writing
1. Neutral technical voice in docs, changelog, commits.
2. Use `--` instead of em-dashes.
3. No customer names, private identifiers, or secrets in docs, fixtures, or tests. Fixtures
   are sanitized.

## 6. Repository layout (target, see `docs/HLD.md` section 3)

```
icuhub/
├── docs/                      # BRD, HLD, COMMATRIX, INTEGRATION_INVENTORY, OPTIONS, PRIOR_ART, CONNECTOR_FRAMEWORK, VENDOR_CONNECTORS, ROADMAP, CONNECTOR_GUIDE, adr/
├── packages/
│   ├── icuhub-schemas/        # OCSF models, SARIF codec, CloudEvents envelope (P1)
│   ├── icuhub-sdk/            # generated client (P3)
│   └── icuhub-connector-kit/  # protocols, HTTP toolkit, fixture harness (P2)
├── src/icuhub/                # api/, core/, connectors/, parsers/, collectors/, workers/, storage/
├── fixtures/                  # vendor-shaped payloads + expected outputs
├── deploy/helm/icuhub/        # Kubernetes / OpenShift chart
└── tests/
```

Only create a directory when you put real content in it.

## 7. Build and verify

```bash
python -m pip install -e ".[dev]" -e packages/icuhub-schemas
python -m ruff check .
python -m compileall -q src packages tools
python -m pytest -q packages/icuhub-schemas/tests tests
python tools/license_check.py   # runtime dependency licenses (NFR-15)
```

All must pass before you yield or open a PR. While developing a step, run only the tests
for the code you changed (`docs/ROADMAP.md` section 1).

`icuhub-schemas` is versioned independently of the service (BRD R2): its version lives in
`packages/icuhub-schemas/pyproject.toml` and `icuhub_schemas/__init__.py`.

## 8. Git workflow and versioning

- `main` holds released state. `dev` is the integration branch. Work on `dev` or on
  short-lived `feat/*` / `fix/*` branches from `dev`, merged back through PRs.
- Release: PR `dev -> main`, merge, then tag `vX.Y.Z` on the merge commit.
- Semantic versioning. Stay on `0.0.x` PATCH bumps until the operator says otherwise.
  Version lives in `pyproject.toml` and `src/icuhub/__init__.py` (bump both in lockstep).
- `CHANGELOG.md` follows Keep a Changelog; describe observable behaviour, not the diff.
- Stage explicit paths. Never `git add -A`.

## 9. Consumers

ICUHUB is consumed as an optional dependency. AILA includes this repository as a git
submodule at `external/icuhub` and integrates through the contract in `docs/HLD.md`
section 15 (AILA RFC-296). Changes to REST, MCP tool naming, event topics, or
`icuhub-schemas` are contract changes: version them (`docs/HLD.md` section 14) and note
them in `CHANGELOG.md`.
