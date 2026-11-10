# ICUHUB -- Connector Guide

How to add a vendor connector. The framework itself is designed in `docs/HLD.md`
section 5 and `docs/CONNECTOR_FRAMEWORK.md`, and is built in Phase 2; this guide is the
contract every connector follows. Connectors are first-party code in this repository
(ADR-0018).

## 1. Before writing code

| Step | Check |
|---|---|
| 1 | The vendor is listed in `docs/BRD.md` section 11 (integration catalog). If not, open a connector proposal issue first. If `docs/VENDOR_CONNECTORS.md` has a spec for the vendor, start from it and resolve its section 9 open questions. |
| 2 | Every network flow the connector needs has a row in `docs/COMMATRIX.md` (on-prem `F-1xx`, SaaS `F-2xx`, webhooks `F-02x`). Add rows with new IDs; never renumber. |
| 3 | Pick the connector type: native, MCP-backed, or file parser (`docs/HLD.md` 5.4). |
| 4 | List the capability protocols the vendor supports (`docs/HLD.md` 5.1). Only those. |
| 5 | List every operation with classification, egress class, idempotency, input/output schema. Get the list reviewed. |
| 6 | List the streams (one OCSF class each), their cursor kind, and whether the vendor supports complete snapshots (`CONNECTOR_FRAMEWORK.md` section 5). |
| 7 | List the vendor scopes each stream, operation, and action needs, with a cheap probe request for each (FR-CON-09). |

## 2. Operation table template

| Operation | Capability | Classification | Egress class | Idempotent | Input | Output | Vendor endpoint |
|---|---|---|---|---|---|---|---|
| `list_virtual_servers` | (vendor-specific) | read | vendor_tenant | yes | `Empty` | `VirtualServerList` | `GET /mgmt/tm/ltm/virtual` |
| `block` | Enforcer | destructive | vendor_tenant | yes | `BlockInput` | `BlockResult` | data-group / address-list update |

Classification guide:

| Classification | Meaning | Examples |
|---|---|---|
| `read` | No state change in the vendor system | list, get, search, pull findings |
| `write` | Creates or changes state that is reversible and low impact | comment, open ticket, open draft PR, set check status |
| `destructive` | Changes enforcement, availability, or security posture, or is hard to reverse | block IP, isolate host, delete, merge, change WAF policy, trigger production deploy |

Egress class guide:

| Egress class | Meaning |
|---|---|
| `internal` | Data stays inside the customer network |
| `vendor_tenant` | Data goes to the customer's own tenant of a SaaS product |
| `third_party_shared` | Data may join a dataset shared beyond the customer (for example public threat-intel corpus queries) |

## 3. Implementation checklist

- [ ] Connector class with `kind`, `version`, `sdk`, `owner`, `support`, `config` (secrets typed `SecretRef`), and auth strategies.
- [ ] Reads as `@operation`, ingestion as `@stream` plus `@mapper`, writes and destructive changes as `@action` with `plan` and `apply`, pushes as `@webhook` sharing the stream mapper.
- [ ] Every member declares `stability`; scopes declared with probes.
- [ ] `check` returns per-capability health and `not_evaluated` for missing scopes; `discover` yields targets with stable source IDs.
- [ ] Errors raised from the typed taxonomy (`CONNECTOR_FRAMEWORK.md` section 3.4), never generic exceptions for vendor states.
- [ ] Registered in `CONNECTORS` (plain dict); `manifest.json` regenerated and committed (ADR-0017).
- [ ] Uses the connector-kit HTTP toolkit (timeouts, retries only for idempotent operations or reads, rate limits, pagination, custom CA, proxy).
- [ ] Never reads secrets directly; auth comes from the credential broker.
- [ ] Vendor-specific operations exposed where agents need vendor depth.
- [ ] Parse and map are separate; mapper versioned; JMESPath expressions for extraction only (ADR-0019); unmapped vendor fields in `unmapped`; `actor.kind` from the vendor's documented field.
- [ ] Source record ID, fingerprint inputs (no mutable fields), and `AssetRef` for resources defined (`CONNECTOR_FRAMEWORK.md` section 6).
- [ ] Webhook verification implemented if the vendor pushes events (`docs/HLD.md` 7.4).
- [ ] Conformance suite and HTTP contract cassettes pass; `core` tier also passes live acceptance (`ICUHUB_ACC=1`) before release.
- [ ] MCP-backed: every upstream tool classified; unclassified tools hidden.

## 4. Fixture proof (earned-executable)

For each mapping:

1. `fixtures/<kind>/<case>.json`: sanitized vendor-shaped payload (from vendor docs or a scrubbed real response; no customer data).
2. `fixtures/<kind>/<case>.expected.ocsf.json`: expected normalized output.
3. Replay test: payload through the real connector + normalizer equals the expected output.
4. Prove gate: with the mapping reverted, the expected output is not produced.
5. A mapping is reported live only when both pass.

## 5. Pull request

- Cite BRD/FR IDs and COMMATRIX flow IDs.
- List anything not verified against current vendor documentation (ports, header names, paths, API versions).
- `CHANGELOG.md` entry under `Unreleased`.

## 6. Runtime implementation rules (verified in this repository)

- **Target scope**: `StreamSpec.requires_target` defaults to `True`. Connection-wide streams MUST declare `requires_target=False`. When a target-scoped stream runs without an explicit target, the sync engine calls `discover()` and executes once per discovered target, each with its own `stream_state`, `sync_run`, and checkpoint. Connectors without a `discover()` override run once with a null target.
- **Target objects**: streams receive a kit `Target` (`source_uid`, `kind`, `display_name`, `attributes`), never the ORM row. `TargetRecord.attributes` is persisted as `target.attributes_json`.
- **OCSF classes without shared models**: `icuhub_schemas` types only part of OCSF 1.9.0 (see GAP-SCHEMA-001). For every other class emit kit `SourceRecord` whose `data` is the full OCSF-shaped JSON including `class_uid`; never create connector-local OCSF model classes, because core treats non-`SourceRecord` mapper output as findings.
- **Non-HTTP connectors**: set `uses_http = False` (for example SMTP). The runtime and `kit.testing.make_connector` then skip HTTP client creation; `self.http` raises if touched.
- **Login calls inside an auth strategy**: use `VendorHttp.request(..., authenticate=False)`. This skips `_auth.apply` and the 401 refresh, so `SessionLogin` cannot deadlock on its own lock. It is only for the strategy's login request.
- **Sync and replay modes**: scheduler jobs use `incremental` and `full`. Core raw-batch replay remains separate from scheduler execution. A deterministic file-backed stream MAY also declare `replay` when its DoD requires replaying the original artifact through the same parser and snapshot identity. Receiver-only streams declare `event`; their stream function rejects direct pulls because verified webhook deliveries drive them.
- **Authoritative webhook reconciliation**: a parser can emit `StreamRecord(..., reconcile="incremental"|"full")` for a hint-only delivery. The webhook worker enqueues that canonical stream instead of mapping the hint. Use this for configurable payloads that must not replace authoritative REST reads; persist any required receipt metadata through a separate event stream.
- **Test module names**: pytest imports test files by basename. `tests/connectors/<kind>/test_<x>.py` and `tests/acceptance/test_<x>.py` collide when the basenames match, so connector test files use `test_<kind>_connector.py`, `test_<kind>_actions.py`, and similar distinct names.
- **Gap log**: implementation unknowns and live-only checks go to `docs/IMPLEMENTATION_GAPS.md` (append-only IDs). Missing required implementation is not a gap; finish it.
