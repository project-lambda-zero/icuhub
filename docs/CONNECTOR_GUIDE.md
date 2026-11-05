# ICUHUB -- Connector Guide

How to add a vendor connector. The framework itself is designed in `docs/HLD.md`
section 5 and is built in Phase 2; this guide is the contract every connector follows.

## 1. Before writing code

| Step | Check |
|---|---|
| 1 | The vendor is listed in `docs/BRD.md` section 11 (integration catalog). If not, open a connector proposal issue first. |
| 2 | Every network flow the connector needs has a row in `docs/COMMATRIX.md` (on-prem `F-1xx`, SaaS `F-2xx`, webhooks `F-02x`). Add rows with new IDs; never renumber. |
| 3 | Pick the connector type: native, MCP-backed, or file parser (`docs/HLD.md` 5.4). |
| 4 | List the capability protocols the vendor supports (`docs/HLD.md` 5.1). Only those. |
| 5 | List every operation with classification, egress class, idempotency, input/output schema. Get the list reviewed. |

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

- [ ] Connector class with `kind`, `capabilities`, auth strategy, operations decorated with `@operation(...)`.
- [ ] Registered in `CONNECTORS` (plain dict).
- [ ] Uses the connector-kit HTTP toolkit (timeouts, retries only for idempotent operations or reads, rate limits, pagination, custom CA, proxy).
- [ ] Never reads secrets directly; auth comes from the credential broker.
- [ ] Vendor-specific operations exposed where agents need vendor depth.
- [ ] Normalization uses the shared schema package; unmapped fields null and listed; `actor.kind` from the vendor's documented field.
- [ ] Webhook verification implemented if the vendor pushes events (`docs/HLD.md` 7.4).
- [ ] Health check operation.
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
