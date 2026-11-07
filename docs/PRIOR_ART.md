# ICUHUB -- Prior Art

| Field | Value |
|---|---|
| Document | Prior art for connector packaging, synchronization, mapping, actions, and operations |
| Status | v0.1 |
| Date | 2026-11-07 |
| Inputs | Research on public primary sources: official documentation, source files, tests, release notes, and issue trackers |
| Feeds | `CONNECTOR_FRAMEWORK.md` |

---

## 1. Scope and method

This survey compares how public projects package integrations, isolate execution, define
host contracts, persist synchronization state, normalize data, and test changes. It covers
51 projects and protocol families in eight domains. Hosted products are included only
where their public API or configuration contract provides useful implementation evidence.

| Domain | Projects | Main design questions |
|---|---:|---|
| Vulnerability aggregation and ASPM | 8 | Report import, target mapping, reconciliation, finding identity |
| Threat intelligence | 3 | Connector services, feed deltas, typed plugin configuration |
| SOAR | 6 | Action manifests, assets, registries, analyzer and responder isolation |
| Data pipelines and security data lakes | 7 | Stream protocols, checkpoints, OCSF/ECS mapping, golden tests |
| Posture and MCP gateways | 8 | Query plugins, posture checks, scoped limits, gateway security |
| Developer portals | 4 | Entity identity, catalog reconciliation, mapping ownership, actions |
| CI/CD and IaC | 8 | Process isolation, plan/apply, package revisions, schema migration |
| Operations automation | 7 | Module protocols, telemetry components, alert identity, delivery |

Method and limits:

1. Only primary sources linked by the research are cited. Project marketing is not used as
   evidence for protocol behavior when source, schema, tests, or operator docs are available.
2. Repository links to `main`, `master`, `dev`, or `latest` describe the revision reviewed
   on 2026-11-07. They are moving references and must be pinned at adoption.
3. A missing feature in a cited public contract is not proof that a whole product lacks it.
4. Claims not confirmed by the research are marked `[UNVERIFIED]`; material dependencies
   are collected in section 6 for re-checking before implementation.
5. Vector and Fluent Bit were considered in the pipeline research but excluded from full
   comparison because no comparable native OCSF manifest/mapping contract was confirmed.
6. The comparison separates file import, live API synchronization, notification delivery,
   ticket synchronization, and governed writes. These are not interchangeable lifecycles.
7. ICUHUB borrows design ideas only unless the exact artifact license permits code reuse.
   Permissive code still requires notices; mixed repositories require subtree review.
   ELv2, proprietary, unlicensed, and unclear artifacts are ideas-only by default. See
   section 5 and the per-connector provenance rule in PA-06.

Table cells are deliberately terse. "Not specified" refers to the reviewed public
contract, not to private implementations. License entries identify the artifact inspected,
not every component distributed under the same project name.

## 2. Projects surveyed

### 2.1 Vulnerability aggregation and ASPM

This domain contrasts in-process parser registries with public commercial configuration
APIs. Snapshot absence, source identity, and target lifecycle are the important fault lines.

| Project | Integration unit | Isolation | Contract / lifecycle | State and sync | Mapping and identity | Testing | License | Key source |
|---|---|---|---|---|---|---|---|---|
| DefectDojo | Python parser in Django app | In-process, shared instances | `get_findings`; import vs reimport | Complete-report reconciliation; close/reactivate | Python to `Finding`; configurable dedup | Report fixtures and field assertions | BSD-3-Clause | [Parser factory](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/tools/factory.py) |
| Faraday plugins | Python plugin package | In-process parser; Docker agents for execution | Detect, parse report/output | One report/run; local caches only | Python host/service/vuln model; extension fields | External report corpus and hashes | GPL-3.0 | [Plugin base](https://raw.githubusercontent.com/infobyte/faraday_plugins/master/faraday_plugins/plugins/plugin.py) |
| OWASP Dependency-Track | Java uploader or notification publisher | In-process | BOM ingest; scheduled upload; notify | Async analysis; periodic uploads | CycloneDX first; Java transformers; UUID matrix | WireMock publisher contracts | Apache-2.0 | [Integration sources](https://github.com/DependencyTrack/dependency-track/tree/master/src/main/java/org/dependencytrack/integrations) |
| SecObserve | Python file/API parser | In-process; optional scanner image | `check_connection`; `get_observations` | Transactional snapshot resolve/reopen | SARIF/CycloneDX/OCSF plus Python; raw evidence | Parser fixtures and import-service tests | BSD-3-Clause | [Base parser](https://raw.githubusercontent.com/SecObserve/SecObserve/dev/backend/application/import_observations/parsers/base_parser.py) |
| ArcherySec | Python parser registry; bespoke scanner connectors | In-process Django | Upload and dispatch; custom live scans | New scan snapshots; custom polling | Direct ORM writes; parser-local hashes | API tests; separate sample corpus | GPL-3.0-only | [Parser registry](https://raw.githubusercontent.com/archerysec/archerysec/master/scanners/scanner_parser/scanner_parser.py) |
| Phoenix Security | Configured scanner connection and capability | Public runtime not specified | Validate, discover targets, collect | Include/exclude, pause, missing-target aging | Public asset/vuln views; internals private | Credential and capability validation | Commercial; ideas only | [Scanner management](https://kb.phoenix.security/?ht_kb=scanner-integration-management) |
| ArmorCode | Public beta Python API SDK | SDK client; connector runtime private | Login, project discovery, product mapping | Last/next/failure metadata; mixed pagination | Product mappings; `additionalDetails` | Usage examples; beta, unstable API | UNLICENSED | [Login and mapping API](https://raw.githubusercontent.com/armor-code/acsdk/main/acsdk/logins/USAGE.md) |
| Apiiro | Guardian CLI and remote MCP manifest | Local CLI; hosted MCP | Scan, risk query/update, doctor | Bounded pages; async scan IDs | Public risk profile; aggregation internals private | Checksums, doctor; fail-open CI policy | Mixed Apache/MIT/EULA artifacts | [Marketplace contract](https://raw.githubusercontent.com/apiiro/marketplace/main/README.md) |

### 2.2 Threat intelligence

The three designs separate connector containers, a shared module service, and database-
configured worker plugins. Their state and testing guarantees differ substantially.

| Project | Integration unit | Isolation | Contract / lifecycle | State and sync | Mapping and identity | Testing | License | Key source |
|---|---|---|---|---|---|---|---|---|
| OpenCTI connectors | Standalone connector service/container | Process/container per connector | Import, enrich, file, export, stream; work records | Arbitrary JSON state; backlog-aware schedule | Python to STIX 2.1; deterministic SDK IDs | Changed-connector CI and custom tests | Apache-2.0 with subtree overrides | [Connector guide](https://docs.opencti.io/latest/development/connectors/) |
| MISP / misp-modules | Python expansion/import/export module | Shared Tornado process and thread pool | `handler`, introspection, version; separate feeds/TAXII | Stateless modules; feed delta and background jobs | Python MISP/STIX maps; UUID guidance | Service CI with some live providers | AGPL-3.0 | [Module contract](https://raw.githubusercontent.com/MISP/misp-modules/master/README.md) |
| IntelOwl | Python plugin plus DB configuration | Worker process; optional analyzer container | `Plugin.start`; analyzer, connector, pivot, ingestor | Job retry; scheduled ingestors; no common cursor | Raw reports; dotted-path DataModel mapping | Mocked unit-test bases; service CI | AGPL-3.0 | [Plugin lifecycle](https://raw.githubusercontent.com/intelowlproject/IntelOwl/master/api_app/classes.py) |

### 2.3 SOAR

Packs and apps carry both action schemas and operator configuration. Container boundaries,
registry pinning, and support-tier test depth vary by ecosystem.

| Project | Integration unit | Isolation | Contract / lifecycle | State and sync | Mapping and identity | Testing | License | Key source |
|---|---|---|---|---|---|---|---|---|
| Cortex XSOAR content | Content Pack and integration directory | Declared Docker image | `test-module`, commands, fetch, mirror | Server `lastRun`; lookback and mirror state | Incidents, context, `rawJSON`; classifiers/mappers | SDK validation, mocked pytest, playbooks | MIT content | [Fetch contract](https://xsoar.pan.dev/docs/integrations/fetching-incidents) |
| Splunk SOAR apps | Python app with JSON manifest | Imported connector; action isolation not established | Initialize, dispatch, finalize; poll/test | Per-asset saved state; connector pagination | Containers/artifacts, CEF, source IDs | Static matrix; support-tier functional tests | Apache-2.0 for inspected app | [ZeroFox manifest](https://raw.githubusercontent.com/splunk-soar-connectors/zerofoxalerts/main/zerofox.json) |
| TheHive/Cortex | Analyzer or responder flavor | Optional disposable Docker worker | One job, full/summary report, operations | One-shot; no standard cursor | Arbitrary full JSON; artifacts and taxonomies | Review, pinned deps, image build CI | AGPL-3.0 with worker overrides | [Worker protocol](https://docs.strangebee.com/cortex/operations/input-output/) |
| Shuffle apps | Versioned Python app and `api.yaml` | Fresh container per action | AppBase methods; generated OpenAPI apps | Action/workflow owned; no standard cursor | JSON/string results; workflow expressions | Standalone execution and SDK pytest | AGPL platform; MIT apps/SDK | [App guide](https://raw.githubusercontent.com/Shuffle/shuffle-docs/master/docs/apps.md) |
| Tracecat | Python UDF or YAML action in Git registry | Subprocess or `nsjail` | Typed async action; workflow orchestration | Workflow-owned; bounded HTTP helpers | Typed inputs, arbitrary JSON, expressions | Local tests; registry import/version diff | AGPL-3.0 plus separate EE paths | [Custom registry](https://docs.tracecat.com/custom-actions/custom-registry) |
| StackStorm | Pack with actions, sensors, rules | Pack virtualenv; sensor per process | Action `run`; sensor `setup/run/cleanup` | Sensor-local string datastore | Trigger payloads; Jinja rules; action JSON | Pack fixtures and base test cases | Apache-2.0 core; packs vary | [Pack anatomy](https://docs.stackstorm.com/latest/reference/packs.html) |

### 2.4 Data pipelines and security data lakes

These projects provide the strongest checkpoint and golden-fixture evidence. Their canonical
models differ: arbitrary JSON streams, ECS, OCSF, Parquet, or vendor-specific schemas.

| Project | Integration unit | Isolation | Contract / lifecycle | State and sync | Mapping and identity | Testing | License | Key source |
|---|---|---|---|---|---|---|---|---|
| Airbyte | Source/destination actor or declarative manifest | Container per actor | `spec`, `check`, `discover`, `read`, `write` | Per-stream state; destination acknowledgement | JSON Schema streams; primary-key dedup | Connector acceptance suite; support tiers | MIT protocol/CDK; ELv2 connectors | [Airbyte protocol](https://docs.airbyte.com/platform/understanding-airbyte/airbyte-protocol.md) |
| Singer / Meltano SDK | Tap and Target executables | Separate processes; usual per-app virtualenv | Discover/sync; JSONL schema, record, state | Tap-owned bookmarks; target ack; at least once | Arbitrary JSON; key and bookmark properties | SDK runners; no base-spec certification | Spec grant unclear; SDK grants unverified | [Singer specification](https://raw.githubusercontent.com/singer-io/getting-started/master/docs/SPEC.md) |
| Elastic integrations | Versioned package of Agent and Stack assets | Agent inputs; in-Stack pipelines | Validate, publish, install, collect, ingest | Input-specific cursor and polling | ECS ingest pipelines; optional original event | Golden pipeline tests; system matrix | Elastic License / ELv2 by artifact | [Package specification](https://raw.githubusercontent.com/elastic/package-spec/main/README.md) |
| Amazon Security Lake | External OCSF Parquet producer | Producer-managed; AWS destination | Register source; batch and write objects | Object partitions; producer-owned replay | Pre-delivery OCSF, one class per object | AWS validation tool recommendation | Proprietary service; OCSF Apache-2.0 | [Custom sources](https://docs.aws.amazon.com/security-lake/latest/userguide/custom-sources.md) |
| Tenzir | Package of TQL operators and pipelines | Inside Tenzir engine | Source, parser UDO, mapper UDO, sink | Bounded channels; checkpoint recovery limited | Native parse then OCSF; `unmapped` and raw | Local baselines and fixture services | BSD-3-Clause engine | [Source onboarding](https://tenzir.com/docs/tutorials/onboard-a-data-source.md) |
| Matano | Log-source YAML and VRL transform | Serverless ingestion transformer | S3/SQS ingest, transform, Avro write | Batch retry, DLQ, raw-line sideline | VRL to ECS; schema validation | Separate `logtest` golden utility | Apache-2.0 | [Transformer](https://raw.githubusercontent.com/matanolabs/matano/main/lib/rust/transformer/src/main.rs) |
| Panther | Custom YAML log schema | Managed ingestion service | Infer, draft, parse, publish, table | Transport-owned; no schema cursor | Panther typed fields; separate OCSF source | `pantherlog` input/result tests | Managed service proprietary; PAT grant unverified | [Custom schemas](https://docs.panther.com/data-onboarding/custom-log-types.md) |

### 2.5 Posture and MCP gateways

Query-driven plugins and hosted provider registries contribute scoped-rate and checkpoint
patterns. Gateway rows are security-boundary evidence, not synchronization models.

| Project | Integration unit | Isolation | Contract / lifecycle | State and sync | Mapping and identity | Testing | License | Key source |
|---|---|---|---|---|---|---|---|---|
| Steampipe | Go plugin binary serving SQL tables | Process per plugin config/QoS group | `List`, `Get`, `Hydrate`; query RPC | On-demand freshness; query/plugin caches | Typed SQL columns; Go transforms | Release checklist; real-account tests | Apache-2.0 SDK | [Plugin basics](https://steampipe.io/docs/develop/writing_plugins/the-basics) |
| CloudQuery | Source/destination gRPC process | Standalone process | Init, sync, read, write, transform | Versioned checkpoints; sharding; at least once | Arrow records; deterministic CQ ID option | Protocol connection/table checks | MPL-2.0 SDK; other grants unverified | [Plugin protocol](https://raw.githubusercontent.com/cloudquery/plugin-pb/main/plugin/v3/plugin.proto) |
| Prowler | Python provider package and check | In-process scan | Check `execute`; PASS/FAIL/MANUAL | Scan snapshots; provider-owned pagination | OCSF DetectionFinding; `unmapped` | Metadata validation; fixture details unverified | Apache-2.0 | [Check metadata rules](https://docs.prowler.com/developer-guide/check-metadata-guidelines) |
| Nango | YAML provider plus TypeScript sync/action | Hosted or self-hosted runtime | OAuth connection, sync exec, action | Typed checkpoint per batch | Zod models; imperative TypeScript maps | Local dry run with checkpoint | ELv2; ideas only | [Provider configuration](https://nango.dev/docs/integrations/api-configuration) |
| Docker MCP Gateway | Gateway fronting MCP servers | Typically backend containers | Stdio/SSE/streaming proxy; tool policy | Request proxy; no sync model | Backend schemas to bounded JSON Schema | Security model; harness unverified | MIT, grant marked unverified | [Security model](https://raw.githubusercontent.com/docker/mcp-gateway/main/docs/security.md) |
| Microsoft mcp-gateway | Kubernetes reverse proxy and registry | Stateless router replicas | Adapter/tool CRUD and MCP route | Metadata in Redis/Cosmos; stateless sessions | Registered MCP tool definitions | Deployment E2E tree | MIT | [Gateway repository](https://github.com/microsoft/mcp-gateway) |
| IBM ContextForge | Python/OCI federation gateway | Gateway process; peer federation | Tool/gateway registration and invocation | Postgres/SQLite; optional Redis | Virtual servers; schema behavior unverified | Linked smoke tests unverified | License unverified in research | [Gateway FAQ](https://ibm.github.io/mcp-context-forge/faq) |
| ToolHive | MCP server management platform | Platform-managed servers | Public contract not read beyond overview | Unverified | Unverified | Unverified | Apache-2.0 per README | [Project README](https://github.com/stacklok/toolhive/blob/main/README.md) |

### 2.6 Developer portals

Portal frameworks make entity ownership and destructive reconciliation visible. They also
show why declarative mapping and independent writers need explicit merge rules.

| Project | Integration unit | Isolation | Contract / lifecycle | State and sync | Mapping and identity | Testing | License | Key source |
|---|---|---|---|---|---|---|---|---|
| Backstage | npm backend module; provider/processor | Usually shared Node backend | Provider mutation; process; stitch | Full/delta; incremental bursts and cursors | Kubernetes-like entities; stable provider bucket | Generated unit tests; MSW/backend utils | Apache-2.0 | [Entity providers](https://backstage.io/docs/features/software-catalog/external-integrations/entity-providers/) |
| Port Ocean | Python integration HTTP process/container | Process/container per integration | Resync, live event, action executor | Full reconcile; incremental creates/updates only | Raw batches, JQ, blueprints and identifiers | Mocked HTTP, probes, acceptance checklist | Apache-2.0 Ocean | [Ocean resyncs](https://docs.port.io/context-lake/ingestion/ingest-data-into-port/custom-integration/custom-coded-ocean-integration/build/resyncs/) |
| Cortex | Iframe plugin, custom webhook, Workflow | Iframe and managed proxy; hosted workflows | Draft plugin; webhook ingest; block runs | Run state and idempotency key; no public native cursor | OpenAPI extensions; tag JQ; custom metadata | Plugin Jest; workflow validation | Proprietary platform; MIT examples | [Workflow runs](https://docs.cortex.io/streamline/workflows/run) |
| OpsLevel | Custom Integration mapping or Action webhook | Hosted configuration | Extract, transform, invoke, async callback | Daily polling, expiry; YAML source locks | External kind/ID, aliases, JQ transforms | YAML schema, draft actions, invocation audit | Proprietary platform; MIT helpers | [Custom data mapping](https://docs.opslevel.com/docs/mapping-integration-data-to-custom-properties) |

### 2.7 CI/CD and infrastructure as code

This domain supplies process isolation, immutable packaging, plan/apply, and schema
migration patterns. CI step flexibility is not itself a governed connector contract.

| Project | Integration unit | Isolation | Contract / lifecycle | State and sync | Mapping and identity | Testing | License | Key source |
|---|---|---|---|---|---|---|---|---|
| Terraform Plugin Framework | Go provider executable | Separate OS process, gRPC | Schema, configure, CRUD, plan/apply | Core-owned plan/state; refresh drift | Typed config/plan/state; external resource ID | Opt-in `TF_ACC` acceptance harness | MPL-2.0 | [Provider architecture](https://developer.hashicorp.com/terraform/plugin/how-terraform-works) |
| Crossplane / Upjet | Provider controller plus CRDs; xpkg | Provider pod | Observe, compare, create/update/delete | Desired/observed state; create-pending markers | `forProvider`; external-name; generated schemas | Live examples; schema diff/conversion | Apache-2.0; docs CC-BY-4.0 | [Managed resources](https://docs.crossplane.io/latest/managed-resources/managed-resources/) |
| Argo CD | Configured notifier or Kubernetes hook | In-controller services; hook resources | Trigger/template; sync phases and waves | Desired Git vs live state; retry/backoff | Go templates; diff-ignore rules | E2E fixtures and sync tests | Apache-2.0 | [Notification triggers](https://argo-cd.readthedocs.io/en/stable/operator-manual/notifications/triggers/) |
| Flux | Source, Provider, Alert, Receiver CRDs | Controller reconciliation | Poll/artifact; filter/notify; receiver trigger | Content revision/digest state | Typed Event JSON; selectors and metadata precedence | Controller tests; CRD examples | Apache-2.0 | [Receiver contract](https://fluxcd.io/flux/components/notification/receivers/) |
| GitHub Actions | Git repo with `action.yml` | Runner process or Docker action | Pre/main/post or composite steps | Ephemeral run; action-owned continuation | String inputs, declared outputs | Unit/integration/E2E guidance | Per action; official example MIT | [Metadata syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/metadata-syntax) |
| Tekton | Task, StepAction, TaskRun, OCI bundle | Containers in TaskRun Pod | Ordered steps; typed params/results | Kubernetes status and workspaces | Substitution and explicit result mapping | CRD checks; external API tests custom | Apache-2.0; docs CC-BY-4.0 | [Task contract](https://tekton.dev/docs/pipelines/tasks/) |
| Dagger | SDK module with typed functions | Sandboxed engine operations | Lazy DAG; checks and generators | Content caching; generated diff staleness | Typed SDK/API artifacts | `dagger check`; generated drift checks | Apache-2.0 engine | [Module configuration](https://docs.dagger.io/reference/config-files/dagger-toml) |
| Jenkins | `.hpi` plugin archive | Controller class loaders, not processes | Extensions and shared plugin APIs | Core/plugin/config dependency graph | Shared Java classes and persisted config | Test Harness, BOM, compatibility tester | MIT core; plugins vary | [Dependency management](https://www.jenkins.io/doc/developer/plugin-development/dependency-management/) |

### 2.8 Operations automation

These projects cover one-shot convergence, linked telemetry, standalone exporters, and
hosted alert APIs. Delivery identity and asynchronous acceptance need separate state.

| Project | Integration unit | Isolation | Contract / lifecycle | State and sync | Mapping and identity | Testing | License | Key source |
|---|---|---|---|---|---|---|---|---|
| Ansible | Collection and one-shot module | Transferred module process | JSON stdout; check/diff; declarative convergence | No common cursor; outer-loop retries | Module JSON and `RETURN`; facts | Sanity, unit, integration matrices | Per collection; inspected one GPL-3.0-or-later | [Collection layout](https://docs.ansible.com/projects/ansible/latest/dev_guide/developing_collections_structure.html) |
| Grafana | Plugin directory and optional Go backend | Backend subprocess over gRPC | Query, resource, stream, health, metrics | Query/stream state; no common sync cursor | Data frames; instance settings | Playwright host-version matrix | Apache-2.0 SDK; plugins vary | [Plugin manifest](https://grafana.com/developers/plugin-tools/reference/plugin-json.md) |
| Prometheus exporters | Standalone HTTP collector process | Separate exporter process | Describe/Collect; synchronous scrape | Current-state sampling; optional cache | Metric descriptors and label identity | `CollectAndCompare` and lint | Apache-2.0 client; exporters vary | [Exporter guidance](https://prometheus.io/docs/instrumenting/writing_exporters/) |
| OpenTelemetry Collector | Go component linked into distribution | In-process factories | Create, start, consume/produce, shutdown | Optional storage and persistent queues | Typed traces/metrics/logs; Go conversion | Lifecycle, coverage, stability gates | Apache-2.0 core; modules vary | [Component stability](https://raw.githubusercontent.com/open-telemetry/opentelemetry-collector/main/docs/component-stability.md) |
| PagerDuty | Hosted Events API integration and webhook | Hosted service | Trigger/ack/resolve; 202 acceptance | Alert dedup key; separate webhook delivery ID | PD-CEF and orchestration rules | Live samples and signature test vectors | Proprietary API | [Event contract](https://docs.pagerduty.com/developer/send-alert-event) |
| Opsgenie | Hosted API Integration | Hosted service | Alert create/action; 202 plus request status | Open-alert alias dedup; domain rate buckets | Alert fields, responders, details | Request-status and rate-limit oracles | Proprietary API | [Alert API](https://docs.opsgenie.com/docs/alert-api.md) |
| Prometheus Alertmanager | YAML receiver and generic webhook | Alertmanager server | Alert/silence API; grouped notification | Label/time lifecycle; HA at-least-once | Labels, annotations, fingerprint, group key | OpenAPI and config reload validation | Apache-2.0 | [Alertmanager configuration](https://raw.githubusercontent.com/prometheus/alertmanager/main/docs/configuration.md) |

## 3. Cross-cutting lessons

Verdict meanings: `adopt` transfers the design rule directly; `adapt` preserves the idea
but changes its mechanism for ICUHUB; `avoid-the-anti-pattern` is a prohibition derived
from observed failure modes. Evidence links name the projects that substantiate each row.

### 3.1 Packaging, manifest, versioning

Package identity, host compatibility, and support metadata must be reviewable data. A
package version alone does not establish schema or behavioral compatibility.

| ID | Lesson | Verdict | Evidence |
|---|---|---|---|
| PA-01 | Versioned manifest and machine schema: stable ID, connector and format versions, host/SDK range, config schema with secret flags, auth, capabilities, typed operations, scopes, owner, support tier, license. | adopt | [OpenCTI manifest](https://raw.githubusercontent.com/OpenCTI-Platform/connectors/master/external-import/alienvault/__metadata__/connector_manifest.json); [XSOAR YAML](https://xsoar.pan.dev/docs/integrations/yaml-file); [Grafana plugin.json](https://grafana.com/developers/plugin-tools/reference/plugin-json.md); [Ocean spec](https://docs.port.io/context-lake/ingestion/ingest-data-into-port/custom-integration/custom-coded-ocean-integration/build/configuration-files/) |
| PA-02 | Keep manifest-format and host-protocol versions separate from connector version; declare compatibility as ranges. | adopt | [Terraform registry manifest](https://developer.hashicorp.com/terraform/registry/providers/publishing#terraform-registry-manifest-file); [Elastic format versions](https://raw.githubusercontent.com/elastic/package-spec/main/README.md#specification-versioning); [Airbyte actor spec](https://docs.airbyte.com/platform/understanding-airbyte/airbyte-protocol.md#actor-specification); [Ansible collections](https://docs.ansible.com/projects/ansible/latest/dev_guide/developing_collections_structure.html) |
| PA-03 | Diff every config/input/output schema before release; removal or retype requires migration. | adopt | [Upjet schema diff](https://raw.githubusercontent.com/crossplane/upjet/main/docs/breaking-change-detection.md); [Tekton v1 migration](https://tekton.dev/docs/pipelines/migrating-v1beta1-to-v1/); [Ocean status migration](https://docs.port.io/context-lake/ingestion/ingest-data-into-port/native-integrations/sync-mechanisms/full-resync/) |
| PA-04 | Pin immutable versions, never mutable `latest`; retain prior versions for rollback and block deletion while used. | adopt | [Tracecat registry](https://docs.tracecat.com/custom-actions/custom-registry); [GitHub dependency guidance](https://docs.github.com/en/actions/reference/security/secure-use#using-third-party-actions); [Crossplane revisions](https://docs.crossplane.io/latest/packages/providers/); [StackStorm installation](https://docs.stackstorm.com/latest/packs.html) |
| PA-05 | Declare ownership and support tiers; mark stability per capability; deprecate and remove unmaintained connectors. | adopt | [Airbyte support levels](https://docs.airbyte.com/integrations/connector-support-levels.md); [OTel stability and owners](https://raw.githubusercontent.com/open-telemetry/opentelemetry-collector/main/docs/component-stability.md); [Elastic owner CI](https://raw.githubusercontent.com/elastic/integrations/main/docs/ci_pipelines.md); [XSOAR pack metadata](https://xsoar.pan.dev/docs/packs/packs-format) |
| PA-06 | Record license provenance per borrowed artifact; default to ideas-only for ELv2, proprietary, copyleft-unclear, or unlicensed sources. | adopt | [Nango license](https://raw.githubusercontent.com/NangoHQ/nango/master/LICENSE); [Airbyte license](https://raw.githubusercontent.com/airbytehq/airbyte/master/LICENSE); [Faraday license](https://raw.githubusercontent.com/infobyte/faraday_plugins/master/COPYING); [ArmorCode package](https://raw.githubusercontent.com/armor-code/acsdk/main/setup.py) |

### 3.2 Runtime and isolation

Surveyed hosts keep third-party or dependency-conflicting code behind a process or
container boundary and run trusted built-ins as in-process factories.

| ID | Lesson | Verdict | Evidence |
|---|---|---|---|
| PA-07 | Tier isolation: trusted first-party code in worker processes; third-party or dependency-conflicting connectors out of process; never in the API process. | adapt | [Terraform process model](https://developer.hashicorp.com/terraform/plugin/how-terraform-works); [Grafana backends](https://grafana.com/developers/plugin-tools/key-concepts/backend-plugins.md); [OpenCTI connectors](https://docs.opencti.io/latest/development/connectors/); [MISP dependency failure](https://github.com/MISP/misp-modules/issues/544) |
| PA-08 | Provide one SDK facade for logging, state, scheduling, and dispatch so protocol changes do not rewrite connectors. | adapt | [StackStorm sensor service](https://docs.stackstorm.com/latest/sensors.html); [OpenCTI helper](https://raw.githubusercontent.com/OpenCTI-Platform/client-python/master/pycti/connector/opencti_connector_helper.py); [Ocean framework](https://raw.githubusercontent.com/port-labs/ocean/main/README.md); [Cortex job protocol](https://docs.strangebee.com/cortex/operations/input-output/) |

ICUHUB outcome: ADR-0018 (D16) keeps every connector first-party, in this repository,
and in-process; no third-party connector code is loaded, so the out-of-process tier of
PA-07 has no ICUHUB counterpart. PA-08 still applies through the SDK facade
(`CONNECTOR_FRAMEWORK.md` section 3.3).

### 3.3 Lifecycle

Connection validation, target discovery, and health are explicit interfaces. Ingestion and
actions use separate typed contracts rather than a catch-all synchronous `sync()` method.

| ID | Lesson | Verdict | Evidence |
|---|---|---|---|
| PA-09 | Use a small typed lifecycle: spec, check, discover, read; actions are a separate contract, not overloaded ingestion. | adopt | [Airbyte interface](https://docs.airbyte.com/platform/understanding-airbyte/airbyte-protocol.md#actor-interface); [Singer spec](https://raw.githubusercontent.com/singer-io/getting-started/master/docs/SPEC.md); [SecObserve base](https://raw.githubusercontent.com/SecObserve/SecObserve/dev/backend/application/import_observations/parsers/base_parser.py); [Cortex authoring](https://thehive-project.github.io/Cortex-Analyzers/dev_guides/how-to-create-an-analyzer/) |
| PA-10 | Separate connection, target discovery, and target mapping; make include/exclude, fetch-all, pause, and missing-target aging explicit. | adopt | [ArmorCode mappings](https://raw.githubusercontent.com/armor-code/acsdk/main/acsdk/logins/USAGE.md); [Phoenix targets](https://kb.phoenix.security/?ht_kb=scanner-integration-management); [Splunk asset manifest](https://raw.githubusercontent.com/splunk-soar-connectors/zerofoxalerts/main/zerofox.json) |
| PA-11 | Require health; permission or read errors become `not evaluated`, never `fail` and never `clean`. | adopt | [Grafana health RPC](https://raw.githubusercontent.com/grafana/grafana-plugin-sdk-go/main/proto/backend.proto); [Prowler MANUAL rule](https://docs.prowler.com/developer-guide/check-metadata-guidelines); [Apiiro fail-open behavior](https://raw.githubusercontent.com/apiiro/marketplace/main/README.md) |

### 3.4 Sync and state

The host owns durable, monotonic, per-stream progress. Connector state emission is only a
proposal until normalized records and the outbox are durable in the same transaction.

| ID | Lesson | Verdict | Evidence |
|---|---|---|---|
| PA-12 | Host owns typed per-stream checkpoints; connector proposes and host commits after durable downstream write and outbox in one transaction. | adapt | [Airbyte state acknowledgement](https://docs.airbyte.com/platform/understanding-airbyte/airbyte-protocol.md#state--checkpointing); [XSOAR lastRun](https://xsoar.pan.dev/docs/integrations/fetching-incidents); [Nango batch checkpoints](https://docs.nango.dev/docs/guides/platform/migrations/migrate-to-checkpoints); [OpenCTI state](https://raw.githubusercontent.com/OpenCTI-Platform/client-python/master/pycti/connector/opencti_connector_helper.py) |
| PA-13 | Use monotonic checkpoint versions, highest wins, so replay cannot regress cursors; cursor reset is an audited operator command. | adopt | [CloudQuery checkpoint protocol](https://raw.githubusercontent.com/cloudquery/plugin-pb/main/plugin/v3/plugin.proto); [OpenCTI reset-capable state](https://raw.githubusercontent.com/OpenCTI-Platform/client-python/master/pycti/connector/opencti_connector_helper.py) |
| PA-14 | Timestamp cursors need tie-breaker IDs and bounded overlap; equal timestamps and late indexing otherwise lose events. | adopt | [XSOAR lookback](https://xsoar.pan.dev/docs/integrations/fetch-incidents-lookback); [Airbyte incremental ordering](https://docs.airbyte.com/platform/connector-development/cdk-python/incremental-stream.md) |
| PA-15 | Keep full reconciliation distinct from incremental/event deltas; delete or close only after a declared-complete snapshot with a removal-ratio circuit breaker. | adopt | [DefectDojo reimport](https://docs.defectdojo.com/import_data/import_intro/reimport/); [SecObserve import](https://secobserve.github.io/SecObserve/usage/import_observations/); [Backstage removal guards](https://backstage.io/docs/features/software-catalog/external-integrations/incremental-entity-providers/); [Ocean full resync](https://docs.port.io/context-lake/ingestion/ingest-data-into-port/native-integrations/sync-mechanisms/full-resync/) |
| PA-16 | State at-least-once delivery honestly; deduplicate downstream by stable keys. | adopt | [Singer delivery](https://sdk.meltano.com/en/latest/implementation/at_least_once.html); [PagerDuty webhooks](https://docs.pagerduty.com/developer/webhook-behavior); [Alertmanager HA](https://prometheus.io/docs/alerting/latest/high_availability/); [CloudQuery incremental tables](https://www.cloudquery.io/docs/cli/advanced/managing-incremental-tables) |
| PA-17 | Use bounded batches, leases, per-tenant fairness, and backlog-aware scheduling rather than blind cron. | adapt | [OpenCTI scheduling template](https://raw.githubusercontent.com/OpenCTI-Platform/connectors/master/templates/README.md); [IntelOwl queues](https://intelowlproject.github.io/docs/IntelOwl/advanced_configuration/); [Tenzir backpressure](https://tenzir.com/docs/explanations/executor.md); [Backstage bursts](https://backstage.io/docs/features/software-catalog/external-integrations/incremental-entity-providers/) |
| PA-18 | Send failures to visible dead-letter/quarantine with replay; never silently disable an integration. | adopt | [Matano DLQ](https://raw.githubusercontent.com/matanolabs/matano/main/lib/rust/transformer/src/main.rs); [OTel exporter helper](https://raw.githubusercontent.com/open-telemetry/opentelemetry-collector/main/exporter/exporterhelper/README.md); [PagerDuty disablement](https://docs.pagerduty.com/developer/webhook-behavior); [OpenCTI retry](https://raw.githubusercontent.com/OpenCTI-Platform/client-python/master/pycti/connector/opencti_connector_helper.py) |

### 3.5 Mapping and identity

Parsing preserves the source shape; semantic mapping is separately versioned. Raw evidence,
residue, and three different identities remain available for audit and replay.

| ID | Lesson | Verdict | Evidence |
|---|---|---|---|
| PA-19 | Separate parse and map stages; parsers keep native names while mappers target the canonical model. | adopt | [Tenzir onboarding](https://tenzir.com/docs/tutorials/onboard-a-data-source.md); [Backstage integrations](https://backstage.io/docs/features/software-catalog/external-integrations/); [Ocean resync handlers](https://docs.port.io/context-lake/ingestion/ingest-data-into-port/custom-integration/custom-coded-ocean-integration/build/resyncs/) |
| PA-20 | Make mapping versioned code with small declarative helpers; arbitrary templates or JQ are at most an advanced sandboxed path. | adapt | [IntelOwl mapping](https://intelowlproject.github.io/docs/IntelOwl/contribute/); [Port JQ mapping](https://docs.port.io/context-lake/ingestion/configure-mapping/overview/); [Tracecat template limits](https://docs.tracecat.com/custom-actions/yaml-template); [Alertmanager custom payload](https://raw.githubusercontent.com/prometheus/alertmanager/main/docs/configuration.md) |
| PA-21 | Retain bounded raw payload and unmapped residue; emit mapper diagnostics and quarantine unknown layouts instead of silent drops. | adopt | [XSOAR rawJSON](https://xsoar.pan.dev/docs/integrations/fetching-incidents); [Cortex full report](https://raw.githubusercontent.com/TheHive-Project/cortexutils/master/cortexutils/analyzer.py); [Tenzir OCSF mapping](https://tenzir.com/docs/tutorials/onboard-a-data-source.md#map-to-ocsf); [Prowler unmapped fields](https://raw.githubusercontent.com/prowler-cloud/prowler/master/prowler/lib/outputs/ocsf/ocsf.py) |
| PA-22 | Require reviewed golden raw-to-canonical fixtures for every mapping. | adopt | [Elastic pipeline tests](https://raw.githubusercontent.com/elastic/elastic-package/main/docs/howto/pipeline_testing.md); [Tenzir baselines](https://tenzir.com/docs/guides/packages/test-packages.md); [Panther schema tests](https://docs.panther.com/panther-developer-workflows/pantherlog.md#test-run-tests-for-a-schema); [Prometheus fixtures](https://raw.githubusercontent.com/prometheus/client_golang/main/prometheus/testutil/testutil.go) |
| PA-23 | Keep source record ID, finding fingerprint, and delivery ID apart; prefer source IDs, exclude mutable fields, include asset identity, and version the fingerprint algorithm. | adopt | [PagerDuty alert identity](https://docs.pagerduty.com/developer/send-alert-event); [PagerDuty delivery identity](https://docs.pagerduty.com/developer/webhook-behavior); [DefectDojo identity failure](https://github.com/DefectDojo/django-DefectDojo/issues/4663); [OpenCTI source models](https://raw.githubusercontent.com/OpenCTI-Platform/connectors/master/external-import/alienvault/src/alienvault/models.py) |
| PA-24 | Prefer SARIF, CycloneDX, and OCSF, but isolate vendor/version quirks in compatibility modules. | adopt | [SecObserve SARIF branches](https://raw.githubusercontent.com/SecObserve/SecObserve/dev/backend/application/import_observations/parsers/sarif/parser.py); [SecObserve OCSF branches](https://raw.githubusercontent.com/SecObserve/SecObserve/dev/backend/application/import_observations/parsers/ocsf/parser.py); [Dependency-Track CycloneDX](https://docs.dependencytrack.org/usage/cicd/) |
| PA-25 | Define field ownership and merge rules when several sources write one entity; never silently apply last-writer-wins. | adopt | [Port relation replacement](https://docs.port.io/context-lake/ingestion/configure-mapping/overview/); [OpsLevel field locks](https://docs.opslevel.com/docs/opslevel-yml) |

ICUHUB outcome for PA-20: ADR-0019 (D17) uses JMESPath for extraction only, compiled at
load, built-in functions only, with typed validation and golden fixtures
(`CONNECTOR_FRAMEWORK.md` section 6.1).

### 3.6 Actions and outbound sync

Writes have their own durable state machine. Acceptance is not completion, a retry is not
necessarily safe, and compensation exists only where the action explicitly defines it.

| ID | Lesson | Verdict | Evidence |
|---|---|---|---|
| PA-26 | Use typed plan then apply: dry-run diff, persisted plan hash, and rejection if inputs or target changed. | adopt | [Terraform plan modification](https://developer.hashicorp.com/terraform/plugin/framework/resources/plan-modification); [Dagger changeset checks](https://docs.dagger.io/using/checking#checks-and-generators); [Backstage dry run](https://backstage.io/docs/features/software-templates/dry-run-testing/); [Ansible check/diff](https://docs.ansible.com/projects/ansible/latest/dev_guide/developing_modules_best_practices.html) |
| PA-27 | Persist uncertain outcome, idempotency key, and remote ID before retry; never blind-retry writes; vendor 202 acceptance is distinct from completion. | adopt | [Crossplane create-pending](https://docs.crossplane.io/latest/managed-resources/managed-resources/#creation-annotations); [Ocean transport retry](https://docs.port.io/context-lake/ingestion/ingest-data-into-port/native-integrations/ocean-framework/advanced-configuration/); [PagerDuty 202](https://docs.pagerduty.com/developer/events-api-v2-overview); [Opsgenie request status](https://docs.opsgenie.com/docs/alert-api.md) |
| PA-28 | Order actions per target with partition keys; run unrelated targets in parallel. | adapt | [Ocean partitioned actions](https://docs.port.io/context-lake/ingestion/ingest-data-into-port/native-integrations/ocean-framework/actions-processing/); [Tenzir keyed parallelism](https://tenzir.com/docs/explanations/executor.md#parallel-execution) |
| PA-29 | Give outbound sync its own state machine with loop prevention and grouping; one ticket per raw notification floods trackers. | adapt | [Dependency-Track ticket flood](https://github.com/DependencyTrack/dependency-track/issues/2347); [XSOAR mirroring](https://xsoar.pan.dev/docs/integrations/mirroring_integration); [Faraday Jira](https://docs.faradaysec.com/integration-jira/); [SecObserve one-way push](https://secobserve.github.io/SecObserve/integrations/issue_trackers/) |
| PA-30 | Offer rollback only where an action declares compensation; never promise generic rollback. | avoid-the-anti-pattern | [Backstage idempotency design](https://raw.githubusercontent.com/backstage/backstage/master/beps/0004-scaffolder-task-idempotency/README.md); [Cortex retry warning](https://docs.cortex.io/streamline/workflows/run); [Ocean action contract](https://docs.port.io/context-lake/ingestion/ingest-data-into-port/native-integrations/ocean-framework/actions-processing/) |

### 3.7 Auth, secrets, webhooks

Configuration contains references, not credentials. Verification uses exact request bytes,
and trust is scoped to a connection and vendor account rather than a shared global key.

| ID | Lesson | Verdict | Evidence |
|---|---|---|---|
| PA-31 | Config holds secret references only; decrypt at egress; declare secret fields in schema, never infer them from names. | adopt | [Grafana secure settings](https://grafana.com/developers/plugin-tools/how-to-guides/data-source-plugins/add-authentication-for-data-source-plugins.md); [Cortexutils name heuristic](https://raw.githubusercontent.com/TheHive-Project/cortexutils/master/cortexutils/worker.py); [Elastic secret vars](https://raw.githubusercontent.com/elastic/package-spec/main/spec/integration/data_stream/manifest.spec.yml); [Airbyte secret test](https://docs.airbyte.com/platform/connector-development/testing-connectors/connector-acceptance-tests-reference.md#test-spec) |
| PA-32 | Use per-connection least-privilege identities; declare required scopes and probe them during check. | adopt | [OpenCTI connector users](https://docs.opencti.io/latest/deployment/connectors/); [Crossplane management policies](https://docs.crossplane.io/latest/managed-resources/managed-resources/#managementpolicies); [GitHub token hardening](https://docs.github.com/en/actions/reference/security/secure-use) |
| PA-33 | Verify webhooks over raw bytes with a timestamp window and overlapping-key rotation. | adopt | [PagerDuty signatures](https://docs.pagerduty.com/developer/verifying-webhook-signatures); [Nango dual-key window](https://docs.nango.dev/docs/guides/platform/webhooks-from-nango); [Port webhook security](https://docs.port.io/workflows/actions-and-automations/setup-backend/webhook/); [OpsLevel signatures](https://docs.opslevel.com/docs/webhook-signatures) |
| PA-34 | Prefer short-lived OIDC workload identity over static keys where the vendor supports it. | adopt | [GitHub OIDC](https://docs.github.com/en/actions/concepts/security/openid-connect); [Flux OCI identity](https://fluxcd.io/flux/components/source/ocirepositories/#provider); [Dagger secret providers](https://docs.dagger.io/config/secrets) |

### 3.8 Rate limits and operations

Quota and telemetry dimensions must match actual failure domains: tenant, connection,
vendor account, target, and stream. A process-global bucket is not fair across replicas.

| ID | Lesson | Verdict | Evidence |
|---|---|---|---|
| PA-35 | Scope rate limits per connection and vendor account, shared across replicas; honor `Retry-After`; prevent one noisy connector from starving others. | adapt | [Steampipe scoped limiters](https://steampipe.io/docs/guides/limiter); [Opsgenie buckets](https://docs.opsgenie.com/docs/api-rate-limiting.md); [Airbyte rate-limit gap](https://docs.airbyte.com/platform/connector-development/cdk-python/http-streams.md#rate-limiting) |
| PA-36 | Expose per-connection/target/stream last success, next run, lag, fetched/mapped/quarantined/deleted counts, and action logs. | adopt | [ArmorCode operational fields](https://raw.githubusercontent.com/armor-code/acsdk/main/acsdk/logins/USAGE.md); [Phoenix target status](https://kb.phoenix.security/?ht_kb=scanner-integration-management); [Ocean sync metrics](https://docs.port.io/context-lake/ingestion/ingest-data-into-port/native-integrations/sync-mechanisms/full-resync/); [Grafana metrics RPC](https://raw.githubusercontent.com/grafana/grafana-plugin-sdk-go/main/proto/backend.proto) |

### 3.9 Testing

Fast deterministic tests are mandatory; live acceptance is explicit and support-tiered.
Every connector runs the same conformance suite before its own vendor-specific tests.

| ID | Lesson | Verdict | Evidence |
|---|---|---|---|
| PA-37 | Layer static manifest validation, offline fixtures, mocked HTTP contract tests, and opt-in live acceptance gated by environment and support tier. | adopt | [XSOAR linting](https://xsoar.pan.dev/docs/integrations/linting); [Terraform acceptance](https://developer.hashicorp.com/terraform/plugin/framework/acctests); [Airbyte acceptance tests](https://docs.airbyte.com/platform/connector-development/testing-connectors/connector-acceptance-tests-reference.md); [Dependency-Track WireMock](https://raw.githubusercontent.com/DependencyTrack/dependency-track/master/src/test/java/org/dependencytrack/notification/publisher/JiraPublisherTest.java) |
| PA-38 | Require a generic conformance suite: spec validity, secrets marked, clean bad-credential failure, and checkpoint resume. | adopt | [Airbyte connector acceptance](https://docs.airbyte.com/platform/connector-development/testing-connectors/connector-acceptance-tests-reference.md); [Ansible testing](https://docs.ansible.com/projects/ansible/latest/dev_guide/developing_collections_testing.html); [OTel lifecycle requirements](https://raw.githubusercontent.com/open-telemetry/opentelemetry-collector/main/docs/component-stability.md) |

### 3.10 MCP gateway

Gateway security is a default-deny policy problem. Registry metadata is untrusted input,
not executable configuration, and protocol migration must be explicit.

| ID | Lesson | Verdict | Evidence |
|---|---|---|---|
| PA-39 | Default deny; require bearer auth on network transports; scope secrets to their declaring server; prevent image/package metadata shaping runtime; pin protocol version. | adopt | [Docker security model](https://raw.githubusercontent.com/docker/mcp-gateway/main/docs/security.md); [Microsoft protocol and RBAC](https://github.com/microsoft/mcp-gateway) |

### 3.11 Developer and platform engineering

Canonical references connect records across sources. Generation accelerates drafts only;
it cannot infer synchronization, credential, or deletion semantics.

| ID | Lesson | Verdict | Evidence |
|---|---|---|---|
| PA-40 | Use canonical entity references: kind + namespace + name and external kind + external ID link records to the same asset. | adopt | [Backstage descriptors](https://backstage.io/docs/features/software-catalog/descriptor-format/); [Port blueprints](https://docs.port.io/context-lake/data-model/setup-blueprint/overview/); [OpsLevel external identity](https://docs.opslevel.com/docs/mapping-integration-data-to-custom-properties) |
| PA-41 | Treat OpenAPI/sample-generated scaffolds as drafts; review lifecycle, cursor, mapping, and auth, then pass golden tests before publish. | adapt | [Shuffle OpenAPI apps](https://raw.githubusercontent.com/Shuffle/shuffle-docs/master/docs/apps.md); [Panther inference limits](https://docs.panther.com/panther-developer-workflows/pantherlog.md#infer-limitations); [Upjet generation](https://raw.githubusercontent.com/crossplane/upjet/main/docs/generating-a-provider.md) |

## 4. Anti-patterns observed

Each rule is a design constraint derived from the linked implementation or operator
evidence. The PA reference identifies the positive requirement that prevents recurrence.

| ID | Anti-pattern | Where seen (linked) | ICUHUB rule |
|---|---|---|---|
| AP-01 | Mutable `latest` installs and hot updates change production without review | [StackStorm packs](https://docs.stackstorm.com/latest/packs.html); [Shuffle apps](https://raw.githubusercontent.com/Shuffle/shuffle-docs/master/docs/apps.md) | Immutable pins, retained revisions, usage-aware deletion (PA-04) |
| AP-02 | Shared dependency/class-loader space lets one connector break others | [MISP import failure](https://github.com/MISP/misp-modules/issues/544); [Jenkins class loading](https://www.jenkins.io/doc/developer/plugin-development/dependencies-and-class-loading/) | Tiered process and dependency isolation (PA-07) |
| AP-03 | Timestamp-only high-water marks miss equal-time and late-indexed records | [XSOAR lookback rationale](https://xsoar.pan.dev/docs/integrations/fetch-incidents-lookback) | Stable cursor or timestamp plus bounded ID overlap (PA-14) |
| AP-04 | Advancing source state before downstream commit loses records | [Singer state cautions](https://raw.githubusercontent.com/singer-io/getting-started/master/docs/CONFIG_AND_STATE.md); [Airbyte state](https://docs.airbyte.com/platform/understanding-airbyte/airbyte-protocol.md#state--checkpointing) | Transactional checkpoint after durable outbox write (PA-12) |
| AP-05 | Treating a partial report as complete causes close/reopen churn | [DefectDojo reimport](https://docs.defectdojo.com/import_data/import_intro/reimport/); [SecObserve imports](https://secobserve.github.io/SecObserve/usage/import_observations/) | Completeness declaration and removal breaker (PA-15) |
| AP-06 | Retry queues drop history and silently disable delivery | [PagerDuty webhook behavior](https://docs.pagerduty.com/developer/webhook-behavior) | Visible dead letter, audit, and operator replay (PA-18) |
| AP-07 | Giant imperative mappings and unknown-field drops hide vendor drift | [Matano CloudTrail](https://raw.githubusercontent.com/matanolabs/matano/main/data/managed/log_sources/aws_cloudtrail/log_source.yml); [Tenzir mapper](https://tenzir.com/docs/tutorials/onboard-a-data-source.md#create-the-mapper) | Modular mapping, residue, diagnostics, quarantine (PA-20, PA-21) |
| AP-08 | Mutable, organization-wide fingerprints over-collapse findings | [ArcherySec Semgrep](https://raw.githubusercontent.com/archerysec/archerysec/master/scanners/scanner_parser/staticscanner_parser/semgrep_json_report_parser.py); [DefectDojo #4663](https://github.com/DefectDojo/django-DefectDojo/issues/4663) | Stable scoped identity and algorithm versioning (PA-23) |
| AP-09 | Independent mappings silently erase shared fields or relations | [Port mapping ownership](https://docs.port.io/context-lake/ingestion/configure-mapping/overview/) | Explicit ownership, merge rules, conflicts (PA-25) |
| AP-10 | Blind create-on-retry duplicates or strands remote objects | [IntelOwl MISP connector](https://raw.githubusercontent.com/intelowlproject/IntelOwl/master/api_app/connectors_manager/connectors/misp.py); [Ocean transport](https://docs.port.io/context-lake/ingestion/ingest-data-into-port/native-integrations/ocean-framework/advanced-configuration/) | Persist intent and remote ID; reconcile uncertainty (PA-27) |
| AP-11 | One ticket per raw notification floods the tracker | [Dependency-Track #2347](https://github.com/DependencyTrack/dependency-track/issues/2347) | Group, route, deduplicate, and prevent loops (PA-29) |
| AP-12 | Generic retry or cancellation is presented as rollback | [Backstage recovery](https://backstage.io/docs/features/software-templates/configuration/); [Cortex retry](https://docs.cortex.io/streamline/workflows/run) | Only declared action-specific compensation (PA-30) |
| AP-13 | Name-based redaction or signing-only storage is treated as secret protection | [Cortexutils redaction](https://raw.githubusercontent.com/TheHive-Project/cortexutils/master/cortexutils/worker.py); [ArcherySec credentials](https://raw.githubusercontent.com/archerysec/archerysec/master/jiraticketing/views.py) | Typed secret references and egress-only decryption (PA-31) |
| AP-14 | One process-global or account-global bucket starves unrelated connectors | [Opsgenie rate limits](https://docs.opsgenie.com/docs/api-rate-limiting.md); [Steampipe limiters](https://steampipe.io/docs/guides/limiter) | Shared scoped buckets and fairness (PA-35) |
| AP-15 | Required CI calls live third-party APIs | [MISP expansion tests](https://raw.githubusercontent.com/MISP/misp-modules/master/tests/test_expansions.py) | Hermetic default tests; opt-in live acceptance (PA-37) |
| AP-16 | Generated OpenAPI or inferred schemas publish without lifecycle review | [Shuffle generation](https://raw.githubusercontent.com/Shuffle/shuffle-docs/master/docs/apps.md); [Panther inference](https://docs.panther.com/panther-developer-workflows/pantherlog.md#infer-limitations) | Human review, compatibility checks, golden proof (PA-41) |
| AP-17 | Untrusted package metadata shapes runtime and network egress defaults open | [Docker MCP security](https://raw.githubusercontent.com/docker/mcp-gateway/main/docs/security.md) | Metadata cannot inject runtime; deny by default (PA-39) |
| AP-18 | Auth, timeout, or permission failure is reported as clean or as a rule failure | [Apiiro fail-open scan](https://raw.githubusercontent.com/apiiro/marketplace/main/README.md); [Prowler check rules](https://docs.prowler.com/developer-guide/check-metadata-guidelines) | Explicit `not evaluated` health and evidence state (PA-11) |

## 5. License notes

"Code with notice" is conditional on preserving the exact license, copyright, source, and
modification obligations and on reviewing the specific file or subtree. It is not a blanket
approval to copy a whole repository. "Ideas only" means clean implementation from the
public contract without copying code, schemas, manifests, or documentation text.

| Project | License | Reuse in ICUHUB |
|---|---|---|
| DefectDojo | BSD-3-Clause | Code with notice |
| Faraday plugins | GPL-3.0 | Code with notice only after copyleft review; otherwise ideas only |
| OWASP Dependency-Track | Apache-2.0 | Code with notice |
| SecObserve | BSD-3-Clause | Code with notice |
| ArcherySec | GPL-3.0-only | Code with notice only after copyleft review; otherwise ideas only |
| Phoenix Security | Commercial; no connector source grant identified | Ideas only |
| ArmorCode acsdk | UNLICENSED | Ideas only |
| Apiiro | MCP Apache-2.0; marketplace MIT; CLI also subject to EULA | Code with notice only for the exact permissive artifact; CLI ideas only pending review |
| OpenCTI connectors | Apache-2.0 unless a connector subtree overrides | Code with notice after subtree check |
| MISP / misp-modules | AGPL-3.0 | Code with notice and AGPL provenance/source obligations |
| IntelOwl | AGPL-3.0 | Code with notice and AGPL provenance/source obligations |
| Cortex XSOAR content | MIT for `demisto/content` | Code with notice; platform behavior remains an external contract |
| Splunk SOAR apps | Apache-2.0 for inspected ZeroFox app | Code with notice from that app only; check each other app |
| TheHive/Cortex | AGPL-3.0 unless worker subtree overrides | Code with notice after worker license check |
| Shuffle | AGPL-3.0 platform; MIT apps, SDK, OpenAPI specs | Code with notice per artifact |
| Tracecat | AGPL-3.0 except restrictive EE paths | Code with notice only from verified AGPL paths; EE ideas only |
| StackStorm | Apache-2.0 core/examples; Exchange packs vary | Code with notice from core; check every pack |
| Airbyte | MIT protocol/CDK; ELv2 main repo and inspected connectors | Code with notice from MIT artifacts; ELv2 ideas only |
| Singer / Meltano SDK | Specification has no root grant; SDK grants unverified | Ideas only until each exact grant is confirmed |
| Elastic integrations | Elastic License for package-spec; ELv2 default for integrations | Ideas only unless exact subtree review permits otherwise |
| Amazon Security Lake | Proprietary service docs; OCSF schema Apache-2.0 | Service ideas only; OCSF code/schema with notice |
| Tenzir | BSD-3-Clause engine | Code with notice |
| Matano | Apache-2.0 | Code with notice |
| Panther | Managed service proprietary; PAT license unverified | Ideas only until PAT grant is confirmed |
| Steampipe | Apache-2.0 SDK | Code with notice |
| CloudQuery | MPL-2.0 SDK; plugin-pb/core grants unverified | SDK code with notice and file-level MPL compliance; other parts ideas only pending review |
| Prowler | Apache-2.0 | Code with notice |
| Nango | ELv2 | Ideas only |
| Docker MCP Gateway | MIT reported but not re-read | Ideas only until LICENSE is re-read; then code with notice if confirmed |
| Microsoft mcp-gateway | MIT | Code with notice |
| IBM ContextForge | License unverified in research | Ideas only until LICENSE is confirmed |
| ToolHive | Apache-2.0 per README | Code with notice after exact artifact review |
| Backstage | Apache-2.0 | Code with notice |
| Port Ocean | Apache-2.0 for published Ocean source | Code with notice; hosted platform ideas only |
| Cortex | Proprietary platform; MIT example plugins | Platform ideas only; examples code with notice |
| OpsLevel | Proprietary platform; MIT CLI/community helpers | Platform ideas only; helper code with notice |
| Terraform Plugin Framework | MPL-2.0 | Code with notice and file-level MPL compliance |
| Crossplane / Upjet | Apache-2.0 code; Upjet docs CC-BY-4.0 | Code with notice; docs under their separate attribution terms |
| Argo CD | Apache-2.0 | Code with notice |
| Flux | Apache-2.0 | Code with notice |
| GitHub Actions | Per-action license; official JavaScript example MIT | Code with notice only from the exact reviewed action |
| Tekton | Apache-2.0 code/samples; docs CC-BY-4.0 | Code with notice; docs under their separate attribution terms |
| Dagger | Apache-2.0 engine | Code with notice |
| Jenkins | MIT core; plugins vary | Core code with notice; check each plugin |
| Ansible | Per collection; inspected community.general is GPL-3.0-or-later | Code with notice only after per-file/copyleft review |
| Grafana | Apache-2.0 Go SDK; plugins vary | SDK code with notice; check each plugin |
| Prometheus exporters | Apache-2.0 `client_golang`; exporters vary | Client code with notice; check each exporter |
| OpenTelemetry Collector | Apache-2.0 core; third-party modules vary | Core code with notice; check each module |
| PagerDuty | Proprietary hosted API | Ideas only; check client libraries separately |
| Opsgenie | Proprietary hosted API | Ideas only; check client libraries separately |
| Prometheus Alertmanager | Apache-2.0 | Code and schema with notice |

## 6. Unverified items

The following claims remain material to adoption and must be re-checked against a pinned
revision before implementation. They are not treated as established facts elsewhere in
this document.

- **Singer and Meltano licenses:** the `singer-python` and Meltano SDK grants were not
  re-confirmed, and the specification repository has no root LICENSE. This blocks code
  copying under PA-06, not use of the documented protocol ideas.
- **CloudQuery artifact licenses:** only the SDK MPL-2.0 grant was confirmed; `plugin-pb`
  and core CLI grants remain open. Confirm them before reusing protocol generated code
  under PA-06. The highest-version checkpoint behavior used by PA-13 is source-confirmed.
- **Docker MCP Gateway license:** MIT was reported from repository metadata but LICENSE was
  not re-read. PA-39 relies on the read security model, while PA-06 still requires the
  license check before copying.
- **IBM ContextForge license and test details:** neither was confirmed. No PA-39 security
  default relies on ContextForge; its survey cells remain limited to the FAQ evidence.
- **ToolHive public contract:** only the overview and Apache-2.0 README statement were read.
  Do not infer its isolation, authentication, secret scoping, or protocol enforcement.
- **Panther Analysis Tool license:** the PAT grant was not confirmed. PA-41 uses official
  inference-limit documentation, but code reuse remains blocked pending license review.
- **OpenCTI certification procedure:** `verified`, `last_verified_date`, and `support_version`
  are confirmed fields, but the public certification process and compatibility matrix were
  not established. PA-05 must define ICUHUB's own evidence requirements.
- **Opsgenie integration fairness caps:** domain buckets and throttling are documented, but
  the optional per-integration fairness mechanism was not confirmed. PA-35 therefore needs
  an ICUHUB-owned fairness implementation and acceptance tests.
- **Dagger 1.0-beta changeset details:** generated diff/stale checks are documented, while
  parts of the 1.0 manifest migration and exact `Changeset` API remain version-sensitive.
  Pin and re-read the current contract before using it as the PA-26 implementation model.
- **Crossplane downgrade behavior:** retained revisions are documented, but dependency and
  storage-version behavior on downgrade was not confirmed. PA-04 rollback must remain a
  staged operator action with schema compatibility checks.
- **Amazon Security Lake supported OCSF classes:** the exact current enumeration was not
  re-verified, and the reviewed custom-source page supports OCSF 1.3 and earlier. An OCSF
  1.9.0 exporter needs explicit version and class compatibility tests under PA-24.
- **Commercial connector internals:** Phoenix, ArmorCode, Apiiro, Cortex, OpsLevel,
  PagerDuty, and Opsgenie do not expose all queue, cursor, encryption, or isolation details.
  Lessons use only their documented external behavior and must not imply private internals.
