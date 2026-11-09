# Architecture Decision Records

| ADR | Title | Status |
|---|---|---|
| [0001](0001-standalone-repository.md) | ICUHUB is a standalone repository and service | Accepted |
| [0002](0002-capability-protocols-and-dict-registry.md) | Capability protocols and a plain dict connector registry | Accepted |
| [0003](0003-ocsf-and-sarif-standardization.md) | OCSF and SARIF are the normalization standards | Accepted |
| [0004](0004-service-language-python.md) | Service language is Python 3.11+ | Accepted |
| [0005](0005-event-backbone-postgres-outbox-kafka.md) | Event backbone: PostgreSQL outbox feeding Apache Kafka | Accepted |
| [0006](0006-credentials-envelope-encryption-openbao-kek.md) | Credential storage: envelope encryption in PostgreSQL with an OpenBao KEK | Accepted |
| [0007](0007-deployment-one-hub-per-install.md) | Deployment model: one ICUHUB per enterprise install | Accepted |
| [0008](0008-ocsf-1-9-0-own-models.md) | OCSF 1.9.0 pinned, ICUHUB-owned models | Accepted |
| [0009](0009-cloudevents-envelope.md) | Event envelope: CloudEvents 1.0 | Accepted |
| [0010](0010-wave-1-connectors.md) | First-wave connectors | Accepted |
| [0011](0011-host-execution-stays-in-consumers.md) | Remote host execution stays in consumers | Accepted |
| [0012](0012-vulnerability-intelligence-mirror.md) | Public vulnerability intelligence is mirrored by ICUHUB | Accepted |
| [0013](0013-policy-typed-rules.md) | Policy engine: typed rules in PostgreSQL | Accepted |
| [0014](0014-durable-execution-postgres.md) | Durable actions and approvals: PostgreSQL state machine and job queue | Accepted |
| [0015](0015-ticket-routing-in-icuhub.md) | Finding-to-ticket routing lives in ICUHUB | Accepted |
| [0016](0016-http-toolkit-stack.md) | HTTP toolkit dependency set | Accepted |
| [0017](0017-connector-manifest-generated.md) | Connector manifests are generated from code and committed | Accepted |
| [0018](0018-connectors-first-party-in-process.md) | Connectors are first-party and run in-process | Accepted |
| [0019](0019-jmespath-mapping-expressions.md) | JMESPath for declarative field extraction in mappers | Accepted |
| [0020](0020-mvp-scope.md) | MVP scope: ten vendors, every specced edition, full hub runtime | Accepted |
| [0021](0021-service-stack-dependencies.md) | Service stack dependency set | Accepted |

Format: Status, Date, Closes (decision ID, when applicable), Context, Decision,
Consequences, Requirements affected. Decisions D1-D21 are closed (`docs/BRD.md`
section 18). New open decisions are appended there as D22 onward until an ADR closes
them.
