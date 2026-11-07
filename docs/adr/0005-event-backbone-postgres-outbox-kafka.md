# ADR-0005 -- Event backbone: PostgreSQL outbox feeding Apache Kafka

- Status: Accepted
- Date: 2026-11-07
- Closes: D2

## Context

ICUHUB publishes events (findings, action outcomes, approvals, webhook deliveries) that must survive restarts and be replayable (FR-API-03, NFR-06). `OPTIONS.md` section 7 compares NATS JetStream, Kafka, RabbitMQ streams, Redpanda, Redis Streams, and an outbox-only design.

## Decision

- Every event is first written as a row in a PostgreSQL transactional outbox in the same transaction as the state change it describes. The outbox row is the canonical record.
- A relay publishes outbox rows to Apache Kafka (KRaft mode, Apache-2.0) and marks a row published only after the broker acknowledges.
- The Kafka message key is derived from the tenant and event `source`; the CloudEvents `id` (ADR-0009) is the dedupe key for consumers.
- Publishing goes through one `EventPublisher` interface; Kafka is its only implementation until another backbone is decided by ADR.

## Consequences

- Deployments run a Kafka cluster (single broker for development, replicated for production); its images are mirrored for air-gapped installs.
- Consumers dedupe by `(source, id)` in their own inbox; the broker's retention window is not a dedupe guarantee.
- NATS JetStream, Redpanda, and Redis Streams are not adopted.

## Requirements affected

FR-API-03, NFR-06, NFR-08; HLD section 7.3; COMMATRIX event-stream flows.
