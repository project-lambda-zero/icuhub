# ADR-0006 -- Credential storage: envelope encryption in PostgreSQL with an OpenBao KEK

- Status: Accepted
- Date: 2026-11-07
- Closes: D3

## Context

Vendor credentials must never reach consumers and must be stored outside plain database columns (BR-02, FR-CON-03). `OPTIONS.md` section 8 compares OpenBao, HashiCorp Vault, Conjur, External Secrets Operator, SOPS, and application envelope encryption.

## Decision

- Every stored credential is encrypted with AES-256-GCM under a fresh data key per value; tenant, object, field, and key version are bound as associated data.
- Data keys are wrapped by a key-encryption key (KEK) supplied through a `KeyProvider` interface.
- Production KEK provider: OpenBao Transit (MPL-2.0), one named key per tenant. Development KEK provider: a read-only file key. Vault and HSM providers are adapters added on request.
- Providers never fall back to one another; a provider outage fails closed.

## Consequences

- KEK rotation rewraps data keys without re-encrypting every value.
- OpenBao is a required service in production installs.
- HashiCorp Vault is not bundled (BSL 1.1, NFR-15).

## Requirements affected

BR-02, FR-CON-03, FR-CON-05, NFR-01; HLD section 10; BRD section 15.
