# ADR-0022 -- Safe kubeconfig YAML parsing

- Status: Accepted
- Date: 2026-11-10

## Context

ADR-0021 requires a new ADR for every further runtime dependency. The Kubernetes and OpenShift connector contracts require standard kubeconfig authentication. Kubeconfig files are YAML, and JSON-only support would reject normal operator configuration. A connector-local YAML parser would be unsafe and would duplicate a mature parsing contract.

Managed audit transport remains within the existing dependency set. CloudWatch uses SigV4 over the approved HTTP kit, Event Hub uses Capture files through Blob REST with bounded Avro object-container decoding, and Pub/Sub service-account OAuth uses the already approved `cryptography` dependency. No cloud SDK or AMQP client is added.

## Decision

Add `PyYAML==6.0.2` as a direct runtime dependency. Connectors must call `yaml.safe_load`, reject non-mapping documents and unsafe or duplicate-key constructs before authentication, and enforce the existing credential, URL, TLS, and file-size limits. No general-purpose YAML object construction is permitted.

PyYAML is MIT licensed and is suitable for the AGPL-3.0 distribution and offline installation model.

## Consequences

- Standard YAML and JSON kubeconfig files share one validated configuration path.
- The runtime dependency license inventory and installation documentation must include PyYAML.
- No other runtime dependency is authorized by this ADR.

## Requirements affected

- MVP 4.13 and 4.14 kubeconfig authentication.
- ADR-0021 runtime dependency governance.
