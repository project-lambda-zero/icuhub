# Mend SCA fixture provenance

All fixtures under `tests/fixtures/mend_sca/` are sanitized, synthetic JSON bodies
shaped after the public Mend API documentation. No customer data, hostnames, real
tokens, or real project identifiers are present. UUIDs, tokens, emails, and names
are documentation-style examples.

## Vendor sources

- Mend Platform API 3.0 documentation: https://api-docs.mend.io/platform/3.0
  - OpenAPI bundle: https://api-docs.mend.io/_bundle/platform/3.0.yaml
  - Used for: `v3/` login and access-token bodies, security findings pages,
    libraries pages, legal violations, activity logs, project pages, and the
    `report/` Platform 3.0 `response` report shape.
- Mend SCA API 2.0 documentation: https://api-docs.mend.io/sca/2.0
  - OpenAPI bundle: https://api-docs.mend.io/_bundle/sca/2.0.yaml
  - Used for: `v2/` login session body, security alert pages, legal alert pages,
    and the `report/` direct 2.0 `retVal` rejection case.

Field names and envelope keys (`response`, `additionalData`, `retVal`) follow the
component schemas in those bundles. Example values are adapted from the bundled
examples with all identifying values replaced.

## Unverified shapes

The Unified Agent `libraries` report, the manual `vulnerabilities` report, and the
grouped Platform `components` report have no authoritative schema in the bundles
above. Their fixtures follow the historically documented report layouts and are
marked `[UNVERIFIED]` in `src/icuhub/connectors/mend_sca/report.py`. They must be
confirmed against real exported reports before the corresponding parser shapes are
considered verified. See `docs/IMPLEMENTATION_GAPS.md` for the open gap entries.

## License

The Mend API documentation is publicly available vendor material. Fixtures here are
original sanitized JSON written for this project, not copied response captures.
