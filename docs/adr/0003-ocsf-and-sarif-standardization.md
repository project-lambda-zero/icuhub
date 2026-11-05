# ADR-0003 -- OCSF and SARIF are the normalization standards

- Status: Accepted
- Date: 2026-11-05

## Context

Every tool emits its own format. Consumers (AILA, posture console, customer SIEM/GRC)
need one shape. OCSF is the vendor-neutral schema adopted by AWS Security Hub and Security
Lake and many security vendors; SARIF 2.1.0 is the interchange format for code-scanning
surfaces.

## Decision

- Events and findings are normalized to OCSF (Findings category: Vulnerability Finding
  2002, Compliance Finding 2003, Detection Finding 2004, Incident Finding 2005, Data
  Security Finding 2006; activity classes for audit export).
- Code-located findings are additionally exported as SARIF 2.1.0.
- The models and codecs live in a shared, separately versioned package (`icuhub-schemas`)
  used by ICUHUB and its consumers.
- This standardization is required regardless of other choices.
- The exact OCSF version pin (D5) and whether to reuse an existing model library (D6)
  remain open.

## Consequences

- Consumers read one schema; customer SIEM ingestion needs no custom mapping.
- Raw vendor payloads are retained by reference for fields OCSF does not cover.

## Requirements affected

BR-05, FR-NRM-01..06, FR-AUD-03.
