# Archer fixture sources

All fixtures under `tests/fixtures/archer/` reproduce response shapes documented
in the sources below. Field ids, content ids, and names are synthetic; envelope,
element, and attribute shapes are not invented.

1. `docs/MVP.md` section 4.17 (Archer definition of done) and
   `docs/VENDOR_CONNECTORS.md` section 10 (Archer REST Content API, SOAP Web
   Services, data feeds, attachments, auth, version, permissions).
2. Cortex XSOAR `ArcherV2` integration (MIT license),
   `Packs/ArcherRSA/Integrations/ArcherV2/ArcherV2.py`, demisto/content
   repository. Source of the REST login body and `SessionToken` envelope, the
   list-of-envelopes metadata responses, `FieldContents` value shapes
   (`ValuesListIds`, `UserList`/`GroupList`, `ContentID`, `IpAddressBytes`), the
   SOAP namespace `http://archer-tech.com/webservices/`, in-body `sessionToken`,
   `ExecuteSearch` `SearchReport` CDATA with `DisplayField`/`Criteria`, and
   `Record`/`Field` response attributes (`contentId`, `id`, `type`,
   `xmlConvertedValue`, `ListValue@displayName`).
3. OCSF schema 1.x class definitions for `VulnerabilityFinding` (2002) and
   `ComplianceFinding` (2003) as implemented in
   `packages/icuhub-schemas/src/icuhub_schemas/ocsf.py`.

Endpoints and shapes marked `[UNVERIFIED]` in source comments (delete, data-feed
execute and history, attachment upload body, content history path, SOAP
`GetRecordById`, version field name) have no authoritative sample in the sources
above; their fixtures are minimal placeholders consistent with the documented
envelope convention and are tracked in `docs/IMPLEMENTATION_GAPS.md`.
