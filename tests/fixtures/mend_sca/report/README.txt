Mend SCA report fixtures
========================

Sources: see ../SOURCES.md.

- platform_3_response.json: VERIFIED shape. Direct Mend Platform 3.0 `response`
  envelope; the finding objects are copied from ../v3/security_findings_page1.json.
- direct_v2_retval.json: intentionally NOT a valid report. A 2.0 `retVal` body
  that the report parser must reject.
- unified_agent_libraries.json: [UNVERIFIED] Unified Agent `libraries` report
  layout (`libraries[]` with `name`, `version`, `sha1`, `vulnerabilities[]`).
  No authoritative schema in the bundled docs. Confirm against a real export.
- manual_vulnerabilities.json: [UNVERIFIED] manual export layout
  (`vulnerabilities[]` with `node.project`, `node.library`, `vulnerability`).
  No authoritative schema in the bundled docs. Confirm against a real export.
- platform_components.json: [UNVERIFIED] grouped Platform `components` report
  layout (`components[]` with `component` and `vulnerabilities[]`). No
  authoritative schema in the bundled docs. Confirm against a real export.
