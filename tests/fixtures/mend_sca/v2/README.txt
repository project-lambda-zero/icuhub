Mend SCA API 2.0 fixtures
==========================

Sources: https://api-docs.mend.io/sca/2.0 (see ../SOURCES.md).

Shapes and status:

- login.json: `{"retVal": {"jwtToken"}}` uses the key names given in the fixture
  assignment for the 2.0 login response. [UNVERIFIED] against the bundled 2.0
  login example and against a live response; no additional response keys are
  represented.
- security_alerts_page1.json, security_alerts_page2.json: the `additionalData`
  (`totalItems`, `isLastPage`), `supportToken`, and `retVal` envelope and the
  alert keys follow the shape specified for the 2.0 security alert pages.
  [UNVERIFIED] against the bundled 2.0 schema and against a live response.
- legal_alerts_page1.json: [UNVERIFIED] the legal alert shape. The `type` value
  "LEGAL", the `license` object (`name`, `type`), and the omission of
  `vulnerability` are not confirmed against the 2.0 legal alert schema. Do not
  treat the parser contract for legal alerts as verified until this is checked
  against a real response.
- direct_v2_retval.json (under ../report/): a 2.0 `retVal` body, intentionally
  not a valid report.
