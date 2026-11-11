# Fortify SSC fixture sources

All fixtures in this directory are synthetic, hand-written for tests. No
production SSC data, tokens, hostnames, or customer identifiers appear here.

Sourced from `docs/VENDOR_CONNECTORS.md` (Fortify SSC section, lines 875-947):

- Endpoint and parameter names: `projectVersions/{id}/issues`, `artifacts`,
  `activities`, `projectVersions`; paging with `start`, `limit`, `withoutCount`,
  `orderby`, `fields`; response envelope with `data` and `count`.
- Issue identity: `issueInstanceId`, numeric `id`, `revision`.
- Folder reference: `folderGuid` (not the deprecated `folderId`).
- Webhook header `X-SSC-Signature: sha256=<hex>` (HMAC-SHA256 over the raw body
  with the `Date` value appended) and the application-version event names
  `ANALYSIS_RESULT_UPLOAD_COMPLETE_SUCCESS`, `ANALYSIS_RESULT_UPLOAD_FAILURE`,
  `ANALYSIS_RESULT_INDEXING_COMPLETED`. Source: Micro Focus Fortify Software
  Security Center 25.4.0 documentation, "Webhooks" page
  (https://www.microfocus.com/documentation/fortify-software-security-center/2540/ssc-ugd-html-25.4.0/doc/2405_25.4.0/e957dd67eef5_cr_webhook.html).

Not sourced. These keys appear in fixtures only as synthetic placeholders and
are marked `[UNVERIFIED]` in the connector; they must be confirmed against a
live SSC 24.2+ response before being relied on:

- `primaryRuleGuid`, `category`, `fileName`, `lineNumber`, `updated`,
  `removed`, `suppressed`, `audit.auditState`, `status`, `uploadDate`,
  `versionNumber`, `fileURL`, `userName`, `timestamp`.
- Webhook payload keys `event`, `webhookId`, `triggeredAt`, `projectVersionId`,
  `issueId`. The vendor page documents the event names and signature, but not
  the payload field names. The connector reads `event` for dispatch and
  `webhookId` plus `triggeredAt` for dedupe.
- Session probe `POST userSession/info` (used by `check()`) and its response
  keys `webappVersion`, `applicationContextPath`, `licenseCapabilities`,
  `permissions`. Not sourced; `[UNVERIFIED]` in the connector. The probe fixture
  bodies in `test_fortify_ssc_connector.py` are synthetic and are not proof of
  the wire contract.

Files:

- `issues_page1.json`, `issues_page2.json`: paged issue responses.
- `artifacts.json`: artifact listing.
- `activities.json`: activity listing.
- `project_versions.json`: project version discovery listing.
- `webhook_issue_changed.json`: a synthetic `ANALYSIS_RESULT_UPLOAD_COMPLETE_SUCCESS`
  delivery body. Its payload keys are unverified; see above.
