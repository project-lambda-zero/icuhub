# Fortify SSC fixture sources

All fixtures in this directory are synthetic, hand-written for tests. No
production SSC data, tokens, hostnames, or customer identifiers appear here.

Sourced from `docs/VENDOR_CONNECTORS.md` (Fortify SSC section, lines 875-947):

- Endpoint and parameter names: `projectVersions/{id}/issues`, `artifacts`,
  `activities`, `projectVersions`; paging with `start`, `limit`, `withoutCount`,
  `orderby`, `fields`; response envelope with `data` and `count`.
- Issue identity: `issueInstanceId`, numeric `id`, `revision`.
- Folder reference: `folderGuid` (not the deprecated `folderId`).
- Webhook header `X-SSC-Signature` and event body fields.

Not sourced. These keys appear in fixtures only as synthetic placeholders and
are marked `[UNVERIFIED]` in the connector; they must be confirmed against a
live SSC 24.2+ response before being relied on:

- `primaryRuleGuid`, `category`, `fileName`, `lineNumber`, `updated`,
  `removed`, `suppressed`, `audit.auditState`, `status`, `uploadDate`,
  `versionNumber`, `fileURL`, `userName`, `timestamp`, `triggeredAt`,
  `webhookId`, `issueId`, `event`.

Files:

- `issues_page1.json`, `issues_page2.json`: paged issue responses.
- `artifacts.json`: artifact listing.
- `activities.json`: activity listing.
- `project_versions.json`: project version discovery listing.
- `webhook_issue_changed.json`: an `ISSUE_CHANGED` delivery body.
