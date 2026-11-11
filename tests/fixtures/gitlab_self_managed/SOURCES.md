# Fixture sources: gitlab_self_managed (Self-Managed and Dedicated)

All fixtures use the documented response field sets of the GitLab REST API v4.
Scalar values are illustrative; no live instance was queried. Fixtures contain
only fields documented at the sources below.

- `audit_events.json`: `GET /api/v4/audit_events` instance audit events list
  response (administrator-only on Self-Managed). Source:
  https://docs.gitlab.com/api/audit_events/ (instance audit events; fields
  `id`, `author_id`, `entity_id`, `entity_type`, `created_at`, `event_type`,
  and `details` with `author_name`, `author_email`, `custom_message`,
  `target_id`, `target_type`, `target_details`, `ip_address`, `entity_path`).
- `projects.json`: `GET /api/v4/projects?membership=true&simple=true` list
  response. Source: https://docs.gitlab.com/api/projects/ (simple listing
  fields `id`, `name`, `path`, `path_with_namespace`, `description`,
  `web_url`, `last_activity_at`).
- `user.json`: `GET /api/v4/user` identity probe response. Source:
  https://docs.gitlab.com/api/users/ (current user fields `id`, `username`,
  `name`, `state`, `web_url`). [UNVERIFIED] The probe path itself is pinned
  by connector behavior tests, not by a live capture.
- `merge_request_hook.json`, `pipeline_hook.json`: project webhook event
  payloads. Source: https://docs.gitlab.com/user/project/integrations/webhook_events/
  (`object_kind` values `merge_request` and `pipeline`). Hostnames, project
  identifiers, and names are synthetic.
- `audit_event_hook.json`: instance audit event delivery shape. [UNVERIFIED]
  No documented standard webhook schema for `object_kind: audit_event` was
  confirmed; fields mirror `GET /api/v4/audit_events`
  (https://docs.gitlab.com/api/audit_events/). All values are synthetic.
- Merge request fixtures are shared in shape with `tests/fixtures/gitlab/`
  (`GET /api/v4/merge_requests`, https://docs.gitlab.com/api/merge_requests/).
