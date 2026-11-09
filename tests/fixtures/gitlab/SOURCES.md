# Fixture sources: gitlab (GitLab.com)

All fixtures use the documented response field sets of the GitLab REST API v4.
Scalar values are illustrative; no live instance was queried. Fixtures contain
only fields documented at the sources below.

- `merge_requests_page1.json`: `GET /api/v4/merge_requests` list response.
  Source: https://docs.gitlab.com/api/merge_requests/ (list merge requests,
  response attributes `id`, `iid`, `project_id`, `title`, `description`,
  `state`, `draft`, `created_at`, `updated_at`, `merged_at`, `closed_at`,
  `target_branch`, `source_branch`, `author`, `merge_user`, `sha`, `web_url`,
  `labels`, `references`, `detailed_merge_status`, `has_conflicts`,
  `user_notes_count`).
- `audit_events.json`: `GET /api/v4/groups/:id/audit_events` list response.
  Source: https://docs.gitlab.com/api/audit_events/ (group audit events;
  fields `id`, `author_id`, `entity_id`, `entity_type`, `created_at`,
  `event_type`, `target_id`, `target_type`, and `details` with
  `author_name`, `author_email`, `custom_message`, `target_id`,
  `target_type`, `target_details`, `ip_address`, `entity_path`).
- `projects.json`: `GET /api/v4/projects?membership=true&simple=true` list
  response. Source: https://docs.gitlab.com/api/projects/ (list projects;
  simple listing fields `id`, `name`, `path`, `path_with_namespace`,
  `description`, `web_url`, `last_activity_at`).
- `user.json`: `GET /api/v4/user` identity probe response. Source:
  https://docs.gitlab.com/api/users/ (current user fields `id`, `username`,
  `name`, `state`, `web_url`). [UNVERIFIED] The probe path itself is pinned
  by connector behavior tests, not by a live capture.
