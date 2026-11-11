"""GitLab GraphQL traversal of native vulnerability findings.

The project's ``vulnerabilities`` connection is traversed page by page through ``pageInfo``. GitLab
exposes no ``updatedAfter`` filter on this connection, so incremental selection happens client-side
in the stream through ``time_id_batches``. A traversal that cannot finish within ``max_pages``
reports ``complete=False`` so no absence claim is made from it.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit, urlunsplit

from icuhub.kit.errors import NotFound, VendorContractError

if TYPE_CHECKING:
    from icuhub.connectors._gitlab.connector import GitLabConnectorBase

__all__ = ["normalize_vulnerability", "traverse_vulnerabilities"]

_VULNERABILITIES_QUERY = """
query ProjectVulnerabilities($fullPath: ID!, $first: Int!, $after: String) {
  project(fullPath: $fullPath) {
    vulnerabilities(first: $first, after: $after) {
      pageInfo { hasNextPage endCursor }
      nodes {
        id
        uuid
        state
        severity
        reportType
        updatedAt
        identifiers { name externalType externalId url }
        location {
          ... on VulnerabilityLocationSast { file startLine endLine }
        }
      }
    }
  }
}
"""

_GID = re.compile(r"^gid://gitlab/Vulnerability/([1-9][0-9]*)$")


def _graphql_error(body: dict[str, Any]) -> None:
    errors = body.get("errors")
    if errors:
        messages = [str(item.get("message", "")) for item in errors if isinstance(item, dict)]
        raise VendorContractError(f"GitLab GraphQL returned errors: {'; '.join(messages)[:500]}")


def graphql_url(base_url: str) -> str:
    """Return the host-root GraphQL endpoint for a REST ``base_url`` such as ``https://host/api/v4``.

    GitLab serves GraphQL at ``/api/graphql`` on the instance origin, not under the REST ``/api/v4``
    prefix, so the absolute same-origin URL is built here rather than joined onto the REST base.
    """
    parts = urlsplit(base_url)
    return urlunsplit((parts.scheme, parts.netloc, "/api/graphql", "", ""))


async def _full_path(connector: GitLabConnectorBase, project_id: int) -> str:
    result = await connector.http.request("GET", f"/projects/{project_id}")
    body = result.json()
    path = body.get("path_with_namespace") if isinstance(body, dict) else None
    if not isinstance(path, str) or not path:
        raise VendorContractError("GitLab project response has no path_with_namespace")
    return path


def _native_id(gid: Any) -> int:
    match = _GID.fullmatch(gid) if isinstance(gid, str) else None
    if match is None:
        raise VendorContractError("GitLab vulnerability id is not a Vulnerability gid")
    return int(match.group(1))


def normalize_vulnerability(node: dict[str, Any]) -> dict[str, Any]:
    """Return the REST-shaped finding the native mapper consumes, keeping the GraphQL gid for cursors.

    Enum values are lowered to the REST vocabulary the mapper already validates. Identifiers without
    an external id carry no value and are dropped rather than failing the whole finding.
    """
    identifiers = [
        {
            "type": str(item["externalType"]).lower(),
            "value": item["externalId"],
            "name": item.get("name"),
            "url": item.get("url"),
        }
        for item in node.get("identifiers") or []
        if isinstance(item, dict)
        and isinstance(item.get("externalType"), str)
        and isinstance(item.get("externalId"), str)
    ]
    location = node.get("location")
    affected = (
        {"file": location["file"], "start_line": location.get("startLine"), "end_line": location.get("endLine")}
        if isinstance(location, dict) and isinstance(location.get("file"), str)
        else None
    )
    return {
        "id": _native_id(node.get("id")),
        "gid": node["id"],
        "uuid": node.get("uuid"),
        "state": str(node["state"]).lower() if node.get("state") else None,
        "severity": str(node["severity"]).lower() if node.get("severity") else None,
        "report_type": str(node["reportType"]).lower() if node.get("reportType") else None,
        "updated_at": node.get("updatedAt"),
        "identifiers": identifiers,
        "location": affected,
    }


async def traverse_vulnerabilities(connector: GitLabConnectorBase, project_id: int) -> tuple[list[dict[str, Any]], bool]:
    """Return every native finding of the project and whether the traversal finished.

    Raises ``NotFound`` when the project is absent. A ``False`` completeness flag means the page
    budget ran out before ``hasNextPage`` turned false; callers must not treat absence as proof.
    """
    config = connector._config()
    full_path = await _full_path(connector, project_id)
    findings: list[dict[str, Any]] = []
    after: str | None = None
    for _ in range(config.max_pages):
        result = await connector.http.request(
            "POST",
            graphql_url(config.base_url),
            json={
                "query": _VULNERABILITIES_QUERY,
                "variables": {"fullPath": full_path, "first": config.page_size, "after": after},
            },
            idempotency="safe_read",
        )
        body = result.json()
        if not isinstance(body, dict):
            raise VendorContractError("GitLab GraphQL response is not a JSON object")
        _graphql_error(body)
        project = (body.get("data") or {}).get("project")
        if project is None:
            raise NotFound(f"GitLab project {project_id} is not visible to the token")
        connection = project.get("vulnerabilities")
        if not isinstance(connection, dict):
            raise VendorContractError("GitLab GraphQL vulnerabilities connection is missing")
        for node in connection.get("nodes") or []:
            findings.append(normalize_vulnerability(node))
        page_info = connection.get("pageInfo") or {}
        if not page_info.get("hasNextPage"):
            return findings, True
        after = page_info.get("endCursor")
        if not isinstance(after, str) or not after:
            raise VendorContractError("GitLab GraphQL hasNextPage without endCursor")
    return findings, False
