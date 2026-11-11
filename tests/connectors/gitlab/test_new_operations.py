"""Operation-level behavior for GitLab downloads, repository file metadata, and blame.

Each test dispatches through ``execute_operation`` and asserts on the returned ``VendorResult``: digests and sizes
are present, while trace text, artifact bytes, file content, and blamed source lines are not.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from pathlib import Path
from typing import Any, ClassVar, cast

from icuhub.connectors._gitlab.connector import GitLabConnectorBase
from icuhub.connectors._gitlab.models import ArtifactRef, GitLabConfig, JobRef, RepositoryPathRef
from icuhub.connectors._gitlab.operations import execute_operation
from icuhub.kit import ConnectorConfig
from icuhub.kit.testing import RouteTransport, make_connector

PROJECT_ID = 42
JOB_ID = 301
API = "/api/v4"
TOKEN_REF = "gitlab-token"
SECRETS = {TOKEN_REF: b"glpat-synthetic"}
FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "gitlab"

ONE_MIB = 1024 * 1024
EIGHT_MIB = 8 * ONE_MIB
THIRTY_TWO_MIB = 32 * ONE_MIB

TRACE = (FIXTURES / "job_trace.txt").read_bytes()
ARTIFACT = (FIXTURES / "job_artifact_meta.json").read_bytes()
REPOSITORY_FILE_BYTES = (FIXTURES / "repository_file_hello.txt.json").read_bytes()
BLAME = json.loads((FIXTURES / "file_blame.json").read_text(encoding="utf-8"))


class _OperationGitLab(GitLabConnectorBase):
    """Concrete test connector: the shared GitLab base plus the class attributes an edition package supplies."""

    kind: ClassVar[str] = "gitlab"
    display_name: ClassVar[str] = "GitLab (operation test)"
    config_model: ClassVar[type[ConnectorConfig]] = GitLabConfig
    flows: ClassVar[tuple[str, ...]] = ()


def _connector(routes: dict[tuple[str, str], Any]) -> _OperationGitLab:
    config: dict[str, Any] = {"access_token": {"ref": TOKEN_REF}}
    return cast(_OperationGitLab, make_connector(_OperationGitLab, config, RouteTransport(routes), SECRETS))


def _get(path: str) -> tuple[str, str]:
    return ("GET", f"{API}{path}")


def _digest(content: bytes) -> dict[str, Any]:
    return {"sha256": hashlib.sha256(content).hexdigest(), "bytes": len(content), "truncated": False}


def _serialized(value: Any) -> str:
    return json.dumps(value.model_dump(mode="json"), sort_keys=True)


def _run(connector: _OperationGitLab, name: str, args: Any) -> Any:
    return asyncio.run(execute_operation(connector, name, args))


def test_download_job_log_returns_digest_and_no_trace_text() -> None:
    connector = _connector({_get(f"/projects/{PROJECT_ID}/jobs/{JOB_ID}/trace"): {"status": 200, "content": TRACE}})

    result = _run(connector, "download_job_log", JobRef(project_id=PROJECT_ID, job_id=JOB_ID))

    assert result.coverage == "complete"
    assert result.data == _digest(TRACE)
    assert set(result.data) == {"sha256", "bytes", "truncated"}
    assert "FIXTURE-LOG-LINE" not in _serialized(result)


def test_download_job_log_oversize_is_partial_and_truncated() -> None:
    oversize = b"x" * (EIGHT_MIB + 1)
    connector = _connector({_get(f"/projects/{PROJECT_ID}/jobs/{JOB_ID}/trace"): {"status": 200, "content": oversize}})

    result = _run(connector, "download_job_log", JobRef(project_id=PROJECT_ID, job_id=JOB_ID))

    assert result.coverage == "partial"
    assert result.data == {"sha256": None, "bytes": 0, "truncated": True}


def test_download_job_artifact_returns_digest_and_no_artifact_bytes() -> None:
    connector = _connector({_get(f"/projects/{PROJECT_ID}/jobs/{JOB_ID}/artifacts"): {"status": 200, "content": ARTIFACT}})

    result = _run(connector, "download_job_artifact", ArtifactRef(project_id=PROJECT_ID, job_id=JOB_ID))

    assert result.coverage == "complete"
    assert result.data == _digest(ARTIFACT)
    assert set(result.data) == {"sha256", "bytes", "truncated"}
    assert "FIXTURE-ARTIFACT-BYTES" not in _serialized(result)


def test_download_job_artifact_named_path_returns_digest_and_no_artifact_bytes() -> None:
    path = f"/projects/{PROJECT_ID}/jobs/{JOB_ID}/artifacts/reports/synthetic-report.json"
    connector = _connector({_get(path): {"status": 200, "content": ARTIFACT}})
    args = ArtifactRef(project_id=PROJECT_ID, job_id=JOB_ID, artifact_path="reports/synthetic-report.json")

    result = _run(connector, "download_job_artifact", args)

    assert result.data == _digest(ARTIFACT)
    assert "FIXTURE-ARTIFACT-BYTES" not in _serialized(result)


def test_download_job_artifact_oversize_is_partial_and_truncated() -> None:
    oversize = b"x" * (THIRTY_TWO_MIB + 1)
    connector = _connector({_get(f"/projects/{PROJECT_ID}/jobs/{JOB_ID}/artifacts"): {"status": 200, "content": oversize}})

    result = _run(connector, "download_job_artifact", ArtifactRef(project_id=PROJECT_ID, job_id=JOB_ID))

    assert result.coverage == "partial"
    assert result.data == {"sha256": None, "bytes": 0, "truncated": True}


def test_get_repository_file_returns_digest_ref_and_no_content_key() -> None:
    fixture = json.loads(REPOSITORY_FILE_BYTES)
    decoded = base64.b64decode(fixture["content"])
    connector = _connector({_get(f"/projects/{PROJECT_ID}/repository/files/hello.txt"): {"status": 200, "content": REPOSITORY_FILE_BYTES}})

    result = _run(connector, "get_repository_file", RepositoryPathRef(project_id=PROJECT_ID, path="hello.txt", ref="main"))

    assert result.coverage == "complete"
    assert "content" not in result.data
    assert result.data["ref"] == "main"
    assert result.data["sha256"] == hashlib.sha256(decoded).hexdigest()
    assert result.data["bytes"] == len(decoded) == 6
    assert result.data["truncated"] is False
    assert fixture["content"] not in _serialized(result)


def test_get_repository_file_defaults_ref_to_head() -> None:
    connector = _connector({_get(f"/projects/{PROJECT_ID}/repository/files/hello.txt"): {"status": 200, "content": REPOSITORY_FILE_BYTES}})

    result = _run(connector, "get_repository_file", RepositoryPathRef(project_id=PROJECT_ID, path="hello.txt"))

    assert result.data["ref"] == "HEAD"


def test_get_repository_file_oversize_is_partial_and_truncated() -> None:
    oversize = b"x" * (ONE_MIB + 1)
    connector = _connector({_get(f"/projects/{PROJECT_ID}/repository/files/big.bin"): {"status": 200, "content": oversize}})

    result = _run(connector, "get_repository_file", RepositoryPathRef(project_id=PROJECT_ID, path="big.bin"))

    assert result.coverage == "partial"
    assert result.data["truncated"] is True
    assert result.data["sha256"] is None
    assert result.data["bytes"] == 0
    assert "content" not in result.data


def test_get_file_blame_returns_commit_and_line_count_without_source_lines() -> None:
    connector = _connector({_get(f"/projects/{PROJECT_ID}/repository/files/hello.txt/blame"): {"status": 200, "json": BLAME}})

    result = _run(connector, "get_file_blame", RepositoryPathRef(project_id=PROJECT_ID, path="hello.txt"))

    assert result.coverage == "complete"
    assert len(result.data) == len(BLAME) == 1
    [item] = result.data
    assert item["commit"] == BLAME[0]["commit"]
    assert item["line_count"] == 1
    assert "lines" not in item
    assert "hello" not in json.dumps(result.data)


def test_get_file_blame_oversize_is_partial_and_empty() -> None:
    oversize = b"x" * (ONE_MIB + 1)
    connector = _connector({_get(f"/projects/{PROJECT_ID}/repository/files/hello.txt/blame"): {"status": 200, "content": oversize}})

    result = _run(connector, "get_file_blame", RepositoryPathRef(project_id=PROJECT_ID, path="hello.txt"))

    assert result.coverage == "partial"
    assert result.data == []
