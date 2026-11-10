"""Behavior tests for the GitLab commit, repository, blame, job, and audit object streams."""

from __future__ import annotations

import gzip
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar, cast

import pytest

from icuhub.connectors._gitlab.connector import GitLabConnectorBase
from icuhub.connectors._gitlab.models import GitLabConfig
from icuhub.connectors.gitlab.connector import GitLab
from icuhub.connectors.gitlab_self_managed.connector import GitLabSelfManaged
from icuhub.kit import ConnectorConfig
from icuhub.kit.cursors import SequenceCursor, TimeIdCursor
from icuhub.kit.errors import ConfigError, VendorContractError
from icuhub.kit.testing import RouteTransport, collect_stream, make_connector, map_all
from icuhub.kit.types import Target

PROJECT_ID = 42
API = "/api/v4"
TOKEN_REF = "gitlab-token"
SECRETS = {TOKEN_REF: b"glpat-synthetic"}
FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "gitlab"

SHA_A = "a" * 40
SHA_B = "b" * 40
COMMITS_PATH = f"/projects/{PROJECT_ID}/repository/commits"
TREE_PATH = f"/projects/{PROJECT_ID}/repository/tree"
JOBS_PATH = f"/projects/{PROJECT_ID}/jobs"
ONE_MIB = 1024 * 1024
EIGHT_MIB = 8 * 1024 * 1024


class _StreamGitLab(GitLabConnectorBase):
    """Concrete test connector: the shared GitLab base plus the class attributes an edition package supplies."""

    kind: ClassVar[str] = "gitlab"
    display_name: ClassVar[str] = "GitLab (stream test)"
    config_model: ClassVar[type[ConnectorConfig]] = GitLabConfig
    flows: ClassVar[tuple[str, ...]] = ()


def _connector(routes: dict[tuple[str, str], Any], **config_extra: Any) -> _StreamGitLab:
    config: dict[str, Any] = {"access_token": {"ref": TOKEN_REF}, **config_extra}
    return cast(_StreamGitLab, make_connector(_StreamGitLab, config, RouteTransport(routes), SECRETS))


def _gitlab_com(routes: dict[tuple[str, str], Any]) -> GitLab:
    config: dict[str, Any] = {"access_token": {"ref": TOKEN_REF}}
    return cast(GitLab, make_connector(GitLab, config, RouteTransport(routes), SECRETS))


def _project_target() -> Target:
    return Target(
        id=str(PROJECT_ID),
        source_uid=f"gitlab:project:{PROJECT_ID}",
        kind="project",
        display_name="demo",
        attributes={},
    )


def _records(batches: list[Any]) -> list[dict[str, Any]]:
    return [record for batch in batches for record in batch.records]


def _fixture(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _get(path: str) -> tuple[str, str]:
    return ("GET", f"{API}{path}")


def _next_link(path: str, page: int) -> dict[str, str]:
    return {"link": f'<https://gitlab.com{API}{path}?page={page}>; rel="next"'}


def _paged_route(path: str, pages: dict[int, Any], last_page: int) -> Any:
    """Serve ``pages`` by the ``page`` query parameter, linking each page to the next until ``last_page``."""

    def respond(request: Any) -> dict[str, Any]:
        page = int(request.url.params.get("page", "1"))
        spec: dict[str, Any] = {"status": 200, "json": pages[page]}
        if page < last_page:
            spec["headers"] = _next_link(path, page + 1)
        return spec

    return respond


def _commit_routes() -> dict[tuple[str, str], Any]:
    return {
        _get(COMMITS_PATH): _paged_route(
            COMMITS_PATH,
            {1: _fixture("commit_diffs_commits_page1.json"), 2: _fixture("commit_diffs_commits_page2.json")},
            last_page=2,
        ),
        _get(f"{COMMITS_PATH}/{SHA_A}/diff"): {"status": 200, "json": _fixture(f"commit_diff_{SHA_A}.json")},
        _get(f"{COMMITS_PATH}/{SHA_B}/diff"): {"status": 200, "json": _fixture(f"commit_diff_{SHA_B}.json")},
    }


def _tree_routes() -> dict[tuple[str, str], Any]:
    return {
        _get(TREE_PATH): _paged_route(
            TREE_PATH,
            {1: _fixture("repository_tree_page1.json"), 2: _fixture("repository_tree_page2.json")},
            last_page=2,
        ),
        _get(f"/projects/{PROJECT_ID}/repository/files/hello.txt"): {
            "status": 200,
            "content": (FIXTURES / "repository_file_hello.txt.json").read_bytes(),
        },
        _get(f"/projects/{PROJECT_ID}/repository/files/notes.txt"): {
            "status": 200,
            "content": (FIXTURES / "repository_file_notes.txt.json").read_bytes(),
        },
    }


def _blame_route(path: str) -> dict[tuple[str, str], Any]:
    return {_get(f"/projects/{PROJECT_ID}/repository/files/{path}/blame"): {"status": 200, "json": _fixture("file_blame.json")}}


TRACE = (FIXTURES / "job_trace.txt").read_bytes()


def _job(job_id: int, finished_at: str) -> dict[str, Any]:
    return {"id": job_id, "finished_at": finished_at, "pipeline": {"id": job_id + 4900}}


def _job_routes(jobs: list[dict[str, Any]], traces: dict[int, bytes]) -> dict[tuple[str, str], Any]:
    routes: dict[tuple[str, str], Any] = {_get(JOBS_PATH): {"status": 200, "json": jobs}}
    for job_id, body in traces.items():
        routes[_get(f"/projects/{PROJECT_ID}/jobs/{job_id}/trace")] = {"status": 200, "content": body}
    return routes


ARTIFACT_META = _fixture("job_artifact_meta.json")
ARTIFACT_PAYLOAD = str(ARTIFACT_META["artifact_payload"]).encode("utf-8")
ARTIFACT_JOBS: list[dict[str, Any]] = [
    {
        "id": 301,
        "finished_at": "2026-11-09T11:00:00Z",
        "pipeline": {"id": 5301},
        "artifacts": [{"filename": "synthetic-report.json", "size": 32}],
    },
    {"id": 302, "finished_at": "2026-11-09T11:05:00Z", "pipeline": {"id": 5302}, "artifacts": []},
]
ARTIFACT_ROUTES: dict[tuple[str, str], Any] = {
    _get(JOBS_PATH): {"status": 200, "json": ARTIFACT_JOBS},
    _get(f"/projects/{PROJECT_ID}/jobs/301/artifacts"): {"status": 200, "content": ARTIFACT_PAYLOAD},
}

# Documented layout: YYYY/MM/DD/<ms-epoch>_<first-event-id>.json. The timestamps are deliberately
# unequal in digit count, so a lexical sort (1000000 < 1000 < 999) disagrees with the chronological order.
AUDIT_KEYS = (
    "2026/11/09/999_9001.json",
    "2026/11/09/1000_9003.json",
    "2026/11/09/1000000_9001.json",
)


def _audit_bodies() -> dict[str, bytes]:
    return {
        AUDIT_KEYS[0]: (FIXTURES / "audit_objects_array.json").read_bytes(),
        AUDIT_KEYS[1]: (FIXTURES / "audit_object_single.json").read_bytes(),
        AUDIT_KEYS[2]: (FIXTURES / "audit_object_retry.json").read_bytes(),
    }


def _audit_routes(bodies: dict[str, bytes]) -> dict[tuple[str, str], Any]:
    return {("GET", f"/presigned/{key}"): {"status": 200, "content": body} for key, body in bodies.items()}


def _audit_target(keys: tuple[str, ...] = AUDIT_KEYS) -> Target:
    objects = [{"key": key, "url": f"https://gitlab.com/presigned/{key}?X-Amz-Signature=synthetic"} for key in keys]
    return Target(
        id=str(PROJECT_ID),
        source_uid=f"gitlab:project:{PROJECT_ID}",
        kind="project",
        display_name="demo",
        attributes={"objects": objects},
    )


# Commit diffs: full snapshot over the paged commit list.


def test_commit_diffs_pages_through_commit_list_and_emits_every_diff() -> None:
    connector = _connector(_commit_routes())

    batches = collect_stream(connector, "commit_diffs", _project_target(), mode="full")

    records = _records(batches)
    assert [(record["_commit_sha"], record["new_path"]) for record in records] == [
        (SHA_A, "hello.txt"),
        (SHA_B, "notes.txt"),
    ]
    assert all("diff" not in record for record in records)
    assert all(batch.complete is False for batch in batches[:-1])
    assert batches[-1].complete is True


def test_commit_diffs_exhausted_page_budget_is_not_complete() -> None:
    connector = _connector(_commit_routes(), max_pages=1)

    batches = collect_stream(connector, "commit_diffs", _project_target(), mode="full")

    assert [(record["_commit_sha"], record["new_path"]) for record in _records(batches)] == [(SHA_A, "hello.txt")]
    assert all(batch.complete is False for batch in batches)


# Repository files: full snapshot over the recursive tree, metadata only.


def test_repository_files_pages_tree_and_records_metadata_only() -> None:
    connector = _connector(_tree_routes())

    batches = collect_stream(connector, "repository_files", _project_target(), mode="full")

    records = _records(batches)
    hello_body = (FIXTURES / "repository_file_hello.txt.json").read_bytes()
    notes_body = (FIXTURES / "repository_file_notes.txt.json").read_bytes()
    assert [record["path"] for record in records] == ["hello.txt", "notes.txt"]
    assert records[0]["bytes"] == len(hello_body)
    assert records[0]["sha256"] == hashlib.sha256(hello_body).hexdigest()
    assert records[0]["truncated"] is False
    assert records[1]["bytes"] == len(notes_body)
    assert records[1]["sha256"] == hashlib.sha256(notes_body).hexdigest()
    dumped = json.dumps(records)
    assert "aGVsbG8K" not in dumped
    assert "bm90ZXMK" not in dumped
    assert batches[-1].complete is True


def test_repository_files_oversize_blob_is_truncated_and_not_downloaded() -> None:
    tree = [
        {
            "id": "3" * 40,
            "name": "big.bin",
            "type": "blob",
            "path": "big.bin",
            "mode": "100644",
            "size": ONE_MIB + 1,
        }
    ]
    downloads: list[str] = []

    def record_download(request: Any) -> dict[str, Any]:
        downloads.append(request.url.path)
        return {"status": 200, "content": b"x"}

    routes: dict[tuple[str, str], Any] = {
        _get(TREE_PATH): {"status": 200, "json": tree},
        _get(f"/projects/{PROJECT_ID}/repository/files/big.bin"): record_download,
    }
    connector = _connector(routes)

    batches = collect_stream(connector, "repository_files", _project_target(), mode="full")

    [record] = _records(batches)
    assert record["path"] == "big.bin"
    assert record["truncated"] is True
    assert record["bytes"] == 0
    assert record["sha256"] is None
    assert downloads == []


def test_repository_files_exhausted_page_budget_is_not_complete() -> None:
    connector = _connector(_tree_routes(), max_pages=1)

    batches = collect_stream(connector, "repository_files", _project_target(), mode="full")

    assert [record["path"] for record in _records(batches)] == ["hello.txt"]
    assert all(batch.complete is False for batch in batches)


# File blame: full snapshot, one blame request per blob.


def test_file_blame_collects_ranges_per_blob_and_completes() -> None:
    routes = {**_tree_routes(), **_blame_route("hello.txt"), **_blame_route("notes.txt")}
    connector = _connector(routes)

    batches = collect_stream(connector, "file_blame", _project_target(), mode="full")

    records = _records(batches)
    assert sorted(record["_file_path"] for record in records) == ["hello.txt", "notes.txt"]
    assert all((record["start"], record["end"]) == (1, 1) for record in records)
    assert all(record["_commit_sha"] == "c" * 40 for record in records)
    assert batches[-1].complete is True


def test_file_blame_child_budget_exhaustion_is_not_complete() -> None:
    blame_pages: list[str] = []

    def blame_respond(request: Any) -> dict[str, Any]:
        blame_pages.append(request.url.params.get("page", "1"))
        return {"status": 200, "json": _fixture("file_blame.json"), "headers": _next_link("/blame", 2)}

    routes: dict[tuple[str, str], Any] = {
        _get(TREE_PATH): {"status": 200, "json": _fixture("repository_tree_page1.json")},
        _get(f"/projects/{PROJECT_ID}/repository/files/hello.txt/blame"): blame_respond,
    }
    connector = _connector(routes, max_pages=1)

    batches = collect_stream(connector, "file_blame", _project_target(), mode="full")

    assert blame_pages == ["1"]
    assert batches[-1].complete is False
    assert all(batch.complete is False for batch in batches)


# Job logs: incremental over the job list, trace metadata only.


def test_job_logs_resume_skips_jobs_at_checkpoint_timestamp_and_id() -> None:
    jobs = [
        _job(101, "2026-11-09T09:00:00Z"),
        _job(102, "2026-11-09T09:05:00Z"),
        _job(103, "2026-11-09T09:05:00Z"),
    ]
    connector = _connector(_job_routes(jobs, {101: TRACE, 102: TRACE, 103: TRACE}))
    checkpoint = TimeIdCursor(ts=datetime(2026, 11, 9, 9, 5, tzinfo=UTC), last_ids_at_ts=["42:102"], overlap_s=0)

    batches = collect_stream(connector, "job_logs", _project_target(), checkpoint=checkpoint, mode="incremental")

    assert [record["job_id"] for record in _records(batches)] == [103]
    assert batches[-1].complete is True


def test_job_logs_replay_is_identical_for_identical_input() -> None:
    jobs = [_job(101, "2026-11-09T09:00:00Z"), _job(102, "2026-11-09T09:05:00Z")]
    routes = _job_routes(jobs, {101: TRACE, 102: TRACE})

    first = collect_stream(_connector(routes), "job_logs", _project_target(), mode="incremental")
    second = collect_stream(_connector(routes), "job_logs", _project_target(), mode="incremental")

    assert _records(first) == _records(second)
    assert first[-1].checkpoint == second[-1].checkpoint


def test_job_logs_oversize_trace_is_truncated_and_metadata_only() -> None:
    oversize = b"x" * (EIGHT_MIB + 1)
    connector = _connector(_job_routes([_job(201, "2026-11-09T09:10:00Z")], {201: oversize}))

    batches = collect_stream(connector, "job_logs", _project_target(), mode="incremental")

    [record] = _records(batches)
    assert record["job_id"] == 201
    assert record["truncated"] is True
    assert record["bytes"] == 0
    assert record["sha256"] is None


def test_job_logs_cursor_does_not_pass_truncated_job() -> None:
    oversize = b"x" * (EIGHT_MIB + 1)
    durable_at = datetime(2026, 11, 9, 9, 5, tzinfo=UTC)
    jobs = [_job(101, "2026-11-09T09:00:00Z"), _job(102, "2026-11-09T09:05:00Z"), _job(201, "2026-11-09T09:10:00Z")]
    connector = _connector(_job_routes(jobs, {101: TRACE, 102: TRACE, 201: oversize}))

    batches = collect_stream(connector, "job_logs", _project_target(), mode="incremental")

    emitted = {record["job_id"]: record for record in _records(batches)}
    assert sorted(emitted) == [101, 102, 201]
    assert emitted[201]["truncated"] is True
    assert emitted[201]["bytes"] == 0
    assert emitted[201]["sha256"] is None
    final = batches[-1]
    assert final.complete is False
    assert final.checkpoint.ts == durable_at
    assert final.checkpoint.last_ids_at_ts == [f"{PROJECT_ID}:102"]


def test_job_logs_metadata_only_no_trace_text_leaks() -> None:
    connector = _connector(_job_routes([_job(101, "2026-11-09T09:00:00Z")], {101: TRACE}))

    records = _records(collect_stream(connector, "job_logs", _project_target(), mode="incremental"))

    assert "FIXTURE-LOG-LINE" not in json.dumps(records)
    assert records[0]["bytes"] == len(TRACE)
    assert records[0]["sha256"] == hashlib.sha256(TRACE).hexdigest()
    assert records[0]["truncated"] is False


# Job artifacts: incremental over the job list, artifact metadata only.


def test_job_artifacts_metadata_only_no_artifact_bytes_leak() -> None:
    connector = _connector(ARTIFACT_ROUTES)

    records = _records(collect_stream(connector, "job_artifacts", _project_target(), mode="incremental"))

    assert [record["job_id"] for record in records] == [301]
    assert records[0]["artifact_names"] == ["synthetic-report.json"]
    assert records[0]["bytes"] == len(ARTIFACT_PAYLOAD)
    assert records[0]["sha256"] == hashlib.sha256(ARTIFACT_PAYLOAD).hexdigest()
    assert "FIXTURE-ARTIFACT-BYTES" not in json.dumps(records)


def test_job_artifacts_replay_is_identical() -> None:
    first = collect_stream(_connector(ARTIFACT_ROUTES), "job_artifacts", _project_target(), mode="incremental")
    second = collect_stream(_connector(ARTIFACT_ROUTES), "job_artifacts", _project_target(), mode="incremental")

    assert _records(first) == _records(second)
    assert first[-1].checkpoint == second[-1].checkpoint


ARTIFACT_MAX_BYTES = 32 * 1024 * 1024
ARTIFACT_FAILED_AT = datetime(2026, 11, 9, 11, 0, tzinfo=UTC)


def test_job_artifacts_resume_skips_job_at_checkpoint_timestamp_and_id() -> None:
    later_job = {
        "id": 303,
        "finished_at": "2026-11-09T11:05:00Z",
        "pipeline": {"id": 5303},
        "artifacts": [{"filename": "later.json", "size": 32}],
    }
    routes = {
        **ARTIFACT_ROUTES,
        _get(JOBS_PATH): {"status": 200, "json": [*ARTIFACT_JOBS, later_job]},
        _get(f"/projects/{PROJECT_ID}/jobs/303/artifacts"): {"status": 200, "content": ARTIFACT_PAYLOAD},
    }
    checkpoint = TimeIdCursor(ts=ARTIFACT_FAILED_AT, last_ids_at_ts=[f"{PROJECT_ID}:301"], overlap_s=0)

    batches = collect_stream(
        _connector(routes), "job_artifacts", _project_target(), checkpoint=checkpoint, mode="incremental"
    )

    assert [record["job_id"] for record in _records(batches)] == [303]
    assert batches[-1].complete is True


def test_job_artifacts_oversize_artifact_is_truncated_and_metadata_only() -> None:
    oversize = b"x" * (ARTIFACT_MAX_BYTES + 1)
    routes = {
        **ARTIFACT_ROUTES,
        _get(f"/projects/{PROJECT_ID}/jobs/301/artifacts"): {"status": 200, "content": oversize},
    }

    batches = collect_stream(_connector(routes), "job_artifacts", _project_target(), mode="incremental")

    [record] = _records(batches)
    assert record["job_id"] == 301
    assert record["artifact_names"] == ["synthetic-report.json"]
    assert record["truncated"] is True
    assert record["bytes"] == 0
    assert record["sha256"] is None


def test_job_artifacts_cursor_does_not_pass_truncated_job() -> None:
    oversize = b"x" * (ARTIFACT_MAX_BYTES + 1)
    durable_at = datetime(2026, 11, 9, 10, 55, tzinfo=UTC)
    durable_job = {
        "id": 300,
        "finished_at": "2026-11-09T10:55:00Z",
        "pipeline": {"id": 5300},
        "artifacts": [{"filename": "small.json", "size": len(ARTIFACT_PAYLOAD)}],
    }
    routes = {
        **ARTIFACT_ROUTES,
        _get(JOBS_PATH): {"status": 200, "json": [durable_job, *ARTIFACT_JOBS]},
        _get(f"/projects/{PROJECT_ID}/jobs/300/artifacts"): {"status": 200, "content": ARTIFACT_PAYLOAD},
        _get(f"/projects/{PROJECT_ID}/jobs/301/artifacts"): {"status": 200, "content": oversize},
    }

    batches = collect_stream(_connector(routes), "job_artifacts", _project_target(), mode="incremental")

    emitted = {record["job_id"]: record for record in _records(batches)}
    assert sorted(emitted) == [300, 301]
    assert emitted[301]["truncated"] is True
    assert emitted[301]["bytes"] == 0
    assert emitted[301]["sha256"] is None
    final = batches[-1]
    assert final.complete is False
    assert final.checkpoint.ts == durable_at
    assert final.checkpoint.last_ids_at_ts == [f"{PROJECT_ID}:300"]


# Audit stream objects: GitLab.com only, incremental over presigned objects.


def test_audit_stream_objects_reads_array_payloads_in_numeric_order() -> None:
    connector = _gitlab_com(_audit_routes(_audit_bodies()))

    batches = collect_stream(connector, "audit_stream_objects", _audit_target(), mode="incremental")

    # Lexical key order would read the retry object (1000000_...) first and emit 9001 from it.
    records = _records(batches)
    assert [record["id"] for record in records] == [9001, 9002, 9003, 9004, 9005]
    assert [record["_audit_object_key"] for record in records] == [
        AUDIT_KEYS[0],
        AUDIT_KEYS[0],
        AUDIT_KEYS[1],
        AUDIT_KEYS[2],
        AUDIT_KEYS[2],
    ]
    assert batches[-1].complete is True
    assert batches[-1].checkpoint.seq == AUDIT_KEYS[2]


def test_audit_stream_objects_rejects_non_array_payload() -> None:
    connector = _gitlab_com(_audit_routes({AUDIT_KEYS[0]: b'{"id": 1}'}))

    with pytest.raises(VendorContractError, match="not a JSON array"):
        collect_stream(connector, "audit_stream_objects", _audit_target((AUDIT_KEYS[0],)), mode="incremental")


def test_audit_stream_objects_rejects_key_outside_documented_layout() -> None:
    connector = _gitlab_com(_audit_routes(_audit_bodies()))
    target = _audit_target((AUDIT_KEYS[0], "2026-11-09/c.json"))

    with pytest.raises(ConfigError, match="does not match"):
        collect_stream(connector, "audit_stream_objects", target, mode="incremental")


def test_audit_retried_batch_under_new_key_maps_to_the_same_event_uid() -> None:
    connector = _gitlab_com(_audit_routes(_audit_bodies()))
    original_target = _audit_target((AUDIT_KEYS[0],))
    retry_target = _audit_target((AUDIT_KEYS[2],))

    original = map_all(
        connector,
        "audit_stream_objects",
        _records(collect_stream(connector, "audit_stream_objects", original_target, mode="incremental")),
        original_target,
    )
    retry = map_all(
        connector,
        "audit_stream_objects",
        _records(collect_stream(connector, "audit_stream_objects", retry_target, mode="incremental")),
        retry_target,
    )

    original_uids = {item.uid for item in original}
    retry_uids = {item.uid for item in retry}
    # Events 9001 and 9002 were delivered under both keys and must collapse to one evidence uid each.
    assert original_uids == {"gitlab:audit_stream_object:audit_event:9001", "gitlab:audit_stream_object:audit_event:9002"}
    assert retry_uids == original_uids | {
        "gitlab:audit_stream_object:audit_event:9004",
        "gitlab:audit_stream_object:audit_event:9005",
    }


def test_audit_stream_objects_presigned_urls_never_leak_into_records_or_mapped_evidence() -> None:
    connector = _gitlab_com(_audit_routes(_audit_bodies()))
    target = _audit_target()

    records = _records(collect_stream(connector, "audit_stream_objects", target, mode="incremental"))
    mapped = map_all(connector, "audit_stream_objects", records, target)

    assert mapped
    texts = [json.dumps(records), *(item.model_dump_json() for item in mapped)]
    for text in texts:
        assert "presigned" not in text
        assert "X-Amz" not in text


def test_audit_stream_objects_gzip_payload_fails_closed() -> None:
    target = _audit_target((AUDIT_KEYS[2],))
    connector = _gitlab_com(_audit_routes({AUDIT_KEYS[2]: gzip.compress(b'[{"id": 1}]')}))

    with pytest.raises(VendorContractError):
        collect_stream(connector, "audit_stream_objects", target, mode="incremental")


def test_audit_stream_objects_non_utf8_payload_fails_closed() -> None:
    target = _audit_target((AUDIT_KEYS[2],))
    connector = _gitlab_com(_audit_routes({AUDIT_KEYS[2]: b"\xff\xfe\x00"}))

    with pytest.raises(VendorContractError):
        collect_stream(connector, "audit_stream_objects", target, mode="incremental")


def test_audit_stream_objects_resume_skips_keys_up_to_checkpoint_in_numeric_order() -> None:
    bodies = _audit_bodies()
    # Only b and c have routes: requesting a would fail the test with an unknown-route error.
    connector = _gitlab_com(_audit_routes({key: body for key, body in bodies.items() if key != AUDIT_KEYS[0]}))
    checkpoint = SequenceCursor(seq=AUDIT_KEYS[0])

    batches = collect_stream(
        connector, "audit_stream_objects", _audit_target(), checkpoint=checkpoint, mode="incremental"
    )

    # Within a run the seen-id set starts empty, so 9001 and 9002 re-emit from the retry object. Their
    # evidence uids are event-scoped, so they collapse onto the records already written from object a.
    assert [record["id"] for record in _records(batches)] == [9003, 9001, 9002, 9004, 9005]
    assert batches[-1].checkpoint.seq == AUDIT_KEYS[2]


def test_audit_stream_objects_bound_on_cloud_connector_only() -> None:
    assert hasattr(GitLab, "audit_stream_objects")
    assert hasattr(GitLab, "map_audit_stream_object")
    assert not hasattr(GitLabSelfManaged, "audit_stream_objects")
    assert not hasattr(GitLabSelfManaged, "map_audit_stream_object")
