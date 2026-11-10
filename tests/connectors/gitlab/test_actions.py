"""Plan, apply, and reconcile tests for GitLab governed-write actions."""

from __future__ import annotations

import asyncio
import copy
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from icuhub.connectors._gitlab.actions import (
    action_identity,
    apply_approve_merge_request,
    apply_change_vulnerability_state,
    apply_control_job,
    apply_control_pipeline,
    apply_create_merge_request,
    apply_create_mr_note_or_discussion,
    apply_merge_merge_request,
    apply_publish_security_report_artifact,
    plan_approve_merge_request,
    plan_change_vulnerability_state,
    plan_control_job,
    plan_control_pipeline,
    plan_create_merge_request,
    plan_create_mr_note_or_discussion,
    plan_merge_merge_request,
    plan_publish_security_report_artifact,
    reconcile_approve_merge_request,
    reconcile_change_vulnerability_state,
    reconcile_create_merge_request,
    reconcile_create_mr_note_or_discussion,
    reconcile_merge_merge_request,
    reconcile_publish_security_report_artifact,
)
from icuhub.connectors._gitlab.models import (
    ApproveMergeRequestArgs,
    ChangeVulnerabilityStateArgs,
    ControlJobArgs,
    ControlPipelineArgs,
    CreateMergeRequestArgs,
    CreateMrNoteOrDiscussionArgs,
    MergeMergeRequestArgs,
    PublishSecurityReportArtifactArgs,
)
from icuhub.kit import ConfigError, Conflict, NotFound, OutcomeUnknown, StalePlan, VendorContractError

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "gitlab"
EDITIONS = ["gitlab", "gitlab_self_managed"]
PROJECT_ID = 42
IID = 7
JOB_ID = 9101
PIPELINE_ID = 3301
VULNERABILITY_ID = 5
PLAN_PLACEHOLDER = "0" * 64
HEAD = "89abcdef0123456789abcdef0123456789abcdef"
NEW_HEAD = "feedface00112233445566778899aabbccddeeff"
MERGE_SHA = "cafe" * 10


def _load(edition: str, name: str) -> Any:
    return json.loads((FIXTURES.parent / edition / name).read_text(encoding="utf-8"))


def _uids(edition: str) -> list[str]:
    return [str(item["uuid"]) for item in _load(edition, "native_findings_complete.json")["items"]]


def _mr(iid: int, source: str, target: str, sha: str) -> dict[str, Any]:
    return {
        "id": 1000 + iid,
        "iid": iid,
        "sha": sha,
        "state": "opened",
        "source_branch": source,
        "target_branch": target,
        "merge_commit_sha": None,
    }


def _row(table: dict[int, Any], key: int, what: str) -> Any:
    if key not in table:
        raise NotFound(f"{what} {key} not found")
    return table[key]


class FakeGitLab:
    """In-memory connector implementing the contract the actions module depends on."""

    def __init__(self) -> None:
        self.config = SimpleNamespace(
            write_enabled=True,
            destructive_enabled=True,
            max_sarif_runs=20,
            max_sarif_results_per_run=5000,
        )
        self.ctx = SimpleNamespace(tenant_id="tenant-a")
        self.mrs: dict[int, dict[str, Any]] = {}
        self.discussions: list[dict[str, Any]] = []
        self.approvals: dict[int, bool] = {}
        self.vulnerabilities: dict[int, str] = {}
        self.pipelines: dict[int, str] = {}
        self.jobs: dict[int, dict[str, Any]] = {}
        self.artifacts: dict[int, bytes] = {}
        self.artifact_error: Exception | None = None
        self.native_found: set[str] = set()
        self.native_complete = True
        self.create_ambiguous = False
        self.merge_ambiguous = False
        self.merge_conflict = False
        self._next_id = 10_000

    def _config(self) -> SimpleNamespace:
        return self.config

    def _allocate(self) -> int:
        self._next_id += 1
        return self._next_id

    def add_mr(self, iid: int, source: str, target: str, sha: str) -> None:
        self.mrs[iid] = _mr(iid, source, target, sha)

    async def require_ultimate(self) -> None:
        return None

    async def get_merge_request(self, project_id: int, iid: int) -> dict[str, Any]:
        return dict(_row(self.mrs, iid, "merge request"))

    async def find_open_merge_request(
        self, project_id: int, source_branch: str, target_branch: str
    ) -> dict[str, Any] | None:
        for mr in self.mrs.values():
            if mr["state"] == "opened" and mr["source_branch"] == source_branch and mr["target_branch"] == target_branch:
                return dict(mr)
        return None

    async def create_merge_request(
        self, *, project_id: int, source_branch: str, target_branch: str, title: str, description: str | None
    ) -> dict[str, Any]:
        iid = self._allocate()
        self.mrs[iid] = _mr(iid, source_branch, target_branch, HEAD)
        if self.create_ambiguous:
            raise OutcomeUnknown("create response was lost")
        return {"id": self.mrs[iid]["id"], "iid": iid}

    async def find_discussion(self, project_id: int, iid: int, action_key: str) -> dict[str, Any] | None:
        marker = f"icuhub-action-key:{action_key}"
        for discussion in self.discussions:
            if discussion["iid"] == iid and marker in discussion["body"]:
                return dict(discussion)
        return None

    async def create_discussion(
        self, project_id: int, iid: int, body: str, position: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        discussion = {"id": self._allocate(), "iid": iid, "body": body, "position": position}
        self.discussions.append(discussion)
        return {"id": discussion["id"]}

    async def get_merge_approvals(self, project_id: int, iid: int) -> dict[str, Any]:
        return {"approved": self.approvals.get(iid, False)}

    async def approve_merge_request(self, project_id: int, iid: int, sha: str) -> None:
        _row(self.mrs, iid, "merge request")
        self.approvals[iid] = True

    async def merge_merge_request(self, project_id: int, iid: int, sha: str) -> None:
        if self.merge_conflict:
            raise Conflict("merge request has conflicts")
        mr = _row(self.mrs, iid, "merge request")
        mr["state"] = "merged"
        mr["merge_commit_sha"] = MERGE_SHA
        if self.merge_ambiguous:
            raise OutcomeUnknown("merge response was lost")

    async def get_vulnerability(self, vulnerability_id: int) -> dict[str, Any]:
        return {"id": vulnerability_id, "state": _row(self.vulnerabilities, vulnerability_id, "vulnerability")}

    async def set_vulnerability_state(self, vulnerability_id: int, state: str) -> None:
        _row(self.vulnerabilities, vulnerability_id, "vulnerability")
        self.vulnerabilities[vulnerability_id] = state

    async def get_pipeline(self, project_id: int, pipeline_id: int) -> dict[str, Any]:
        return {"id": pipeline_id, "status": _row(self.pipelines, pipeline_id, "pipeline")}

    async def control_pipeline(self, project_id: int, pipeline_id: int, operation: str) -> None:
        _row(self.pipelines, pipeline_id, "pipeline")
        self.pipelines[pipeline_id] = "canceled" if operation == "cancel" else "pending"

    async def get_job(self, project_id: int, job_id: int) -> dict[str, Any]:
        return dict(_row(self.jobs, job_id, "job"))

    async def control_job(self, project_id: int, job_id: int, operation: str) -> dict[str, Any]:
        job = _row(self.jobs, job_id, "job")
        if operation == "play":
            job["status"] = "pending"
            return {"id": job_id}
        if operation == "retry":
            new_id = self._allocate()
            self.jobs[new_id] = {**job, "id": new_id, "status": "pending"}
            return {"id": new_id}
        job["status"] = "canceled"
        return {"id": job_id}

    async def download_sarif_artifact(self, project_id: int, job_id: int) -> bytes:
        if self.artifact_error is not None:
            raise self.artifact_error
        if job_id not in self.artifacts:
            raise NotFound("job has no SARIF artifact")
        return self.artifacts[job_id]

    async def reconcile_native_vulnerabilities(self, project_id: int, uids: list[str]) -> dict[str, Any]:
        return {"complete": self.native_complete, "found": [uid for uid in uids if uid in self.native_found]}


def _create_args(**overrides: Any) -> CreateMergeRequestArgs:
    base: dict[str, Any] = {
        "project_id": PROJECT_ID,
        "source_branch": "fix/cve-2026-1234",
        "target_branch": "main",
        "title": "Fix parser bounds",
        "description": None,
        "action_key": "mr-create-0001",
        "approved_plan_hash": PLAN_PLACEHOLDER,
    }
    return CreateMergeRequestArgs(**{**base, **overrides})


def test_action_identity_is_tenant_scoped() -> None:
    first = FakeGitLab()
    second = FakeGitLab()
    second.ctx = SimpleNamespace(tenant_id="tenant-b")

    assert action_identity(first, "merge_merge_request", "k") == action_identity(first, "merge_merge_request", "k")
    assert action_identity(first, "merge_merge_request", "k") != action_identity(second, "merge_merge_request", "k")


def test_write_gate_blocks_apply_when_writes_or_destructive_actions_are_disabled() -> None:
    async def scenario() -> None:
        fake = FakeGitLab()
        fake.add_mr(IID, "fix/cve-2026-1234", "main", HEAD)
        args = _create_args()
        plan = await plan_create_merge_request(fake, args)
        fake.config.write_enabled = False
        with pytest.raises(ConfigError):
            await apply_create_merge_request(fake, plan)

        fake.config.write_enabled = True
        fake.config.destructive_enabled = False
        merge_args = MergeMergeRequestArgs(
            project_id=PROJECT_ID,
            iid=IID,
            sha=HEAD,
            action_key="merge-gate-0001",
            approved_plan_hash=PLAN_PLACEHOLDER,
        )
        merge_plan = await plan_merge_merge_request(fake, merge_args)
        with pytest.raises(ConfigError):
            await apply_merge_merge_request(fake, merge_plan)

    asyncio.run(scenario())


def test_create_merge_request_plan_apply_reconcile_then_no_op() -> None:
    async def scenario() -> None:
        fake = FakeGitLab()
        args = _create_args()
        plan = await plan_create_merge_request(fake, args)
        assert plan.changed is True

        outcome = await apply_create_merge_request(fake, plan)
        assert outcome.status == "succeeded"
        assert outcome.result["project_id"] == PROJECT_ID
        assert outcome.vendor_ref is not None

        reconciled = await reconcile_create_merge_request(fake, plan, outcome)
        assert reconciled.status == "succeeded"
        assert reconciled.vendor_ref == outcome.vendor_ref

        replan = await plan_create_merge_request(fake, args)
        assert replan.changed is False
        repeat = await apply_create_merge_request(fake, replan)
        assert repeat.status == "no_op"
        assert repeat.vendor_ref == outcome.vendor_ref

    asyncio.run(scenario())


def test_create_merge_request_ambiguous_send_reconciles_to_succeeded() -> None:
    async def scenario() -> None:
        fake = FakeGitLab()
        fake.create_ambiguous = True
        args = _create_args()
        plan = await plan_create_merge_request(fake, args)

        outcome = await apply_create_merge_request(fake, plan)
        assert outcome.status == "outcome_unknown"

        reconciled = await reconcile_create_merge_request(fake, plan, outcome)
        assert reconciled.status == "succeeded"
        assert len(fake.mrs) == 1

    asyncio.run(scenario())


def test_create_mr_note_is_marked_and_reconciles_then_no_op() -> None:
    async def scenario() -> None:
        fake = FakeGitLab()
        args = CreateMrNoteOrDiscussionArgs(
            project_id=PROJECT_ID,
            iid=IID,
            body="Reviewed the parser fix.",
            action_key="note-review-0001",
            approved_plan_hash=PLAN_PLACEHOLDER,
        )
        plan = await plan_create_mr_note_or_discussion(fake, args)
        assert plan.changed is True

        outcome = await apply_create_mr_note_or_discussion(fake, plan)
        assert outcome.status == "succeeded"
        assert fake.discussions[0]["body"].endswith("<!-- icuhub-action-key:note-review-0001 -->")

        reconciled = await reconcile_create_mr_note_or_discussion(fake, plan, outcome)
        assert reconciled.status == "succeeded"

        replan = await plan_create_mr_note_or_discussion(fake, args)
        assert replan.changed is False
        repeat = await apply_create_mr_note_or_discussion(fake, replan)
        assert repeat.status == "no_op"
        assert len(fake.discussions) == 1

    asyncio.run(scenario())


def test_approve_plan_rejects_moved_head() -> None:
    async def scenario() -> None:
        fake = FakeGitLab()
        fake.add_mr(IID, "fix/cve-2026-1234", "main", NEW_HEAD)
        args = ApproveMergeRequestArgs(
            project_id=PROJECT_ID,
            iid=IID,
            sha=HEAD,
            action_key="approve-stale-01",
            approved_plan_hash=PLAN_PLACEHOLDER,
        )
        with pytest.raises(StalePlan):
            await plan_approve_merge_request(fake, args)

    asyncio.run(scenario())


def test_approve_apply_rejects_head_that_moved_after_plan() -> None:
    async def scenario() -> None:
        fake = FakeGitLab()
        fake.add_mr(IID, "fix/cve-2026-1234", "main", HEAD)
        args = ApproveMergeRequestArgs(
            project_id=PROJECT_ID,
            iid=IID,
            sha=HEAD,
            action_key="approve-moved-01",
            approved_plan_hash=PLAN_PLACEHOLDER,
        )
        plan = await plan_approve_merge_request(fake, args)
        fake.mrs[IID]["sha"] = NEW_HEAD
        with pytest.raises(StalePlan):
            await apply_approve_merge_request(fake, plan)

    asyncio.run(scenario())


def test_approve_then_reconciles_and_already_approved_is_no_op() -> None:
    async def scenario() -> None:
        fake = FakeGitLab()
        fake.add_mr(IID, "fix/cve-2026-1234", "main", HEAD)
        args = ApproveMergeRequestArgs(
            project_id=PROJECT_ID,
            iid=IID,
            sha=HEAD,
            action_key="approve-first-01",
            approved_plan_hash=PLAN_PLACEHOLDER,
        )
        plan = await plan_approve_merge_request(fake, args)
        assert plan.changed is True
        outcome = await apply_approve_merge_request(fake, plan)
        assert outcome.status == "succeeded"
        reconciled = await reconcile_approve_merge_request(fake, plan, outcome)
        assert reconciled.status == "succeeded"

        replan = await plan_approve_merge_request(fake, args)
        assert replan.changed is False
        repeat = await apply_approve_merge_request(fake, replan)
        assert repeat.status == "no_op"

    asyncio.run(scenario())


def test_merge_ambiguous_send_reads_back_merged_as_succeeded() -> None:
    async def scenario() -> None:
        fake = FakeGitLab()
        fake.add_mr(IID, "fix/cve-2026-1234", "main", HEAD)
        fake.merge_ambiguous = True
        args = MergeMergeRequestArgs(
            project_id=PROJECT_ID,
            iid=IID,
            sha=HEAD,
            action_key="merge-ambig-01",
            approved_plan_hash=PLAN_PLACEHOLDER,
        )
        plan = await plan_merge_merge_request(fake, args)
        outcome = await apply_merge_merge_request(fake, plan)
        assert outcome.status == "succeeded"
        assert outcome.result["merge_commit_sha"] == MERGE_SHA

        reconciled = await reconcile_merge_merge_request(fake, plan, outcome)
        assert reconciled.status == "succeeded"

    asyncio.run(scenario())


def test_merge_conflict_without_state_change_fails() -> None:
    async def scenario() -> None:
        fake = FakeGitLab()
        fake.add_mr(IID, "fix/cve-2026-1234", "main", HEAD)
        fake.merge_conflict = True
        args = MergeMergeRequestArgs(
            project_id=PROJECT_ID,
            iid=IID,
            sha=HEAD,
            action_key="merge-conflict-01",
            approved_plan_hash=PLAN_PLACEHOLDER,
        )
        plan = await plan_merge_merge_request(fake, args)
        outcome = await apply_merge_merge_request(fake, plan)
        assert outcome.status == "failed"
        assert outcome.error == "merge request has conflicts"
        assert fake.mrs[IID]["state"] == "opened"

    asyncio.run(scenario())


def test_vulnerability_state_change_plan_apply_reconcile() -> None:
    async def scenario() -> None:
        fake = FakeGitLab()
        fake.vulnerabilities[VULNERABILITY_ID] = "detected"
        args = ChangeVulnerabilityStateArgs(
            vulnerability_id=VULNERABILITY_ID,
            expected_state="detected",
            state="resolved",
            action_key="vuln-resolve-01",
            approved_plan_hash=PLAN_PLACEHOLDER,
        )
        plan = await plan_change_vulnerability_state(fake, args)
        assert plan.changed is True
        outcome = await apply_change_vulnerability_state(fake, plan)
        assert outcome.status == "succeeded"
        reconciled = await reconcile_change_vulnerability_state(fake, plan, outcome)
        assert reconciled.status == "succeeded"

    asyncio.run(scenario())


def test_vulnerability_stale_expected_state_raises_stale_plan() -> None:
    async def scenario() -> None:
        fake = FakeGitLab()
        fake.vulnerabilities[VULNERABILITY_ID] = "dismissed"
        args = ChangeVulnerabilityStateArgs(
            vulnerability_id=VULNERABILITY_ID,
            expected_state="detected",
            state="resolved",
            action_key="vuln-stale-01",
            approved_plan_hash=PLAN_PLACEHOLDER,
        )
        with pytest.raises(StalePlan):
            await plan_change_vulnerability_state(fake, args)

    asyncio.run(scenario())


def test_vulnerability_already_at_target_is_no_op() -> None:
    async def scenario() -> None:
        fake = FakeGitLab()
        fake.vulnerabilities[VULNERABILITY_ID] = "resolved"
        args = ChangeVulnerabilityStateArgs(
            vulnerability_id=VULNERABILITY_ID,
            expected_state="detected",
            state="resolved",
            action_key="vuln-target-01",
            approved_plan_hash=PLAN_PLACEHOLDER,
        )
        plan = await plan_change_vulnerability_state(fake, args)
        assert plan.changed is False
        outcome = await apply_change_vulnerability_state(fake, plan)
        assert outcome.status == "no_op"

    asyncio.run(scenario())


def test_pipeline_cancel_reads_back_canceled_as_succeeded() -> None:
    async def scenario() -> None:
        fake = FakeGitLab()
        fake.pipelines[PIPELINE_ID] = "running"
        args = ControlPipelineArgs(
            project_id=PROJECT_ID,
            pipeline_id=PIPELINE_ID,
            operation="cancel",
            expected_status="running",
            action_key="pipeline-cancel-01",
        )
        plan = await plan_control_pipeline(fake, args)
        outcome = await apply_control_pipeline(fake, plan)
        assert outcome.status == "succeeded"
        assert fake.pipelines[PIPELINE_ID] == "canceled"

    asyncio.run(scenario())


def test_job_play_reads_back_departed_manual_status_as_succeeded() -> None:
    async def scenario() -> None:
        fake = FakeGitLab()
        fake.jobs[JOB_ID] = {**_load("gitlab", "job_publish_success.json"), "status": "manual"}
        args = ControlJobArgs(
            project_id=PROJECT_ID,
            job_id=JOB_ID,
            operation="play",
            expected_status="manual",
            action_key="job-play-0001",
        )
        plan = await plan_control_job(fake, args)
        outcome = await apply_control_job(fake, plan)
        assert outcome.status == "succeeded"
        assert outcome.result == {"job_id": JOB_ID, "job_status": "pending"}

    asyncio.run(scenario())


def test_job_retry_reads_back_new_job_as_succeeded() -> None:
    async def scenario() -> None:
        fake = FakeGitLab()
        fake.jobs[JOB_ID] = _load("gitlab", "job_publish_failed_allowed.json")
        args = ControlJobArgs(
            project_id=PROJECT_ID,
            job_id=JOB_ID,
            operation="retry",
            expected_status="failed",
            action_key="job-retry-0001",
        )
        plan = await plan_control_job(fake, args)
        outcome = await apply_control_job(fake, plan)
        assert outcome.status == "succeeded"
        new_job_id = outcome.result["job_id"]
        assert new_job_id != JOB_ID
        assert fake.jobs[new_job_id]["status"] == "pending"

    asyncio.run(scenario())


def _seed_publish(fake: FakeGitLab, edition: str, status: str) -> str:
    job = _load(edition, "job_publish_success.json")
    head = str(job["commit"]["id"])
    fake.add_mr(IID, "fix/cve-2026-1234", "main", head)
    fake.jobs[JOB_ID] = {**job, "status": status}
    return head


def _publish_args(head: str, document: dict[str, Any], uids: list[str]) -> PublishSecurityReportArtifactArgs:
    return PublishSecurityReportArtifactArgs(
        project_id=PROJECT_ID,
        iid=IID,
        job_id=JOB_ID,
        expected_head_sha=head,
        sarif=document,
        native_finding_uids=uids,
        action_key="publish-report-01",
    )


@pytest.mark.parametrize("edition", EDITIONS)
def test_publish_roundtrip_plays_then_publishes_verified_artifact(edition: str) -> None:
    document = _load(edition, "sarif_report_valid.sarif.json")
    uids = _uids(edition)

    async def scenario() -> None:
        fake = FakeGitLab()
        head = _seed_publish(fake, edition, "manual")
        fake.native_found = set(uids)
        args = _publish_args(head, document, uids)

        plan = await plan_publish_security_report_artifact(fake, args)
        assert plan.changed is True
        assert plan.request["operation"] == "play"
        assert plan.request["dropped"] == []
        started = await apply_publish_security_report_artifact(fake, plan)
        assert started.status == "accepted_async"
        assert started.vendor_ref == str(JOB_ID)

        fake.jobs[JOB_ID]["status"] = "success"
        fake.artifacts[JOB_ID] = json.dumps(document).encode("utf-8")
        replan = await plan_publish_security_report_artifact(fake, args)
        assert replan.changed is False
        done = await apply_publish_security_report_artifact(fake, replan)
        assert done.status == "succeeded"
        assert done.result["artifact_sha256"] == replan.request["sarif_sha256"]

        reconciled = await reconcile_publish_security_report_artifact(fake, replan, done)
        assert reconciled.status == "succeeded"

    asyncio.run(scenario())


@pytest.mark.parametrize("edition", EDITIONS)
def test_publish_plan_records_dropped_results_without_rule(edition: str) -> None:
    document = _load(edition, "sarif_report_with_drop.sarif.json")
    uids = _uids(edition)

    async def scenario() -> None:
        fake = FakeGitLab()
        head = _seed_publish(fake, edition, "manual")
        plan = await plan_publish_security_report_artifact(fake, _publish_args(head, document, uids))
        assert plan.request["dropped"] == [
            {"reason": "missing ruleId", "message": "Result without a rule identifier.", "uri": "src/loader.py"}
        ]
        assert plan.request["result_count"] == 1
        assert plan.diff["operation"] == "play"

    asyncio.run(scenario())


@pytest.mark.parametrize("edition", EDITIONS)
def test_publish_digest_mismatch_fails(edition: str) -> None:
    document = _load(edition, "sarif_report_valid.sarif.json")
    tampered = copy.deepcopy(document)
    tampered["runs"][0]["results"][0]["message"]["text"] = "Tampered finding text."
    uids = _uids(edition)

    async def scenario() -> None:
        fake = FakeGitLab()
        head = _seed_publish(fake, edition, "success")
        fake.native_found = set(uids)
        fake.artifacts[JOB_ID] = json.dumps(tampered).encode("utf-8")
        args = _publish_args(head, document, uids)
        plan = await plan_publish_security_report_artifact(fake, args)
        outcome = await apply_publish_security_report_artifact(fake, plan)
        assert outcome.status == "failed"
        assert outcome.error == "artifact digest differs from the planned SARIF"

    asyncio.run(scenario())


@pytest.mark.parametrize("edition", EDITIONS)
def test_publish_invalid_archive_fails(edition: str) -> None:
    document = _load(edition, "sarif_report_valid.sarif.json")
    uids = _uids(edition)

    async def scenario() -> None:
        fake = FakeGitLab()
        head = _seed_publish(fake, edition, "success")
        fake.artifact_error = VendorContractError("archive is not a valid zip")
        args = _publish_args(head, document, uids)
        plan = await plan_publish_security_report_artifact(fake, args)
        outcome = await apply_publish_security_report_artifact(fake, plan)
        assert outcome.status == "failed"
        assert "not a valid publish SARIF" in str(outcome.error)

    asyncio.run(scenario())


@pytest.mark.parametrize("edition", EDITIONS)
def test_publish_missing_native_findings_fails(edition: str) -> None:
    document = _load(edition, "sarif_report_valid.sarif.json")
    uids = _uids(edition)

    async def scenario() -> None:
        fake = FakeGitLab()
        head = _seed_publish(fake, edition, "success")
        fake.artifacts[JOB_ID] = json.dumps(document).encode("utf-8")
        fake.native_found = set()
        args = _publish_args(head, document, uids)
        plan = await plan_publish_security_report_artifact(fake, args)
        outcome = await apply_publish_security_report_artifact(fake, plan)
        assert outcome.status == "failed"
        assert outcome.result["native_missing"] == uids

    asyncio.run(scenario())


@pytest.mark.parametrize("edition", EDITIONS)
def test_publish_incomplete_native_reconciliation_is_accepted_async(edition: str) -> None:
    document = _load(edition, "sarif_report_valid.sarif.json")
    uids = _uids(edition)

    async def scenario() -> None:
        fake = FakeGitLab()
        head = _seed_publish(fake, edition, "success")
        fake.artifacts[JOB_ID] = json.dumps(document).encode("utf-8")
        fake.native_complete = False
        args = _publish_args(head, document, uids)
        plan = await plan_publish_security_report_artifact(fake, args)
        outcome = await apply_publish_security_report_artifact(fake, plan)
        assert outcome.status == "accepted_async"

    asyncio.run(scenario())
