"""Contract tests for the GitLab connector models."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from icuhub.connectors._gitlab.models import (
    ApproveMergeRequestArgs,
    ChangeVulnerabilityStateArgs,
    ControlJobArgs,
    ControlPipelineArgs,
    CreateMergeRequestArgs,
    CreateMrNoteOrDiscussionArgs,
    CreateVulnerabilityExportInput,
    DiffPosition,
    GitLabConfig,
    ListAuditEventsInput,
    ListMergeRequestsInput,
    ProjectRef,
    PublishSecurityReportArtifactArgs,
    SelfManagedGitLabConfig,
    VendorResult,
)
from icuhub.kit.types import SecretRef

_ACTION_KEY = "icuhub:plan-0001"
_PLAN_HASH = "a" * 64
_SHA = "0123456789abcdef0123456789abcdef01234567"
_MAX_ID = 9_223_372_036_854_775_807


def _token() -> SecretRef:
    return SecretRef(ref="vault://gitlab/access-token")


def _self_managed(**overrides: object) -> SelfManagedGitLabConfig:
    values: dict[str, object] = {
        "base_url": "https://gitlab.example.test/api/v4",
        "access_token": _token(),
    }
    values.update(overrides)
    return SelfManagedGitLabConfig(**values)  # type: ignore[arg-type]


def _diff_position() -> DiffPosition:
    return DiffPosition(base_sha=_SHA, head_sha=_SHA, start_sha=_SHA, path="app/main.py", line=12)


# Editions and base URLs


def test_gitlab_com_default_base_url() -> None:
    config = GitLabConfig(access_token=_token())
    assert config.base_url == "https://gitlab.com/api/v4"


def test_self_managed_requires_explicit_base_url() -> None:
    with pytest.raises(ValidationError):
        SelfManagedGitLabConfig(access_token=_token())  # type: ignore[call-arg]


@pytest.mark.parametrize(
    "base_url",
    [
        "https://gitlab.com/api/v4",
        "https://GitLab.com./api/v4",
    ],
)
def test_self_managed_rejects_gitlab_com_host(base_url: str) -> None:
    with pytest.raises(ValidationError):
        _self_managed(base_url=base_url)


def test_self_managed_preserves_ca_bundle_pem() -> None:
    pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
    config = _self_managed(ca_bundle_pem=pem)
    assert config.ca_bundle_pem == pem


@pytest.mark.parametrize(
    "base_url",
    [
        "http://gitlab.example.test/api/v4",
        "http://127.0.0.1:8080/api/v4",
        "https://gitlab.example.test/api/v4?page=1",
        "https://gitlab.example.test/api/v4#fragment",
        "https://user:secret@gitlab.example.test/api/v4",
        "ftp://gitlab.example.test/api/v4",
    ],
)
def test_self_managed_rejects_unsafe_base_urls(base_url: str) -> None:
    with pytest.raises(ValidationError):
        _self_managed(base_url=base_url)


def test_plain_http_loopback_requires_opt_in() -> None:
    with pytest.raises(ValidationError):
        _self_managed(base_url="http://127.0.0.1:8080/api/v4")
    config = _self_managed(base_url="http://127.0.0.1:8080/api/v4", allow_plain_http_loopback=True)
    assert config.base_url == "http://127.0.0.1:8080/api/v4"


def test_gitlab_config_rejects_plain_http_non_loopback() -> None:
    with pytest.raises(ValidationError):
        GitLabConfig(base_url="http://gitlab.example.test/api/v4", access_token=_token())


# Authentication compatibility


@pytest.mark.parametrize(
    ("auth_method", "principal_kind"),
    [
        ("private_token", "personal"),
        ("private_token", "project"),
        ("private_token", "group"),
        ("oauth_bearer", "oauth"),
        ("job_token", "ci_job"),
    ],
)
def test_compatible_auth_method_and_principal_kind_accepted(auth_method: str, principal_kind: str) -> None:
    config = GitLabConfig(access_token=_token(), auth_method=auth_method, principal_kind=principal_kind)  # type: ignore[arg-type]
    assert config.principal_kind == principal_kind


@pytest.mark.parametrize(
    ("auth_method", "principal_kind"),
    [
        ("job_token", "personal"),
        ("private_token", "oauth"),
        ("private_token", "ci_job"),
        ("oauth_bearer", "personal"),
        ("oauth_bearer", "ci_job"),
    ],
)
def test_incompatible_auth_method_and_principal_kind_rejected(auth_method: str, principal_kind: str) -> None:
    with pytest.raises(ValidationError):
        GitLabConfig(access_token=_token(), auth_method=auth_method, principal_kind=principal_kind)  # type: ignore[arg-type]


# Webhook secret rotation


def test_previous_webhook_secret_requires_current_secret() -> None:
    with pytest.raises(ValidationError):
        GitLabConfig(access_token=_token(), previous_webhook_secret=SecretRef(ref="vault://old"))


def test_webhook_rotation_rejects_identical_refs() -> None:
    with pytest.raises(ValidationError):
        GitLabConfig(
            access_token=_token(),
            webhook_secret=SecretRef(ref="vault://hook"),
            previous_webhook_secret=SecretRef(ref="vault://hook"),
        )


def test_webhook_rotation_accepts_distinct_refs() -> None:
    config = GitLabConfig(
        access_token=_token(),
        webhook_secret=SecretRef(ref="vault://hook-new"),
        previous_webhook_secret=SecretRef(ref="vault://hook-old"),
    )
    assert config.webhook_secret is not None
    assert config.previous_webhook_secret is not None


# Configuration bounds and defaults


def test_bounded_config_defaults() -> None:
    config = GitLabConfig(access_token=_token())
    assert config.max_job_log_bytes == 1024 * 1024
    assert config.max_artifact_bytes == 10 * 1024 * 1024
    assert config.max_sarif_runs == 20
    assert config.max_sarif_results_per_run == 5000
    assert config.write_enabled is False
    assert config.destructive_enabled is False


@pytest.mark.parametrize(
    "overrides",
    [
        {"page_size": 0},
        {"page_size": 101},
        {"max_artifact_bytes": 10 * 1024 * 1024 + 1},
        {"max_job_log_bytes": 10 * 1024 * 1024 + 1},
        {"max_sarif_runs": 21},
        {"max_sarif_results_per_run": 5001},
        {"webhook_tolerance_s": -1},
        {"publication_poll_interval_s": 0},
        {"publication_max_polls": 0},
        {"max_pages": 0},
        {"max_tie_ids": 0},
    ],
)
def test_out_of_bounds_config_rejected(overrides: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        GitLabConfig(access_token=_token(), **overrides)  # type: ignore[arg-type]


# Secret write-only behavior


def test_secret_repr_masks_reference() -> None:
    rendered = repr(SecretRef(ref="vault://gitlab/access-token"))
    assert "********" in rendered
    assert "vault://gitlab/access-token" not in rendered


def test_secret_fields_are_write_only_in_json_schema() -> None:
    schema = GitLabConfig.model_json_schema()
    secret_def = schema["$defs"]["SecretRef"]
    assert secret_def["writeOnly"] is True
    assert secret_def["properties"]["ref"]["writeOnly"] is True


def test_config_holds_only_secret_references() -> None:
    for name, field in GitLabConfig.model_fields.items():
        if name.endswith(("_token", "_secret", "_password")):
            assert "SecretRef" in str(field.annotation), name


def test_config_dump_keeps_reference_not_material() -> None:
    config = GitLabConfig(access_token=_token())
    dumped = config.model_dump()
    assert dumped["access_token"] == {"ref": "vault://gitlab/access-token"}


def test_empty_secret_reference_rejected() -> None:
    with pytest.raises(ValidationError):
        SecretRef(ref="")


# Input rejection


def test_unknown_fields_rejected_on_inputs() -> None:
    with pytest.raises(ValidationError):
        ProjectRef(project_id=1, extra_field="x")  # type: ignore[call-arg]
    with pytest.raises(ValidationError):
        ControlJobArgs(
            project_id=1,
            job_id=2,
            operation="retry",
            expected_status="failed",
            action_key=_ACTION_KEY,
            unexpected=True,  # type: ignore[call-arg]
        )
    with pytest.raises(ValidationError):
        CreateMergeRequestArgs(
            project_id=1,
            source_branch="feature",
            target_branch="main",
            title="Fix",
            action_key=_ACTION_KEY,
            approved_plan_hash=_PLAN_HASH,
            surprise="x",  # type: ignore[call-arg]
        )


@pytest.mark.parametrize("bad_id", [0, -1, _MAX_ID + 1])
def test_out_of_range_ids_rejected(bad_id: int) -> None:
    with pytest.raises(ValidationError):
        ProjectRef(project_id=bad_id)


def test_max_id_accepted() -> None:
    assert ProjectRef(project_id=_MAX_ID).project_id == _MAX_ID


def test_export_requires_exactly_one_scope() -> None:
    with pytest.raises(ValidationError):
        CreateVulnerabilityExportInput()
    with pytest.raises(ValidationError):
        CreateVulnerabilityExportInput(project_id=1, group_id=2)
    with pytest.raises(ValidationError):
        CreateVulnerabilityExportInput(project_id=1, authorized_instance=True)
    assert CreateVulnerabilityExportInput(project_id=1).project_id == 1
    assert CreateVulnerabilityExportInput(group_id=2).group_id == 2
    assert CreateVulnerabilityExportInput(authorized_instance=True).authorized_instance is True


def test_diff_position_requires_all_fields() -> None:
    with pytest.raises(ValidationError):
        DiffPosition(base_sha=_SHA, head_sha=_SHA, start_sha=_SHA, path="app/main.py")  # type: ignore[call-arg]
    assert _diff_position().line == 12


def test_discussion_accepts_full_position() -> None:
    args = CreateMrNoteOrDiscussionArgs(
        project_id=1,
        iid=2,
        body="Please review",
        action_key=_ACTION_KEY,
        approved_plan_hash=_PLAN_HASH,
        position=_diff_position(),
    )
    assert args.position is not None


def test_discussion_without_position_accepted() -> None:
    args = CreateMrNoteOrDiscussionArgs(
        project_id=1,
        iid=2,
        body="General note",
        action_key=_ACTION_KEY,
        approved_plan_hash=_PLAN_HASH,
    )
    assert args.position is None


@pytest.mark.parametrize("bad_sha", ["not-a-sha", "zz" * 20, "abc"])
def test_non_hex_sha_rejected(bad_sha: str) -> None:
    with pytest.raises(ValidationError):
        ApproveMergeRequestArgs(
            project_id=1,
            iid=2,
            sha=bad_sha,
            action_key=_ACTION_KEY,
            approved_plan_hash=_PLAN_HASH,
        )


def test_short_action_key_rejected() -> None:
    with pytest.raises(ValidationError):
        ApproveMergeRequestArgs(
            project_id=1,
            iid=2,
            sha=_SHA,
            action_key="short",
            approved_plan_hash=_PLAN_HASH,
        )


@pytest.mark.parametrize("bad_hash", ["A" * 64, "a" * 63, "g" * 64])
def test_plan_hash_must_be_lowercase_sha256_hex(bad_hash: str) -> None:
    with pytest.raises(ValidationError):
        ChangeVulnerabilityStateArgs(
            vulnerability_id=1,
            expected_state="detected",
            state="resolved",
            action_key=_ACTION_KEY,
            approved_plan_hash=bad_hash,
        )


def test_change_vulnerability_state_rejects_zero_id() -> None:
    with pytest.raises(ValidationError):
        ChangeVulnerabilityStateArgs(
            vulnerability_id=0,
            expected_state="detected",
            state="resolved",
            action_key=_ACTION_KEY,
            approved_plan_hash=_PLAN_HASH,
        )


def test_pipeline_rejects_unknown_operation() -> None:
    with pytest.raises(ValidationError):
        ControlPipelineArgs(
            project_id=1,
            pipeline_id=2,
            operation="play",  # type: ignore[arg-type]
            expected_status="running",
            action_key=_ACTION_KEY,
        )


def test_pipeline_accepts_cancel() -> None:
    args = ControlPipelineArgs(
        project_id=1,
        pipeline_id=2,
        operation="cancel",
        expected_status="running",
        action_key=_ACTION_KEY,
    )
    assert args.operation == "cancel"


def test_job_accepts_play() -> None:
    args = ControlJobArgs(
        project_id=1,
        job_id=2,
        operation="play",
        expected_status="manual",
        action_key=_ACTION_KEY,
    )
    assert args.operation == "play"


def test_merge_request_args_accept_valid_sha() -> None:
    args = ApproveMergeRequestArgs(
        project_id=1,
        iid=2,
        sha=_SHA,
        action_key=_ACTION_KEY,
        approved_plan_hash=_PLAN_HASH,
    )
    assert args.sha == _SHA


# Timestamps


def test_naive_merge_request_timestamp_rejected() -> None:
    with pytest.raises(ValidationError):
        ListMergeRequestsInput(updated_after=datetime(2026, 1, 1))


def test_aware_merge_request_timestamp_accepted() -> None:
    value = datetime(2026, 1, 1, tzinfo=UTC)
    assert ListMergeRequestsInput(updated_after=value).updated_after == value


def test_naive_audit_timestamp_rejected() -> None:
    with pytest.raises(ValidationError):
        ListAuditEventsInput(created_after=datetime(2026, 1, 1))


def test_aware_audit_timestamp_accepted() -> None:
    value = datetime(2026, 1, 1, tzinfo=UTC)
    assert ListAuditEventsInput(created_after=value).created_after == value


# Publication artifact


def _publish_args(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "project_id": 1,
        "iid": 2,
        "job_id": 3,
        "expected_head_sha": _SHA,
        "sarif": {"version": "2.1.0", "runs": []},
        "native_finding_uids": ["finding-1"],
        "action_key": _ACTION_KEY,
    }
    values.update(overrides)
    return values


def test_publication_accepts_mapping_sarif() -> None:
    args = PublishSecurityReportArtifactArgs(**_publish_args())  # type: ignore[arg-type]
    assert args.sarif["version"] == "2.1.0"


@pytest.mark.parametrize("bad_sarif", [[], "not-a-mapping", None])
def test_publication_rejects_non_mapping_sarif(bad_sarif: object) -> None:
    with pytest.raises(ValidationError):
        PublishSecurityReportArtifactArgs(**_publish_args(sarif=bad_sarif))  # type: ignore[arg-type]


def test_publication_rejects_more_than_5000_finding_uids() -> None:
    uids = [f"finding-{index}" for index in range(5001)]
    with pytest.raises(ValidationError):
        PublishSecurityReportArtifactArgs(**_publish_args(native_finding_uids=uids))  # type: ignore[arg-type]


def test_publication_accepts_5000_finding_uids() -> None:
    uids = [f"finding-{index}" for index in range(5000)]
    args = PublishSecurityReportArtifactArgs(**_publish_args(native_finding_uids=uids))  # type: ignore[arg-type]
    assert len(args.native_finding_uids) == 5000


# Vendor result


def test_vendor_result_defaults() -> None:
    result = VendorResult(data={"items": []})
    assert result.status_code == 200
    assert result.coverage == "complete"
    assert result.dropped == []


def test_vendor_result_rejects_unknown_coverage() -> None:
    with pytest.raises(ValidationError):
        VendorResult(data={}, coverage="maybe")  # type: ignore[arg-type]


def test_vendor_result_rejects_out_of_range_status() -> None:
    with pytest.raises(ValidationError):
        VendorResult(data={}, status_code=99)


def test_list_merge_requests_defaults_page_one() -> None:
    assert ListMergeRequestsInput().page == 1


def test_create_merge_request_accepts_optional_description() -> None:
    args = CreateMergeRequestArgs(
        project_id=1,
        source_branch="feature",
        target_branch="main",
        title="Fix",
        action_key=_ACTION_KEY,
        approved_plan_hash=_PLAN_HASH,
    )
    assert args.description is None
