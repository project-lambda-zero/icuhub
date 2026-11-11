"""Policy decision table (ADR-0013, HLD 6.4)."""

from __future__ import annotations

import uuid

from icuhub.core.auth_types import Caller
from icuhub.core.policy import PolicyInput, effective_outcome, evaluate
from icuhub.storage.models import PolicyRule

TENANT = uuid.uuid4()
CONNECTION = uuid.uuid4()
CALLER = Caller(id="alice", tenant_id=TENANT, roles=frozenset({"operator"}), groups=frozenset({"secops"}))


def req(classification: str = "read", **kwargs: object) -> PolicyInput:
    return PolicyInput(
        caller=CALLER,
        connection_id=CONNECTION,
        connection_kind="jira_cloud",
        operation=kwargs.pop("operation", "create_issue"),
        classification=classification,  # type: ignore[arg-type]
        args=kwargs.pop("args", {}),  # type: ignore[arg-type]
        **kwargs,  # type: ignore[arg-type]
    )


def rule(priority: int, decision: str, match: dict, **kwargs: object) -> PolicyRule:
    return PolicyRule(
        id=uuid.uuid4(),
        tenant_id=TENANT,
        priority=priority,
        name=f"r{priority}",
        match_json=match,
        decision=decision,
        approver_group=kwargs.get("approver_group", "secops"),
        approval_ttl_s=3600,
        auto_execute_enabled=bool(kwargs.get("auto_execute_enabled", False)),
    )


def test_default_reads_allow_writes_require_approval() -> None:
    assert evaluate([], req()).decision == "allow"
    assert evaluate([], req("write")).decision == "require_approval"
    assert evaluate([], req("destructive")).decision == "require_approval"


def test_first_match_by_priority_wins() -> None:
    rules = [rule(1, "deny", {"operations": ["create_*"]}), rule(10, "allow", {"operations": ["*"]})]
    assert evaluate(rules, req("write")).decision == "deny"
    assert evaluate(rules, req("write")).rule_id == rules[0].id
    assert evaluate(rules, req("write", operation="delete_issue")).decision == "allow"


def test_match_fields() -> None:
    rules = [
        rule(
            1,
            "deny",
            {
                "caller_roles": ["operator"],
                "caller_groups": ["secops"],
                "connection_kinds": ["jira_*"],
                "operations": ["create_issue"],
                "classifications": ["write"],
                "args": {"priority": {"in": ["High", "Critical"]}},
            },
        )
    ]
    assert evaluate(rules, req("write", args={"priority": "High"})).decision == "deny"
    assert evaluate(rules, req("write", args={"priority": "Low"})).decision == "require_approval"
    assert evaluate(rules, req("write", args={})).decision == "require_approval"
    assert evaluate(rules, req()).decision == "allow"


def test_numeric_predicates_and_missing_path() -> None:
    rules = [rule(1, "deny", {"args": {"finding.severity_id": {"gte": 4}}})]
    assert evaluate(rules, req("write", args={"finding": {"severity_id": 5}})).decision == "deny"
    assert evaluate(rules, req("write", args={"finding": {"severity_id": 2}})).decision == "require_approval"
    assert evaluate(rules, req("write", args={"finding": {"severity_id": "5"}})).decision == "require_approval"
    assert evaluate(rules, req("write", args={})).decision == "require_approval"


def test_three_switches_gate_auto_execute() -> None:
    decision = evaluate([rule(1, "allow", {"operations": ["*"]}, auto_execute_enabled=True)], req("write"))
    assert effective_outcome(decision, req("write"), deployment_switch=True, tenant_switch=True) == "execute"
    assert effective_outcome(decision, req("write"), deployment_switch=False, tenant_switch=True) == "pending_approval"
    assert effective_outcome(decision, req("write"), deployment_switch=True, tenant_switch=False) == "pending_approval"
    rule_off = evaluate([rule(1, "allow", {"operations": ["*"]})], req("write"))
    assert effective_outcome(rule_off, req("write"), deployment_switch=True, tenant_switch=True) == "pending_approval"


def test_destructive_never_auto_executes() -> None:
    decision = evaluate([rule(1, "allow", {"operations": ["*"]}, auto_execute_enabled=True)], req("destructive"))
    assert effective_outcome(decision, req("destructive"), deployment_switch=True, tenant_switch=True) == "pending_approval"


def test_replay_forces_preview() -> None:
    decision = evaluate([rule(1, "allow", {"operations": ["*"]}, auto_execute_enabled=True)], req("write"))
    assert effective_outcome(decision, req("write", mode="replay"), deployment_switch=True, tenant_switch=True) == "preview"


def test_deny_short_circuits() -> None:
    decision = evaluate([rule(1, "deny", {"operations": ["*"]})], req())
    assert effective_outcome(decision, req(), deployment_switch=True, tenant_switch=True) == "denied"
