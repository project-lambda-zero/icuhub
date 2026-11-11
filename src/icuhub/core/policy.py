"""Typed policy rules evaluated in-process (ADR-0013, HLD section 6.4).

First matching rule by priority wins. When no rule matches, reads are allowed and
write/destructive operations require approval. A write executes without a human
approval only when the deployment, tenant, and rule switches are all on and the rule
decision is ``allow``; destructive operations never auto-execute. ``mode=replay``
forces ``preview`` for write/destructive operations (FR-POL-08).
"""

from __future__ import annotations

import fnmatch
import uuid
from dataclasses import dataclass, field
from typing import Any, Literal

from icuhub.core.auth_types import Caller
from icuhub.storage.models import PolicyRule

__all__ = ["PolicyDecision", "PolicyInput", "effective_outcome", "evaluate"]

Decision = Literal["allow", "deny", "require_approval", "preview"]


@dataclass(frozen=True)
class PolicyInput:
    caller: Caller
    connection_id: uuid.UUID
    connection_kind: str
    operation: str
    classification: Literal["read", "write", "destructive"]
    egress_class: str = "vendor_tenant"
    args: dict[str, Any] = field(default_factory=dict)
    mode: Literal["live", "replay"] = "live"


@dataclass(frozen=True)
class PolicyDecision:
    decision: Decision
    rule_id: uuid.UUID | None
    approver_group: str | None = None
    ttl_s: int = 86400
    auto_execute: bool = False
    reason: str = ""


def _path(args: dict[str, Any], dotted: str) -> Any:
    node: Any = args
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def _predicate(args: dict[str, Any], dotted: str, expected: Any) -> bool:
    value = _path(args, dotted)
    if isinstance(expected, dict):
        for op, operand in expected.items():
            if op == "equals" and value != operand:
                return False
            if op == "in" and (not isinstance(operand, list | tuple) or value not in operand):
                return False
            if op in ("gte", "lte"):
                if not isinstance(value, int | float) or isinstance(value, bool):
                    return False
                if not isinstance(operand, int | float) or isinstance(operand, bool):
                    return False
                if op == "gte" and value < operand:
                    return False
                if op == "lte" and value > operand:
                    return False
            if op not in ("equals", "in", "gte", "lte"):
                return False
        return True
    return value == expected


def _matches(rule: PolicyRule, req: PolicyInput) -> bool:
    m = rule.match_json or {}
    if (roles := m.get("caller_roles")) and not req.caller.roles.intersection(roles):
        return False
    if (groups := m.get("caller_groups")) and not req.caller.groups.intersection(groups):
        return False
    if (callers := m.get("callers")) and req.caller.id not in callers:
        return False
    if (connections := m.get("connection_ids")) and str(req.connection_id) not in connections:
        return False
    if (kinds := m.get("connection_kinds")) and not any(
        fnmatch.fnmatchcase(req.connection_kind, k) for k in kinds
    ):
        return False
    if (operations := m.get("operations")) and not any(
        fnmatch.fnmatchcase(req.operation, o) for o in operations
    ):
        return False
    if (classes := m.get("classifications")) and req.classification not in classes:
        return False
    if (egress := m.get("egress_classes")) and req.egress_class not in egress:
        return False
    return all(_predicate(req.args, dotted, expected) for dotted, expected in (m.get("args") or {}).items())


def evaluate(rules: list[PolicyRule], req: PolicyInput) -> PolicyDecision:
    """Return the decision of the first matching rule, or the safe default."""
    for rule in sorted(rules, key=lambda r: (r.priority, str(r.id))):
        if _matches(rule, req):
            return PolicyDecision(
                decision=rule.decision,  # type: ignore[arg-type]
                rule_id=rule.id,
                approver_group=rule.approver_group,
                ttl_s=rule.approval_ttl_s,
                auto_execute=rule.auto_execute_enabled,
                reason=f"rule {rule.name}",
            )
    if req.classification == "read":
        return PolicyDecision(decision="allow", rule_id=None, reason="default: reads allowed")
    return PolicyDecision(decision="require_approval", rule_id=None, reason="default: writes need approval")


def effective_outcome(
    decision: PolicyDecision, req: PolicyInput, *, deployment_switch: bool, tenant_switch: bool
) -> Literal["execute", "pending_approval", "preview", "denied"]:
    """Combine the rule decision with replay mode and the three switches (HLD 6.4)."""
    if decision.decision == "deny":
        return "denied"
    if req.classification == "read":
        return "execute"
    if req.mode == "replay" or decision.decision == "preview":
        return "preview"
    if decision.decision == "require_approval":
        return "pending_approval"
    if req.classification == "destructive":
        return "pending_approval"
    if decision.auto_execute and deployment_switch and tenant_switch:
        return "execute"
    return "pending_approval"
