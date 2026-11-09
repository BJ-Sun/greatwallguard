"""Small JSON-native authorization language for runtime-derived parameters."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping


SUPPORTED_EXPR_OPS = frozenset({
    "literal", "tool_result", "project", "argmax", "argmin", "find_eq",
    "semantic_extract",
})
SUPPORTED_GUARD_OPS = frozenset({"literal", "no_overlap"})


class ScopeValidationError(ValueError):
    """Raised when an authorization scope is not executable by the kernel."""


def validate_expression(expr: Mapping[str, Any], *, guard: bool = False) -> None:
    if not isinstance(expr, Mapping):
        raise ScopeValidationError("expression must be an object")
    op = expr.get("op")
    allowed = SUPPORTED_GUARD_OPS if guard else SUPPORTED_EXPR_OPS
    if op not in allowed:
        raise ScopeValidationError(f"unsupported expression operator: {op!r}")
    if op == "literal" and "value" not in expr:
        raise ScopeValidationError("literal expression requires value")
    if op == "tool_result" and not expr.get("tool"):
        raise ScopeValidationError("tool_result requires tool")
    if op in {"project", "argmax", "argmin", "find_eq"}:
        if not expr.get("field") or not isinstance(expr.get("source"), Mapping):
            raise ScopeValidationError(f"{op} requires field and source")
        validate_expression(expr["source"])
    if op == "find_eq" and "value" not in expr:
        raise ScopeValidationError("find_eq requires value")
    if op == "semantic_extract":
        if not expr.get("binding_id") or not isinstance(expr.get("source"), Mapping):
            raise ScopeValidationError("semantic_extract requires binding_id and source")
        validate_expression(expr["source"])
    if op == "no_overlap":
        if not isinstance(expr.get("source"), Mapping):
            raise ScopeValidationError("no_overlap requires source")
        if not expr.get("start") or not expr.get("end"):
            raise ScopeValidationError("no_overlap requires start and end")
        validate_expression(expr["source"])


@dataclass(frozen=True)
class SymbolicGrant:
    """One bounded permission for an effect and its critical operands."""

    grant_id: str
    effect: str
    bindings: Mapping[str, Mapping[str, Any]]
    guard: Mapping[str, Any] = field(default_factory=lambda: {"op": "literal", "value": True})
    budget: int = 1

    def __post_init__(self) -> None:
        if not self.grant_id or not self.effect:
            raise ScopeValidationError("grant_id and effect are required")
        if type(self.budget) is not int or self.budget < 1:
            raise ScopeValidationError("budget must be a positive integer")
        if not isinstance(self.bindings, Mapping) or not self.bindings:
            raise ScopeValidationError("bindings must contain critical parameters")
        for path, expr in self.bindings.items():
            if not isinstance(path, str) or not path:
                raise ScopeValidationError("binding paths must be non-empty strings")
            validate_expression(expr)
        validate_expression(self.guard, guard=True)


@dataclass(frozen=True)
class SymbolicTaskScope:
    """Authorization state rooted in trusted user messages."""

    scope_id: str
    grants: tuple[SymbolicGrant, ...]
    evidence: str

    def __post_init__(self) -> None:
        if not self.scope_id or not self.evidence:
            raise ScopeValidationError("scope_id and user evidence are required")
        if not self.grants:
            raise ScopeValidationError("scope requires at least one grant")
        ids = [grant.grant_id for grant in self.grants]
        if len(ids) != len(set(ids)):
            raise ScopeValidationError("grant ids must be unique")

    @classmethod
    def from_dict(cls, value: Mapping[str, Any], *, evidence: str) -> "SymbolicTaskScope":
        if not isinstance(value, Mapping):
            raise ScopeValidationError("scope must be an object")
        raw_grants = value.get("grants")
        if not isinstance(raw_grants, list):
            raise ScopeValidationError("scope grants must be a list")
        grants = []
        for raw in raw_grants:
            if not isinstance(raw, Mapping):
                raise ScopeValidationError("each grant must be an object")
            grants.append(SymbolicGrant(
                grant_id=str(raw.get("grant_id") or ""),
                effect=str(raw.get("effect") or ""),
                bindings=raw.get("bindings") if isinstance(raw.get("bindings"), Mapping) else {},
                guard=raw.get("guard") if isinstance(raw.get("guard"), Mapping)
                else {"op": "literal", "value": True},
                budget=raw.get("budget", 1),
            ))
        return cls(str(value.get("scope_id") or ""), tuple(grants), evidence)
