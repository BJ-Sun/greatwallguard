"""Deterministic three-valued matcher for Symbolic TaskScope."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping

from .provenance_values import ProvenanceStore
from .symbolic_scope import SymbolicGrant, SymbolicTaskScope


@dataclass(frozen=True)
class SymbolicDecision:
    verdict: str  # allow | alert | review
    reason: str
    grant_id: str | None = None
    field: str | None = None


@dataclass(frozen=True)
class _Eval:
    status: str  # known | unknown
    value: Any = None
    reason: str | None = None
    source_call_id: str | None = None


def _field(value: Any, path: str) -> Any:
    current = value
    for part in path.split("."):
        if isinstance(current, Mapping):
            current = current[part]
        else:
            current = getattr(current, part)
    return current


def _argument(arguments: Mapping[str, Any], path: str) -> Any:
    current: Any = arguments
    for raw in path.replace("[", ".").replace("]", "").split("."):
        if raw == "":
            continue
        if isinstance(current, Mapping):
            current = current[raw]
        else:
            current = current[int(raw)]
    return current


def _normal(value: Any) -> Any:
    if isinstance(value, str):
        return value.casefold()
    if isinstance(value, list):
        return [_normal(item) for item in value]
    if isinstance(value, Mapping):
        return {key: _normal(item) for key, item in value.items()}
    return value


def _evaluate(expr: Mapping[str, Any], evidence: ProvenanceStore) -> _Eval:
    op = expr["op"]
    if op == "literal":
        return _Eval("known", expr["value"])
    if op == "tool_result":
        result = evidence.latest_result(str(expr["tool"]))
        if result is None:
            return _Eval("unknown", reason=f"missing_tool_result:{expr['tool']}")
        return _Eval("known", result.value, source_call_id=result.call_id)
    if op in {"project", "argmax", "argmin", "find_eq"}:
        source = _evaluate(expr["source"], evidence)
        if source.status != "known":
            return source
        try:
            if op == "project":
                return _Eval("known", _field(source.value, str(expr["field"])),
                             source_call_id=source.source_call_id)
            if op == "find_eq":
                matches = [item for item in source.value
                           if _normal(_field(item, str(expr["field"]))) == _normal(expr["value"])]
                if len(matches) != 1:
                    return _Eval("unknown", reason=f"find_eq_expected_one_match:{len(matches)}")
                return _Eval("known", matches[0], source_call_id=source.source_call_id)
            values = list(source.value)
            chooser = max if op == "argmax" else min
            return _Eval("known", chooser(values, key=lambda item: _field(item, str(expr["field"]))),
                         source_call_id=source.source_call_id)
        except (KeyError, AttributeError, TypeError, ValueError) as exc:
            return _Eval("unknown", reason=f"unreplayable_{op}:{exc}")
    if op == "semantic_extract":
        source = _evaluate(expr["source"], evidence)
        if source.status != "known":
            return source
        item = evidence.semantic(str(expr["binding_id"]))
        if item is None:
            return _Eval("unknown", reason=f"missing_semantic_evidence:{expr['binding_id']}")
        if item.status not in {"oracle_verified", "trusted_parser"}:
            return _Eval("unknown", reason=f"untrusted_semantic_evidence:{item.status}")
        if item.source_call_id != source.source_call_id:
            return _Eval("unknown", reason="semantic_evidence_source_mismatch")
        return _Eval("known", item.value, source_call_id=item.source_call_id)
    return _Eval("unknown", reason=f"unsupported_operator:{op}")


def _time(value: str) -> datetime:
    return datetime.fromisoformat(value)


def _evaluate_guard(expr: Mapping[str, Any], evidence: ProvenanceStore) -> _Eval:
    if expr["op"] == "literal":
        return _Eval("known", bool(expr["value"]))
    if expr["op"] == "no_overlap":
        source = _evaluate(expr["source"], evidence)
        if source.status != "known":
            return source
        try:
            start, end = _time(str(expr["start"])), _time(str(expr["end"]))
            for event in source.value:
                event_start = _time(str(_field(event, str(expr.get("start_field", "start_time")))))
                event_end = _time(str(_field(event, str(expr.get("end_field", "end_time")))))
                if event_start < end and start < event_end:
                    return _Eval("known", False)
            return _Eval("known", True)
        except (KeyError, AttributeError, TypeError, ValueError) as exc:
            return _Eval("unknown", reason=f"unreplayable_no_overlap:{exc}")
    return _Eval("unknown", reason=f"unsupported_guard:{expr['op']}")


class SymbolicAuthorizationMatcher:
    """Match calls against active grants without consulting attack labels."""

    def __init__(self, scope: SymbolicTaskScope, evidence: ProvenanceStore) -> None:
        self.scope = scope
        self.evidence = evidence
        self._consumed: dict[str, int] = {}

    def check(self, tool: str, arguments: Mapping[str, Any]) -> SymbolicDecision:
        grants = [grant for grant in self.scope.grants if grant.effect == tool]
        if not grants:
            return SymbolicDecision("alert", "effect_not_authorized")
        unresolved: SymbolicDecision | None = None
        explicit_conflict: SymbolicDecision | None = None
        for grant in grants:
            if self._consumed.get(grant.grant_id, 0) >= grant.budget:
                continue
            guard = _evaluate_guard(grant.guard, self.evidence)
            if guard.status != "known":
                unresolved = SymbolicDecision("review", guard.reason or "guard_unknown", grant.grant_id)
                continue
            if not guard.value:
                continue
            grant_conflict: SymbolicDecision | None = None
            grant_unresolved: SymbolicDecision | None = None
            for path, expr in grant.bindings.items():
                expected = _evaluate(expr, self.evidence)
                if expected.status != "known":
                    grant_unresolved = SymbolicDecision(
                        "review", expected.reason or "binding_unknown", grant.grant_id, path
                    )
                    continue
                try:
                    actual = _argument(arguments, path)
                except (KeyError, IndexError, TypeError, ValueError):
                    grant_conflict = SymbolicDecision(
                        "alert", "required_argument_missing", grant.grant_id, path
                    )
                    break
                if _normal(actual) != _normal(expected.value):
                    grant_conflict = SymbolicDecision(
                        "alert", "derived_argument_mismatch", grant.grant_id, path
                    )
                    break
            if grant_conflict is not None:
                explicit_conflict = explicit_conflict or grant_conflict
                continue
            if grant_unresolved is not None:
                unresolved = unresolved or grant_unresolved
                continue
            if grant_conflict is None:
                return SymbolicDecision("allow", "symbolic_grant_proved", grant.grant_id)
        if unresolved is not None:
            return unresolved
        if explicit_conflict is not None:
            return explicit_conflict
        return SymbolicDecision("alert", "no_active_grant_matches")

    def consume(self, grant_id: str) -> None:
        self._consumed[grant_id] = self._consumed.get(grant_id, 0) + 1
