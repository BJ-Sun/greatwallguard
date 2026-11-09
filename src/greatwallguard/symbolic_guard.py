"""Online façade for symbolic task-scoped authorization."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any, Mapping

from .provenance_values import ProvenanceStore
from .symbolic_matcher import SymbolicAuthorizationMatcher, SymbolicDecision
from .symbolic_scope import SymbolicTaskScope


class SymbolicAuthorizationGuard:
    """Execute one validated Symbolic TaskScope at a tool boundary.

    Scope compilation is intentionally outside this class.  The guard is the
    deterministic enforcement kernel: it records observable evidence, checks
    proposed calls, and consumes bounded grants only after successful effects.
    """

    def __init__(self, scope: SymbolicTaskScope) -> None:
        self.scope = scope
        self.evidence = ProvenanceStore()
        self.matcher = SymbolicAuthorizationMatcher(scope, self.evidence)
        self._pending: dict[str, str | None] = {}
        self._audit: list[dict[str, Any]] = []

    def record_tool_result(self, call_id: str, tool: str, result: Any, *,
                           object_version: str | None = None) -> None:
        self.evidence.record_tool_result(
            call_id, tool, result, object_version=object_version
        )

    def record_semantic_evidence(self, binding_id: str, value: Any, *, status: str,
                                 source_call_id: str | None = None,
                                 source_path: str | None = None) -> None:
        self.evidence.record_semantic(
            binding_id, value, status=status, source_call_id=source_call_id,
            source_path=source_path,
        )

    def before_tool_call(self, tool: str, arguments: Mapping[str, Any], *,
                         call_id: str) -> SymbolicDecision:
        if call_id in self._pending:
            raise ValueError(f"call_id already pending: {call_id}")
        decision = self.matcher.check(tool, arguments)
        self._pending[call_id] = decision.grant_id if decision.verdict == "allow" else None
        self._audit.append({
            "event": "before_tool_call", "call_id": call_id, "tool": tool,
            "arguments": dict(arguments), "decision": asdict(decision),
        })
        return decision

    def after_tool_result(self, call_id: str, *, succeeded: bool,
                          result: Any | None = None, tool: str | None = None,
                          object_version: str | None = None) -> None:
        if call_id not in self._pending:
            raise ValueError(f"unknown pending call_id: {call_id}")
        grant_id = self._pending.pop(call_id)
        if succeeded and grant_id is not None:
            self.matcher.consume(grant_id)
        if succeeded and result is not None:
            if not tool:
                raise ValueError("tool is required when registering a result")
            self.record_tool_result(call_id, tool, result, object_version=object_version)
        self._audit.append({
            "event": "after_tool_result", "call_id": call_id,
            "succeeded": succeeded, "consumed_grant": grant_id if succeeded else None,
        })

    def audit_log(self) -> list[dict[str, Any]]:
        return [dict(item) for item in self._audit]
