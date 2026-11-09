"""Runtime evidence store for values used by symbolic authorization."""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ToolResultEvidence:
    call_id: str
    tool: str
    value: Any
    object_version: str | None = None


@dataclass(frozen=True)
class SemanticEvidence:
    binding_id: str
    value: Any
    status: str  # oracle_verified | trusted_parser | claimed
    source_call_id: str | None = None
    source_path: str | None = None


class ProvenanceStore:
    """Append-only evidence visible to the deterministic matcher."""

    def __init__(self) -> None:
        self._results: list[ToolResultEvidence] = []
        self._semantic: dict[str, SemanticEvidence] = {}

    def record_tool_result(self, call_id: str, tool: str, value: Any, *,
                           object_version: str | None = None) -> None:
        if any(item.call_id == call_id for item in self._results):
            raise ValueError(f"duplicate result call_id: {call_id}")
        self._results.append(ToolResultEvidence(
            call_id, tool, copy.deepcopy(value), object_version
        ))

    def latest_result(self, tool: str) -> ToolResultEvidence | None:
        for item in reversed(self._results):
            if item.tool == tool:
                return item
        return None

    def record_semantic(self, binding_id: str, value: Any, *, status: str,
                        source_call_id: str | None = None,
                        source_path: str | None = None) -> None:
        if status not in {"oracle_verified", "trusted_parser", "claimed"}:
            raise ValueError(f"unsupported semantic evidence status: {status}")
        self._semantic[binding_id] = SemanticEvidence(
            binding_id, copy.deepcopy(value), status, source_call_id, source_path
        )

    def semantic(self, binding_id: str) -> SemanticEvidence | None:
        return self._semantic.get(binding_id)
