"""Stable data objects shared by graph construction and authorization."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence


class EffectType(str, Enum):
    READ = "read"
    WRITE = "write"
    CREATE = "create"
    DELETE = "delete"
    SEND = "send"
    EXECUTE = "execute"
    PERMISSION_CHANGE = "permission_change"
    UNKNOWN = "unknown"


class NodeType(str, Enum):
    OBSERVATION = "observation"
    ACTION = "action"
    EFFECT = "effect"
    STATE = "state"


class EdgeType(str, Enum):
    DERIVED_FROM = "derived_from"
    CAUSES = "causes"
    UPDATES = "updates"
    READS = "reads"
    RETURNS = "returns"
    PARAMETER_CANDIDATE = "parameter_candidate"
    CONFIRMS = "confirms"
    NEXT = "next"


class DecisionKind(str, Enum):
    ALLOW = "allow"
    ASK = "ask"
    BLOCK = "block"


@dataclass(frozen=True)
class TaskScope:
    """The authority granted for one user task.

    A scope is intentionally small.  A semantic gate may create it, but data
    returned by tools, files, and memory cannot enlarge it at runtime.
    """

    task_id: str
    intent: str
    allowed_effects: frozenset[EffectType] = frozenset()
    allowed_resources: tuple[str, ...] = ()
    allowed_destinations: tuple[str, ...] = ()
    # Optional fields used by the lightweight pre-execution scope generator.
    # Empty values preserve the original effect-only authorization behavior.
    allowed_tools: tuple[str, ...] = ()
    parameter_constraints: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def _matches(pattern: str, value: str) -> bool:
        return pattern == "*" or value == pattern or value.startswith(pattern)

    def permits_tool(self, tool: str) -> bool:
        """Return whether a non-empty tool envelope admits ``tool``."""
        return not self.allowed_tools or tool in self.allowed_tools

    def permits_effect(self, effect: "Effect") -> bool:
        if effect.kind not in self.allowed_effects:
            return False
        # A send Effect targets a destination; attached/input resources are
        # checked by parameter provenance in later versions, not against the
        # destination namespace.
        if effect.kind is EffectType.SEND or not self.allowed_resources:
            resource_ok = True
        else:
            resource_ok = any(self._matches(prefix, effect.target) for prefix in self.allowed_resources)
        if not resource_ok:
            return False
        if effect.kind is EffectType.SEND and self.allowed_destinations:
            return any(
                destination == "*"
                or destination == effect.target
                or effect.target.endswith(destination)
                for destination in self.allowed_destinations
            )
        return effect.kind is not EffectType.SEND or bool(self.allowed_destinations)

    def as_dict(self) -> dict[str, Any]:
        """Serialize the scope without exposing mutable implementation details."""
        return {
            "task_id": self.task_id,
            "intent": self.intent,
            "allowed_effects": sorted(effect.value for effect in self.allowed_effects),
            "allowed_resources": list(self.allowed_resources),
            "allowed_destinations": list(self.allowed_destinations),
            "allowed_tools": list(self.allowed_tools),
            "parameter_constraints": dict(self.parameter_constraints),
            "metadata": dict(self.metadata),
        }


@dataclass
class Effect:
    kind: EffectType
    target: str
    operation: str
    persistent: bool = True
    reversible: bool = True
    source_node_ids: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str | None = None
    turn: int = 0


@dataclass(frozen=True)
class StateTransition:
    """Observed object fingerprints; None denotes an absent object.

    Fingerprint scope must be explicit, e.g. file content excludes mtime/perms.
    A successful operation with equal fingerprints does not create a version.
    """
    object_id: str
    before: str | None
    after: str | None
    method: str = "file_content_sha256"


@dataclass
class GraphNode:
    id: str
    node_type: NodeType
    turn: int
    label: str
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    source: str
    target: str
    edge_type: EdgeType
    turn: int
    # A relationship's existence is distinct from the evidence supporting it.
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Decision:
    kind: DecisionKind
    reason: str
    effect_ids: tuple[str, ...] = ()
    action_id: str | None = None
