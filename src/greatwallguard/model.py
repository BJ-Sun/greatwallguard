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

    def permits_effect(self, effect: "Effect") -> bool:
        if effect.kind not in self.allowed_effects:
            return False
        if not self.allowed_resources:
            resource_ok = True
        else:
            resource_ok = any(
                effect.target == prefix or effect.target.startswith(prefix)
                for prefix in self.allowed_resources
            )
        if not resource_ok:
            return False
        if effect.kind is EffectType.SEND and self.allowed_destinations:
            return any(
                destination == effect.target
                or effect.target.endswith(destination)
                for destination in self.allowed_destinations
            )
        return effect.kind is not EffectType.SEND or bool(self.allowed_destinations)


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


@dataclass(frozen=True)
class Decision:
    kind: DecisionKind
    reason: str
    effect_ids: tuple[str, ...] = ()
    action_id: str | None = None

