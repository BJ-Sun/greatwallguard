"""Append-only compressed state graph.

The graph stores summaries and digests instead of raw prompts or tool
payloads.  This keeps the cross-turn object small while retaining the causal
links needed by authorization and auditing.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any, Iterable

from .model import EdgeType, Effect, GraphEdge, GraphNode, NodeType


def digest(value: Any) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def compact_summary(value: Any, limit: int = 160) -> str:
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)
    text = " ".join(text.split())
    return text[:limit] + ("…" if len(text) > limit else "")


class EffectGraph:
    """A small, serializable graph of agent behavior and persistent effects."""

    def __init__(self) -> None:
        self.nodes: dict[str, GraphNode] = {}
        self.edges: list[GraphEdge] = []
        self.state_versions: dict[str, int] = {}
        self._last_node_by_turn: dict[int, str] = {}
        self._counter = 0

    def _new_id(self, prefix: str) -> str:
        self._counter += 1
        return f"{prefix}-{self._counter:05d}"

    def _add_node(self, node: GraphNode) -> str:
        self.nodes[node.id] = node
        previous = self._last_node_by_turn.get(node.turn)
        if previous:
            self.edges.append(GraphEdge(previous, node.id, EdgeType.NEXT, node.turn))
        self._last_node_by_turn[node.turn] = node.id
        return node.id

    def _edge(self, source: str, target: str, edge_type: EdgeType, turn: int) -> None:
        if source in self.nodes and target in self.nodes:
            self.edges.append(GraphEdge(source, target, edge_type, turn))

    def add_observation(
        self,
        source: str,
        summary: str,
        *,
        turn: int = 0,
        integrity: str = "unknown",
        object_id: str | None = None,
        raw_payload: Any = None,
    ) -> str:
        node_id = self._new_id("obs")
        node = GraphNode(
            node_id,
            NodeType.OBSERVATION,
            turn,
            summary,
            {
                "source": source,
                "integrity": integrity,
                "object_id": object_id,
                "digest": digest(raw_payload if raw_payload is not None else summary),
            },
        )
        return self._add_node(node)

    def add_action(
        self,
        tool: str,
        arguments: Any,
        *,
        turn: int = 0,
        observation_ids: Iterable[str] = (),
    ) -> str:
        node_id = self._new_id("act")
        node = GraphNode(
            node_id,
            NodeType.ACTION,
            turn,
            f"{tool}()",
            {"tool": tool, "arguments_digest": digest(arguments)},
        )
        self._add_node(node)
        for observation_id in observation_ids:
            self._edge(observation_id, node_id, EdgeType.DERIVED_FROM, turn)
        return node_id

    def add_effect(self, effect: Effect, *, action_id: str, turn: int | None = None) -> str:
        effect_id = effect.id or self._new_id("eff")
        effect.id = effect_id
        effect.turn = effect.turn if turn is None else turn
        node = GraphNode(
            effect_id,
            NodeType.EFFECT,
            effect.turn,
            f"{effect.kind.value}:{effect.target}",
            {
                "kind": effect.kind.value,
                "target": effect.target,
                "operation": effect.operation,
                "persistent": effect.persistent,
                "reversible": effect.reversible,
                "source_node_ids": list(effect.source_node_ids),
                "metadata": effect.metadata,
            },
        )
        self._add_node(node)
        self._edge(action_id, effect_id, EdgeType.CAUSES, effect.turn)
        for source_id in effect.source_node_ids:
            self._edge(source_id, effect_id, EdgeType.DERIVED_FROM, effect.turn)

        if effect.persistent:
            version = self.state_versions.get(effect.target, 0) + 1
            self.state_versions[effect.target] = version
            state_id = self._new_id("state")
            state = GraphNode(
                state_id,
                NodeType.STATE,
                effect.turn,
                f"{effect.target}@v{version}",
                {
                    "object_id": effect.target,
                    "version": version,
                    "effect_id": effect_id,
                    "kind": effect.kind.value,
                },
            )
            self._add_node(state)
            self._edge(effect_id, state_id, EdgeType.UPDATES, effect.turn)
        return effect_id

    def node(self, node_id: str) -> GraphNode:
        return self.nodes[node_id]

    def source_integrities(self, node_ids: Iterable[str]) -> set[str]:
        return {
            str(self.nodes[node_id].data.get("integrity", "unknown"))
            for node_id in node_ids
            if node_id in self.nodes and self.nodes[node_id].node_type is NodeType.OBSERVATION
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [asdict(node) for node in self.nodes.values()],
            "edges": [asdict(edge) for edge in self.edges],
            "state_versions": dict(self.state_versions),
        }

    def write_json(self, path: str | Path) -> None:
        Path(path).write_text(
            json.dumps(self.to_dict(), ensure_ascii=False, indent=2, default=lambda x: x.value),
            encoding="utf-8",
        )

