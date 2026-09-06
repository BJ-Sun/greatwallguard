"""Append-only compressed state graph.

The graph stores summaries and digests instead of raw prompts or tool
payloads.  This keeps the cross-turn object small while retaining the causal
links needed by authorization and auditing.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
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
        self._latest_state_node: dict[str, str] = {}
        self._effect_state_node: dict[str, str] = {}
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
            compact_summary(summary),
            {
                "source": source,
                "integrity": integrity,
                "object_id": object_id,
                "digest": digest(raw_payload if raw_payload is not None else summary),
            },
        )
        node_id = self._add_node(node)
        # A later observation of a persistent object explicitly points back
        # to its latest committed version.  This is the first cross-turn edge
        # in the graph; raw conversation history is not needed to recover it.
        if object_id and object_id in self._latest_state_node:
            self._edge(self._latest_state_node[object_id], node_id, EdgeType.READS, turn)
        return node_id

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
                "status": effect.metadata.get("status", "authorized"),
                "source_node_ids": list(effect.source_node_ids),
                "metadata": effect.metadata,
            },
        )
        self._add_node(node)
        self._edge(action_id, effect_id, EdgeType.CAUSES, effect.turn)
        for source_id in effect.source_node_ids:
            self._edge(source_id, effect_id, EdgeType.DERIVED_FROM, effect.turn)
        return effect_id

    def commit_effect(
        self,
        effect_id: str,
        *,
        succeeded: bool,
        result_summary: str | None = None,
    ) -> str | None:
        """Mark an authorized effect and materialize its state only on success."""
        effect_node = self.nodes[effect_id]
        effect_node.data["status"] = "succeeded" if succeeded else "failed"
        if result_summary is not None:
            effect_node.data["result_summary"] = compact_summary(result_summary)
        if not succeeded or not effect_node.data.get("persistent"):
            return None
        if effect_id in self._effect_state_node:
            return self._effect_state_node[effect_id]

        target = str(effect_node.data["target"])
        turn = effect_node.turn
        version = self.state_versions.get(target, 0) + 1
        self.state_versions[target] = version
        state_id = self._new_id("state")
        state = GraphNode(
            state_id,
            NodeType.STATE,
            turn,
            f"{target}@v{version}",
            {
                "object_id": target,
                "version": version,
                "effect_id": effect_id,
                "kind": effect_node.data["kind"],
                "status": "committed",
            },
        )
        self._add_node(state)
        self._edge(effect_id, state_id, EdgeType.UPDATES, turn)
        self._latest_state_node[target] = state_id
        self._effect_state_node[effect_id] = state_id
        return state_id

    def state_node(self, object_id: str) -> str | None:
        """Return the latest committed state node for an object, if any."""
        return self._latest_state_node.get(object_id)

    def compact_view(
        self,
        *,
        recent_actions: int = 8,
        max_states: int = 32,
        max_sources_per_state: int = 4,
    ) -> dict[str, Any]:
        """Return a budgeted runtime view, separate from the full audit graph.

        The full graph is useful for offline auditing.  The agent-facing view
        keeps only the newest ``max_states`` persistent objects, aggregate
        Effect counts, and a fixed action tail.  Older state objects are
        represented by counts and a digest so the view remains bounded without
        discarding evidence that additional state exists.
        """
        if max_states < 0 or max_sources_per_state < 0 or recent_actions < 0:
            raise ValueError("compact view budgets must be non-negative")
        action_nodes = sorted(
            (node for node in self.nodes.values() if node.node_type is NodeType.ACTION),
            key=lambda node: (node.turn, node.id),
        )
        effect_nodes = [node for node in self.nodes.values() if node.node_type is NodeType.EFFECT]
        all_states = []
        for object_id, state_id in self._latest_state_node.items():
            state = self.nodes[state_id]
            effect_id = state.data.get("effect_id")
            effect = self.nodes.get(effect_id)
            sources = list(effect.data.get("source_node_ids", []) if effect else [])
            all_states.append({
                "object_id": object_id,
                "version": state.data.get("version"),
                "kind": state.data.get("kind"),
                "turn": state.turn,
                "source_node_ids": sources[:max_sources_per_state],
                "source_count": len(sources),
            })
        all_states.sort(key=lambda state: (state["turn"], state["object_id"]), reverse=True)
        states = all_states[:max_states]
        omitted_states = all_states[max_states:]
        return {
            "schema_version": "gwg-compact-v2",
            "persistent_states": states,
            "state_budget": {
                "max_states": max_states,
                "total_objects": len(all_states),
                "included_objects": len(states),
                "omitted_objects": len(omitted_states),
                "omitted_kinds": dict(Counter(state["kind"] for state in omitted_states)),
                "omitted_object_digest": digest([state["object_id"] for state in omitted_states]) if omitted_states else None,
            },
            "effect_counts": dict(Counter(node.data.get("kind", "unknown") for node in effect_nodes)),
            "recent_actions": [
                {
                    "turn": node.turn,
                    "tool": node.data.get("tool"),
                    "decision": node.data.get("decision"),
                    "execution_status": node.data.get("execution_status"),
                    "arguments_digest": node.data.get("arguments_digest"),
                }
                for node in action_nodes[-recent_actions:]
            ],
            "total_actions": len(action_nodes),
            "total_effects": len(effect_nodes),
        }

    def project_minimal(self, task_scope=None) -> dict[str, Any]:
        """Project the audit ledger to the paper-level Entity / Action graph."""
        nodes: list[dict[str, Any]] = []
        node_map: dict[str, str] = {}
        for node in self.nodes.values():
            if node.node_type is NodeType.ACTION:
                node_map[node.id] = node.id
                nodes.append({
                    "id": node.id,
                    "type": "action",
                    "turn": node.turn,
                    "label": node.label,
                    "data": node.data,
                })
            elif node.node_type in {NodeType.OBSERVATION, NodeType.STATE}:
                entity_id = f"x-{node.id}"
                node_map[node.id] = entity_id
                nodes.append({
                    "id": entity_id,
                    "type": "entity",
                    "turn": node.turn,
                    "label": node.label,
                    "data": {"kind": node.node_type.value, **node.data},
                })

        effect_target_map: dict[str, str] = {}
        for effect in (node for node in self.nodes.values() if node.node_type is NodeType.EFFECT):
            state_id = self._effect_state_node.get(effect.id)
            if state_id:
                effect_target_map[effect.id] = node_map[state_id]
                continue
            entity_id = f"x-{effect.id}"
            effect_target_map[effect.id] = entity_id
            nodes.append({
                "id": entity_id,
                "type": "entity",
                "turn": effect.turn,
                "label": effect.label,
                "data": {
                    "kind": "effect_target",
                    "target": effect.data.get("target"),
                    "persistent": False,
                },
            })

        edges: list[dict[str, Any]] = []
        for edge in self.edges:
            if edge.edge_type is EdgeType.DERIVED_FROM and edge.target in self.nodes:
                target_node = self.nodes[edge.target]
                if target_node.node_type is NodeType.ACTION:
                    source = node_map.get(edge.source)
                    if source:
                        source_node = self.nodes.get(edge.source)
                        edges.append({
                            "source": source,
                            "target": edge.target,
                            "relation": "consume",
                            "turn": edge.turn,
                            "data": {
                                "role": (
                                    "state"
                                    if source_node and (
                                        source_node.data.get("source") in {"memory", "file", "workspace_bootstrap"}
                                        or str(source_node.data.get("object_id", "")).startswith(("file://", "memory://"))
                                    )
                                    else "data"
                                ),
                                "integrity": source_node.data.get("integrity") if source_node else "unknown",
                            },
                        })
            elif edge.edge_type is EdgeType.CAUSES:
                target = effect_target_map.get(edge.target)
                if target:
                    effect = self.nodes[edge.target]
                    edges.append({
                        "source": edge.source,
                        "target": target,
                        "relation": "produce",
                        "turn": edge.turn,
                        "data": {
                            "effect_kind": effect.data.get("kind"),
                            "target_object": effect.data.get("target"),
                            "persistent": effect.data.get("persistent", False),
                            "status": effect.data.get("status"),
                        },
                    })
            elif edge.edge_type is EdgeType.READS:
                # State → observation → action becomes a single consume edge.
                for follow in self.edges:
                    if follow.edge_type is EdgeType.DERIVED_FROM and follow.source == edge.target and follow.target in self.nodes and self.nodes[follow.target].node_type is NodeType.ACTION:
                        edges.append({
                            "source": node_map.get(edge.source),
                            "target": follow.target,
                            "relation": "consume",
                            "turn": edge.turn,
                            "data": {"role": "state", "activation": True},
                        })
            elif edge.edge_type is EdgeType.NEXT:
                if edge.source in self.nodes and edge.target in self.nodes and self.nodes[edge.source].node_type is NodeType.ACTION and self.nodes[edge.target].node_type is NodeType.ACTION:
                    edges.append({
                        "source": edge.source,
                        "target": edge.target,
                        "relation": "precede",
                        "turn": edge.turn,
                        "data": {},
                    })

        if task_scope is not None:
            scope_id = f"scope-{task_scope.task_id}"
            nodes.append({
                "id": scope_id,
                "type": "entity",
                "turn": 0,
                "label": task_scope.intent,
                "data": {"kind": "task_scope", "task_id": task_scope.task_id},
            })
            for action in (node for node in self.nodes.values() if node.node_type is NodeType.ACTION):
                edges.append({
                    "source": scope_id,
                    "target": action.id,
                    "relation": "authorize",
                    "turn": action.turn,
                    "data": {
                        "decision": action.data.get("decision"),
                        "reason": action.data.get("reason"),
                    },
                })

        return {"nodes": nodes, "edges": edges}

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
