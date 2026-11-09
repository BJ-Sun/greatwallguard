"""Scoped derivation of temporary capabilities from authorized terminal effects."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .authorization_dag import AuthorizationDAG, DagDecision
from .dag_evidence_evaluator import DAGEvidenceEvaluator


@dataclass(frozen=True)
class CapabilityLink:
    prerequisite_field: str
    terminal_field: str


@dataclass(frozen=True)
class CapabilityRule:
    prerequisite_tool: str
    terminal_tool: str
    links: tuple[CapabilityLink, ...] = ()


class ScopedCapabilityDeriver:
    """Issue a provisional decision for a known tool-dependency edge.

    A rule with proven parameter links can be automatically allowed.  A known
    dependency whose links are not yet provable is REVIEW, never ALLOW.
    """

    def __init__(self, graph: AuthorizationDAG,
                 evaluator: DAGEvidenceEvaluator,
                 rules: tuple[CapabilityRule, ...]) -> None:
        self.graph = graph
        self.evaluator = evaluator
        self.rules = rules

    def derive(self, tool: str, arguments: Mapping[str, Any]) -> DagDecision | None:
        candidates = [rule for rule in self.rules if rule.prerequisite_tool == tool]
        for rule in candidates:
            effects = [
                node for node in self.graph.nodes.values()
                if node.kind == "effect" and node.attrs.get("tool") == rule.terminal_tool
            ]
            if not effects:
                continue
            if not rule.links:
                return DagDecision(
                    "review", "instrumental_capability_requires_link_proof"
                )
            for effect in effects:
                proved = True
                proof_nodes = []
                for link in rule.links:
                    if link.prerequisite_field not in arguments:
                        proved = False
                        break
                    binding_edges = [
                        edge for edge in self.graph.incoming(effect.id, "binds")
                        if edge.attrs.get("field") == link.terminal_field
                    ]
                    if not binding_edges:
                        proved = False
                        break
                    proof = self.evaluator.prove_binding(
                        binding_edges[0].source, arguments[link.prerequisite_field]
                    )
                    if proof is None:
                        proved = False
                        break
                    proof_nodes.extend(proof.source_call_ids)
                if proved:
                    return DagDecision(
                        "allow", "instrumental_capability_proved",
                        proof_nodes=tuple(dict.fromkeys(proof_nodes)),
                    )
            return DagDecision("review", "instrumental_capability_unproved")
        return None
