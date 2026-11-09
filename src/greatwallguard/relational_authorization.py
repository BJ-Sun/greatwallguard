"""Authorization over semantic relations rather than predicted plans."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .relation_proof import DEFAULT_RELATION_RULES, Fact, ProofGraph, Rule


def _argument(arguments: Mapping[str, Any], path: str) -> Any:
    current: Any = arguments
    for raw in path.replace("[", ".").replace("]", "").split("."):
        if not raw:
            continue
        current = current[raw] if isinstance(current, Mapping) else current[int(raw)]
    return current


def _normal(value: Any) -> Any:
    if isinstance(value, str):
        return value.casefold()
    if isinstance(value, list):
        return [_normal(item) for item in value]
    return value


@dataclass(frozen=True)
class RelationConstraint:
    argument_path: str
    relation: str
    authority_object: str
    role: str


@dataclass(frozen=True)
class RelationalGrant:
    grant_id: str
    effect: str
    literals: Mapping[str, Any]
    relations: tuple[RelationConstraint, ...]
    budget: int = 1


@dataclass(frozen=True)
class RelationalDecision:
    verdict: str
    reason: str
    grant_id: str | None = None
    field: str | None = None
    proof: Fact | None = None


class RelationalVerifier:
    """Check whether any execution path proves the authorized relation."""

    def __init__(self, grants: tuple[RelationalGrant, ...], graph: ProofGraph, *,
                 rules: tuple[Rule, ...] = DEFAULT_RELATION_RULES) -> None:
        self.grants = grants
        self.graph = graph
        self.graph.derive(rules)

    def check(self, tool: str, arguments: Mapping[str, Any]) -> RelationalDecision:
        grants = [grant for grant in self.grants if grant.effect == tool]
        if not grants:
            return RelationalDecision("alert", "effect_not_authorized")
        unresolved: RelationalDecision | None = None
        conflicts: RelationalDecision | None = None
        for grant in grants:
            literal_conflict = None
            for path, expected in grant.literals.items():
                try:
                    actual = _argument(arguments, path)
                except (KeyError, IndexError, TypeError, ValueError):
                    literal_conflict = RelationalDecision(
                        "alert", "required_argument_missing", grant.grant_id, path
                    )
                    break
                if _normal(actual) != _normal(expected):
                    literal_conflict = RelationalDecision(
                        "alert", "literal_constraint_mismatch", grant.grant_id, path
                    )
                    break
            if literal_conflict:
                conflicts = conflicts or literal_conflict
                continue

            missing: RelationalDecision | None = None
            relation_conflict: RelationalDecision | None = None
            proofs: list[Fact] = []
            for constraint in grant.relations:
                try:
                    value = _argument(arguments, constraint.argument_path)
                except (KeyError, IndexError, TypeError, ValueError):
                    relation_conflict = RelationalDecision(
                        "alert", "required_argument_missing", grant.grant_id,
                        constraint.argument_path,
                    )
                    break
                proof = self.graph.find(
                    constraint.relation, constraint.authority_object, value, constraint.role
                )
                if proof is not None:
                    proofs.append(proof)
                    continue
                sources = [fact for fact in self.graph.values("value_source")
                           if _normal(fact.arguments[0]) == _normal(value)]
                if sources and all(str(fact.arguments[1]) != constraint.authority_object
                                   for fact in sources):
                    relation_conflict = RelationalDecision(
                        "alert", "value_derived_from_unrelated_source", grant.grant_id,
                        constraint.argument_path, sources[0],
                    )
                    break
                missing = RelationalDecision(
                    "review", "authorized_relation_not_proved", grant.grant_id,
                    constraint.argument_path,
                )
            if relation_conflict:
                conflicts = conflicts or relation_conflict
                continue
            if missing:
                unresolved = unresolved or missing
                continue
            return RelationalDecision(
                "allow", "all_authorized_relations_proved", grant.grant_id,
                proof=proofs[0] if proofs else None,
            )
        if unresolved is not None:
            return unresolved
        return conflicts or RelationalDecision("alert", "no_grant_matches")
