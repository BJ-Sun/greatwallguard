"""Plan-invariant relation proofs for runtime authorization.

Facts describe what the host observed.  Rules derive task-level relations from
those facts without requiring one predicted tool sequence.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Iterable


@dataclass(frozen=True)
class Fact:
    predicate: str
    arguments: tuple[Any, ...]
    evidence: str
    basis: str = "verified"
    parents: tuple["Fact", ...] = ()


Rule = Callable[[set[Fact]], Iterable[Fact]]


class ProofGraph:
    """Monotone fact graph with replayable derivation parents."""

    def __init__(self) -> None:
        self._facts: set[Fact] = set()

    @property
    def facts(self) -> frozenset[Fact]:
        return frozenset(self._facts)

    def add(self, predicate: str, *arguments: Any, evidence: str,
            basis: str = "verified") -> Fact:
        fact = Fact(predicate, tuple(arguments), evidence, basis)
        self._facts.add(fact)
        return fact

    def derive(self, rules: Iterable[Rule], *, max_rounds: int = 16) -> None:
        for _ in range(max_rounds):
            before = len(self._facts)
            snapshot = set(self._facts)
            for rule in rules:
                self._facts.update(rule(snapshot))
            if len(self._facts) == before:
                return
        raise RuntimeError("proof rules did not reach a fixed point")

    def find(self, predicate: str, *arguments: Any,
             admissible_only: bool = True) -> Fact | None:
        target = tuple(arguments)
        return next((fact for fact in self._facts
                     if fact.predicate == predicate and fact.arguments == target
                     and (not admissible_only or fact.basis == "verified")), None)

    def values(self, predicate: str) -> list[Fact]:
        return [fact for fact in self._facts if fact.predicate == predicate]


def direct_document_relation(facts: set[Fact]) -> Iterable[Fact]:
    """Promote a trusted structured document-role assertion."""
    for fact in facts:
        if fact.predicate == "document_role_value":
            document, role, value = fact.arguments
            yield Fact(
                "associated_with", (document, value, role),
                "direct_document_relation", fact.basis, (fact,),
            )


def document_role_contact_join(facts: set[Fact]) -> Iterable[Fact]:
    """Join a document role mention with a contact lookup result."""
    roles = [fact for fact in facts if fact.predicate == "document_role_entity"]
    contacts = [fact for fact in facts if fact.predicate == "contact_email"]
    for role_fact in roles:
        document, role, entity = role_fact.arguments
        for contact_fact in contacts:
            contact_entity, email = contact_fact.arguments
            if str(entity).casefold() == str(contact_entity).casefold():
                basis = "verified" if (
                    role_fact.basis == "verified" and contact_fact.basis == "verified"
                ) else "candidate"
                yield Fact(
                    "associated_with", (document, email, role),
                    "document_role_contact_join", basis, (role_fact, contact_fact),
                )


DEFAULT_RELATION_RULES: tuple[Rule, ...] = (
    direct_document_relation,
    document_role_contact_join,
)
