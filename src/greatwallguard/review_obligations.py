"""Typed hand-off from deterministic authorization to semantic audit."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .authorization_dag import AuthorizationDAG, DagDecision


@dataclass(frozen=True)
class ReviewObligation:
    claim_type: str
    question: str
    review_type: str
    tool: str
    arguments: Mapping[str, Any]
    field: str | None = None
    effect_id: str | None = None
    delegation_id: str | None = None
    required_evidence: tuple[str, ...] = ()

    @property
    def semantic_audit_allowed(self) -> bool:
        return self.review_type == "semantic_unresolved"


def build_review_obligation(decision: DagDecision, *, tool: str,
                            arguments: Mapping[str, Any],
                            graph: AuthorizationDAG) -> ReviewObligation:
    if decision.verdict != "review":
        raise ValueError("only REVIEW decisions create obligations")
    reason = decision.reason
    claim_type = "authorization_relation"
    question = "Does the trusted user authorization support this exact tool call?"
    required = tuple(decision.missing_evidence)
    if reason == "authorized_effect_has_unproved_binding":
        claim_type = "parameter_binding"
        question = f"Is argument {decision.field!r} supported by an authorized source?"
        required = required or ((decision.field or "parameter_source"),)
    elif reason == "constraint_unproved":
        claim_type = "condition_satisfaction"
        question = "Does observed evidence establish every user-specified condition?"
        required = required or ("constraint_operands",)
    elif reason in {
        "effect_delegated_to_external_content",
        "delegated_effect_requires_semantic_proof",
    }:
        claim_type = "delegation_scope"
        question = "Does the user's explicit delegation cover this effect and its arguments?"
        required = required or ("delegated_source_content", "delegation_scope")
    elif reason in {
        "broad_effect_delegation_requires_confirmation",
        "delegation_requires_confirmation",
    }:
        claim_type = "broad_delegation_confirmation"
        question = "Which finite terminal effects should the user explicitly confirm?"
        required = required or ("user_confirmation",)
    elif reason == "generated_presentation_literal_requires_review":
        claim_type = "generated_content_fidelity"
        question = f"Does generated field {decision.field!r} faithfully express the task?"
    elif reason == "repository_owner_scope_requires_proof":
        claim_type = "object_ownership"
        question = "Is the target object inside the user's authorized ownership scope?"
        required = required or ("object_owner",)
    elif reason == "unspecified_parameter_requires_review":
        claim_type = "unspecified_parameter"
        question = f"Is field {decision.field!r} safely implied by the task and evidence?"
    return ReviewObligation(
        claim_type=claim_type,
        question=question,
        review_type=decision.review_type or "semantic_unresolved",
        tool=tool,
        arguments=dict(arguments),
        field=decision.field,
        effect_id=decision.effect_id,
        delegation_id=decision.delegation_id,
        required_evidence=required,
    )
