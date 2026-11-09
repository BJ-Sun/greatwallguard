"""Claim-centered evidence packets for bounded Stage-3 semantic proof."""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Mapping, Sequence


REASON_TO_CLAIM = {
    "authorized_effect_has_unproved_binding": "parameter_binding",
    "constraint_unproved": "condition_satisfaction",
    "effect_delegated_to_external_content": "delegation_scope",
    "delegated_effect_requires_semantic_proof": "delegation_scope",
    "broad_effect_delegation_requires_confirmation": "finite_delegation",
    "generated_presentation_literal_requires_review": "generated_content_fidelity",
    "repository_owner_scope_requires_proof": "object_ownership",
    "unspecified_parameter_requires_review": "unspecified_parameter",
    "outbound_observation_requires_effect_contract": "observation_effect",
    "unscoped_observation_requires_review": "observation_scope",
    "instrumental_capability_requires_link_proof": "instrumental_effect_link",
    "instrumental_capability_unproved": "instrumental_effect_link",
    "unplanned_effect_requires_capability_proof": "instrumental_effect_link",
    "authorization_budget_requires_proof": "authorization_budget",
}


@dataclass(frozen=True)
class ProofObligation:
    obligation_id: str
    claim_type: str
    predicate: str
    field: str | None
    candidate_value: Any
    question: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.obligation_id,
            "claim_type": self.claim_type,
            "predicate": self.predicate,
            "field": self.field,
            "candidate_value": self.candidate_value,
            "question": self.question,
        }


@dataclass(frozen=True)
class EvidenceItem:
    ref: str
    tool: str
    arguments: Mapping[str, Any]
    observation: Any = None
    trust: str = "runtime_observation"
    score: int = 0

    def to_dict(self) -> dict[str, Any]:
        value = {
            "ref": self.ref,
            "tool": self.tool,
            "arguments": dict(self.arguments),
            "trust": self.trust,
        }
        if self.observation is not None:
            value["observation"] = self.observation
        return value


@dataclass(frozen=True)
class ProofPacket:
    trusted_user_request: str
    authorized_effect: str
    candidate_call: Mapping[str, Any]
    obligation: ProofObligation
    evidence: tuple[EvidenceItem, ...]
    omitted_evidence_refs: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "trusted_authorization": {
                "ref": "trusted_user_request",
                "user_request": self.trusted_user_request,
                "authorized_effect": self.authorized_effect,
            },
            "candidate_call": {"ref": "pending_call", **dict(self.candidate_call)},
            "proof_obligation": self.obligation.to_dict(),
            "evidence": [item.to_dict() for item in self.evidence],
            "omitted_evidence_count": len(self.omitted_evidence_refs),
        }


def _get_path(arguments: Mapping[str, Any], field: str | None) -> Any:
    if not field:
        return None
    current: Any = arguments
    try:
        for part in field.replace("[", ".").replace("]", "").split("."):
            if not part:
                continue
            current = current[part] if isinstance(current, Mapping) else current[int(part)]
        return current
    except (KeyError, IndexError, TypeError, ValueError):
        return None


def _flatten(value: Any) -> list[str]:
    if isinstance(value, Mapping):
        output = []
        for item in value.values():
            output.extend(_flatten(item))
        return output
    if isinstance(value, (list, tuple, set)):
        output = []
        for item in value:
            output.extend(_flatten(item))
        return output
    text = str(value).strip()
    return [text] if text else []


def _question(claim_type: str, field: str | None, tool: str) -> tuple[str, str]:
    name = field or "__effect__"
    questions = {
        "parameter_binding": ("authorized_binding", f"Does evidence prove that {name} is an authorized value for {tool}?"),
        "condition_satisfaction": ("condition_holds", "Does evidence prove every user-specified precondition for this call?"),
        "delegation_scope": ("delegation_covers", "Did the user delegate this exact effect and its security-relevant arguments?"),
        "finite_delegation": ("finite_delegation_covers", "Can the broad instruction be reduced to a finite user-authorized effect?"),
        "generated_content_fidelity": ("content_faithful_to_goal", f"Is generated field {name} faithful to the authorized goal?"),
        "object_ownership": ("object_in_authorized_scope", "Is the target object inside the user's authorized ownership scope?"),
        "unspecified_parameter": ("parameter_safely_implied", f"Is unspecified field {name} safely implied by the task?"),
        "observation_effect": ("observation_within_scope", "Can this observation occur without an unauthorized outbound effect?"),
        "observation_scope": ("observation_within_scope", "Is this observation restricted to the task's authorized source scope?"),
        "instrumental_effect_link": ("instrumental_to_authorized_effect", "Is this intermediate effect necessary and scoped to an authorized terminal effect?"),
        "authorization_budget": ("within_authorized_budget", "Is this additional effect instance within the user's authorized object budget?"),
    }
    return questions.get(claim_type, ("authorization_relation", "Does the trusted request authorize this exact call?"))


class ProofPacketBuilder:
    def __init__(self, *, max_evidence_items: int = 6) -> None:
        self.max_evidence_items = max_evidence_items

    def build(
        self,
        *,
        obligation_id: str,
        trusted_user_request: str,
        pending_call: Mapping[str, Any],
        review_reason: str,
        review_field: str | None,
        execution_prefix: Sequence[Mapping[str, Any]],
        expand_all: bool = False,
    ) -> ProofPacket:
        tool = str(pending_call["tool"])
        arguments = pending_call.get("arguments") or {}
        claim_type = REASON_TO_CLAIM.get(review_reason, "authorization_relation")
        predicate, question = _question(claim_type, review_field, tool)
        candidate = _get_path(arguments, review_field)
        needles = {item.casefold() for item in _flatten(candidate) + _flatten(arguments) if len(item) >= 2}
        scored = []
        total = len(execution_prefix)
        for index, item in enumerate(execution_prefix):
            observation = item.get("observation")
            haystack = json.dumps({
                "tool": item.get("tool"), "arguments": item.get("arguments"),
                "observation": observation,
            }, ensure_ascii=False, default=str).casefold()
            score = sum(4 for needle in needles if needle in haystack)
            if review_field and review_field.casefold() in haystack:
                score += 2
            if index >= max(0, total - 2):
                score += 1
            scored.append(EvidenceItem(
                ref=f"E{index}", tool=str(item.get("tool")),
                arguments=item.get("arguments") or {}, observation=observation, score=score,
            ))
        ordered = sorted(scored, key=lambda item: (-item.score, item.ref))
        if expand_all:
            selected = tuple(sorted(scored, key=lambda item: int(item.ref[1:])))
        else:
            positive = [item for item in ordered if item.score > 0]
            selected = tuple((positive or ordered)[: self.max_evidence_items])
        selected_refs = {item.ref for item in selected}
        omitted = tuple(item.ref for item in scored if item.ref not in selected_refs)
        return ProofPacket(
            trusted_user_request=trusted_user_request,
            authorized_effect=tool,
            candidate_call={"tool": tool, "arguments": dict(arguments)},
            obligation=ProofObligation(
                obligation_id, claim_type, predicate, review_field, candidate, question,
            ),
            evidence=selected,
            omitted_evidence_refs=omitted,
        )
