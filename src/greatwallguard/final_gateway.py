"""Terminal resolution for authorization decisions.

REVIEW is an internal evidence state, never a terminal gateway outcome.  The
gateway either commits the original effect, commits a bounded lower-impact
substitute, denies the effect, or (only when user preference is the missing
fact) requests confirmation.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Mapping

from .semantic_audit import ConflictValidation, SemanticAuditResult


class FinalDisposition(str, Enum):
    ALLOW_ORIGINAL = "allow_original"
    ALLOW_SAFE_SUBSTITUTE = "allow_safe_substitute"
    DENY = "deny"
    REQUEST_CONFIRMATION = "request_confirmation"


@dataclass(frozen=True)
class SafeSubstitute:
    operation: str
    description: str
    preserves_original_effect: bool = False
    requires_later_commit: bool = True


@dataclass(frozen=True)
class EffectSafetyContract:
    tool: str
    effect_class: str
    externally_committing: bool
    reversible: bool
    substitute: SafeSubstitute | None = None
    confirmation_when_unresolved: bool = False


@dataclass(frozen=True)
class EvidenceRecoveryAction:
    operation: str
    target: str


@dataclass(frozen=True)
class FinalGatewayDecision:
    disposition: FinalDisposition
    reason: str
    substitute: SafeSubstitute | None = None
    recovery_actions: tuple[EvidenceRecoveryAction, ...] = ()

    @property
    def original_effect_committed(self) -> bool:
        return self.disposition == FinalDisposition.ALLOW_ORIGINAL

    @property
    def harmful_effect_possible(self) -> bool:
        return self.disposition == FinalDisposition.ALLOW_ORIGINAL


@dataclass(frozen=True)
class SafeExecutionResult:
    disposition: FinalDisposition
    executed_operation: str | None
    original_tool_called: bool
    value: Any = None


class SafeSubstituteExecutor:
    """Execute a terminal decision without falling through to the original tool."""

    def __init__(self, handlers: Mapping[str, Callable[[str, Mapping[str, Any]], Any]]) -> None:
        self.handlers = dict(handlers)

    def execute(
        self,
        decision: FinalGatewayDecision,
        *,
        original_tool: str,
        arguments: Mapping[str, Any],
        original_executor: Callable[[str, Mapping[str, Any]], Any],
    ) -> SafeExecutionResult:
        if decision.disposition == FinalDisposition.ALLOW_ORIGINAL:
            return SafeExecutionResult(
                decision.disposition, original_tool, True,
                original_executor(original_tool, arguments),
            )
        if decision.disposition == FinalDisposition.ALLOW_SAFE_SUBSTITUTE:
            if decision.substitute is None:
                raise ValueError("safe-substitute disposition requires a substitute")
            handler = self.handlers.get(decision.substitute.operation)
            if handler is None:
                raise KeyError(f"missing safe substitute handler: {decision.substitute.operation}")
            return SafeExecutionResult(
                decision.disposition, decision.substitute.operation, False,
                handler(original_tool, arguments),
            )
        return SafeExecutionResult(decision.disposition, None, False, None)


def recovery_plan(review_type: str | None, required_evidence: tuple[str, ...] = ()) -> tuple[EvidenceRecoveryAction, ...]:
    """Translate an internal REVIEW cause into bounded automatic evidence work."""
    if review_type == "evidence_missing":
        targets = required_evidence or ("runtime_source_or_contract",)
        return tuple(EvidenceRecoveryAction("fetch_or_reconstruct", item) for item in targets)
    if review_type == "semantic_unresolved":
        return (
            EvidenceRecoveryAction("slice_minimal_provenance", "pending_call"),
            EvidenceRecoveryAction("boundary_local_replay", "untrusted_observations"),
        )
    if review_type == "policy_confirmation":
        return (EvidenceRecoveryAction("derive_finite_delegation", "broad_user_delegation"),)
    return ()


class FinalAuthorizationGateway:
    def __init__(self, contracts: Mapping[str, EffectSafetyContract]) -> None:
        self.contracts = dict(contracts)

    def resolve(
        self,
        *,
        tool: str,
        stage2_verdict: str,
        review_type: str | None = None,
        required_evidence: tuple[str, ...] = (),
        semantic_result: SemanticAuditResult | None = None,
        conflict_validation: ConflictValidation | None = None,
        recovery_succeeded: bool = False,
    ) -> FinalGatewayDecision:
        if stage2_verdict == "allow":
            return FinalGatewayDecision(FinalDisposition.ALLOW_ORIGINAL, "programmatic_proof_complete")
        if stage2_verdict == "alert":
            return FinalGatewayDecision(FinalDisposition.DENY, "programmatic_conflict")

        actions = recovery_plan(review_type, required_evidence)
        if recovery_succeeded:
            return FinalGatewayDecision(
                FinalDisposition.ALLOW_ORIGINAL,
                "automatic_evidence_recovery_completed_proof",
                recovery_actions=actions,
            )
        if semantic_result is not None and semantic_result.verdict == "verified":
            return FinalGatewayDecision(
                FinalDisposition.ALLOW_ORIGINAL,
                "semantic_support_proved",
                recovery_actions=actions,
            )
        if (
            semantic_result is not None
            and semantic_result.verdict == "contradicted"
            and conflict_validation is not None
            and conflict_validation.accepted
        ):
            return FinalGatewayDecision(
                FinalDisposition.DENY,
                "validated_semantic_contradiction",
                recovery_actions=actions,
            )

        contract = self.contracts.get(tool)
        if contract is None:
            return FinalGatewayDecision(
                FinalDisposition.DENY,
                "missing_effect_safety_contract",
                recovery_actions=actions,
            )
        if contract.substitute is not None:
            return FinalGatewayDecision(
                FinalDisposition.ALLOW_SAFE_SUBSTITUTE,
                "unresolved_original_replaced_by_bounded_effect",
                substitute=contract.substitute,
                recovery_actions=actions,
            )
        if contract.confirmation_when_unresolved:
            return FinalGatewayDecision(
                FinalDisposition.REQUEST_CONFIRMATION,
                "user_preference_is_only_remaining_authority",
                recovery_actions=actions,
            )
        return FinalGatewayDecision(
            FinalDisposition.DENY,
            "unresolved_effect_has_no_safe_substitute",
            recovery_actions=actions,
        )


def contract(
    tool: str,
    effect_class: str,
    substitute_operation: str,
    substitute_description: str,
    *,
    externally_committing: bool = True,
    reversible: bool = False,
) -> EffectSafetyContract:
    """Convenience constructor for deployment adapters, not an authorization grant."""
    return EffectSafetyContract(
        tool=tool,
        effect_class=effect_class,
        externally_committing=externally_committing,
        reversible=reversible,
        substitute=SafeSubstitute(substitute_operation, substitute_description),
    )
