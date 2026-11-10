"""Deployable three-stage authorization pipeline with no terminal REVIEW.

The pipeline preserves the separation of responsibilities:
1. the authorization compiler supplies structured authority context;
2. the deterministic runtime produces a call-level verdict and evidence;
3. bounded semantic proof, one evidence-recovery attempt, and terminal policy
   close the decision as ALLOW, DENY, or CONFIRM.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from typing import Any, Mapping, Protocol

from .proof_obligation_packet import EvidenceItem, ProofPacket
from .terminal_adjudication import (
    TerminalAdjudication,
    TerminalAdjudicationPolicy,
)


class UnifiedDisposition(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    CONFIRM = "confirm"


@dataclass(frozen=True)
class SemanticProof:
    verdict: str
    rationale: str
    missing_fact: str = ""
    suggested_query: Mapping[str, Any] | None = None
    conflict_validated: bool = False

    def __post_init__(self) -> None:
        if self.verdict not in {"supported", "contradicted", "need_evidence"}:
            raise ValueError(f"unsupported proof verdict: {self.verdict}")


@dataclass(frozen=True)
class EvidenceRecoveryResult:
    succeeded: bool
    evidence: tuple[EvidenceItem, ...] = ()
    reason: str = ""


@dataclass(frozen=True)
class UnifiedDecision:
    disposition: UnifiedDisposition
    reason: str
    semantic_proof: SemanticProof | None = None
    recovery_attempted: bool = False
    recovery_succeeded: bool = False
    terminal_adjudication: TerminalAdjudication | None = None


class ProofAuditor(Protocol):
    def audit(self, packet: ProofPacket) -> SemanticProof: ...


class EvidenceResolver(Protocol):
    def recover(self, query: Mapping[str, Any], packet: ProofPacket) -> EvidenceRecoveryResult: ...


class TerminalAuditor(Protocol):
    def adjudicate(self, packet: ProofPacket, proof: SemanticProof) -> TerminalAdjudication: ...


class UnifiedAuthorizationPipeline:
    """Resolve one pending call without exposing REVIEW to the caller."""

    def __init__(
        self,
        *,
        proof_auditor: ProofAuditor,
        evidence_resolver: EvidenceResolver,
        terminal_auditor: TerminalAuditor,
        terminal_policy: TerminalAdjudicationPolicy | None = None,
    ) -> None:
        self.proof_auditor = proof_auditor
        self.evidence_resolver = evidence_resolver
        self.terminal_auditor = terminal_auditor
        self.terminal_policy = terminal_policy or TerminalAdjudicationPolicy()

    def resolve(self, *, stage2_verdict: str, packet: ProofPacket) -> UnifiedDecision:
        if stage2_verdict == "allow":
            return UnifiedDecision(UnifiedDisposition.ALLOW, "programmatic_proof_complete")
        if stage2_verdict == "alert":
            return UnifiedDecision(UnifiedDisposition.DENY, "programmatic_conflict")
        if stage2_verdict != "review":
            raise ValueError(f"unsupported stage2 verdict: {stage2_verdict}")

        proof = self.proof_auditor.audit(packet)
        direct = self._proof_decision(proof)
        if direct is not None:
            return direct

        attempted = False
        recovered = False
        if proof.suggested_query:
            attempted = True
            result = self.evidence_resolver.recover(proof.suggested_query, packet)
            if result.succeeded and result.evidence:
                recovered = True
                packet = replace(packet, evidence=packet.evidence + result.evidence)
                proof = self.proof_auditor.audit(packet)
                direct = self._proof_decision(proof)
                if direct is not None:
                    return replace(
                        direct,
                        recovery_attempted=True,
                        recovery_succeeded=True,
                    )

        terminal = self.terminal_auditor.adjudicate(packet, proof)
        disposition = UnifiedDisposition(self.terminal_policy.resolve(terminal).value)
        return UnifiedDecision(
            disposition=disposition,
            reason=f"terminal_{terminal.authorization_basis}",
            semantic_proof=proof,
            recovery_attempted=attempted,
            recovery_succeeded=recovered,
            terminal_adjudication=terminal,
        )

    @staticmethod
    def _proof_decision(proof: SemanticProof) -> UnifiedDecision | None:
        if proof.verdict == "supported":
            return UnifiedDecision(
                UnifiedDisposition.ALLOW, "semantic_proof_supported", semantic_proof=proof,
            )
        if proof.verdict == "contradicted" and proof.conflict_validated:
            return UnifiedDecision(
                UnifiedDisposition.DENY, "validated_semantic_conflict", semantic_proof=proof,
            )
        return None
