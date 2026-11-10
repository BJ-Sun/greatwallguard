"""Minimal cross-step persistent-effect authorization runtime."""

from .authorizer import EffectAuthorizer
from .contracts import ToolContractRegistry
from .graph import EffectGraph
from .model import Decision, DecisionKind, Effect, EffectType, TaskScope
from .runtime import GreatWallGuardRuntime
from .adapters.agentlab import AgentLabTraceAdapter
from .trace import TraceEventType, TraceRecorder
from .metrics import summarize_runtime
from .agentlab_recorder import AgentLabGraphRecorder, patch_agentlab
from .effect_process_ledger import build_effect_process_ledger
from .graph_detection import detect_graph_baseline
from .task_scope import generate_task_scope
from .multi_level_graph import (
    build_level1_process_graph,
    build_level2_state_graph,
    build_multi_level_graph,
)
from .programmatic_guard import (
    GuardDecision,
    ProgrammaticAuthorizationGuard,
    ProgrammaticEffectGuardV1,
)
from .provenance_values import ProvenanceStore
from .symbolic_matcher import SymbolicAuthorizationMatcher, SymbolicDecision
from .symbolic_scope import SymbolicGrant, SymbolicTaskScope
from .symbolic_guard import SymbolicAuthorizationGuard
from .relation_proof import Fact, ProofGraph, DEFAULT_RELATION_RULES
from .relational_authorization import (
    RelationConstraint,
    RelationalDecision,
    RelationalGrant,
    RelationalVerifier,
)
from .behavior_graph_relations import BehaviorGraphRelationAdapter
from .semantic_audit import (
    ConflictValidation,
    HybridRelationalGuard,
    JsonSemanticAuditor,
    SemanticAuditRequest,
    SemanticAuditResult,
    audit_prompt,
    request_from_obligation,
    validate_contradiction,
)
from .delegation import (
    DELEGATION_AUTHORITIES, DelegationGrant, infer_explicit_delegations,
)
from .review_obligations import ReviewObligation, build_review_obligation
from .structured_effect_authorization import (
    StructuredEffectAuthorizer,
    StructuredEffectDecision,
    StructuredEffectGrant,
)
from .schema_grounded_authorization import EffectContract, SchemaGroundedAuthorization
from .runtime_relation_resolver import ParameterProof, RuntimeFact, RuntimeRelationResolver
from .versioned_evidence import StateVersion, VersionLedger, VersionProof
from .evidence_relations import EvidenceRelation, SourceRef, relation_from_rows
from .authorization_dag import (
    AuthorizationDAG,
    AuthorizationDAGCompiler,
    AuthorizationDAGVerifier,
    AuthorizationEdge,
    AuthorizationNode,
    DagDecision,
    proof_core_op,
)
from .intent_dag_compiler import (
    ConstrainedIntentDAGCompiler,
    IntentCompilationError,
    IntentCompilerBackend,
    ObservationTool,
    OpenAICompatibleIntentBackend,
)
from .dag_evidence_evaluator import (
    DAGConstraintResult, DAGEvidenceEvaluator, DAGEvidenceResult,
)
from .capability_derivation import (
    CapabilityLink, CapabilityRule, ScopedCapabilityDeriver,
)
from .authorization_runtime import (
    AuthorizationRuntime, ObservationContract, PendingAuthorization,
)
from .method import GreatWallGuardMethod
from .final_gateway import (
    EffectSafetyContract,
    EvidenceRecoveryAction,
    FinalAuthorizationGateway,
    FinalDisposition,
    FinalGatewayDecision,
    SafeExecutionResult,
    SafeSubstitute,
    SafeSubstituteExecutor,
    contract,
    recovery_plan,
)
from .proof_obligation_packet import (
    EvidenceItem,
    ProofObligation,
    ProofPacket,
    ProofPacketBuilder,
)
from .terminal_adjudication import (
    TERMINAL_SYSTEM_PROMPT,
    TerminalAdjudication,
    TerminalAdjudicationPolicy,
    TerminalDisposition,
)
from .unified_authorization import (
    EvidenceRecoveryResult,
    SemanticProof,
    UnifiedAuthorizationPipeline,
    UnifiedDecision,
    UnifiedDisposition,
)
from .dynamic_delegation import (
    AuthorizationDelta,
    DelegationEnvelope,
    DeltaDisposition,
    DeltaValidation,
    DynamicDelegationExpander,
    ObservedDelegatedSource,
    ProposedEffect,
)
from .deployment_adapters import (
    CallableEvidenceResolver,
    JsonProofAuditor,
    JsonTerminalAuditor,
    PROOF_SYSTEM_PROMPT,
)

__all__ = [
    "Decision",
    "DecisionKind",
    "Effect",
    "EffectAuthorizer",
    "EffectGraph",
    "EffectType",
    "GreatWallGuardRuntime",
    "AgentLabTraceAdapter",
    "TraceEventType",
    "TraceRecorder",
    "summarize_runtime",
    "TaskScope",
    "ToolContractRegistry",
    "AgentLabGraphRecorder",
    "patch_agentlab",
    "build_effect_process_ledger",
    "detect_graph_baseline",
    "generate_task_scope",
    "build_level1_process_graph",
    "build_level2_state_graph",
    "build_multi_level_graph",
    "GuardDecision",
    "ProgrammaticAuthorizationGuard",
    "ProgrammaticEffectGuardV1",
    "ProvenanceStore",
    "SymbolicAuthorizationMatcher",
    "SymbolicAuthorizationGuard",
    "SymbolicDecision",
    "SymbolicGrant",
    "SymbolicTaskScope",
    "Fact",
    "ProofGraph",
    "DEFAULT_RELATION_RULES",
    "RelationConstraint",
    "RelationalDecision",
    "RelationalGrant",
    "RelationalVerifier",
    "BehaviorGraphRelationAdapter",
    "HybridRelationalGuard",
    "ConflictValidation",
    "JsonSemanticAuditor",
    "SemanticAuditRequest",
    "SemanticAuditResult",
    "validate_contradiction",
    "audit_prompt",
    "request_from_obligation",
    "DELEGATION_AUTHORITIES",
    "DelegationGrant",
    "infer_explicit_delegations",
    "ReviewObligation",
    "build_review_obligation",
    "StructuredEffectAuthorizer",
    "StructuredEffectDecision",
    "StructuredEffectGrant",
    "EffectContract",
    "SchemaGroundedAuthorization",
    "ParameterProof",
    "RuntimeRelationResolver",
    "RuntimeFact",
    "AuthorizationDAG",
    "AuthorizationDAGCompiler",
    "AuthorizationDAGVerifier",
    "AuthorizationEdge",
    "AuthorizationNode",
    "DagDecision",
    "proof_core_op",
    "ConstrainedIntentDAGCompiler",
    "IntentCompilationError",
    "IntentCompilerBackend",
    "ObservationTool",
    "OpenAICompatibleIntentBackend",
    "DAGEvidenceEvaluator",
    "DAGEvidenceResult",
    "DAGConstraintResult",
    "CapabilityLink",
    "CapabilityRule",
    "ScopedCapabilityDeriver",
    "AuthorizationRuntime",
    "ObservationContract",
    "PendingAuthorization",
    "GreatWallGuardMethod",
    "EffectSafetyContract",
    "EvidenceRecoveryAction",
    "FinalAuthorizationGateway",
    "FinalDisposition",
    "FinalGatewayDecision",
    "SafeExecutionResult",
    "SafeSubstitute",
    "SafeSubstituteExecutor",
    "contract",
    "recovery_plan",
    "EvidenceItem",
    "ProofObligation",
    "ProofPacket",
    "ProofPacketBuilder",
    "TERMINAL_SYSTEM_PROMPT",
    "TerminalAdjudication",
    "TerminalAdjudicationPolicy",
    "TerminalDisposition",
    "EvidenceRecoveryResult",
    "SemanticProof",
    "UnifiedAuthorizationPipeline",
    "UnifiedDecision",
    "UnifiedDisposition",
    "AuthorizationDelta",
    "DelegationEnvelope",
    "DeltaDisposition",
    "DeltaValidation",
    "DynamicDelegationExpander",
    "ObservedDelegatedSource",
    "ProposedEffect",
    "CallableEvidenceResolver",
    "JsonProofAuditor",
    "JsonTerminalAuditor",
    "PROOF_SYSTEM_PROMPT",
]
