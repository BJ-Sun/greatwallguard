"""Single public facade for the complete GreatWallGuard pipeline."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping

from .authorization_dag import AuthorizationDAG
from .authorization_runtime import AuthorizationRuntime, ObservationContract
from .authorization_timeline import AuthorizationTimeline, AuthorizationUpdateRecord
from .authorization_update_compiler import ConstrainedAuthorizationUpdateCompiler
from .capability_derivation import CapabilityRule
from .intent_dag_compiler import (
    ConstrainedIntentDAGCompiler, IntentCompilerBackend, ObservationTool,
)
from .schema_grounded_authorization import EffectContract
from .unified_authorization import (
    EvidenceResolver, ProofAuditor, TerminalAuditor, UnifiedAuthorizationPipeline,
)


class GreatWallGuardMethod:
    """Compile trusted intent and construct online proof and terminal stages."""

    def __init__(self, *, effect_contracts: Iterable[EffectContract],
                 observation_tools: Iterable[ObservationTool],
                 intent_backend: IntentCompilerBackend,
                 observation_contracts: Iterable[ObservationContract] = (),
                 source_aliases: Mapping[str, Iterable[str]] | None = None,
                 capability_rules: Iterable[CapabilityRule] = (),
                 provisional_effect_tools: Iterable[str] | None = None,
                 allow_partial_compilation: bool = True) -> None:
        self.effect_contracts = tuple(effect_contracts)
        self.observation_tools = tuple(observation_tools)
        self.observation_contracts = tuple(observation_contracts)
        self.source_aliases = dict(source_aliases or {})
        self.capability_rules = tuple(capability_rules)
        # By default, only tools declared as prerequisites in deployment
        # capability rules may be treated as unplanned intermediates.  This
        # prevents the set of all known tools from becoming an implicit
        # terminal-effect whitelist.
        self.provisional_effect_tools = tuple(
            provisional_effect_tools
            if provisional_effect_tools is not None
            else sorted({rule.prerequisite_tool for rule in self.capability_rules})
        )
        self.compiler = ConstrainedIntentDAGCompiler(
            self.effect_contracts, self.observation_tools, intent_backend,
            allow_partial=allow_partial_compilation,
        )
        self.update_compiler = ConstrainedAuthorizationUpdateCompiler(
            self.compiler, intent_backend,
        )

    def start_task(self, trusted_user_message: str, *,
                   version: str = "intent-auth-v1") -> AuthorizationRuntime:
        graph = self.compiler.compile(trusted_user_message, version=version)
        return AuthorizationRuntime(
            graph, user_message=trusted_user_message,
            source_aliases=self.source_aliases,
            capability_rules=self.capability_rules,
            observation_contracts=self.observation_contracts,
            known_effect_tools=(contract.tool for contract in self.effect_contracts),
            provisional_effect_tools=self.provisional_effect_tools,
        )

    def start_session(self, *, version: str = "intent-auth-timeline-v1"
                      ) -> "GreatWallGuardSession":
        """Start an empty online session whose authorization grows by user turn."""
        runtime = AuthorizationRuntime(
            AuthorizationDAG(version=version), user_message="",
            source_aliases=self.source_aliases,
            capability_rules=self.capability_rules,
            observation_contracts=self.observation_contracts,
            known_effect_tools=(contract.tool for contract in self.effect_contracts),
            provisional_effect_tools=self.provisional_effect_tools,
        )
        return GreatWallGuardSession(self, runtime, AuthorizationTimeline(runtime))

    @staticmethod
    def restore_task(snapshot) -> AuthorizationRuntime:
        return AuthorizationRuntime.from_snapshot(snapshot)

    @staticmethod
    def build_terminal_pipeline(
        *,
        proof_auditor: ProofAuditor,
        evidence_resolver: EvidenceResolver,
        terminal_auditor: TerminalAuditor,
    ) -> UnifiedAuthorizationPipeline:
        """Bind deployment adapters to the no-REVIEW authorization pipeline."""
        return UnifiedAuthorizationPipeline(
            proof_auditor=proof_auditor,
            evidence_resolver=evidence_resolver,
            terminal_auditor=terminal_auditor,
        )


@dataclass
class GreatWallGuardSession:
    """Reusable online facade for turn-ordered authorization maintenance."""

    method: GreatWallGuardMethod
    runtime: AuthorizationRuntime
    timeline: AuthorizationTimeline

    def apply_user_turn(self, turn: int,
                        trusted_user_message: str) -> AuthorizationUpdateRecord:
        plan = self.method.update_compiler.compile(
            trusted_message=trusted_user_message,
            runtime=self.runtime, turn=turn,
        )
        return self.method.update_compiler.apply(
            plan=plan, timeline=self.timeline, turn=turn,
            trusted_message=trusted_user_message,
        )
