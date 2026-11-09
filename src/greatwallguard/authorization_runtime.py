"""Stateful online runtime for the first two GreatWallGuard stages."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Iterable, Mapping

from .authorization_dag import AuthorizationDAG, AuthorizationDAGVerifier, DagDecision
from .capability_derivation import CapabilityRule, ScopedCapabilityDeriver
from .dag_evidence_evaluator import DAGEvidenceEvaluator
from .runtime_relation_resolver import RuntimeRelationResolver
from .versioned_evidence import StateVersion, VersionLedger


@dataclass(frozen=True)
class PendingAuthorization:
    call_id: str
    tool: str
    arguments: Mapping[str, Any]
    effect_id: str | None
    budget_key: str | None = None


@dataclass(frozen=True)
class ObservationContract:
    tool: str
    mode: str = "scoped"

    def __post_init__(self) -> None:
        if self.mode not in {"passive", "scoped", "outbound"}:
            raise ValueError(f"unknown observation mode: {self.mode}")


class AuthorizationRuntime:
    """Compile-independent online orchestration of an Authorization DAG.

    The runtime owns evidence, grant consumption, revocation, and pending call
    state.  A successful effect consumes budget; a failed tool call does not.
    """

    def __init__(self, graph: AuthorizationDAG, *, user_message: str | None = None,
                 source_aliases: Mapping[str, Iterable[str]] | None = None,
                 capability_rules: Iterable[CapabilityRule] = (),
                 observation_contracts: Iterable[ObservationContract] = (),
                 known_effect_tools: Iterable[str] = (),
                 provisional_effect_tools: Iterable[str] | None = None) -> None:
        self.graph = graph
        intent = graph.nodes.get("trusted_user_intent")
        self.user_message = user_message if user_message is not None else (
            str(intent.attrs.get("text", "")) if intent is not None else ""
        )
        self.resolver = RuntimeRelationResolver(self.user_message)
        self.source_aliases = {
            key: tuple(dict.fromkeys(values))
            for key, values in (source_aliases or {}).items()
        }
        self.capability_rules = tuple(capability_rules)
        self.known_effect_tools = frozenset(known_effect_tools)
        # ``None`` preserves the earlier conservative policy in which every
        # known effect may be an unmodelled intermediate.  An explicit set
        # enables terminal-effect enforcement: only listed tools may fall
        # back to REVIEW; every other unplanned effect remains an ALERT.
        self.provisional_effect_tools = (
            None if provisional_effect_tools is None
            else frozenset(provisional_effect_tools)
        )
        self.observation_contracts = {
            contract.tool: contract for contract in observation_contracts
        }
        self.consumed: dict[str, int] = {}
        self.consumed_bindings: dict[str, dict[str, int]] = {}
        self.revoked: set[str] = set()
        self.pending: dict[str, PendingAuthorization] = {}
        self.version_ledger = VersionLedger()
        self.observation_versions: dict[str, tuple[str, str]] = {}

    def _evaluator(self) -> DAGEvidenceEvaluator:
        return DAGEvidenceEvaluator(
            self.graph, self.resolver, source_aliases=self.source_aliases,
        )

    def authorize_tool_call(self, call_id: str, tool: str,
                            arguments: Mapping[str, Any], *,
                            read_only: bool = False) -> DagDecision:
        if call_id in self.pending:
            return DagDecision("alert", "duplicate_call_id")
        if read_only:
            contract = self.observation_contracts.get(tool)
            if contract is not None and contract.mode == "passive":
                decision = DagDecision("allow", "passive_observation_contract")
                self.pending[call_id] = PendingAuthorization(
                    call_id, tool, dict(arguments), None, None,
                )
                return decision
            if contract is not None and contract.mode == "outbound":
                # An outbound read can also transmit data through its request
                # arguments.  It is safe to auto-admit only when every leaf is
                # directly grounded in the trusted request; runtime-derived
                # destinations or payloads still require an effect contract.
                leaves = tuple(self._argument_leaves(arguments))
                if leaves and all(
                        self.resolver.explicitly_authorizes(value)
                        for value in leaves):
                    decision = DagDecision(
                        "allow", "outbound_arguments_explicitly_authorized"
                    )
                    self.pending[call_id] = PendingAuthorization(
                        call_id, tool, dict(arguments), None, None,
                    )
                    return decision
                return DagDecision(
                    "review", "outbound_observation_requires_effect_contract"
                )
        evaluator = self._evaluator()
        decision, _ = AuthorizationDAGVerifier(self.graph).verify(
            tool, arguments, self.resolver, read_only=read_only,
            evidence_evaluator=evaluator,
        )
        if (decision.verdict == "alert"
                and decision.reason == "effect_not_authorized"
                and self.capability_rules):
            derived = ScopedCapabilityDeriver(
                self.graph, evaluator, self.capability_rules,
            ).derive(tool, arguments)
            if derived is not None:
                decision = derived
        if (decision.verdict == "alert"
                and decision.reason == "effect_not_authorized"
                and tool in self.known_effect_tools
                and (self.provisional_effect_tools is None
                     or tool in self.provisional_effect_tools)):
            decision = DagDecision(
                "review", "unplanned_effect_requires_capability_proof"
            )
        if decision.verdict != "allow":
            return decision
        version_decision = self._verify_proof_versions(decision)
        if version_decision is not None:
            return version_decision
        budget_key = None
        if decision.effect_id is not None:
            if decision.effect_id in self.revoked:
                return DagDecision(
                    "alert", "authorization_revoked", effect_id=decision.effect_id,
                )
            effect = self.graph.nodes[decision.effect_id]
            budget = effect.attrs.get("budget")
            policy = effect.attrs.get("budget_policy")
            used = self.consumed.get(decision.effect_id, 0)
            if isinstance(policy, Mapping):
                fields = policy.get("fields")
                if (policy.get("mode") != "per_binding"
                        or not isinstance(fields, list) or not fields
                        or any(field not in arguments for field in fields)):
                    return DagDecision(
                        "review", "invalid_dynamic_budget_policy",
                        effect_id=decision.effect_id,
                    )
                payload = {str(field): arguments[field] for field in fields}
                budget_key = hashlib.sha256(json.dumps(
                    payload, ensure_ascii=False, sort_keys=True, default=str,
                ).encode()).hexdigest()[:20]
                per_binding = policy.get("max_per_binding", 1)
                max_total = policy.get("max_total")
                if type(per_binding) is not int or per_binding < 1:
                    return DagDecision(
                        "review", "invalid_dynamic_budget_policy",
                        effect_id=decision.effect_id,
                    )
                binding_used = self.consumed_bindings.get(
                    decision.effect_id, {}
                ).get(budget_key, 0)
                if binding_used >= per_binding:
                    return DagDecision(
                        "alert", "authorization_binding_budget_exhausted",
                        effect_id=decision.effect_id,
                    )
                if max_total is not None:
                    if type(max_total) is not int or max_total < 1:
                        return DagDecision(
                            "review", "invalid_dynamic_budget_policy",
                            effect_id=decision.effect_id,
                        )
                    if used >= max_total:
                        return DagDecision(
                            "alert", "authorization_budget_exhausted",
                            effect_id=decision.effect_id,
                        )
            elif budget is None:
                if used:
                    return DagDecision(
                        "review", "authorization_budget_requires_proof",
                        effect_id=decision.effect_id,
                    )
            elif type(budget) is not int or budget < 1:
                return DagDecision(
                    "review", "invalid_authorization_budget",
                    effect_id=decision.effect_id,
                )
            elif used >= budget:
                return DagDecision(
                    "alert", "authorization_budget_exhausted",
                    effect_id=decision.effect_id,
                )
        self.pending[call_id] = PendingAuthorization(
            call_id, tool, dict(arguments), decision.effect_id, budget_key,
        )
        return decision

    def _verify_proof_versions(self, decision: DagDecision) -> DagDecision | None:
        for source_call_id in decision.proof_nodes:
            version = self.observation_versions.get(source_call_id)
            if version is None:
                continue
            proof = self.version_ledger.prove_usable(*version)
            if proof.verdict == "alert":
                return DagDecision(
                    "alert", "parameter_uses_unauthorized_state_version",
                    proof_nodes=decision.proof_nodes,
                    core_ops=decision.core_ops,
                    effect_id=decision.effect_id,
                    proof_evidence=decision.proof_evidence,
                )
            if proof.verdict != "allow":
                return DagDecision(
                    "review", "parameter_state_version_unresolved",
                    proof_nodes=decision.proof_nodes,
                    core_ops=decision.core_ops,
                    effect_id=decision.effect_id,
                    proof_evidence=decision.proof_evidence,
                )
        return None

    @staticmethod
    def _argument_leaves(value: Any):
        if isinstance(value, Mapping):
            for child in value.values():
                yield from AuthorizationRuntime._argument_leaves(child)
        elif isinstance(value, (list, tuple)):
            for child in value:
                yield from AuthorizationRuntime._argument_leaves(child)
        elif value is not None:
            yield value

    def observe_tool_result(self, call_id: str, tool: str, result: Any, *,
                            arguments: Mapping[str, Any] | None = None,
                            object_id: str | None = None,
                            version_id: str | None = None) -> None:
        """Register a host-observed result, including permitted read calls."""
        if (object_id is None) != (version_id is None):
            raise ValueError("object_id and version_id must be supplied together")
        self.resolver.observe(call_id, tool, result, arguments=arguments)
        if object_id is not None and version_id is not None:
            # Unknown versions remain explicit REVIEW evidence rather than
            # being silently treated as trusted.
            self.observation_versions[call_id] = (object_id, version_id)

    def record_state_version(self, *, object_id: str, version_id: str,
                             parent_version_id: str | None,
                             created_by_call_id: str | None,
                             value: Any,
                             write_authorized: bool | None) -> None:
        """Add one immutable host-observed persistent-state version."""
        self.version_ledger.record(StateVersion(
            object_id=object_id, version_id=version_id,
            parent_version_id=parent_version_id,
            created_by_call_id=created_by_call_id, value=value,
            write_authorized=write_authorized,
        ))

    def commit_tool_result(self, call_id: str, *, succeeded: bool,
                           result: Any | None = None) -> None:
        pending = self.pending.pop(call_id, None)
        if pending is None:
            raise KeyError(f"call was not authorized or is unknown: {call_id}")
        if result is not None:
            self.observe_tool_result(
                call_id, pending.tool, result, arguments=pending.arguments,
            )
        if succeeded and pending.effect_id is not None:
            self.consumed[pending.effect_id] = (
                self.consumed.get(pending.effect_id, 0) + 1
            )
            if pending.budget_key is not None:
                counters = self.consumed_bindings.setdefault(pending.effect_id, {})
                counters[pending.budget_key] = counters.get(pending.budget_key, 0) + 1

    def revoke(self, effect_id: str) -> None:
        if effect_id not in self.graph.nodes or self.graph.nodes[effect_id].kind != "effect":
            raise KeyError(f"unknown effect authorization: {effect_id}")
        self.revoked.add(effect_id)

    def snapshot(self) -> dict[str, Any]:
        return {
            "schema": "greatwallguard-authorization-runtime-v1",
            "graph": self.graph.to_dict(),
            "user_message": self.user_message,
            "source_aliases": {key: list(value) for key, value in self.source_aliases.items()},
            "capability_rules": [
                {
                    "prerequisite_tool": rule.prerequisite_tool,
                    "terminal_tool": rule.terminal_tool,
                    "links": [
                        {
                            "prerequisite_field": link.prerequisite_field,
                            "terminal_field": link.terminal_field,
                        }
                        for link in rule.links
                    ],
                }
                for rule in self.capability_rules
            ],
            "observation_contracts": [
                {"tool": item.tool, "mode": item.mode}
                for item in self.observation_contracts.values()
            ],
            "known_effect_tools": sorted(self.known_effect_tools),
            "provisional_effect_tools": (
                None if self.provisional_effect_tools is None
                else sorted(self.provisional_effect_tools)
            ),
            "consumed": dict(self.consumed),
            "consumed_bindings": {
                effect_id: dict(counts)
                for effect_id, counts in self.consumed_bindings.items()
            },
            "revoked": sorted(self.revoked),
            "observations": [
                {
                    "call_id": item.call_id, "tool": item.tool,
                    "value": item.value, "arguments": item.arguments,
                }
                for item in self.resolver.observations
            ],
            "observed_facts": [
                {
                    "call_id": item.call_id, "tool": item.tool,
                    "path": item.path, "value": item.value,
                }
                for item in self.resolver.facts
            ],
            "version_ledger": self.version_ledger.to_dict(),
            "observation_versions": {
                call_id: {"object_id": value[0], "version_id": value[1]}
                for call_id, value in self.observation_versions.items()
            },
        }

    @classmethod
    def from_snapshot(cls, value: Mapping[str, Any]) -> "AuthorizationRuntime":
        from .capability_derivation import CapabilityLink

        if value.get("schema") != "greatwallguard-authorization-runtime-v1":
            raise ValueError("unsupported runtime snapshot")
        rules = tuple(
            CapabilityRule(
                str(raw["prerequisite_tool"]), str(raw["terminal_tool"]),
                tuple(CapabilityLink(
                    str(link["prerequisite_field"]), str(link["terminal_field"]),
                ) for link in raw.get("links", [])),
            )
            for raw in value.get("capability_rules", [])
        )
        runtime = cls(
            AuthorizationDAG.from_dict(value["graph"]),
            user_message=str(value.get("user_message", "")),
            source_aliases=value.get("source_aliases", {}),
            capability_rules=rules,
            observation_contracts=tuple(
                ObservationContract(str(item["tool"]), str(item.get("mode", "scoped")))
                for item in value.get("observation_contracts", [])
            ),
            known_effect_tools=tuple(value.get("known_effect_tools", [])),
            provisional_effect_tools=(
                None if value.get("provisional_effect_tools") is None
                else tuple(value.get("provisional_effect_tools", []))
            ),
        )
        runtime.consumed = {
            str(key): int(count) for key, count in value.get("consumed", {}).items()
        }
        runtime.consumed_bindings = {
            str(effect_id): {str(key): int(count) for key, count in counts.items()}
            for effect_id, counts in value.get("consumed_bindings", {}).items()
        }
        runtime.revoked = {str(item) for item in value.get("revoked", [])}
        ledger = value.get("version_ledger")
        if isinstance(ledger, Mapping):
            runtime.version_ledger = VersionLedger.from_dict(ledger)
        runtime.observation_versions = {
            str(call_id): (str(item["object_id"]), str(item["version_id"]))
            for call_id, item in value.get("observation_versions", {}).items()
        }
        for item in value.get("observations", []):
            runtime.observe_tool_result(
                str(item["call_id"]), str(item["tool"]), item.get("value"),
                arguments=item.get("arguments"),
            )
        return runtime
