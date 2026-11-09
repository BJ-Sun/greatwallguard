"""Finite authorization DAG compiled from trusted intent.

The DAG is the executable form of a small, typed authorization IR.  Its core
vocabulary is deliberately independent of benchmark task IDs and business
domains.  Existing runtime proofs are lowered to a fixed set of relational
operations rather than becoming new authorization primitives.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
import re
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit

from .delegation import DelegationGrant, infer_explicit_delegations
from .runtime_relation_resolver import ParameterProof, RuntimeRelationResolver
from .schema_grounded_authorization import EffectContract, SchemaGroundedAuthorization


NODE_KINDS = frozenset({"source", "transform", "constraint", "effect", "delegation"})
EDGE_KINDS = frozenset({"data_dep", "guards", "binds", "version_dep", "delegates"})
CORE_TRANSFORMS = frozenset({
    "select", "project", "join", "aggregate", "compute", "normalize", "template",
})
NODE_STATES = frozenset({"unbound", "bound", "proved", "failed", "unknown", "revoked"})


@dataclass
class AuthorizationNode:
    id: str
    kind: str
    value_type: str
    op: str | None = None
    attrs: dict[str, Any] = field(default_factory=dict)
    status: str = "unbound"

    def __post_init__(self) -> None:
        if self.kind not in NODE_KINDS:
            raise ValueError(f"unknown node kind: {self.kind}")
        if self.status not in NODE_STATES:
            raise ValueError(f"unknown node status: {self.status}")
        if self.kind == "transform" and self.op not in CORE_TRANSFORMS:
            raise ValueError(f"transform is not in the finite core: {self.op}")


@dataclass(frozen=True)
class AuthorizationEdge:
    source: str
    target: str
    kind: str
    attrs: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.kind not in EDGE_KINDS:
            raise ValueError(f"unknown edge kind: {self.kind}")


@dataclass(frozen=True)
class DagDecision:
    verdict: str
    reason: str
    field: str | None = None
    proof_nodes: tuple[str, ...] = ()
    core_ops: tuple[str, ...] = ()
    effect_id: str | None = None
    proof_evidence: tuple[str, ...] = ()
    review_type: str | None = None
    delegation_id: str | None = None
    missing_evidence: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.verdict != "review" or self.review_type is not None:
            return
        evidence_reasons = {
            "unscoped_observation_requires_review",
            "outbound_observation_requires_effect_contract",
            "instrumental_capability_requires_link_proof",
            "instrumental_capability_unproved",
            "unplanned_effect_requires_capability_proof",
            "authorization_budget_requires_proof",
            "invalid_dynamic_budget_policy",
            "invalid_authorization_budget",
            "parameter_state_version_unresolved",
        }
        confirmation_reasons = {
            "delegation_requires_confirmation",
            "broad_effect_delegation_requires_confirmation",
        }
        review_type = (
            "evidence_missing" if self.reason in evidence_reasons else
            "policy_confirmation" if self.reason in confirmation_reasons else
            "semantic_unresolved"
        )
        object.__setattr__(self, "review_type", review_type)
        if not self.missing_evidence and self.field:
            object.__setattr__(self, "missing_evidence", (self.field,))


class AuthorizationDAG:
    def __init__(self, *, version: str = "auth-v1", delegated: bool = False,
                 delegations: Iterable[DelegationGrant] = ()) -> None:
        self.version = version
        self.delegations = tuple(delegations)
        self.delegated = delegated or bool(self.delegations)
        self.nodes: dict[str, AuthorizationNode] = {}
        self.edges: list[AuthorizationEdge] = []

    def add_node(self, node: AuthorizationNode) -> AuthorizationNode:
        if node.id in self.nodes:
            raise ValueError(f"duplicate node: {node.id}")
        self.nodes[node.id] = node
        return node

    def add_edge(self, edge: AuthorizationEdge) -> AuthorizationEdge:
        if edge.source not in self.nodes or edge.target not in self.nodes:
            raise ValueError("edge endpoint is not present in DAG")
        self.edges.append(edge)
        if not self.is_acyclic():
            self.edges.pop()
            raise ValueError("authorization graph must remain acyclic")
        return edge

    def incoming(self, node_id: str, kind: str | None = None) -> list[AuthorizationEdge]:
        return [edge for edge in self.edges
                if edge.target == node_id and (kind is None or edge.kind == kind)]

    def is_acyclic(self) -> bool:
        outgoing: dict[str, list[str]] = {node_id: [] for node_id in self.nodes}
        indegree = {node_id: 0 for node_id in self.nodes}
        for edge in self.edges:
            outgoing[edge.source].append(edge.target)
            indegree[edge.target] += 1
        ready = [node_id for node_id, degree in indegree.items() if degree == 0]
        visited = 0
        while ready:
            current = ready.pop()
            visited += 1
            for target in outgoing[current]:
                indegree[target] -= 1
                if indegree[target] == 0:
                    ready.append(target)
        return visited == len(self.nodes)

    def reverse_slice(self, node_id: str) -> set[str]:
        selected = {node_id}
        frontier = [node_id]
        while frontier:
            current = frontier.pop()
            for edge in self.incoming(current):
                if edge.source not in selected:
                    selected.add(edge.source)
                    frontier.append(edge.source)
        return selected

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "delegated": self.delegated,
            "delegations": [item.to_dict() for item in self.delegations],
            "nodes": [node.__dict__ for node in self.nodes.values()],
            "edges": [
                {"source": edge.source, "target": edge.target,
                 "kind": edge.kind, "attrs": dict(edge.attrs)}
                for edge in self.edges
            ],
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AuthorizationDAG":
        """Restore a validated DAG snapshot produced by :meth:`to_dict`."""
        graph = cls(
            version=str(value.get("version", "auth-v1")),
            delegated=bool(value.get("delegated", False)),
            delegations=tuple(
                DelegationGrant.from_dict(item)
                for item in value.get("delegations", [])
                if isinstance(item, Mapping)
            ),
        )
        nodes = value.get("nodes")
        edges = value.get("edges")
        if not isinstance(nodes, list) or not isinstance(edges, list):
            raise ValueError("authorization DAG snapshot requires node and edge lists")
        for raw in nodes:
            if not isinstance(raw, Mapping):
                raise ValueError("authorization DAG node must be an object")
            graph.add_node(AuthorizationNode(
                id=str(raw.get("id", "")), kind=str(raw.get("kind", "")),
                value_type=str(raw.get("value_type", "")),
                op=raw.get("op") if isinstance(raw.get("op"), str) else None,
                attrs=dict(raw.get("attrs", {})) if isinstance(raw.get("attrs"), Mapping) else {},
                status=str(raw.get("status", "unbound")),
            ))
        for raw in edges:
            if not isinstance(raw, Mapping):
                raise ValueError("authorization DAG edge must be an object")
            graph.add_edge(AuthorizationEdge(
                source=str(raw.get("source", "")), target=str(raw.get("target", "")),
                kind=str(raw.get("kind", "")),
                attrs=dict(raw.get("attrs", {})) if isinstance(raw.get("attrs"), Mapping) else {},
            ))
        return graph


class AuthorizationDAGCompiler:
    """Lower finite effect contracts and trusted text into an authorization DAG."""

    def __init__(self, contracts: Iterable[EffectContract]) -> None:
        self.contracts = tuple(contracts)

    def compile(self, user_message: str, *, version: str = "auth-v1") -> AuthorizationDAG:
        authorization = SchemaGroundedAuthorization(user_message, self.contracts)
        delegations = infer_explicit_delegations(user_message)
        graph = AuthorizationDAG(
            version=version, delegated=authorization.delegated,
            delegations=delegations,
        )
        graph.add_node(AuthorizationNode(
            "trusted_user_intent", "source", "TrustedUserMessage",
            attrs={"source_type": "trusted_user", "text": user_message}, status="proved",
        ))
        for delegation in delegations:
            graph.add_node(AuthorizationNode(
                delegation.delegation_id, "delegation", "DelegatedAuthority",
                attrs=delegation.to_dict(), status="proved",
            ))
            graph.add_edge(AuthorizationEdge(
                "trusted_user_intent", delegation.delegation_id, "delegates",
                {"authority": delegation.authority},
            ))
        needs_guard = RuntimeRelationResolver(user_message).requires_guard
        for effect_index, grant in enumerate(authorization.grants):
            effect_id = f"effect:{effect_index}:{grant.tool}"
            graph.add_node(AuthorizationNode(
                effect_id, "effect", grant.effect,
                attrs={
                    "tool": grant.tool,
                    "effect": grant.effect,
                    "critical_fields": list(grant.parameters),
                    "required_fields": list(next(
                        (contract.required_fields for contract in self.contracts
                         if contract.tool == grant.tool), ()
                    )),
                    "evidence": grant.evidence,
                },
            ))
            for field_name, rule in grant.parameters.items():
                source_id = f"arg:{effect_index}:{field_name}"
                graph.add_node(AuthorizationNode(
                    source_id, "source", "SymbolicValue",
                    attrs={
                        "field": field_name,
                        "source_type": "trusted_literal" if rule.kind == "literal_set"
                                       else "runtime_deferred",
                        "values": list(rule.values),
                    },
                    status="proved" if rule.kind == "literal_set" else "unbound",
                ))
                graph.add_edge(AuthorizationEdge(
                    source_id, effect_id, "binds", {"field": field_name}
                ))
            if needs_guard:
                guard_id = f"guard:{effect_index}"
                graph.add_node(AuthorizationNode(
                    guard_id, "constraint", "Boolean", op="compare",
                    attrs={"constraint_type": "runtime_numeric_guard"},
                ))
                graph.add_edge(AuthorizationEdge(guard_id, effect_id, "guards"))
        return graph


def proof_core_op(rule: str) -> str | None:
    """Lower legacy proof names to the finite DAG transform vocabulary."""
    if rule == "explicit_user_value":
        return None
    if rule in {"explicit_temporal_components", "natural_date_normalization"}:
        return "normalize"
    if rule in {"duration_from_user_start", "deterministic_numeric_computation"}:
        return "compute"
    if rule == "ordinal_template_instantiation":
        return "template"
    if rule == "bound_source_projection":
        return "project"
    if rule in {"named_object_projection", "prefix_selection"}:
        return "select"
    if rule == "relational_row_projection":
        return "join"
    if (rule.startswith(("max_", "min_"))
            or rule in {"argmax_group_cardinality", "argmax_group_frequency",
                        "ranked_group_frequency"}):
        return "aggregate"
    if rule == "numeric_guard_proved":
        return None
    raise ValueError(f"proof rule has no finite-core lowering: {rule}")


class AuthorizationDAGVerifier:
    """Bind runtime facts to a compiled DAG and verify one candidate effect."""

    def __init__(self, graph: AuthorizationDAG) -> None:
        self.graph = graph

    def verify(self, tool: str, arguments: Mapping[str, Any],
               resolver: RuntimeRelationResolver, *, read_only: bool = False,
               evidence_evaluator: Any | None = None,
               ) -> tuple[DagDecision, AuthorizationDAG]:
        if read_only:
            evaluation = deepcopy(self.graph)
            authorized_sources = {
                node.attrs.get("tool") for node in evaluation.nodes.values()
                if node.kind == "source"
                and node.attrs.get("source_type") == "runtime_deferred"
            }
            if tool in authorized_sources:
                return DagDecision("allow", "authorized_observation"), evaluation
            return DagDecision(
                "review", "unscoped_observation_requires_review"
            ), evaluation
        effects = [node for node in self.graph.nodes.values()
                   if node.kind == "effect" and node.attrs.get("tool") == tool]
        if not effects:
            evaluation = deepcopy(self.graph)
            matching = next((
                item for item in self.graph.delegations
                if item.authority == "effects" and tool in item.allowed_tools
            ), None)
            if matching is not None:
                return DagDecision(
                    "review", "delegated_effect_requires_semantic_proof",
                    delegation_id=matching.delegation_id,
                ), evaluation
            broad = next((
                item for item in self.graph.delegations
                if item.authority == "effects" and item.requires_confirmation
            ), None)
            if broad is not None:
                return DagDecision(
                    "review", "broad_effect_delegation_requires_confirmation",
                    review_type="policy_confirmation",
                    delegation_id=broad.delegation_id,
                ), evaluation
            verdict = "review" if self.graph.delegated else "alert"
            reason = ("effect_delegated_to_external_content" if self.graph.delegated
                      else "effect_not_authorized")
            return DagDecision(verdict, reason), evaluation
        outcomes = [
            self._verify_effect(effect.id, arguments, resolver, evidence_evaluator)
            for effect in effects
        ]
        for verdict in ("allow", "review", "alert"):
            for decision, evaluation in outcomes:
                if decision.verdict == verdict:
                    return decision, evaluation
        raise AssertionError("effect verification produced no decision")

    def _verify_effect(self, effect_id: str, arguments: Mapping[str, Any],
                       resolver: RuntimeRelationResolver,
                       evidence_evaluator: Any | None,
                       ) -> tuple[DagDecision, AuthorizationDAG]:
        evaluation = deepcopy(self.graph)
        effect = evaluation.nodes[effect_id]
        evaluator = evidence_evaluator
        if evaluator is not None and evaluator.graph is not evaluation:
            evaluator = type(evaluator)(
                evaluation, resolver, source_aliases={
                    key: set(value) - {key}
                    for key, value in evaluator.source_aliases.items()
                },
            )
        proof_nodes: list[str] = []
        core_ops: list[str] = []
        proof_evidence: list[str] = []
        deferred_present = False
        for edge in evaluation.incoming(effect.id, "binds"):
            binding = evaluation.nodes[edge.source]
            field_name = str(edge.attrs.get("field"))
            source_type = binding.attrs.get("source_type")
            if source_type == "forbidden_absent":
                if field_name in arguments and arguments[field_name] is not None:
                    binding.status = "failed"
                    if not binding.attrs.get("explicit_forbid", False):
                        return DagDecision(
                            "review", "unspecified_parameter_requires_review",
                            field_name, effect_id=effect.id,
                        ), evaluation
                    return DagDecision(
                        "alert", "parameter_not_authorized", field_name,
                        effect_id=effect.id,
                    ), evaluation
                binding.status = "proved"
                proof_nodes.append(binding.id)
                continue
            if field_name not in arguments:
                if field_name in effect.attrs.get("required_fields", []):
                    binding.status = "failed"
                    return DagDecision(
                        "alert", "required_parameter_missing", field_name,
                        effect_id=effect.id,
                    ), evaluation
                continue
            actual_values = arguments[field_name]
            actual_values = actual_values if isinstance(actual_values, list) else [actual_values]
            if source_type == "trusted_literal":
                expected = list(binding.attrs.get("values", []))
                observed = [value for value in actual_values if value is not None]
                if not observed or not all(
                        any(self._literal_in_scope(field_name, actual, allowed)
                            for allowed in expected)
                        for actual in observed):
                    # The compiler may choose one of several explicit values
                    # for the same authorized effect.  A concrete runtime
                    # value that is independently present in the trusted
                    # request remains grounded without trusting the compiler's
                    # narrower candidate list.
                    if observed and all(
                            resolver.explicitly_authorizes(actual)
                            for actual in observed):
                        binding.status = "proved"
                        proof_nodes.append(binding.id)
                        continue
                    binding.status = "failed"
                    intent = evaluation.nodes.get("trusted_user_intent")
                    intent_text = str(intent.attrs.get("text", "")) if intent else ""
                    presentation_field = field_name.casefold() in {
                        "title", "subject", "body", "content", "description",
                    }
                    literal_grounded = all(
                        not isinstance(value, str)
                        or value.casefold() in intent_text.casefold()
                        for value in expected
                    )
                    # Open presentation fields are commonly synthesized by
                    # the compiler from a semantic request (for example,
                    # mentioning an invoice becomes subject="Invoice").
                    # Unless the IR explicitly records an exact user quote,
                    # a different runtime rendering is unresolved rather than
                    # a proven authorization conflict.
                    exact_literal = bool(binding.attrs.get("exact_literal", False))
                    if presentation_field and not exact_literal:
                        return DagDecision(
                            "review", "generated_presentation_literal_requires_review",
                            field_name, effect_id=effect.id,
                        ), evaluation
                    if field_name.casefold() in {"repo", "repo_name", "repository"}:
                        actual_tails = {str(value).rsplit("/", 1)[-1].casefold()
                                        for value in observed}
                        expected_names = {str(value).rsplit("/", 1)[-1].casefold()
                                          for value in expected}
                        intent_tail_grounded = actual_tails and all(
                            tail in intent_text.casefold() for tail in actual_tails
                        )
                        if actual_tails and (
                                actual_tails.issubset(expected_names)
                                or intent_tail_grounded):
                            return DagDecision(
                                "review", "repository_owner_scope_requires_proof",
                                field_name, effect_id=effect.id,
                            ), evaluation
                    if not literal_grounded:
                        return DagDecision(
                            "review", "compiler_literal_not_grounded",
                            field_name, effect_id=effect.id,
                        ), evaluation
                    return DagDecision(
                        "alert", "explicit_parameter_mismatch", field_name,
                        effect_id=effect.id,
                    ), evaluation
                binding.status = "proved"
                proof_nodes.append(binding.id)
                continue
            deferred_present = True
            if evaluator is not None:
                dag_proof = evaluator.prove_binding(binding.id, actual_values)
                if dag_proof is not None and dag_proof.proved:
                    binding.status = "proved"
                    proof_nodes.extend(dag_proof.source_call_ids)
                    core_ops.extend(dag_proof.operators)
                    proof_evidence.extend(dag_proof.evidence_paths)
                    continue
            for value_index, value in enumerate(actual_values):
                proof = resolver.prove(field_name, value, arguments=arguments)
                if proof is None:
                    binding.status = "unknown"
                    return DagDecision(
                        "review", "authorized_effect_has_unproved_binding", field_name,
                        tuple(proof_nodes), tuple(core_ops), effect.id,
                    ), evaluation
                added, op = self._attach_parameter_proof(
                    evaluation, effect.id, field_name, proof,
                    suffix=f"{len(proof_nodes)}:{value_index}",
                )
                proof_nodes.extend(added)
                if op is not None:
                    core_ops.append(op)
            binding.status = "proved"
        guards = evaluation.incoming(effect.id, "guards")
        if guards:
            if evaluator is None:
                from .dag_evidence_evaluator import DAGEvidenceEvaluator
                evaluator = DAGEvidenceEvaluator(evaluation, resolver)
            for edge in guards:
                if not evaluation.incoming(edge.source, "data_dep"):
                    # Legacy compiler guards are proved by the finite runtime
                    # resolver below; new IR constraints carry explicit inputs.
                    continue
                result = evaluator.evaluate_constraint(edge.source)
                guard = evaluation.nodes[edge.source]
                if result.status == "contradicted":
                    guard.status = "failed"
                    return DagDecision(
                        "alert", "constraint_contradicted", "__constraint__",
                        result.source_call_ids, result.operators, effect.id,
                    ), evaluation
                if result.status != "proved":
                    guard.status = "unknown"
                    return DagDecision(
                        "review", "constraint_unproved", "__constraint__",
                        result.source_call_ids, result.operators, effect.id,
                    ), evaluation
                guard.status = "proved"
                proof_nodes.extend(result.source_call_ids)
                core_ops.extend(result.operators)
        if deferred_present and resolver.requires_guard:
            guard = resolver.prove_guard(arguments)
            if guard is None:
                return DagDecision(
                    "review", "authorized_effect_has_unproved_guard", "__guard__",
                    tuple(proof_nodes), tuple(core_ops), effect.id,
                ), evaluation
            added = self._attach_guard_proof(evaluation, effect.id, guard)
            proof_nodes.extend(added)
        effect.status = "proved"
        reason = "dag_proof_satisfied" if deferred_present else "effect_and_parameters_authorized"
        return DagDecision(
            "allow", reason, proof_nodes=tuple(proof_nodes), core_ops=tuple(core_ops),
            effect_id=effect.id,
            proof_evidence=tuple(dict.fromkeys(proof_evidence)),
        ), evaluation

    @staticmethod
    def _literal_in_scope(field: str, actual: Any, expected: Any) -> bool:
        normalized_field = field.casefold()
        observed = SchemaGroundedAuthorization._normalize(field, actual)
        allowed = SchemaGroundedAuthorization._normalize(field, expected)
        if observed == allowed:
            return True
        if "url" in normalized_field:
            def parts(value: str):
                candidate = value if re.match(r"^[a-z]+://", value, re.I) else f"https://{value}"
                parsed = urlsplit(candidate)
                return parsed.hostname, parsed.path.rstrip("/")
            observed_host, observed_path = parts(str(actual).casefold())
            allowed_host, allowed_path = parts(str(expected).casefold())
            return (
                observed_host == allowed_host
                and (not allowed_path or observed_path == allowed_path
                     or observed_path.startswith(allowed_path + "/"))
            )
        if any(token in normalized_field for token in ("path", "directory", "dir")):
            observed_path = str(actual).rstrip("/")
            allowed_path = str(expected).rstrip("/")
            return observed_path == allowed_path or observed_path.startswith(allowed_path + "/")
        return False

    @staticmethod
    def _attach_parameter_proof(graph: AuthorizationDAG, effect_id: str, field_name: str,
                                proof: ParameterProof, *, suffix: str
                                ) -> tuple[list[str], str | None]:
        node_ids: list[str] = []
        source_ids = []
        call_ids = proof.source_call_ids or ("trusted_user_intent",)
        for index, call_id in enumerate(call_ids):
            if call_id == "trusted_user_intent":
                source_id = "trusted_user_intent"
            else:
                source_id = f"runtime:{field_name}:{suffix}:{index}"
                graph.add_node(AuthorizationNode(
                    source_id, "source", "RuntimeObservation",
                    attrs={"source_type": "runtime_observation", "call_id": call_id},
                    status="proved",
                ))
                node_ids.append(source_id)
            source_ids.append(source_id)
        op = proof_core_op(proof.rule)
        terminal = source_ids[0]
        if op is not None:
            transform_id = f"derive:{field_name}:{suffix}"
            graph.add_node(AuthorizationNode(
                transform_id, "transform", "SymbolicValue", op=op,
                attrs={"field": field_name, "rule": proof.rule,
                       "value": proof.value, "evidence": list(proof.evidence)},
                status="proved",
            ))
            for source_id in source_ids:
                graph.add_edge(AuthorizationEdge(source_id, transform_id, "data_dep"))
            terminal = transform_id
            node_ids.append(transform_id)
        graph.add_edge(AuthorizationEdge(terminal, effect_id, "binds", {"field": field_name}))
        return node_ids, op

    @staticmethod
    def _attach_guard_proof(graph: AuthorizationDAG, effect_id: str,
                            proof: ParameterProof) -> list[str]:
        node_ids = []
        source_ids = []
        for index, call_id in enumerate(proof.source_call_ids):
            source_id = f"runtime:guard:{index}"
            graph.add_node(AuthorizationNode(
                source_id, "source", "RuntimeObservation",
                attrs={"source_type": "runtime_observation", "call_id": call_id},
                status="proved",
            ))
            node_ids.append(source_id)
            source_ids.append(source_id)
        existing = [
            graph.nodes[edge.source] for edge in graph.incoming(effect_id, "guards")
            if graph.nodes[edge.source].kind == "constraint"
        ]
        if existing:
            guard = existing[0]
            guard.status = "proved"
            guard.attrs.update({"rule": proof.rule, "evidence": list(proof.evidence)})
            guard_id = guard.id
        else:
            guard_id = f"proved_guard:{len(graph.nodes)}"
            graph.add_node(AuthorizationNode(
                guard_id, "constraint", "Boolean", op="compare",
                attrs={"rule": proof.rule, "evidence": list(proof.evidence)}, status="proved",
            ))
            graph.add_edge(AuthorizationEdge(guard_id, effect_id, "guards"))
        for source_id in source_ids:
            graph.add_edge(AuthorizationEdge(source_id, guard_id, "data_dep"))
        node_ids.append(guard_id)
        return node_ids
