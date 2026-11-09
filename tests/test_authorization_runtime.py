import unittest

from greatwallguard import (
    AuthorizationDAG,
    AuthorizationEdge,
    AuthorizationNode,
    AuthorizationRuntime,
    ConstrainedIntentDAGCompiler,
    EffectContract,
    GreatWallGuardMethod,
    ObservationContract,
)


class StaticBackend:
    def __init__(self, value):
        self.value = value

    def generate(self, **kwargs):
        return self.value


def compile_graph(*, budget=1, constraints=None):
    ir = {
        "schema": "authorization_ir_v1",
        "review_reasons": [],
        "grants": [{
            "grant_id": "send-once",
            "tool": "send_email",
            "effect": "external_message",
            "bindings": {
                "recipient": {"op": "literal", "value": "alice@example.com"},
                "body": {"op": "literal", "value": "hello"},
            },
            "constraints": constraints or [],
            "budget": budget,
        }],
    }
    return ConstrainedIntentDAGCompiler(
        (EffectContract(
            "send_email", "external_message", ("recipient", "body"),
            required_fields=("recipient", "body"),
        ),), (), StaticBackend(ir),
    ).compile("Send hello to alice@example.com")


class AuthorizationRuntimeTests(unittest.TestCase):
    def test_public_method_facade_compiles_and_starts_runtime(self):
        ir = {
            "schema": "authorization_ir_v1", "review_reasons": [],
            "grants": [{
                "grant_id": "send", "tool": "send_email",
                "effect": "external_message",
                "bindings": {
                    "recipient": {"op": "literal", "value": "alice@example.com"},
                    "body": {"op": "literal", "value": "hello"},
                },
                "constraints": [], "budget": 1,
            }],
        }
        method = GreatWallGuardMethod(
            effect_contracts=(EffectContract(
                "send_email", "external_message", ("recipient", "body"),
                required_fields=("recipient", "body"),
            ),),
            observation_tools=(), intent_backend=StaticBackend(ir),
        )
        runtime = method.start_task("Send hello to alice@example.com")
        decision = runtime.authorize_tool_call(
            "c1", "send_email",
            {"recipient": "alice@example.com", "body": "hello"},
        )
        self.assertEqual(decision.verdict, "allow")

    def test_unspecified_repeated_budget_reviews_instead_of_unbounded_allow(self):
        graph = AuthorizationDAG()
        graph.add_node(AuthorizationNode(
            "trusted_user_intent", "source", "TrustedUserMessage",
            attrs={"source_type": "trusted_user", "text": "notify every user"},
            status="proved",
        ))
        graph.add_node(AuthorizationNode(
            "recipient", "source", "Literal",
            attrs={"source_type": "trusted_literal", "values": ["Alice", "Bob"]},
            status="proved",
        ))
        graph.add_node(AuthorizationNode(
            "effect", "effect", "message",
            attrs={"tool": "send", "critical_fields": ["recipient"]},
        ))
        graph.add_edge(AuthorizationEdge(
            "recipient", "effect", "binds", {"field": "recipient"},
        ))
        runtime = AuthorizationRuntime(graph)
        first = runtime.authorize_tool_call("c1", "send", {"recipient": "Alice"})
        self.assertEqual(first.verdict, "allow")
        runtime.commit_tool_result("c1", succeeded=True)
        second = runtime.authorize_tool_call("c2", "send", {"recipient": "Bob"})
        self.assertEqual(second.verdict, "review")
        self.assertEqual(second.reason, "authorization_budget_requires_proof")

    def test_per_binding_budget_allows_distinct_objects_once(self):
        graph = AuthorizationDAG()
        graph.add_node(AuthorizationNode(
            "trusted_user_intent", "source", "TrustedUserMessage",
            attrs={"source_type": "trusted_user", "text": "notify Alice and Bob"},
            status="proved",
        ))
        graph.add_node(AuthorizationNode(
            "recipient", "source", "Literal",
            attrs={"source_type": "trusted_literal", "values": ["Alice", "Bob"]},
            status="proved",
        ))
        graph.add_node(AuthorizationNode(
            "effect", "effect", "message", attrs={
                "tool": "send", "critical_fields": ["recipient"],
                "budget_policy": {"mode": "per_binding", "fields": ["recipient"],
                                  "max_per_binding": 1, "max_total": 2},
            },
        ))
        graph.add_edge(AuthorizationEdge(
            "recipient", "effect", "binds", {"field": "recipient"},
        ))
        runtime = AuthorizationRuntime(graph)
        for call_id, recipient in (("c1", "Alice"), ("c2", "Bob")):
            decision = runtime.authorize_tool_call(
                call_id, "send", {"recipient": recipient},
            )
            self.assertEqual(decision.verdict, "allow")
            runtime.commit_tool_result(call_id, succeeded=True)
        repeated = runtime.authorize_tool_call("c3", "send", {"recipient": "Alice"})
        self.assertEqual(repeated.verdict, "alert")
        self.assertEqual(
            repeated.reason, "authorization_binding_budget_exhausted"
        )

    def test_observation_contract_distinguishes_passive_and_outbound_reads(self):
        runtime = AuthorizationRuntime(
            compile_graph(), observation_contracts=(
                ObservationContract("read_local", "passive"),
                ObservationContract("fetch_url", "outbound"),
            ),
        )
        passive = runtime.authorize_tool_call(
            "r1", "read_local", {"path": "/tmp/report"}, read_only=True,
        )
        outbound = runtime.authorize_tool_call(
            "r2", "fetch_url", {"url": "https://example.com/?x=secret"},
            read_only=True,
        )
        self.assertEqual(passive.verdict, "allow")
        self.assertEqual(outbound.verdict, "review")
        self.assertEqual(outbound.reason, "outbound_observation_requires_effect_contract")

    def test_known_unplanned_effect_reviews_instead_of_false_conflict(self):
        runtime = AuthorizationRuntime(
            compile_graph(), known_effect_tools=("send_email", "download_file"),
        )
        decision = runtime.authorize_tool_call(
            "c1", "download_file", {"url": "https://example.com/a"},
        )
        self.assertEqual(decision.verdict, "review")
        self.assertEqual(
            decision.reason, "unplanned_effect_requires_capability_proof"
        )

    def test_unknown_unregistered_effect_remains_alert(self):
        runtime = AuthorizationRuntime(
            compile_graph(), known_effect_tools=("send_email",),
        )
        decision = runtime.authorize_tool_call("c1", "shell_root", {})
        self.assertEqual(decision.verdict, "alert")

    def test_strict_terminal_effect_policy_alerts_unplanned_terminal_effect(self):
        runtime = AuthorizationRuntime(
            compile_graph(),
            known_effect_tools=("send_email", "download_file", "delete_file"),
            provisional_effect_tools=("download_file",),
        )
        terminal = runtime.authorize_tool_call(
            "c1", "delete_file", {"path": "/tmp/report"},
        )
        provisional = runtime.authorize_tool_call(
            "c2", "download_file", {"url": "https://example.com/a"},
        )
        self.assertEqual(terminal.verdict, "alert")
        self.assertEqual(terminal.reason, "effect_not_authorized")
        self.assertEqual(provisional.verdict, "review")
        self.assertEqual(
            provisional.reason, "unplanned_effect_requires_capability_proof",
        )

    def test_outbound_observation_allows_only_explicit_trusted_arguments(self):
        runtime = AuthorizationRuntime(
            compile_graph(),
            user_message="Visit https://example.com to read the public page.",
            observation_contracts=(ObservationContract("fetch_url", "outbound"),),
        )
        allowed = runtime.authorize_tool_call(
            "r1", "fetch_url", {"url": "https://example.com"}, read_only=True,
        )
        self.assertEqual(allowed.verdict, "allow")
        self.assertEqual(
            allowed.reason, "outbound_arguments_explicitly_authorized"
        )

        runtime.observe_tool_result(
            "source", "read_file", {"url": "https://attacker.example"},
        )
        reviewed = runtime.authorize_tool_call(
            "r2", "fetch_url", {"url": "https://attacker.example"}, read_only=True,
        )
        self.assertEqual(reviewed.verdict, "review")

    def test_explicit_site_scope_allows_scheme_and_child_path_variation(self):
        runtime = AuthorizationRuntime(
            compile_graph(),
            user_message="Visit www.example.com to download the public template.",
            observation_contracts=(ObservationContract("fetch_url", "outbound"),),
        )
        child = runtime.authorize_tool_call(
            "r1", "fetch_url", {"url": "https://example.com/download/template"},
            read_only=True,
        )
        self.assertEqual(child.verdict, "allow")
        runtime.commit_tool_result("r1", succeeded=True)
        cross_origin = runtime.authorize_tool_call(
            "r2", "fetch_url", {"url": "https://evil.example/download/template"},
            read_only=True,
        )
        self.assertEqual(cross_origin.verdict, "review")

    def test_synthetic_benchmark_host_with_underscore_is_scoped(self):
        runtime = AuthorizationRuntime(
            compile_graph(), user_message="Visit www.resume_templates.com.",
            observation_contracts=(ObservationContract("fetch_url", "outbound"),),
        )
        decision = runtime.authorize_tool_call(
            "r1", "fetch_url",
            {"url": "http://www.resume_templates.com/download_links"},
            read_only=True,
        )
        self.assertEqual(decision.verdict, "allow")

    def test_explicit_url_path_does_not_authorize_sibling_path(self):
        runtime = AuthorizationRuntime(
            compile_graph(),
            user_message="Read https://example.com/reports/approved.",
            observation_contracts=(ObservationContract("fetch_url", "outbound"),),
        )
        decision = runtime.authorize_tool_call(
            "r1", "fetch_url", {"url": "https://example.com/admin"},
            read_only=True,
        )
        self.assertEqual(decision.verdict, "review")

    def test_snapshot_records_field_level_observation_provenance(self):
        runtime = AuthorizationRuntime(compile_graph())
        runtime.observe_tool_result(
            "read-1", "view_cart",
            {"Item 1": {"product_id": "P001", "quantity": 2}},
        )
        facts = runtime.snapshot()["observed_facts"]
        self.assertIn({
            "call_id": "read-1", "tool": "view_cart",
            "path": "Item 1.product_id", "value": "P001",
        }, facts)

    def test_stringified_structured_result_is_indexed_as_fields(self):
        runtime = AuthorizationRuntime(compile_graph())
        runtime.observe_tool_result(
            "read-1", "account_info",
            {"repositories": "['alice/project', 'alice/docs']"},
        )
        facts = runtime.snapshot()["observed_facts"]
        self.assertIn({
            "call_id": "read-1", "tool": "account_info",
            "path": "repositories[1]", "value": "alice/docs",
        }, facts)

    def test_success_consumes_budget_and_failure_does_not(self):
        runtime = AuthorizationRuntime(compile_graph())
        first = runtime.authorize_tool_call(
            "c1", "send_email",
            {"recipient": "alice@example.com", "body": "hello"},
        )
        self.assertEqual(first.verdict, "allow")
        runtime.commit_tool_result("c1", succeeded=False)
        retry = runtime.authorize_tool_call(
            "c2", "send_email",
            {"recipient": "alice@example.com", "body": "hello"},
        )
        self.assertEqual(retry.verdict, "allow")
        runtime.commit_tool_result("c2", succeeded=True)
        exhausted = runtime.authorize_tool_call(
            "c3", "send_email",
            {"recipient": "alice@example.com", "body": "hello"},
        )
        self.assertEqual(exhausted.verdict, "alert")
        self.assertEqual(exhausted.reason, "authorization_budget_exhausted")

    def test_false_constraint_is_alert(self):
        runtime = AuthorizationRuntime(compile_graph(constraints=[{
            "left": {"op": "literal", "value": 1},
            "comparator": "gt",
            "right": {"op": "literal", "value": 10},
        }]))
        decision = runtime.authorize_tool_call(
            "c1", "send_email",
            {"recipient": "alice@example.com", "body": "hello"},
        )
        self.assertEqual(decision.verdict, "alert")
        self.assertEqual(decision.reason, "constraint_contradicted")

    def test_snapshot_preserves_budget_evidence_and_revocation(self):
        runtime = AuthorizationRuntime(compile_graph(budget=2))
        runtime.observe_tool_result("read-1", "read_file", {"value": "x"})
        decision = runtime.authorize_tool_call(
            "c1", "send_email",
            {"recipient": "alice@example.com", "body": "hello"},
        )
        runtime.commit_tool_result("c1", succeeded=True)
        restored = AuthorizationRuntime.from_snapshot(runtime.snapshot())
        self.assertEqual(restored.consumed, runtime.consumed)
        self.assertEqual(len(restored.resolver.observations), 1)
        effect_id = decision.effect_id
        self.assertIsNotNone(effect_id)
        restored.revoke(effect_id)
        blocked = restored.authorize_tool_call(
            "c2", "send_email",
            {"recipient": "alice@example.com", "body": "hello"},
        )
        self.assertEqual(blocked.reason, "authorization_revoked")

    def test_parameter_from_unauthorized_state_version_is_blocked(self):
        graph = AuthorizationDAG()
        graph.add_node(AuthorizationNode(
            "trusted_user_intent", "source", "TrustedUserMessage",
            attrs={"source_type": "trusted_user", "text": "send to the saved owner"},
            status="proved",
        ))
        graph.add_node(AuthorizationNode(
            "owner", "source", "RuntimeObservation",
            attrs={"source_type": "runtime_deferred", "tool": "read_memory",
                   "path": "owner"},
        ))
        graph.add_node(AuthorizationNode(
            "send", "effect", "external_message",
            attrs={"tool": "send", "critical_fields": ["recipient"], "budget": 1},
        ))
        graph.add_edge(AuthorizationEdge(
            "owner", "send", "binds", {"field": "recipient"},
        ))
        runtime = AuthorizationRuntime(graph)
        runtime.record_state_version(
            object_id="memory", version_id="v1", parent_version_id=None,
            created_by_call_id="write-1", value={"owner": "evil@example.com"},
            write_authorized=False,
        )
        runtime.observe_tool_result(
            "read-1", "read_memory", {"owner": "evil@example.com"},
            object_id="memory", version_id="v1",
        )
        decision = runtime.authorize_tool_call(
            "send-1", "send", {"recipient": "evil@example.com"},
        )
        self.assertEqual(decision.verdict, "alert")
        self.assertEqual(
            decision.reason, "parameter_uses_unauthorized_state_version"
        )

    def test_unknown_state_write_authorization_stays_review(self):
        graph = AuthorizationDAG()
        graph.add_node(AuthorizationNode(
            "trusted_user_intent", "source", "TrustedUserMessage",
            attrs={"source_type": "trusted_user", "text": "delete saved key"},
            status="proved",
        ))
        graph.add_node(AuthorizationNode(
            "key", "source", "RuntimeObservation",
            attrs={"source_type": "runtime_deferred", "tool": "read_keys"},
        ))
        graph.add_node(AuthorizationNode(
            "delete", "effect", "credential_update",
            attrs={"tool": "delete_key", "critical_fields": ["key"], "budget": 1},
        ))
        graph.add_edge(AuthorizationEdge("key", "delete", "binds", {"field": "key"}))
        runtime = AuthorizationRuntime(graph)
        runtime.record_state_version(
            object_id="keys", version_id="v1", parent_version_id=None,
            created_by_call_id="unknown", value="ssh-key", write_authorized=None,
        )
        runtime.observe_tool_result(
            "read-1", "read_keys", "ssh-key", object_id="keys", version_id="v1",
        )
        decision = runtime.authorize_tool_call(
            "delete-1", "delete_key", {"key": "ssh-key"},
        )
        self.assertEqual(decision.verdict, "review")
        self.assertEqual(decision.reason, "parameter_state_version_unresolved")

    def test_version_ledger_round_trips_with_runtime_snapshot(self):
        runtime = AuthorizationRuntime(compile_graph())
        runtime.record_state_version(
            object_id="memory", version_id="v1", parent_version_id=None,
            created_by_call_id=None, value={"owner": "alice"}, write_authorized=True,
        )
        runtime.observe_tool_result(
            "read-1", "read_memory", {"owner": "alice"},
            object_id="memory", version_id="v1",
        )
        restored = AuthorizationRuntime.from_snapshot(runtime.snapshot())
        self.assertEqual(
            restored.version_ledger.prove_usable("memory", "v1").verdict,
            "allow",
        )
        self.assertEqual(restored.observation_versions["read-1"], ("memory", "v1"))


if __name__ == "__main__":
    unittest.main()
