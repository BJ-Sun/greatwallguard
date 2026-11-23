import unittest

from greatwallguard import (
    AuthorizationDAG,
    AuthorizationNode,
    AuthorizationRuntime,
    ConstrainedIntentDAGCompiler,
    DagDecision,
    EffectContract,
    ObservationTool,
    PersistentStateMonitor,
)


class StaticBackend:
    def __init__(self, value):
        self.value = value

    def generate(self, **_kwargs):
        return self.value


class PartialCompilationTests(unittest.TestCase):
    def test_omitted_explicit_effect_becomes_review_only_grant(self):
        compiler = ConstrainedIntentDAGCompiler(
            (EffectContract(
                "send_email", "external_message", ("recipients",), ("recipients",),
            ),),
            (), StaticBackend({
                "schema": "authorization_ir_v1",
                "review_reasons": [], "delegations": [], "grants": [],
            }),
            allow_partial=True,
        )
        graph = compiler.compile("Send an email to alice@example.com")
        runtime = AuthorizationRuntime(graph)
        decision = runtime.authorize_tool_call(
            "c1", "send_email", {"recipients": ["alice@example.com"]},
        )
        self.assertEqual(decision.verdict, "review")
        self.assertEqual(decision.reason, "compiler_binding_unresolved")
        intent = graph.nodes["trusted_user_intent"]
        self.assertEqual(
            intent.attrs["compiler_diagnostics"][0]["code"],
            "missing_explicit_effect",
        )

    def test_unknown_delegation_tool_is_removed_not_granted(self):
        compiler = ConstrainedIntentDAGCompiler(
            (EffectContract("send_email", "external_message", ("recipients",)),),
            (ObservationTool("search_contacts"),), StaticBackend({
                "schema": "authorization_ir_v1", "review_reasons": [],
                "delegations": [{
                    "delegation_id": "d1", "source": "the file",
                    "authority": "effects", "allowed_fields": [],
                    "allowed_effects": [], "allowed_tools": ["invented_tool"],
                    "constraints": {}, "requires_confirmation": False,
                }],
                "grants": [],
            }), allow_partial=True,
        )
        graph = compiler.compile("Do the tasks in the file")
        self.assertNotIn("invented_tool", graph.delegations[0].allowed_tools)
        self.assertTrue(graph.delegations[0].requires_confirmation)


class PersistentStateMonitorTests(unittest.TestCase):
    def test_write_decision_is_preserved_in_version_lineage(self):
        graph = AuthorizationDAG()
        graph.add_node(AuthorizationNode(
            "trusted_user_intent", "source", "TrustedUserMessage",
            attrs={"source_type": "trusted_user", "text": "read saved owner"},
            status="proved",
        ))
        runtime = AuthorizationRuntime(graph)
        monitor = PersistentStateMonitor(runtime)
        monitor.record_change(
            object_id="MEMORY.md", before_version_id="v0",
            after_version_id="v1", created_by_call_id="write-1",
            value={"owner": "evil@example.com"},
            decision=DagDecision("alert", "effect_not_authorized"),
        )
        proof = runtime.version_ledger.prove_usable("MEMORY.md", "v1")
        self.assertEqual(proof.verdict, "alert")
        self.assertEqual(proof.reason, "unauthorized_version_in_lineage")

    def test_unknown_write_stays_review_after_read(self):
        graph = AuthorizationDAG()
        graph.add_node(AuthorizationNode(
            "trusted_user_intent", "source", "TrustedUserMessage",
            attrs={"source_type": "trusted_user", "text": "read memory"},
            status="proved",
        ))
        runtime = AuthorizationRuntime(graph)
        monitor = PersistentStateMonitor(runtime)
        monitor.record_change(
            object_id="MEMORY.md", before_version_id="v0",
            after_version_id="v1", created_by_call_id="write-1", value={},
            decision=DagDecision("review", "compiler_binding_unresolved"),
        )
        monitor.record_read(
            call_id="read-1", tool="workspace_state_read",
            object_id="MEMORY.md", version_id="v1", value={},
        )
        self.assertEqual(
            runtime.version_ledger.prove_usable("MEMORY.md", "v1").verdict,
            "review",
        )
        self.assertEqual(
            runtime.observation_versions["read-1"], ("MEMORY.md", "v1"),
        )


if __name__ == "__main__":
    unittest.main()
