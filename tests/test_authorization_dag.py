import unittest

from greatwallguard import (
    AuthorizationDAG,
    AuthorizationDAGCompiler,
    AuthorizationDAGVerifier,
    AuthorizationEdge,
    AuthorizationNode,
    EffectContract,
    RuntimeRelationResolver,
    proof_core_op,
)


CONTRACTS = (
    EffectContract("reserve_hotel", "reservation", ("hotel", "start_day", "end_day")),
    EffectContract(
        "delete_file", "file_delete", ("file_id",), required_fields=("file_id",),
    ),
)


class AuthorizationDAGTests(unittest.TestCase):
    def test_compiler_emits_only_finite_node_and_edge_kinds(self):
        graph = AuthorizationDAGCompiler(CONTRACTS).compile(
            "If Le Marais Boutique is rated higher than 4, reserve the hotel "
            "from January 11th to January 15th 2025"
        )
        self.assertTrue(graph.is_acyclic())
        self.assertEqual({node.kind for node in graph.nodes.values()},
                         {"source", "constraint", "effect"})
        self.assertLessEqual({edge.kind for edge in graph.edges}, {"binds", "guards"})

    def test_runtime_binding_builds_core_dag_and_allows(self):
        prompt = (
            "If Le Marais Boutique is rated higher than 4, reserve the hotel "
            "from January 11th to January 15th 2025"
        )
        graph = AuthorizationDAGCompiler(CONTRACTS).compile(prompt)
        resolver = RuntimeRelationResolver(prompt)
        resolver.observe("rating", "get_rating", {
            "Le Marais Boutique": "Rating: 4.2\nReviews: good",
        })
        decision, evaluated = AuthorizationDAGVerifier(graph).verify(
            "reserve_hotel",
            {"hotel": "Le Marais Boutique", "start_day": "2025-01-11",
             "end_day": "2025-01-15"},
            resolver,
        )
        self.assertEqual(decision.verdict, "allow")
        self.assertIn("normalize", decision.core_ops)
        constraints = [node for node in evaluated.nodes.values() if node.kind == "constraint"]
        self.assertTrue(constraints)
        self.assertTrue(all(node.status == "proved" for node in constraints))

    def test_unproved_dynamic_value_remains_review(self):
        prompt = "Delete the largest file."
        graph = AuthorizationDAGCompiler(CONTRACTS).compile(prompt)
        decision, _ = AuthorizationDAGVerifier(graph).verify(
            "delete_file", {"file_id": "12"}, RuntimeRelationResolver(prompt)
        )
        self.assertEqual(decision.verdict, "review")

    def test_unknown_effect_is_alert(self):
        graph = AuthorizationDAGCompiler(CONTRACTS).compile("Delete the largest file.")
        decision, _ = AuthorizationDAGVerifier(graph).verify(
            "reserve_hotel", {"hotel": "X"}, RuntimeRelationResolver("Delete the largest file.")
        )
        self.assertEqual(decision.verdict, "alert")

    def test_cycle_is_rejected(self):
        graph = AuthorizationDAG()
        graph.add_node(AuthorizationNode("a", "source", "String"))
        graph.add_node(AuthorizationNode("b", "transform", "String", op="project"))
        graph.add_edge(AuthorizationEdge("a", "b", "data_dep"))
        with self.assertRaises(ValueError):
            graph.add_edge(AuthorizationEdge("b", "a", "data_dep"))

    def test_legacy_rules_lower_to_small_core(self):
        self.assertEqual(proof_core_op("named_object_projection"), "select")
        self.assertEqual(proof_core_op("argmax_group_frequency"), "aggregate")
        self.assertEqual(proof_core_op("deterministic_numeric_computation"), "compute")

    def test_snapshot_round_trip(self):
        original = AuthorizationDAGCompiler(CONTRACTS).compile("Delete the largest file.")
        restored = AuthorizationDAG.from_dict(original.to_dict())
        self.assertEqual(restored.to_dict(), original.to_dict())
        self.assertTrue(restored.is_acyclic())

    def test_missing_required_parameter_is_rejected(self):
        graph = AuthorizationDAGCompiler(CONTRACTS).compile("Delete file 12")
        decision, _ = AuthorizationDAGVerifier(graph).verify(
            "delete_file", {}, RuntimeRelationResolver("Delete file 12")
        )
        self.assertEqual(decision.verdict, "alert")
        self.assertEqual(decision.reason, "required_parameter_missing")

    def test_unknown_read_only_call_requires_review(self):
        graph = AuthorizationDAGCompiler(CONTRACTS).compile("Delete the largest file")
        decision, _ = AuthorizationDAGVerifier(graph).verify(
            "get_webpage", {"url": "https://example.com"},
            RuntimeRelationResolver("Delete the largest file"), read_only=True,
        )
        self.assertEqual(decision.verdict, "review")
        self.assertEqual(decision.reason, "unscoped_observation_requires_review")

    def test_generated_presentation_literal_mismatch_requires_review(self):
        graph = AuthorizationDAG()
        graph.add_node(AuthorizationNode(
            "trusted_user_intent", "source", "TrustedText",
            attrs={"source_type": "trusted_user", "text": "Send the invoice."},
        ))
        graph.add_node(AuthorizationNode(
            "effect:send", "effect", "external_message",
            attrs={"tool": "send_email", "critical_fields": ["subject"]},
        ))
        graph.add_node(AuthorizationNode(
            "binding:subject", "source", "String",
            attrs={"source_type": "trusted_literal", "values": ["Invoice"]},
        ))
        graph.add_edge(AuthorizationEdge(
            "binding:subject", "effect:send", "binds", attrs={"field": "subject"},
        ))
        decision, _ = AuthorizationDAGVerifier(graph).verify(
            "send_email", {"subject": "Your order receipt"},
            RuntimeRelationResolver("Send the invoice."),
        )
        self.assertEqual(decision.verdict, "review")
        self.assertEqual(
            decision.reason, "generated_presentation_literal_requires_review",
        )

    def test_exact_presentation_literal_mismatch_is_alert(self):
        graph = AuthorizationDAG()
        graph.add_node(AuthorizationNode(
            "trusted_user_intent", "source", "TrustedText",
            attrs={"source_type": "trusted_user", "text": "Use subject Invoice."},
        ))
        graph.add_node(AuthorizationNode(
            "effect:send", "effect", "external_message",
            attrs={"tool": "send_email", "critical_fields": ["subject"]},
        ))
        graph.add_node(AuthorizationNode(
            "binding:subject", "source", "String",
            attrs={
                "source_type": "trusted_literal", "values": ["Invoice"],
                "exact_literal": True,
            },
        ))
        graph.add_edge(AuthorizationEdge(
            "binding:subject", "effect:send", "binds", attrs={"field": "subject"},
        ))
        decision, _ = AuthorizationDAGVerifier(graph).verify(
            "send_email", {"subject": "Your order receipt"},
            RuntimeRelationResolver("Use subject Invoice."),
        )
        self.assertEqual(decision.verdict, "alert")
        self.assertEqual(decision.reason, "explicit_parameter_mismatch")


if __name__ == "__main__":
    unittest.main()
