import unittest

from greatwallguard import (
    AuthorizationDAG, AuthorizationEdge, AuthorizationNode,
    DAGEvidenceEvaluator, RuntimeRelationResolver,
)


class DAGEvidenceEvaluatorTests(unittest.TestCase):
    def test_projects_parameter_from_runtime_result(self):
        graph = AuthorizationDAG()
        graph.add_node(AuthorizationNode(
            "source", "source", "RuntimeObservation",
            attrs={"source_type": "runtime_deferred", "tool": "orders",
                   "path": "product_id"},
        ))
        graph.add_node(AuthorizationNode(
            "project", "transform", "SymbolicValue", op="project",
            attrs={"field": "product_id"},
        ))
        graph.add_edge(AuthorizationEdge("source", "project", "data_dep"))
        resolver = RuntimeRelationResolver("rebuy the product")
        resolver.observe("c1", "orders", {"Order 1": {"product_id": "P030"}})
        proof = DAGEvidenceEvaluator(graph, resolver).prove_binding("project", ["P030"])
        self.assertIsNotNone(proof)
        self.assertEqual(proof.source_call_ids, ("c1",))
        self.assertEqual(proof.evidence_paths, ("c1:Order 1.product_id",))

    def test_source_capability_alias_tolerates_equivalent_read_tool(self):
        graph = AuthorizationDAG()
        graph.add_node(AuthorizationNode(
            "source", "source", "RuntimeObservation",
            attrs={"source_type": "runtime_deferred", "tool": "search_emails",
                   "path": "sender"},
        ))
        resolver = RuntimeRelationResolver("reply to the sender")
        resolver.observe("c1", "get_received_emails", [{"sender": "alice@example.com"}])
        no_alias = DAGEvidenceEvaluator(graph, resolver).prove_binding(
            "source", ["alice@example.com"]
        )
        with_alias = DAGEvidenceEvaluator(
            graph, resolver,
            source_aliases={"search_emails": {"get_received_emails"}},
        ).prove_binding("source", ["alice@example.com"])
        self.assertIsNone(no_alias)
        self.assertIsNotNone(with_alias)

    def test_literal_path_binding_proves_descendant_but_not_sibling(self):
        graph = AuthorizationDAG()
        graph.add_node(AuthorizationNode(
            "path", "source", "Literal",
            attrs={"source_type": "trusted_literal",
                   "values": ["/workspace/project"]}, status="proved",
        ))
        graph.add_node(AuthorizationNode(
            "effect", "effect", "repository_update",
            attrs={"tool": "push", "critical_fields": ["local_path"]},
        ))
        graph.add_edge(AuthorizationEdge(
            "path", "effect", "binds", {"field": "local_path"},
        ))
        evaluator = DAGEvidenceEvaluator(
            graph, RuntimeRelationResolver("sync /workspace/project")
        )
        self.assertIsNotNone(
            evaluator.prove_binding("path", "/workspace/project/docs")
        )
        self.assertIsNone(
            evaluator.prove_binding("path", "/workspace/other")
        )

    def test_does_not_prove_value_absent_from_evidence(self):
        graph = AuthorizationDAG()
        graph.add_node(AuthorizationNode(
            "source", "source", "RuntimeObservation",
            attrs={"source_type": "runtime_deferred", "tool": "orders",
                   "path": "product_id"},
        ))
        resolver = RuntimeRelationResolver("rebuy the product")
        resolver.observe("c1", "orders", {"product_id": "P030"})
        self.assertIsNone(
            DAGEvidenceEvaluator(graph, resolver).prove_binding("source", ["P999"])
        )

    def test_array_path_syntax_is_evaluated(self):
        graph = AuthorizationDAG()
        graph.add_node(AuthorizationNode(
            "source", "source", "RuntimeObservation",
            attrs={"source_type": "runtime_deferred", "tool": "view_cart",
                   "path": "items[].product_id"},
        ))
        resolver = RuntimeRelationResolver("checkout the remaining item")
        resolver.observe("c1", "view_cart", {
            "items": [{"product_id": "P1"}, {"product_id": "P2"}],
        })
        self.assertIsNotNone(
            DAGEvidenceEvaluator(graph, resolver).prove_binding("source", ["P2"])
        )

    def test_select_without_predicate_is_conservative_projection(self):
        graph = AuthorizationDAG()
        graph.add_node(AuthorizationNode(
            "source", "source", "RuntimeObservation",
            attrs={"source_type": "runtime_deferred", "tool": "search",
                   "path": None},
        ))
        graph.add_node(AuthorizationNode(
            "selected", "transform", "SymbolicValue", op="select",
            attrs={"field": "product_id"},
        ))
        graph.add_edge(AuthorizationEdge("source", "selected", "data_dep"))
        resolver = RuntimeRelationResolver("buy a product")
        resolver.observe("c1", "search", [{"product_id": "P1"}])
        self.assertIsNotNone(
            DAGEvidenceEvaluator(graph, resolver).prove_binding("selected", ["P1"])
        )

    def test_count_aggregate_executes_count_not_value_membership(self):
        graph = AuthorizationDAG()
        graph.add_node(AuthorizationNode(
            "source", "source", "RuntimeObservation",
            attrs={"source_type": "runtime_deferred", "tool": "list_items"},
        ))
        graph.add_node(AuthorizationNode(
            "count", "transform", "Number", op="aggregate",
            attrs={"field": "id", "function": "count"},
        ))
        graph.add_edge(AuthorizationEdge("source", "count", "data_dep"))
        resolver = RuntimeRelationResolver("count items")
        resolver.observe("c1", "list_items", [{"id": 5}, {"id": 9}])
        evaluator = DAGEvidenceEvaluator(graph, resolver)
        self.assertIsNotNone(evaluator.prove_binding("count", [2]))
        self.assertIsNone(evaluator.prove_binding("count", [5]))

    def test_unimplemented_transform_never_proves_by_identity(self):
        graph = AuthorizationDAG()
        graph.add_node(AuthorizationNode(
            "source", "source", "RuntimeObservation",
            attrs={"source_type": "runtime_deferred", "tool": "read"},
        ))
        graph.add_node(AuthorizationNode(
            "computed", "transform", "Number", op="compute",
            attrs={"expression": "x + 1"},
        ))
        graph.add_edge(AuthorizationEdge("source", "computed", "data_dep"))
        resolver = RuntimeRelationResolver("compute")
        resolver.observe("c1", "read", {"x": 1})
        self.assertIsNone(
            DAGEvidenceEvaluator(graph, resolver).prove_binding("computed", [1])
        )

    def test_typed_compute_and_template_are_replayed(self):
        graph = AuthorizationDAG()
        graph.add_node(AuthorizationNode(
            "number", "source", "Literal",
            attrs={"source_type": "trusted_literal", "values": [2]}, status="proved",
        ))
        graph.add_node(AuthorizationNode(
            "computed", "transform", "Number", op="compute",
            attrs={"expression": "x + 3"},
        ))
        graph.add_edge(AuthorizationEdge("number", "computed", "data_dep"))
        graph.add_node(AuthorizationNode(
            "templated", "transform", "String", op="template",
            attrs={"format": "total={0}"},
        ))
        graph.add_edge(AuthorizationEdge("computed", "templated", "data_dep"))
        evaluator = DAGEvidenceEvaluator(graph, RuntimeRelationResolver("compute"))
        self.assertIsNotNone(evaluator.prove_binding("computed", 5))
        self.assertIsNotNone(evaluator.prove_binding("templated", "total=5.0"))

    def test_typed_join_requires_matching_keys(self):
        graph = AuthorizationDAG()
        for node_id, values in (
            ("left", [{"id": "1", "name": "Alice"}]),
            ("right", [{"owner_id": "1", "email": "alice@example.com"}]),
        ):
            graph.add_node(AuthorizationNode(
                node_id, "source", "Literal",
                attrs={"source_type": "trusted_literal", "values": values},
                status="proved",
            ))
        graph.add_node(AuthorizationNode(
            "joined", "transform", "Rows", op="join",
            attrs={"left_key": "id", "right_key": "owner_id"},
        ))
        graph.add_edge(AuthorizationEdge("left", "joined", "data_dep"))
        graph.add_edge(AuthorizationEdge("right", "joined", "data_dep"))
        evaluator = DAGEvidenceEvaluator(graph, RuntimeRelationResolver("join"))
        self.assertIsNotNone(evaluator.prove_binding(
            "joined", "alice@example.com"
        ))
