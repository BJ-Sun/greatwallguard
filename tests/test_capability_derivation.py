import unittest

from greatwallguard import (
    AuthorizationDAG, AuthorizationEdge, AuthorizationNode,
    CapabilityLink, CapabilityRule, DAGEvidenceEvaluator,
    RuntimeRelationResolver, ScopedCapabilityDeriver,
)


class CapabilityDerivationTests(unittest.TestCase):
    def _graph(self):
        graph = AuthorizationDAG()
        graph.add_node(AuthorizationNode(
            "product", "source", "RuntimeObservation",
            attrs={"source_type": "runtime_deferred", "tool": "search_product",
                   "path": "product_id"},
        ))
        graph.add_node(AuthorizationNode(
            "purchase", "effect", "purchase",
            attrs={"tool": "checkout", "critical_fields": ["product_ids"]},
        ))
        graph.add_edge(AuthorizationEdge(
            "product", "purchase", "binds", {"field": "product_ids"},
        ))
        return graph

    def test_linked_prerequisite_is_allowed(self):
        graph = self._graph()
        resolver = RuntimeRelationResolver("buy the product")
        resolver.observe("c1", "search_product", {"product_id": "P1"})
        evaluator = DAGEvidenceEvaluator(graph, resolver)
        decision = ScopedCapabilityDeriver(graph, evaluator, (
            CapabilityRule("cart_add", "checkout", (
                CapabilityLink("product_id", "product_ids"),
            )),
        )).derive("cart_add", {"product_id": "P1"})
        self.assertEqual(decision.verdict, "allow")

    def test_wrong_object_is_not_allowed(self):
        graph = self._graph()
        resolver = RuntimeRelationResolver("buy the product")
        resolver.observe("c1", "search_product", {"product_id": "P1"})
        evaluator = DAGEvidenceEvaluator(graph, resolver)
        decision = ScopedCapabilityDeriver(graph, evaluator, (
            CapabilityRule("cart_add", "checkout", (
                CapabilityLink("product_id", "product_ids"),
            )),
        )).derive("cart_add", {"product_id": "P999"})
        self.assertEqual(decision.verdict, "review")

    def test_unlinked_dependency_never_auto_allows(self):
        graph = self._graph()
        evaluator = DAGEvidenceEvaluator(graph, RuntimeRelationResolver("buy"))
        decision = ScopedCapabilityDeriver(graph, evaluator, (
            CapabilityRule("login_form", "checkout"),
        )).derive("login_form", {"url": "shop.example"})
        self.assertEqual(decision.verdict, "review")
