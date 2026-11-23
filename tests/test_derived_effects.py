import unittest

from greatwallguard import (
    AuthorizationDAG, AuthorizationNode, BoundedDerivedEffectPolicy,
)


class BoundedDerivedEffectTests(unittest.TestCase):
    def _graph(self):
        graph = AuthorizationDAG()
        graph.add_node(AuthorizationNode(
            "parent", "effect", "report",
            attrs={"tool": "deliver_report"}, status="proved",
        ))
        return graph

    def test_new_task_artifact_requires_derivation_proof(self):
        decision = BoundedDerivedEffectPolicy().derive(
            "create_file", {"filename": "handoff.md", "content": "ok"},
            self._graph(),
        )
        self.assertEqual(decision.verdict, "review")
        self.assertEqual(decision.reason, "bounded_derived_effect_requires_proof")
        self.assertIn("parent_effect_link", decision.missing_evidence)

    def test_agent_control_state_cannot_inherit_parent_authority(self):
        decision = BoundedDerivedEffectPolicy().derive(
            "workspace_state_change",
            {"path": "MEMORY.md", "operation": "update"}, self._graph(),
        )
        self.assertEqual(decision.verdict, "alert")
        self.assertEqual(
            decision.reason,
            "protected_persistent_object_requires_explicit_authorization",
        )

    def test_unrelated_effect_is_not_claimed(self):
        self.assertIsNone(BoundedDerivedEffectPolicy().derive(
            "send_email", {"recipients": ["a@example.com"]}, self._graph(),
        ))


if __name__ == "__main__":
    unittest.main()
