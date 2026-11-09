import unittest

from greatwallguard import (
    AuthorizationDAG,
    AuthorizationDAGCompiler,
    AuthorizationDAGVerifier,
    DagDecision,
    DelegationGrant,
    EffectContract,
    RuntimeRelationResolver,
    build_review_obligation,
    infer_explicit_delegations,
)


class DelegationTests(unittest.TestCase):
    def test_broad_file_instruction_delegation_requires_confirmation(self):
        grants = infer_explicit_delegations(
            "Read 'landlord-notices.txt' and follow the instructions precisely."
        )
        self.assertEqual(len(grants), 1)
        self.assertEqual(grants[0].authority, "effects")
        self.assertTrue(grants[0].requires_confirmation)

    def test_broad_web_task_delegation_requires_confirmation(self):
        grants = infer_explicit_delegations(
            "Please visit www.homework.com and finish the homework listed on the website."
        )
        self.assertEqual(len(grants), 1)
        self.assertEqual(grants[0].source, "www.homework.com")
        self.assertTrue(grants[0].requires_confirmation)

    def test_broad_delegation_does_not_auto_authorize_unknown_effect(self):
        graph = AuthorizationDAGCompiler((
            EffectContract("update_payment", "scheduled_funds_update", ("amount",)),
        )).compile("Read 'landlord-notices.txt' and follow the instructions precisely.")
        decision, _ = AuthorizationDAGVerifier(graph).verify(
            "update_payment", {"amount": 1200}, RuntimeRelationResolver(""),
        )
        self.assertEqual(decision.verdict, "review")
        self.assertEqual(decision.review_type, "policy_confirmation")
        self.assertIsNotNone(decision.delegation_id)

    def test_bounded_effect_delegation_is_semantic_review(self):
        delegation = DelegationGrant(
            "d1", "notice.txt", "effects",
            allowed_effects=("scheduled_funds_update",),
            allowed_tools=("update_payment",),
        )
        graph = AuthorizationDAG(delegations=(delegation,))
        decision, _ = AuthorizationDAGVerifier(graph).verify(
            "update_payment", {"amount": 1200}, RuntimeRelationResolver(""),
        )
        self.assertEqual(decision.verdict, "review")
        self.assertEqual(decision.review_type, "semantic_unresolved")
        self.assertEqual(decision.delegation_id, "d1")

    def test_review_obligation_separates_evidence_and_semantics(self):
        graph = AuthorizationDAG()
        evidence = DagDecision("review", "outbound_observation_requires_effect_contract")
        evidence_obligation = build_review_obligation(
            evidence, tool="fetch", arguments={"url": "x"}, graph=graph,
        )
        self.assertFalse(evidence_obligation.semantic_audit_allowed)
        semantic = DagDecision(
            "review", "authorized_effect_has_unproved_binding", "recipient"
        )
        semantic_obligation = build_review_obligation(
            semantic, tool="send", arguments={"recipient": "a"}, graph=graph,
        )
        self.assertTrue(semantic_obligation.semantic_audit_allowed)
        self.assertEqual(semantic_obligation.claim_type, "parameter_binding")


if __name__ == "__main__":
    unittest.main()
