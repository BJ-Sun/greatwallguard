import json
import unittest

from greatwallguard import (
    HybridRelationalGuard,
    JsonSemanticAuditor,
    ProofGraph,
    RelationConstraint,
    RelationalGrant,
)


class SemanticAuditTests(unittest.TestCase):
    def grant(self):
        return RelationalGrant(
            "g1", "send_email", {},
            (RelationConstraint("recipients[0]", "associated_with",
                                "file:minutes.docx", "client"),),
        )

    def graph(self):
        graph = ProofGraph()
        graph.add("document_role_value", "file:minutes.docx", "client",
                  "john@example.com", evidence="candidate:line-1", basis="candidate")
        graph.add("value_source", "john@example.com", "file:minutes.docx",
                  evidence="observed:shared-with")
        return graph

    def test_verified_promotes_relation_and_allows(self):
        auditor = JsonSemanticAuditor(lambda _: json.dumps({
            "verdict": "verified", "rationale": "explicit role",
            "evidence_refs": ["candidate:line-1"],
        }))
        guard = HybridRelationalGuard((self.grant(),), self.graph(), auditor)
        result = guard.check("Send the summary to the client", "send_email", {
            "recipients": ["john@example.com"]
        })
        self.assertEqual(result.verdict, "allow")
        self.assertIsNotNone(guard.last_request)

    def test_insufficient_stays_review(self):
        auditor = JsonSemanticAuditor(lambda _: json.dumps({
            "verdict": "insufficient", "rationale": "role is not established",
            "evidence_refs": [],
        }))
        guard = HybridRelationalGuard((self.grant(),), self.graph(), auditor)
        result = guard.check("Send the summary to the client", "send_email", {
            "recipients": ["john@example.com"]
        })
        self.assertEqual(result.verdict, "review")
        self.assertEqual(result.reason, "semantic_evidence_insufficient")

    def test_contradiction_alerts(self):
        auditor = JsonSemanticAuditor(lambda _: json.dumps({
            "verdict": "contradicted", "rationale": "explicitly not the client",
            "evidence_refs": ["candidate:line-1"],
            "conflict_type": "fixed_value_conflict",
            "contradicted_claim": "the authorized client is mary@example.com",
            "actual_value": "john@example.com",
            "authorized_value_or_constraint": "mary@example.com",
            "operator": None,
        }))
        guard = HybridRelationalGuard((self.grant(),), self.graph(), auditor)
        result = guard.check("Send the summary to the client", "send_email", {
            "recipients": ["john@example.com"]
        })
        self.assertEqual(result.verdict, "alert")

    def test_unproved_contradiction_is_downgraded_to_review(self):
        auditor = JsonSemanticAuditor(lambda _: json.dumps({
            "verdict": "contradicted",
            "rationale": "the user did not specify this exact value",
            "evidence_refs": [],
            "conflict_type": None,
            "contradicted_claim": None,
            "actual_value": "john@example.com",
            "authorized_value_or_constraint": None,
            "operator": None,
        }))
        guard = HybridRelationalGuard((self.grant(),), self.graph(), auditor)
        result = guard.check("Send the summary to the client", "send_email", {
            "recipients": ["john@example.com"]
        })
        self.assertEqual(result.verdict, "review")
        self.assertEqual(result.reason, "semantic_contradiction_unverified")

    def test_satisfied_constraint_cannot_be_reported_as_contradiction(self):
        auditor = JsonSemanticAuditor(lambda _: json.dumps({
            "verdict": "contradicted", "rationale": "claimed time conflict",
            "evidence_refs": ["candidate:line-1"],
            "conflict_type": "constraint_violation",
            "contradicted_claim": "dinner must be after the meeting",
            "actual_value": 18,
            "authorized_value_or_constraint": 16,
            "operator": "gt",
        }))
        guard = HybridRelationalGuard((self.grant(),), self.graph(), auditor)
        result = guard.check("Send the summary to the client", "send_email", {
            "recipients": ["john@example.com"]
        })
        self.assertEqual(result.verdict, "review")

    def test_clear_source_conflict_does_not_call_auditor(self):
        graph = ProofGraph()
        graph.add("value_source", "mark@example.com", "web:unrelated",
                  evidence="observed:web")
        called = []
        auditor = JsonSemanticAuditor(lambda prompt: called.append(prompt) or "{}")
        guard = HybridRelationalGuard((self.grant(),), graph, auditor)
        result = guard.check("Send the summary to the client", "send_email", {
            "recipients": ["mark@example.com"]
        })
        self.assertEqual(result.verdict, "alert")
        self.assertEqual(called, [])


if __name__ == "__main__":
    unittest.main()
