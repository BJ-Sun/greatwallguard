import unittest

from greatwallguard import (
    ConflictValidation,
    FinalAuthorizationGateway,
    FinalDisposition,
    SafeSubstituteExecutor,
    SemanticAuditResult,
    contract,
)


class FinalGatewayTests(unittest.TestCase):
    def gateway(self):
        return FinalAuthorizationGateway({
            "send_email": contract(
                "send_email", "communication", "create_email_draft",
                "Create a draft without transmitting it.",
            ),
        })

    def test_programmatic_allow_commits_original(self):
        result = self.gateway().resolve(tool="send_email", stage2_verdict="allow")
        self.assertEqual(result.disposition, FinalDisposition.ALLOW_ORIGINAL)

    def test_validated_contradiction_denies(self):
        semantic = SemanticAuditResult(
            "contradicted", "recipient conflicts", ("pending_call",),
            conflict_type="fixed_value_conflict", contradicted_claim="recipient",
            actual_value="bob@example.com", authorized_value_or_constraint="alice@example.com",
        )
        result = self.gateway().resolve(
            tool="send_email", stage2_verdict="review",
            review_type="semantic_unresolved", semantic_result=semantic,
            conflict_validation=ConflictValidation(True, "validated_contradiction"),
        )
        self.assertEqual(result.disposition, FinalDisposition.DENY)

    def test_insufficient_uses_safe_substitute(self):
        semantic = SemanticAuditResult("insufficient", "recipient not proved")
        result = self.gateway().resolve(
            tool="send_email", stage2_verdict="review",
            review_type="semantic_unresolved", semantic_result=semantic,
        )
        self.assertEqual(result.disposition, FinalDisposition.ALLOW_SAFE_SUBSTITUTE)
        self.assertEqual(result.substitute.operation, "create_email_draft")
        self.assertFalse(result.original_effect_committed)

    def test_unknown_effect_is_denied_not_reviewed(self):
        result = self.gateway().resolve(
            tool="unknown_effect", stage2_verdict="review",
            review_type="evidence_missing",
        )
        self.assertEqual(result.disposition, FinalDisposition.DENY)
        self.assertTrue(result.recovery_actions)

    def test_safe_substitute_never_calls_original_executor(self):
        semantic = SemanticAuditResult("insufficient", "recipient not proved")
        decision = self.gateway().resolve(
            tool="send_email", stage2_verdict="review",
            review_type="semantic_unresolved", semantic_result=semantic,
        )
        calls = []
        executor = SafeSubstituteExecutor({
            "create_email_draft": lambda tool, args: calls.append(("draft", tool, args)) or "draft-1",
        })
        result = executor.execute(
            decision,
            original_tool="send_email",
            arguments={"recipients": ["alice@example.com"]},
            original_executor=lambda tool, args: calls.append(("original", tool, args)),
        )
        self.assertFalse(result.original_tool_called)
        self.assertEqual(result.value, "draft-1")
        self.assertEqual(calls[0][0], "draft")


if __name__ == "__main__":
    unittest.main()
