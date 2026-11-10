import unittest

from greatwallguard import (
    EvidenceItem,
    EvidenceRecoveryResult,
    ProofObligation,
    ProofPacket,
    SemanticProof,
    TerminalAdjudication,
    UnifiedAuthorizationPipeline,
    UnifiedDisposition,
)


def packet():
    return ProofPacket(
        trusted_user_request="Email the address selected from the minutes.",
        authorized_effect="send_email",
        candidate_call={"tool": "send_email", "arguments": {"recipient": "a@example.com"}},
        obligation=ProofObligation("o1", "parameter_binding", "authorized_binding", "recipient", "a@example.com", "bound?"),
        evidence=(),
        authorization_context={"delegations": [{"source": "minutes", "authority": "fields"}]},
    )


class SequenceAuditor:
    def __init__(self, values): self.values = list(values)
    def audit(self, _packet): return self.values.pop(0)


class Resolver:
    def __init__(self, result): self.result = result
    def recover(self, _query, _packet): return self.result


class Terminal:
    def __init__(self, value): self.value = value
    def adjudicate(self, _packet, _proof): return self.value


class UnifiedAuthorizationPipelineTests(unittest.TestCase):
    def test_programmatic_allow_skips_all_other_stages(self):
        pipeline = UnifiedAuthorizationPipeline(
            proof_auditor=SequenceAuditor([]),
            evidence_resolver=Resolver(EvidenceRecoveryResult(False)),
            terminal_auditor=Terminal(None),
        )
        self.assertEqual(pipeline.resolve(stage2_verdict="allow", packet=packet()).disposition, UnifiedDisposition.ALLOW)

    def test_recovers_evidence_and_reaudits_before_terminal(self):
        auditor = SequenceAuditor([
            SemanticProof("need_evidence", "missing", suggested_query={"operation": "read", "target": "minutes"}),
            SemanticProof("supported", "binding found"),
        ])
        pipeline = UnifiedAuthorizationPipeline(
            proof_auditor=auditor,
            evidence_resolver=Resolver(EvidenceRecoveryResult(True, (EvidenceItem("E1", "read_file", {}, "a@example.com"),))),
            terminal_auditor=Terminal(None),
        )
        result = pipeline.resolve(stage2_verdict="review", packet=packet())
        self.assertEqual(result.disposition, UnifiedDisposition.ALLOW)
        self.assertTrue(result.recovery_succeeded)

    def test_unresolved_authority_becomes_confirmation_not_review(self):
        pipeline = UnifiedAuthorizationPipeline(
            proof_auditor=SequenceAuditor([SemanticProof("need_evidence", "authority missing")]),
            evidence_resolver=Resolver(EvidenceRecoveryResult(False)),
            terminal_auditor=Terminal(TerminalAdjudication("deny", "not delegated", "unresolved_authority")),
        )
        self.assertEqual(pipeline.resolve(stage2_verdict="review", packet=packet()).disposition, UnifiedDisposition.CONFIRM)

    def test_validated_conflict_denies_without_terminal_model(self):
        pipeline = UnifiedAuthorizationPipeline(
            proof_auditor=SequenceAuditor([SemanticProof("contradicted", "wrong recipient", conflict_validated=True)]),
            evidence_resolver=Resolver(EvidenceRecoveryResult(False)),
            terminal_auditor=Terminal(None),
        )
        self.assertEqual(pipeline.resolve(stage2_verdict="review", packet=packet()).disposition, UnifiedDisposition.DENY)


if __name__ == "__main__":
    unittest.main()
