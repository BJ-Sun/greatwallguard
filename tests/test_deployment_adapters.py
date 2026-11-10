import unittest

from greatwallguard import (
    CallableEvidenceResolver,
    JsonProofAuditor,
    JsonTerminalAuditor,
    ProofObligation,
    ProofPacket,
    SemanticProof,
)


def packet():
    return ProofPacket(
        "Send the report to Alice.", "send_email",
        {"tool": "send_email", "arguments": {"recipient": "alice@example.com"}},
        ProofObligation("o1", "parameter_binding", "authorized_binding", "recipient", "alice@example.com", "bound?"),
        (),
    )


class DeploymentAdapterTests(unittest.TestCase):
    def test_json_proof_auditor(self):
        auditor = JsonProofAuditor(lambda _system, _payload: {
            "verdict": "SUPPORTED", "rationale": "literal user binding",
        })
        self.assertEqual(auditor.audit(packet()).verdict, "supported")

    def test_terminal_adapter(self):
        auditor = JsonTerminalAuditor(lambda _system, _payload: {
            "verdict": "DENY", "rationale": "new recipient",
            "authorization_basis": "new_effect", "decisive_refs": ["pending_call"],
        })
        self.assertEqual(
            auditor.adjudicate(packet(), SemanticProof("need_evidence", "missing")).verdict,
            "deny",
        )

    def test_evidence_resolver_rejects_write(self):
        resolver = CallableEvidenceResolver(lambda _query, _packet: "value")
        result = resolver.recover({"operation": "write", "target": "x"}, packet())
        self.assertFalse(result.succeeded)

    def test_evidence_resolver_wraps_read(self):
        resolver = CallableEvidenceResolver(lambda _query, _packet: "alice@example.com")
        result = resolver.recover({"operation": "read", "target": "minutes"}, packet())
        self.assertTrue(result.succeeded)
        self.assertEqual(result.evidence[0].trust, "recovered_runtime_observation")


if __name__ == "__main__":
    unittest.main()
