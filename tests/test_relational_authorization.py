import unittest

from greatwallguard import (
    ProofGraph,
    RelationConstraint,
    RelationalGrant,
    RelationalVerifier,
)


DOCUMENT = "file:client-meeting-minutes.docx"
GRANT = RelationalGrant(
    "send-client-summary", "send_email",
    literals={"subject": "Summary of the client meeting"},
    relations=(RelationConstraint(
        "recipients[0]", "associated_with", DOCUMENT, "client"
    ),),
)


class RelationalAuthorizationTests(unittest.TestCase):
    def test_direct_metadata_and_contact_join_both_prove_same_relation(self):
        direct = ProofGraph()
        direct.add("document_role_value", DOCUMENT, "client", "john@example.com",
                   evidence="trusted file metadata")
        via_contact = ProofGraph()
        via_contact.add("document_role_entity", DOCUMENT, "client", "John Mitchell",
                        evidence="typed extraction from document")
        via_contact.add("contact_email", "John Mitchell", "john@example.com",
                        evidence="search_contacts_by_name result")
        call = {"recipients": ["john@example.com"],
                "subject": "Summary of the client meeting"}
        self.assertEqual(RelationalVerifier((GRANT,), direct).check("send_email", call).verdict,
                         "allow")
        self.assertEqual(RelationalVerifier((GRANT,), via_contact).check("send_email", call).verdict,
                         "allow")

    def test_unrelated_source_alerts(self):
        graph = ProofGraph()
        graph.add("value_source", "attacker@example.com", "web:unrelated",
                  evidence="observed tool result to argument flow")
        call = {"recipients": ["attacker@example.com"],
                "subject": "Summary of the client meeting"}
        decision = RelationalVerifier((GRANT,), graph).check("send_email", call)
        self.assertEqual(decision.verdict, "alert")

    def test_same_document_without_role_proof_reviews(self):
        graph = ProofGraph()
        graph.add("value_source", "unknown@example.com", DOCUMENT,
                  evidence="email string observed in document")
        call = {"recipients": ["unknown@example.com"],
                "subject": "Summary of the client meeting"}
        decision = RelationalVerifier((GRANT,), graph).check("send_email", call)
        self.assertEqual(decision.verdict, "review")


if __name__ == "__main__":
    unittest.main()
