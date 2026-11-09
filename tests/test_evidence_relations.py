import unittest

from greatwallguard import SourceRef, relation_from_rows


class EvidenceRelationTests(unittest.TestCase):
    def test_typed_relations_join_without_plan_order(self):
        documents = relation_from_rows(
            SourceRef("read-1", "read_document", "document_role", {"file": "minutes"}),
            [{"document": "minutes", "role": "client", "person": "John"}],
        )
        contacts = relation_from_rows(
            SourceRef("search-2", "search_contacts", "contact", {"name": "John"}),
            [{"name": "John", "email": "john@example.com"}],
        )
        joined = documents.join(
            contacts, left_key="person", right_key="name",
            left_prefix="document", right_prefix="contact",
        ).filter_eq("document.role", "client")
        self.assertEqual(joined.project_unique("contact.email"), "john@example.com")
        self.assertEqual({source.call_id for source in joined.sources}, {"read-1", "search-2"})

    def test_non_unique_projection_is_not_a_proof(self):
        contacts = relation_from_rows(
            SourceRef("search", "search_contacts", "contact", {}),
            [
                {"name": "John", "email": "one@example.com"},
                {"name": "John", "email": "two@example.com"},
            ],
        )
        self.assertIsNone(contacts.filter_eq("name", "John").project_unique("email"))


if __name__ == "__main__":
    unittest.main()
