import unittest

from greatwallguard import BehaviorGraphRelationAdapter, EffectGraph
from greatwallguard.content import ContentIndex
from greatwallguard.model import EdgeType


class BehaviorGraphRelationAdapterTests(unittest.TestCase):
    def test_file_result_produces_role_and_source_facts(self):
        graph = EffectGraph(content_index=ContentIndex())
        action = graph.add_action(
            "search_files_by_filename", {"filename": "minutes.docx"}, turn=1
        )
        result = graph.add_observation(
            "tool_result", "file search result", turn=1,
            raw_payload=[{
                "id_": "19", "filename": "minutes.docx",
                "content": "Attendees from client: John Mitchell\n",
                "shared_with": {"john.mitchell@gmail.com": "rw"},
            }],
        )
        graph._edge(action, result, EdgeType.RETURNS, 1,
                    evidence={"basis": "observed", "method": "tool_call_id"})
        proof = BehaviorGraphRelationAdapter(graph).build()
        proof.derive(())
        self.assertIsNotNone(proof.find(
            "document_role_value", "file:minutes.docx", "client",
            "john.mitchell@gmail.com",
            admissible_only=False,
        ))
        self.assertIsNone(proof.find(
            "document_role_value", "file:minutes.docx", "client",
            "john.mitchell@gmail.com",
        ))
        self.assertIsNotNone(proof.find(
            "value_source", "john.mitchell@gmail.com", "file:minutes.docx"
        ))


if __name__ == "__main__":
    unittest.main()
