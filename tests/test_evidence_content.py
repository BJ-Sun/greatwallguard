import unittest

from greatwallguard.content import ContentIndex, json_bytes
from greatwallguard.graph import EffectGraph
from greatwallguard.model import EffectType, EdgeType, TaskScope
from greatwallguard.agentlab_recorder import AgentLabGraphRecorder


class EvidenceContentTests(unittest.TestCase):
    def test_index_deduplicates_without_merging_observation_occurrences(self):
        index = ContentIndex()
        graph = EffectGraph(content_index=index)
        a = graph.add_observation("user", "task", raw_payload="Only write a draft.")
        b = graph.add_observation("file", "note", raw_payload="Only write a draft.", turn=2)
        self.assertNotEqual(a, b)
        self.assertEqual(graph.node(a).data["content"], graph.node(b).data["content"])
        self.assertEqual(len(index.records), 1)
        self.assertNotIn("Only write a draft.", str(graph.to_dict()))
        self.assertNotIn("raw_texts", index.export())

    @staticmethod
    def claim(quote):
        return {"kind": "request", "subject": "agent", "predicate": "send",
                "object": "report", "polarity": "positive",
                "conditions": ["after approval"], "quote": quote}

    def test_negation_and_condition_retained_whole_or_explicitly_omitted(self):
        index = ContentIndex()
        ref = index.capture("Send the report only after approval.")["ref"]
        claim = self.claim(index.text(ref))
        result = index.extract(ref, {"claims": [claim]}, method="fixture")
        self.assertEqual(result["claims"][0]["conditions"], ["after approval"])
        span = result["claims"][0]["evidence"]
        self.assertEqual(index.text(ref)[span["start"]:span["end"]], claim["quote"])
        claim["conditions"] = ["条件" * 1000]
        result = index.extract(ref, {"claims": [claim]}, method="fixture", budget_bytes=512)
        self.assertEqual(result["claims"], [])
        self.assertEqual(result["omitted_by_budget"], 1)
        self.assertLessEqual(len(json_bytes(result)), 512)

    def test_unsupported_or_ambiguous_quotes_are_rejected(self):
        index = ContentIndex()
        ref = index.capture("Read. Read.")["ref"]
        result = index.extract(ref, {"claims": [self.claim("not in source"), self.claim("Read.")]}, method="fixture")
        self.assertEqual(result["rejected_claims"], 2)
        self.assertEqual(result["claims"], [])
        self.assertEqual(result["semantic_coverage"], "unmeasured")

    def test_bad_response_is_not_treated_as_empty_complete_extraction(self):
        index = ContentIndex()
        ref = index.capture("A report.")["ref"]
        result = index.extract(ref, {"unexpected": []}, method="fixture")
        self.assertEqual(result["status"], "invalid")
        malformed = self.claim("A report.")
        malformed["kind"] = ["request"]
        result = index.extract(ref, {"claims": [malformed]}, method="fixture")
        self.assertEqual(result["rejected_claims"], 1)

    def test_process_inferences_remain_visible_in_graph_and_projection(self):
        index = ContentIndex()
        recorder = AgentLabGraphRecorder(TaskScope("e", "note", frozenset(EffectType)), content_index=index)
        env = object()
        recorder.begin_session(env, "Write a note, then read it.")
        recorder.before_tool_call(env, "write_file", {"path": "a.md", "content": "note"})
        recorder.after_tool_call(env, "write_file", "ok")
        recorder.before_tool_call(env, "read_file", {"path": "a.md"})
        recorder.after_tool_call(env, "read_file", "note")
        graph = recorder.graph
        for edge in graph.edges:
            self.assertIn("basis", edge.evidence)
            self.assertIn("method", edge.evidence)
        source = next(e for e in graph.edges if e.edge_type is EdgeType.DERIVED_FROM)
        self.assertEqual(source.evidence["method"], "latest_observation_proxy")
        read = next(e for e in graph.edges if e.edge_type is EdgeType.READS)
        self.assertFalse(read.evidence["version_verified"])
        update = next(e for e in graph.edges if e.edge_type is EdgeType.UPDATES)
        self.assertEqual(update.evidence["basis"], "reported")
        projected = graph.project_minimal()
        consume = next(e for e in projected["edges"] if e["relation"] == "consume")
        self.assertEqual(consume["data"]["evidence"]["basis"], "inferred")
        self.assertGreater(len(index.records), 0)


if __name__ == "__main__":
    unittest.main()
