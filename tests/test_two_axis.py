import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "experiments"))
from real_process_support import RealFileEnvironment, evaluate_process
from greatwallguard.agentlab_recorder import AgentLabGraphRecorder
from greatwallguard.content import ContentIndex, json_bytes
from greatwallguard.extractive import paragraph_units, pack_selection
from greatwallguard.model import EffectType, TaskScope


class TwoAxisTests(unittest.TestCase):
    def test_extract_preserves_revision_and_negation_in_original_order(self):
        text = "Earlier request is withdrawn. Do not send anything.\n\nAfter approval, write only a draft."
        units = paragraph_units(text)
        result = pack_selection(text, ref="fixture", candidates={"selected_ids": [1, 0, 999, True]}, budget_bytes=2048)
        self.assertEqual([u["text"] for u in result["units"]], [u["text"] for u in units])
        self.assertEqual(result["rejected_ids"], 2)
        for unit in result["units"]:
            self.assertEqual(unit["text"], text[unit["start"]:unit["end"]])

    def test_oversize_unit_is_flagged_not_cut_before_its_exception(self):
        text = "background " * 100 + "Never send without approval."
        result = pack_selection(text, ref="fixture", candidates={"selected_ids": [0]}, budget_bytes=512)
        self.assertEqual(result["units"], [])
        self.assertEqual(result["omitted_by_budget"], 1)
        self.assertLessEqual(len(json_bytes(result)), 512)

    def test_model_context_association_survives_two_tool_calls(self):
        recorder = AgentLabGraphRecorder(TaskScope("a", "read", frozenset(EffectType)))
        env = object()
        recorder.begin_session(env, "read two files")
        inp = recorder.record_model_boundary(env, phase="input", payload={"messages": [], "tools": []}, call_id="m1")
        out = recorder.record_model_boundary(env, phase="output", payload={"tool_calls": []}, call_id="m1")
        for cid in ("t1", "t2"):
            act = recorder.before_tool_call(env, "read_file", {"path": cid}, call_id=cid)
            recorder.after_tool_call(env, "read_file", "contents")
            sources = [e.source for e in recorder.graph.edges if e.target == act and e.edge_type.value == "derived_from"]
            self.assertEqual(sources, [inp, out])
        recorder.begin_session(env, "new context")
        self.assertNotIn(inp, recorder._source_ids(env))

    def test_disk_oracle_detects_noop_state_and_missing_graph_event(self):
        index = ContentIndex()
        recorder = AgentLabGraphRecorder(TaskScope("a", "files", frozenset(EffectType)), content_index=index)
        oracle = {"model_calls": [], "tool_calls": []}
        with tempfile.TemporaryDirectory() as directory:
            env = RealFileEnvironment(directory, recorder, oracle)
            recorder.begin_session(env, "write twice and read")
            calls = [("write_file", {"path": "note.md", "content": "x"}),
                     ("write_file", {"path": "note.md", "content": "x"}),
                     ("read_file", {"path": "note.md"}),
                     ("read_file", {"path": "missing.md"})]
            for i, (tool, args) in enumerate(calls):
                env.pending = [{"id": str(i), "function": {"name": tool}}]
                env.execute_tool(tool, args)
            graph = recorder.graph.to_dict()
            raw = index.export(include_raw=True)["raw_texts"]
            metrics = evaluate_process(graph, raw, oracle)
            self.assertEqual(metrics["tool_calls"]["matched"], 4)
            self.assertEqual(metrics["content_state_transitions"]["expected"], 1)
            self.assertEqual(metrics["content_state_transitions"]["recorded"], 2)
            self.assertEqual(metrics["content_state_transitions"]["precision"], 0.5)
            self.assertEqual(metrics["state_reads"]["matched"], 0)
            self.assertEqual(metrics["tool_failures"], 1)
            damaged = copy.deepcopy(graph)
            action = next(n for n in damaged["nodes"] if n["node_type"] == "action")
            action["data"]["call_id"] = "missing"
            metrics = evaluate_process(damaged, raw, oracle)
            self.assertEqual(metrics["tool_calls"]["matched"], 3)

    def test_snapshot_mode_preserves_effect_but_not_spurious_version(self):
        index = ContentIndex()
        recorder = AgentLabGraphRecorder(TaskScope("a", "files", frozenset(EffectType)), content_index=index)
        oracle = {"model_calls": [], "tool_calls": []}
        with tempfile.TemporaryDirectory() as directory:
            env = RealFileEnvironment(directory, recorder, oracle, state_evidence="snapshot")
            recorder.begin_session(env, "write and read")
            for i, name in enumerate(("write_file", "write_file", "read_file")):
                env.pending = [{"id": str(i), "function": {"name": name}}]
                args = {"path": "note.md", **({"content": "x"} if name == "write_file" else {})}
                env.execute_tool(name, args)
            metrics = evaluate_process(recorder.graph.to_dict(), index.export(include_raw=True)["raw_texts"], oracle)
            self.assertEqual(metrics["tool_effects"]["matched"], 3)
            self.assertEqual(metrics["content_state_transitions"]["precision"], 1.0)
            self.assertEqual(metrics["content_state_transitions"]["recorded"], 1)
            self.assertEqual(metrics["state_reads"]["matched"], 1)
            edge = next(e for e in recorder.graph.edges if e.edge_type.value == "reads")
            self.assertTrue(edge.evidence["version_verified"])
            # An out-of-band change must not be attributed to the old version.
            Path(directory, "note.md").write_text("externally changed")
            env.pending = [{"id": "external", "function": {"name": "read_file"}}]
            env.execute_tool("read_file", {"path": "note.md"})
            obs = next(n for n in recorder.graph.nodes.values() if n.data.get("call_id") == "external" and n.node_type.value == "observation")
            self.assertEqual(obs.data["state_match"], "fingerprint_mismatch")
            self.assertFalse(any(e.target == obs.id and e.edge_type.value == "reads" for e in recorder.graph.edges))


if __name__ == "__main__":
    unittest.main()
