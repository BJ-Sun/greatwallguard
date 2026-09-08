import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "experiments"))

from longrun_tasks import FAMILIES, MultiFileFamily, RecoveryFamily, RevisionFamily
from real_process_support import RealFileEnvironment, snapshot
from greatwallguard.agentlab_recorder import AgentLabGraphRecorder
from greatwallguard.content import ContentIndex
from greatwallguard.model import EffectType, TaskScope

from longrun_driver import BudgetTracker, build_corpus, rebuild_recorder, _estimate_input_tokens, _trim_messages


class FamilyScriptTests(unittest.TestCase):
    def test_all_families_have_deterministic_gold(self):
        for name, cls in FAMILIES.items():
            family = cls()
            for turn in (1, 10, 25, 75, 150):
                task = family.task(turn)
                self.assertIsInstance(task, str)
                self.assertTrue(task)
                for q in family.questions(turn):
                    self.assertIn(q["gold"], q["options"], (name, turn, q["id"]))
                    self.assertEqual(len(q["options"]), len(set(q["options"])), (name, turn, q["id"]))

    def test_multifile_required_state_round_trips(self):
        family = MultiFileFamily()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, text in family.required_state(5).items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text, encoding="utf-8")
            outcomes = family.task_outcomes(root, 5)
            self.assertEqual(outcomes["exact_matches"], outcomes["total"])
            self.assertTrue(outcomes["report_contains_total"])
            self.assertTrue(outcomes["report_contains_all_facts"])

    def test_revision_delivery_only_when_approved(self):
        family = RevisionFamily()
        self.assertFalse(family.approved(1))
        self.assertTrue(family.approved(4))
        self.assertFalse(family.approved(6))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, text in family.required_state(4).items():
                (root / name).write_text(text, encoding="utf-8")
            outcomes = family.task_outcomes(root, 4)
            self.assertEqual(outcomes["files"]["delivery.md"]["exists"], True)
            self.assertEqual(outcomes["exact_matches"], outcomes["total"])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, text in family.required_state(6).items():
                (root / name).write_text(text, encoding="utf-8")
            outcomes = family.task_outcomes(root, 6)
            self.assertEqual(outcomes["files"]["delivery.md"]["exists"], False)
            self.assertTrue(outcomes["files"]["delivery.md"]["matches"])

    def test_recovery_multi_object_growth(self):
        family = RecoveryFamily()
        self.assertEqual(family.obj_name(3), "objects/obj_003.txt")
        self.assertEqual(family.obj_content(3), "object 003 count 3")
        self.assertIn("again", family.task(10))
        self.assertIn("second time", family.task(5))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, text in family.required_state(4).items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text, encoding="utf-8")
            outcomes = family.task_outcomes(root, 4)
            self.assertEqual(outcomes["exact_matches"], outcomes["total"])
            self.assertTrue(outcomes["memory_has_count"])
            self.assertTrue(outcomes["memory_has_next_index"])


class ResumeReplayTests(unittest.TestCase):
    def _make_run(self, directory):
        index = ContentIndex()
        recorder = AgentLabGraphRecorder(TaskScope("longrun", "replay", frozenset(EffectType)), content_index=index)
        oracle = {"model_calls": [], "tool_calls": [], "sessions": []}
        env = RealFileEnvironment(directory, recorder, oracle, state_evidence="snapshot")
        env.session = 1
        recorder.begin_session(env, "write then read")
        # model call 1 -> write
        request = {"messages": [{"role": "system", "content": "s"}, {"role": "user", "content": "write then read"}],
                   "tools": []}
        recorder.record_model_boundary(env, phase="input", payload=request, call_id="llm-1")
        response = {"content": "", "tool_calls": [
            {"id": "call_a", "function": {"name": "write_file", "arguments": "{\"path\": \"a.txt\", \"content\": \"x\"}"}}]}
        recorder.record_model_boundary(env, phase="output", payload=response, call_id="llm-1")
        oracle["model_calls"].append({"call_id": "llm-1", "session": 1, "request": request, "response": response})
        env.pending = [{"id": "llm-1:call_a", "function": {"name": "write_file"}}]
        env.execute_tool("write_file", {"path": "a.txt", "content": "x"})
        # model call 2 -> read
        request2 = {"messages": [{"role": "user", "content": "read a.txt"}], "tools": []}
        recorder.record_model_boundary(env, phase="input", payload=request2, call_id="llm-2")
        response2 = {"content": "", "tool_calls": [
            {"id": "call_b", "function": {"name": "read_file", "arguments": "{\"path\": \"a.txt\"}"}}]}
        recorder.record_model_boundary(env, phase="output", payload=response2, call_id="llm-2")
        oracle["model_calls"].append({"call_id": "llm-2", "session": 1, "request": request2, "response": response2})
        env.pending = [{"id": "llm-2:call_b", "function": {"name": "read_file"}}]
        env.execute_tool("read_file", {"path": "a.txt"})
        oracle["sessions"].append({"session": 1, "user": "write then read"})
        return recorder, oracle

    def test_rebuild_matches_original_without_api(self):
        with tempfile.TemporaryDirectory() as directory:
            recorder, oracle = self._make_run(directory)
            original = recorder.graph.to_dict()
            original_index = recorder.graph.content_index.export(include_raw=True)["raw_texts"]
            rebuilt = rebuild_recorder(oracle, state_evidence="snapshot")
            rebuilt_graph = rebuilt.graph.to_dict()
            rebuilt_index = rebuilt.graph.content_index.export(include_raw=True)["raw_texts"]
            self.assertEqual(len(rebuilt_graph["nodes"]), len(original["nodes"]))
            self.assertEqual(len(rebuilt_graph["edges"]), len(original["edges"]))
            self.assertEqual(set(rebuilt_index), set(original_index))
            self.assertEqual(rebuilt.runtime.turn, max(n["turn"] for n in original["nodes"]))

    def test_rebuild_skips_error_sessions_without_calls(self):
        oracle = {
            "model_calls": [],
            "tool_calls": [],
            "sessions": [
                {"session": 1, "user": "ok turn"},
                {"session": 2, "user": "failed turn", "error": "402 Payment Required"},
            ],
        }
        rebuilt = rebuild_recorder(oracle, state_evidence="snapshot")
        self.assertEqual(rebuilt.runtime.turn, 0)
        self.assertEqual(len(rebuilt.sessions), 0)

    def test_build_corpus_deduplicates_by_ref(self):
        index = ContentIndex()
        recorder = AgentLabGraphRecorder(TaskScope("longrun", "corpus", frozenset(EffectType)), content_index=index)
        env = object()
        recorder.begin_session(env, "turn 1: write file x")
        recorder.before_tool_call(env, "write_file", {"path": "a.txt", "content": "same"})
        recorder.after_tool_call(env, "write_file", "ok")
        recorder.before_tool_call(env, "write_file", {"path": "a.txt", "content": "same"})
        recorder.after_tool_call(env, "write_file", "ok")
        graph = recorder.graph.to_dict()
        raw = index.export(include_raw=True)["raw_texts"]
        corpus = build_corpus(graph, raw)
        self.assertEqual(sum(1 for c in corpus if c["text"] == "ok"), 1)
        self.assertEqual(sum(1 for c in corpus if "turn 1" in c["text"]), 1)


class BudgetTests(unittest.TestCase):
    def test_usage_recording_prefers_real_tokens(self):
        tracker = BudgetTracker()
        tracker.begin_request("llm-1")
        payload = {"messages": [{"role": "user", "content": "abcd" * 100}]}
        data = {"choices": [{"message": {"content": "efgh" * 50}}]}
        tracker.record_usage(payload, data, {"prompt_tokens": 500, "completion_tokens": 200}, "deepseek")
        self.assertEqual(tracker.input_tokens, 500)
        self.assertEqual(tracker.output_tokens, 200)
        self.assertTrue(tracker.usage_log[-1]["usage_present"])

    def test_usage_falls_back_to_estimate_and_marks_errors(self):
        tracker = BudgetTracker()
        payload = {"messages": [{"role": "user", "content": "a" * 400}]}
        tracker.begin_request("llm-1")
        tracker.record_usage(payload, {"choices": [{"message": {"content": "b" * 200}}]}, {}, "deepseek")
        self.assertEqual(tracker.input_tokens, _estimate_input_tokens(payload))
        self.assertEqual(tracker.output_tokens, 50)
        tracker.begin_request("llm-2")
        tracker.mark_error(RuntimeError("boom"))
        self.assertEqual(tracker.consecutive_api_errors, 1)
        self.assertFalse(tracker.usage_log[-1]["ok"])

    def test_estimate_input_includes_tools(self):
        payload = {"messages": [{"role": "user", "content": "x"}], "tools": [{"function": {"name": "read_file"}}]}
        self.assertGreater(_estimate_input_tokens(payload), 0)

    def test_trim_messages_keeps_system_and_last_turns(self):
        messages = [{"role": "system", "content": "s"}]
        for turn in range(1, 6):
            messages.append({"role": "user", "content": f"turn {turn}"})
            messages.append({"role": "assistant", "content": f"reply {turn}"})
            messages.append({"role": "tool", "tool_call_id": str(turn), "content": "ok"})
        trimmed = _trim_messages(messages, window_turns=2)
        self.assertEqual(trimmed[0], messages[0])
        self.assertNotIn({"role": "user", "content": "turn 1"}, trimmed)
        self.assertIn({"role": "user", "content": "turn 4"}, trimmed)
        self.assertIn({"role": "user", "content": "turn 5"}, trimmed)
        self.assertEqual(trimmed[-1], messages[-1])


if __name__ == "__main__":
    unittest.main()
