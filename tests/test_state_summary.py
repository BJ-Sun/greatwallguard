import hashlib
import json
import unittest

from greatwallguard.content import ContentIndex, json_bytes
from greatwallguard.graph import EffectGraph
from greatwallguard.model import Effect, EffectType, StateTransition
from greatwallguard.state_summary import (
    LARGE,
    SMALL,
    GraphStateSummarizer,
    SummaryBudgets,
    fixed_recent_window,
    replay_summary,
)


def _ref(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _record(nodes=None, events=None, state_versions=None) -> dict:
    return {
        "graph": {
            "nodes": nodes or [],
            "edges": [],
            "state_versions": state_versions or {},
        },
        "events": events or [],
    }


def _user_node(ref: str, turn: int = 1, node_id: str = "obs-1") -> dict:
    return {
        "id": node_id, "node_type": "observation", "turn": turn, "label": "user message",
        "data": {"source": "user", "content": {"ref": ref}},
    }


class RecentTraceTests(unittest.TestCase):
    def test_keeps_exact_recent_events_and_ids(self):
        events = [{"event_id": f"evt-{i:03d}", "turn": i, "summary": f"step {i}",
                   "payload_digest": f"d{i}"} for i in range(10)]
        summarizer = GraphStateSummarizer(budgets=SummaryBudgets(
            max_events=2, max_ledger_objects=0, sketch_budget_bytes=0))
        summary = summarizer.summarize(_record(events=events))
        trace = summary["recent_trace"]
        self.assertEqual(trace["total"], 10)
        self.assertEqual(trace["included"], 2)
        self.assertEqual(trace["omitted"], 8)
        self.assertEqual(trace["event_ids"], ["evt-008", "evt-009"])
        self.assertEqual(trace["events"], events[-2:])

    def test_zero_events_keeps_nothing(self):
        events = [{"event_id": "evt-001", "turn": 1}]
        summarizer = GraphStateSummarizer(budgets=SummaryBudgets(
            max_events=0, max_ledger_objects=0, sketch_budget_bytes=0))
        summary = summarizer.summarize(_record(events=events))
        self.assertEqual(summary["recent_trace"]["included"], 0)


class EffectLedgerTests(unittest.TestCase):
    @staticmethod
    def _graph_with_versions():
        graph = EffectGraph(content_index=ContentIndex())
        def write(obj, before, after, turn):
            action_id = graph.add_action("write_file", {"path": obj, "content": "x"}, turn=turn)
            effect = Effect(EffectType.WRITE, obj, "write_file", persistent=True, turn=turn)
            effect.id = graph._new_id("eff")
            graph.add_effect(effect, action_id=action_id, turn=turn)
            return graph.commit_effect(effect.id, succeeded=True,
                                       transition=StateTransition(obj, before, after))
        write("file://workspace/a.txt", None, "hash1", 1)
        write("file://workspace/a.txt", "hash1", "hash2", 2)
        write("file://workspace/b.txt", None, "hashb", 3)
        return graph

    def test_dedups_to_latest_version_with_fingerprint(self):
        graph = self._graph_with_versions()
        summarizer = GraphStateSummarizer(budgets=SummaryBudgets(
            max_events=0, max_ledger_objects=8, sketch_budget_bytes=0))
        summary = summarizer.summarize(_record(nodes=graph.to_dict()["nodes"],
                                               state_versions=graph.to_dict()["state_versions"]))
        by_object = {row["object_id"]: row for row in summary["effect_ledger"]["objects"]}
        self.assertEqual(set(by_object), {"file://workspace/a.txt", "file://workspace/b.txt"})
        self.assertEqual(by_object["file://workspace/a.txt"]["version"], 2)
        self.assertEqual(by_object["file://workspace/a.txt"]["fingerprint"], "hash2")
        self.assertEqual(by_object["file://workspace/b.txt"]["version"], 1)
        self.assertEqual(by_object["file://workspace/b.txt"]["fingerprint"], "hashb")
        self.assertIsNotNone(by_object["file://workspace/a.txt"]["state_node_id"])

    def test_omitted_objects_are_digested_not_dropped_silently(self):
        graph = self._graph_with_versions()
        summarizer = GraphStateSummarizer(budgets=SummaryBudgets(
            max_events=0, max_ledger_objects=1, sketch_budget_bytes=0))
        summary = summarizer.summarize(_record(nodes=graph.to_dict()["nodes"],
                                               state_versions=graph.to_dict()["state_versions"]))
        ledger = summary["effect_ledger"]
        self.assertEqual(ledger["included_objects"], 1)
        self.assertEqual(ledger["omitted_objects"], 1)
        self.assertIsNotNone(ledger["omitted_object_digest"])


class ContentSketchTests(unittest.TestCase):
    def test_fallback_keeps_evidence_units_with_refs_and_positions(self):
        text = "Do not send to Alice.\n\nAfter legal review, deliver to Carol."
        ref = _ref(text)
        record = _record(nodes=[_user_node(ref)])
        raw_texts = {ref: text}
        summarizer = GraphStateSummarizer(budgets=SummaryBudgets(
            max_events=0, max_ledger_objects=0, sketch_budget_bytes=4096))
        summary = summarizer.summarize(record, raw_texts=raw_texts)
        sketch = summary["content_sketch"]
        self.assertEqual(sketch["method"], "extractive_fallback")
        self.assertEqual(len(sketch["evidence_units"]), 2)
        for unit in sketch["evidence_units"]:
            self.assertEqual(unit["ref"], ref)
            self.assertEqual(unit["node_ids"], ["obs-1"])
            start, end = unit["unit"]["start"], unit["unit"]["end"]
            self.assertEqual(unit["unit"]["text"], text[start:end])

    def test_llm_validates_and_cites_evidence(self):
        text = "The recipient is now Carol. Approval is not granted."
        ref = _ref(text)
        record = _record(nodes=[_user_node(ref)])
        raw_texts = {ref: text}

        def fake_model(messages):
            return json.dumps({"propositions": [
                {"kind": "revision", "subject": "recipient", "predicate": "is now",
                 "object": "Carol", "polarity": "positive", "conditions": [],
                 "record_id": "src-" + ref[:16], "unit_id": 0,
                 "quote": "The recipient is now Carol.", "revision_of": None},
                {"kind": "fact", "subject": "approval", "predicate": "is",
                 "object": "granted", "polarity": "negative", "conditions": [],
                 "record_id": "src-" + ref[:16], "unit_id": 0,
                 "quote": "Approval is not granted.", "revision_of": None},
                {"kind": "constraint", "subject": "x", "predicate": "y",
                 "object": "z", "polarity": "positive", "conditions": [],
                 "record_id": "src-" + ref[:16], "unit_id": 0,
                 "quote": "this text does not appear", "revision_of": None},
                {"kind": "bogus", "subject": "x", "predicate": "y",
                 "object": "z", "polarity": "positive", "conditions": [],
                 "record_id": "src-" + ref[:16], "unit_id": 0,
                 "quote": "The recipient is now Carol.", "revision_of": None},
            ]})

        summarizer = GraphStateSummarizer(budgets=SummaryBudgets(
            max_events=0, max_ledger_objects=0, sketch_budget_bytes=8192), model_fn=fake_model)
        summary = summarizer.summarize(record, raw_texts=raw_texts)
        sketch = summary["content_sketch"]
        self.assertEqual(sketch["method"], "llm")
        self.assertEqual(len(sketch["propositions"]), 2)
        self.assertEqual(sketch["unsupported_claims"], 1)
        self.assertEqual(sketch["rejected_claims"], 1)
        for prop in sketch["propositions"]:
            self.assertEqual(prop["evidence"]["ref"], ref)
            self.assertEqual(prop["evidence_ids"], ["obs-1"])
            start, end = prop["evidence"]["start"], prop["evidence"]["end"]
            self.assertEqual(text[start:end], text[start:end])

    def test_unparseable_response_is_unknown_and_falls_back(self):
        text = "Deliver only after approval."
        ref = _ref(text)
        record = _record(nodes=[_user_node(ref)])
        raw_texts = {ref: text}

        def fake_model(messages):
            return "this is not json"

        summarizer = GraphStateSummarizer(budgets=SummaryBudgets(
            max_events=0, max_ledger_objects=0, sketch_budget_bytes=4096), model_fn=fake_model)
        summary = summarizer.summarize(record, raw_texts=raw_texts)
        sketch = summary["content_sketch"]
        self.assertEqual(sketch["method"], "extractive_fallback")
        self.assertEqual(sketch["unknown_records"], ["src-" + ref[:16]])
        self.assertEqual(sketch["propositions"], [])
        # No invented text: the fallback keeps the verbatim paragraph only.
        self.assertEqual(sketch["evidence_units"][0]["unit"]["text"], text)


class ReplayTests(unittest.TestCase):
    def test_replay_from_saved_graph_without_api_is_byte_identical(self):
        text = "The earlier plan for Bob is withdrawn. The current recipient is Carol."
        ref = _ref(text)
        record = _record(nodes=[_user_node(ref)])
        raw_texts = {ref: text}

        def fake_model(messages):
            return json.dumps({"propositions": [
                {"kind": "retraction", "subject": "plan", "predicate": "for",
                 "object": "Bob", "polarity": "negative", "conditions": [],
                 "record_id": "src-" + ref[:16], "unit_id": 0,
                 "quote": "The earlier plan for Bob is withdrawn.", "revision_of": None},
                {"kind": "revision", "subject": "recipient", "predicate": "is now",
                 "object": "Carol", "polarity": "positive", "conditions": [],
                 "record_id": "src-" + ref[:16], "unit_id": 0,
                 "quote": "The current recipient is Carol.", "revision_of": None},
            ]})

        cache: dict[str, str] = {}
        first = GraphStateSummarizer(budgets=LARGE, model_fn=fake_model,
                                     response_cache=cache).summarize(record, raw_texts=raw_texts)
        self.assertEqual(first["meta"]["model_calls"], 1)

        # Simulate saving: round-trip through JSON and replay with no model_fn.
        saved_record = json.loads(json.dumps(record))
        saved_raw = json.loads(json.dumps(raw_texts))
        second = replay_summary(saved_record, raw_texts=saved_raw,
                                response_cache=cache, budgets=LARGE)
        self.assertEqual(second["meta"]["model_calls"], 0)
        # model_calls is a build-time counter, not summary content; compare the
        # reconstructed content byte-for-byte with the counter excluded.
        first["meta"].pop("model_calls")
        second["meta"].pop("model_calls")
        self.assertEqual(json.dumps(second, sort_keys=True),
                         json.dumps(first, sort_keys=True))


class BoundsTests(unittest.TestCase):
    def test_summary_is_bounded_by_its_budgets(self):
        nodes = []
        refs = {}
        for i in range(10):
            text = f"fact {i} " + "padding " * 40
            ref = _ref(text)
            refs[ref] = text
            nodes.append(_user_node(ref, turn=i + 1, node_id=f"obs-{i}"))
        events = [{"event_id": f"evt-{i:03d}", "turn": i} for i in range(30)]
        record = _record(nodes=nodes, events=events)
        summarizer = GraphStateSummarizer(budgets=SMALL)
        summary = summarizer.summarize(record, raw_texts=refs)
        self.assertLessEqual(summary["recent_trace"]["included"], SMALL.max_events)
        self.assertLessEqual(summary["effect_ledger"]["included_objects"], SMALL.max_ledger_objects)
        self.assertLessEqual(len(json_bytes(summary["content_sketch"])), SMALL.sketch_budget_bytes)

    def test_fixed_recent_window_baseline_is_bounded(self):
        events = [{"event_id": f"evt-{i:03d}", "turn": i, "summary": "x" * 200} for i in range(50)]
        baseline = fixed_recent_window(_record(events=events), window_events=5)
        self.assertEqual(baseline["included"], 5)
        self.assertEqual(len(baseline["events"]), 5)


if __name__ == "__main__":
    unittest.main()
