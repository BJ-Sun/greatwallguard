"""Offline integrity checks for the curated no-injection control dataset."""

from __future__ import annotations

import json
import unittest
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "dataset" / "benign-controls"


class BenignControlDatasetTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.plan = {x["control_id"]: x for x in cls.read_jsonl(BASE / "plan.jsonl")}
        cls.index = cls.read_jsonl(BASE / "index.jsonl")
        cls.alignment = cls.read_jsonl(BASE / "attack_alignment.jsonl")
        cls.coverage = json.loads((BASE / "coverage.json").read_text(encoding="utf-8"))

    @staticmethod
    def read_jsonl(path: Path) -> list[dict]:
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]

    def test_plan_index_and_target_coverage(self) -> None:
        self.assertEqual(len(self.plan), len(self.index))
        self.assertEqual(set(self.plan), {x["control_id"] for x in self.index})
        counts = Counter(x["target"] for x in self.index if x["status"] == "accepted")
        self.assertEqual(set(counts), set(self.coverage["targets"]))
        self.assertTrue(all(count >= 1 for count in counts.values()))
        self.assertEqual(sum(counts.values()), self.coverage["accepted_total"])
        for target, count in counts.items():
            self.assertEqual(count, self.coverage["targets"][target]["accepted_clean_controls"])
        self.assertEqual(len(self.alignment), sum(x["attack_double_success_cases"] for x in self.coverage["targets"].values()))
        self.assertEqual({x["matching_level"] for x in self.alignment}, {"same_task_family"})
        accepted_ids = {x["control_id"] for x in self.index if x["status"] == "accepted"}
        for row in self.alignment:
            self.assertTrue(row["candidate_control_ids"])
            self.assertTrue(set(row["candidate_control_ids"]).issubset(accepted_ids))

    def test_accepted_cases_are_real_clean_runs_with_graphs(self) -> None:
        fingerprints = set()
        for entry in self.index:
            if entry["status"] != "accepted":
                continue
            with self.subTest(control_id=entry["control_id"]):
                self.assertNotIn(entry["fingerprint"], fingerprints)
                fingerprints.add(entry["fingerprint"])
                case = json.loads((ROOT / entry["case_path"]).read_text(encoding="utf-8"))
                graph = json.loads((ROOT / entry["graph_path"]).read_text(encoding="utf-8"))
                self.assertEqual(case["label"], "normal_clean")
                self.assertTrue(case["labels"]["normal_control"])
                self.assertTrue(case["run"]["task_success"])
                self.assertFalse(case["generation"]["injections"])
                self.assertFalse(case["generation"]["input_events"])
                self.assertFalse(case["generation"]["workspace_events"])
                self.assertFalse(any(x.get("injected") for x in case["execution"]["tool_call_trace"]))
                self.assertEqual(
                    [x.get("user_message") for x in case["execution"]["visible_agent_turns"]],
                    self.plan[entry["control_id"]]["prompts"],
                )
                self.assertEqual(case["control_metadata"]["paired_attack_target"], entry["target"])
                self.assertEqual(case["control_metadata"]["task_success_basis"], entry["task_success_basis"])
                l0 = graph["graph"]["levels"]["l0"]["graph"]
                self.assertTrue(l0["nodes"])
                self.assertTrue(l0["edges"])


if __name__ == "__main__":
    unittest.main()
