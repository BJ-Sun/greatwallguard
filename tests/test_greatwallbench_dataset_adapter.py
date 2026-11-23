from pathlib import Path
import importlib.util
import sys


MODULE = (
    Path(__file__).resolve().parents[1]
    / "experiments/greatwallbench_full/dataset_adapter.py"
)
SPEC = importlib.util.spec_from_file_location("greatwallbench_dataset_adapter", MODULE)
adapter = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = adapter
SPEC.loader.exec_module(adapter)


def test_inventory_has_expected_strict_cases():
    rows = list(adapter.iter_cases())
    normal = [row for row in rows if row.label.group == "normal"]
    attacks = [row for row in rows if row.label.group == "attack"]
    assert len(normal) == 240
    assert len(attacks) == 405
    assert all(row.label.task_success for row in rows)
    assert all(row.label.attack_success for row in attacks)


def test_defense_view_excludes_attack_answers():
    case = next(adapter.iter_cases(groups=("attack",)))
    assert case.trusted_messages
    assert case.tool_contract.get("tools")
    assert any(event.kind == "tool_call" for event in case.events)
    # Runtime payloads contain observed facts, never oracle metadata.
    forbidden = {"malicious_goal", "target_effect", "attack_success", "label"}
    for event in case.events:
        assert forbidden.isdisjoint(event.payload)
