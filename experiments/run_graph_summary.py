"""Compression/coverage matrix for the bounded graph-state summary.

Two subcommands share one evaluator:

* ``offline`` (default) — rebuild the audit graph at checkpoints 10/20/30 from
  the already-saved real-agent oracles (``experiments/longrun_20260907`` etc.)
  with zero API calls, then compare five views (full audit graph + raw content,
  fixed recent-window baseline, and the graph summary at small/medium/large
  budgets) on size, process recall, persistent-effect coverage, content
  coverage, evidence-support rate and replay equality.

* ``live`` — run real OpenClaw/AgentLAB turns into a fresh isolated directory
  under ``--output-root`` with the experiment's hard budget caps, stopping after
  three consecutive API failures (e.g. a billing 402). This is the path that
  exercises the real agent; it is used only when the DeepSeek account has
  credit.

Gold coverage strings come from the deterministic task scripts in
``longrun_tasks.py`` and are never shown to a summarizer. Representation
coverage is reported separately from task completion.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from greatwallguard.content import json_bytes
from greatwallguard.state_summary import (
    BUDGETS,
    GraphStateSummarizer,
    fixed_recent_window,
    replay_summary,
)

THIS_DIR = Path(__file__).resolve().parent
GUARD_ROOT = THIS_DIR.parent
WORKSPACE_ROOT = GUARD_ROOT.parent

sys.path.insert(0, str(THIS_DIR))

from longrun_driver import rebuild_recorder  # noqa: E402
from longrun_tasks import FAMILIES, MultiFileFamily, RecoveryFamily, RevisionFamily  # noqa: E402

CHECKPOINTS = (10, 20, 30)
FIXED_WINDOW_EVENTS = 12

# Hard budget caps for THIS experiment (per the task spec).
LIVE_CAPS = {
    "wall_seconds": 2 * 3600,
    "llm_requests": 300,
    "input_tokens": 6_000_000,
    "output_tokens": 500_000,
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(value, ensure_ascii=False, indent=2, default=str),
                   encoding="utf-8")
    tmp.replace(path)


# --------------------------------------------------------------------------- #
# Offline reconstruction from a saved oracle
# --------------------------------------------------------------------------- #

def truncate_oracle(oracle: dict[str, Any], max_turn: int) -> dict[str, Any]:
    """Keep only sessions up to ``max_turn`` that actually ran a model call.

    Error sessions (no completed model call) are dropped so the replay matches
    the live resume path in ``longrun_driver``.
    """
    sessions = [s for s in oracle.get("sessions", [])
                if s.get("session") is not None and s["session"] <= max_turn and not s.get("error")]
    session_ids = {s["session"] for s in sessions}
    model_calls = [mc for mc in oracle.get("model_calls", [])
                   if mc.get("session") in session_ids]
    tool_calls = [tc for tc in oracle.get("tool_calls", [])
                  if tc.get("session") in session_ids]
    return {"initial_files": oracle.get("initial_files", {}),
            "model_calls": model_calls, "tool_calls": tool_calls, "sessions": sessions}


def rebuild_at_turn(oracle: dict[str, Any], turn: int) -> tuple[dict[str, Any], dict[str, str]]:
    """Rebuild the audit record + raw content at ``turn`` with zero API calls."""
    recorder = rebuild_recorder(truncate_oracle(oracle, turn), state_evidence="snapshot")
    index = recorder.graph.content_index
    raw_texts = index.export(include_raw=True)["raw_texts"] if index else {}
    return recorder.runtime.trace_dict(), raw_texts


# --------------------------------------------------------------------------- #
# Coverage measures
# --------------------------------------------------------------------------- #

def extract_known_keys(record: dict[str, Any]) -> dict[str, Any]:
    nodes = record["graph"]["nodes"]
    call_ids, arg_digests, return_refs = set(), set(), set()
    states: dict[str, dict[str, Any]] = {}
    for node in nodes:
        data = node.get("data") or {}
        if node.get("node_type") == "action":
            if data.get("call_id"):
                call_ids.add(str(data["call_id"]))
            if data.get("arguments_digest"):
                arg_digests.add(str(data["arguments_digest"]))
        if node.get("node_type") == "observation" and data.get("source") == "tool_return":
            ref = (data.get("content") or {}).get("ref")
            if ref:
                return_refs.add(str(ref))
        if node.get("node_type") == "state":
            object_id = str(data.get("object_id", ""))
            version = int(data.get("version", 0) or 0)
            if object_id and (object_id not in states or version >= int(states[object_id]["version"] or 0)):
                states[object_id] = {"version": version, "fingerprint": data.get("fingerprint")}
    fingerprints = {str(s["fingerprint"]) for s in states.values() if s.get("fingerprint")}
    return {"call_ids": call_ids, "arg_digests": arg_digests, "return_refs": return_refs,
            "fingerprints": fingerprints, "live_objects": states}


def view_text(view: dict[str, Any]) -> str:
    return json.dumps(view, ensure_ascii=False, sort_keys=True, default=str)


def _live_states_from_nodes(nodes: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    states: dict[str, dict[str, Any]] = {}
    for node in nodes:
        data = node.get("data") or {}
        if node.get("node_type") != "state":
            continue
        object_id = str(data.get("object_id", ""))
        version = int(data.get("version", 0) or 0)
        if object_id and (object_id not in states or version >= int(states[object_id]["version"] or 0)):
            states[object_id] = {"version": version, "fingerprint": data.get("fingerprint")}
    return states


def _extract_view_keys(view: dict[str, Any]) -> dict[str, Any]:
    """Structurally collect process keys from a full record or a bounded view.

    This keeps precision meaningful: instead of substring-searching the JSON
    envelope (which counts the same id in multiple fields), keys are read from
    action/tool-return/state data and the effect ledger.
    """
    if "graph" in view and "nodes" in view.get("graph", {}):
        nodes = view["graph"]["nodes"]
        live = _live_states_from_nodes(nodes)
        call_ids = {str(n["data"]["call_id"]) for n in nodes
                    if n.get("node_type") == "action" and (n.get("data") or {}).get("call_id")}
        arg_digests = {str(n["data"]["arguments_digest"]) for n in nodes
                       if n.get("node_type") == "action" and (n.get("data") or {}).get("arguments_digest")}
        return_refs = {str((n.get("data") or {}).get("content", {}).get("ref")) for n in nodes
                       if n.get("node_type") == "observation"
                       and (n.get("data") or {}).get("source") == "tool_return"
                       and (n.get("data") or {}).get("content", {}).get("ref")}
        fingerprints = {str(s["fingerprint"]) for s in live.values() if s.get("fingerprint")}
        return {"call_ids": call_ids, "arg_digests": arg_digests,
                "return_refs": return_refs, "fingerprints": fingerprints, "live_objects": live}

    events: list[dict[str, Any]] = []
    if "recent_trace" in view:
        events = view.get("recent_trace", {}).get("events", []) or []
    else:
        events = view.get("events", []) or []

    call_ids, arg_digests, return_refs, fingerprints = set(), set(), set(), set()
    for event in events:
        data = event.get("data") or {}
        if data.get("call_id"):
            call_ids.add(str(data["call_id"]))
        if data.get("arguments_digest"):
            arg_digests.add(str(data["arguments_digest"]))
        if data.get("source") == "tool_return":
            ref = (data.get("content") or {}).get("ref")
            if ref:
                return_refs.add(str(ref))
        if data.get("fingerprint"):
            fingerprints.add(str(data["fingerprint"]))
    for row in view.get("effect_ledger", {}).get("objects", []) or []:
        if row.get("fingerprint"):
            fingerprints.add(str(row["fingerprint"]))
    return {"call_ids": call_ids, "arg_digests": arg_digests,
            "return_refs": return_refs, "fingerprints": fingerprints}


def key_recall(known: dict[str, Any], view: dict[str, Any]) -> dict[str, Any]:
    found = _extract_view_keys(view)
    result = {}
    for key in ("call_ids", "arg_digests", "return_refs", "fingerprints"):
        values = known[key]
        present = found[key] & values
        result[key] = {
            "retained": len(present),
            "expected": len(values),
            "recall": len(present) / len(values) if values else None,
            "recorded": len(found[key]),
            "precision": len(present) / len(found[key]) if found[key] else None,
            "false_positives": sorted(found[key] - values),
        }
    return result


def live_state_consistency(known: dict[str, Any], view: dict[str, Any]) -> dict[str, Any]:
    """Does the view retain each live object with the correct version + hash?

    Full audit records are checked directly against their state nodes; bounded
    summaries are checked against their ``effect_ledger``. The fixed-window
    baseline has no ledger and therefore reports 0.0 coverage by design.
    """
    if "graph" in view and "nodes" in view.get("graph", {}):
        ledger = {object_id: {"version": s["version"], "fingerprint": s["fingerprint"]}
                  for object_id, s in _live_states_from_nodes(view["graph"]["nodes"]).items()}
    else:
        ledger = {row.get("object_id"): row for row in view.get("effect_ledger", {}).get("objects", [])}
    matched = 0
    for object_id, state in known["live_objects"].items():
        row = ledger.get(object_id)
        if row and row.get("version") == state["version"] and row.get("fingerprint") == state["fingerprint"]:
            matched += 1
    total = len(known["live_objects"])
    return {"matched": matched, "expected": total, "coverage": matched / total if total else None}


def content_retention(view_text_value: str, spans: list[tuple[str, str]]) -> dict[str, Any]:
    per = {label: span in view_text_value for label, span in spans}
    hits = sum(per.values())
    return {"retained": hits, "expected": len(spans),
            "coverage": hits / len(spans) if spans else None, "per_span": per}


def summary_content_text(summary: dict[str, Any]) -> str:
    parts = [p.get("quote", "") for p in summary["content_sketch"].get("propositions", [])]
    parts += [u.get("unit", {}).get("text", "") for u in summary["content_sketch"].get("evidence_units", [])]
    parts += [e.get("raw", "") for e in summary.get("recent_trace", {}).get("events", []) if e.get("raw")]
    return "\n".join(parts)


def gold_spans(family: str, turn: int) -> list[tuple[str, str]]:
    """Current deterministic task facts that SHOULD be retained at ``turn``.

    Derived only from the task scripts, never from the agent's actual output.
    """
    spans: list[tuple[str, str]] = []
    if family == "multifile":
        # Recent facts always sit in the recent window; older facts only survive
        # if the ledger/sketch retains them, so include a couple of early turns.
        fact_turns = sorted({turn, max(1, turn - 1), max(1, turn - 2), 1, max(1, turn // 2)})
        for s in fact_turns:
            spans.append((f"fact_{s}", MultiFileFamily.fact_text(s)))
        spans.append((f"fact_file_{turn}", MultiFileFamily.fact_file(turn)))
        spans.append((f"total_{turn}", f"total: {turn}"))
        spans.append((f"prohibit_{turn}",
                      f"Do not modify any file other than {MultiFileFamily.fact_file(turn)} and report.md"))
    elif family == "revision":
        current = RevisionFamily.recipient(turn)
        previous = RevisionFamily.recipient(turn - 1)
        condition = RevisionFamily.condition(turn)
        spans = [
            ("recipient_current", current),
            ("recipient_previous", previous),
            ("condition", condition),
            ("withdrawn_plan", f"delivery copy for {previous} is withdrawn"),
            ("withdrawn_marker", "is withdrawn"),
            ("approval", "granted" if RevisionFamily.approved(turn) else "not granted"),
        ]
        if not RevisionFamily.approved(turn):
            spans.append(("negation_approval", "not granted"))
    elif family == "recovery":
        spans = [
            ("count", f"objects created: {turn}"),
            ("next_index", f"next index: {turn + 1}"),
            ("obj_content", RecoveryFamily.obj_content(turn)),
            ("obj_name", RecoveryFamily.obj_name(turn)),
            ("prohibit_other", "Do not modify any other object file"),
        ]
        if turn % 10 == 0 or turn % 5 == 0:
            spans.append(("noop_write", "should be unchanged"))
    return spans


# --------------------------------------------------------------------------- #
# View construction + checkpoint evaluation
# --------------------------------------------------------------------------- #

def replay_task_files(family_cls: Any, oracle: dict[str, Any], turn: int) -> Path:
    """Deterministically rebuild the task directory at ``turn`` (no API).

    The saved oracle contains every write_file arguments plus the initial file
    content from the task script, so task completion can be re-measured offline.
    """
    root = Path(tempfile.mkdtemp(prefix="gws-task-replay-"))
    for name, text in family_cls().initial_files().items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    for call in oracle.get("tool_calls", []):
        if call.get("session") is not None and call["session"] > turn:
            continue
        if call.get("name") != "write_file" or not call.get("success"):
            continue
        args = call.get("args") or {}
        path = root / args["path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(args["content"], encoding="utf-8")
    return root


def oracle_usage(oracle: dict[str, Any]) -> dict[str, Any]:
    """Usage/latency-style counts derived from the saved oracle alone.

    Real token usage is not embedded in the oracle (it lives in the separate
    budget log), so these are chars/4 estimates labelled as such.
    """
    model_calls = oracle.get("model_calls", [])
    tool_calls = oracle.get("tool_calls", [])
    turns = len([s for s in oracle.get("sessions", []) if not s.get("error")])
    est_in = est_out = 0
    for call in model_calls:
        est_in += len(json_bytes(call.get("request", {}))) // 4
        est_out += len(json_bytes(call.get("response", {}))) // 4
    return {
        "completed_turns": turns,
        "model_calls": len(model_calls),
        "tool_calls": len(tool_calls),
        "estimated_input_tokens": est_in,
        "estimated_output_tokens": est_out,
        "estimate_method": "chars/4 from saved oracle",
        "latency_seconds": None,
    }


def build_views(record: dict[str, Any], raw_texts: dict[str, str],
                llm_fn=None, response_cache: dict[str, str] | None = None) -> dict[str, dict[str, Any]]:
    views: dict[str, dict[str, Any]] = {
        "full": record,
        "fixed_window": fixed_recent_window(record, window_events=FIXED_WINDOW_EVENTS,
                                            raw_texts=raw_texts),
    }
    for name, budgets in BUDGETS.items():
        views[f"summary_{name}"] = GraphStateSummarizer(
            budgets=budgets, model_fn=llm_fn, response_cache=response_cache
        ).summarize(record, raw_texts=raw_texts)
    return views


def evaluate_checkpoint(family: str, turn: int, record: dict[str, Any],
                        raw_texts: dict[str, str], llm_fn=None,
                        response_cache: dict[str, str] | None = None,
                        *, oracle: dict[str, Any] | None = None,
                        family_cls: Any | None = None,
                        latency_seconds: float | None = None,
                        save_views_path: Path | None = None) -> dict[str, Any]:
    known = extract_known_keys(record)
    full_text = "\n".join(raw_texts.values())
    spans = gold_spans(family, turn)
    views = build_views(record, raw_texts, llm_fn=llm_fn, response_cache=response_cache)
    if save_views_path is not None:
        # Keep the full audit graph + raw content as their own files; save the
        # bounded runtime views separately so the matrix is inspectable.
        write_json(save_views_path, {name: view for name, view in views.items() if name != "full"})

    full_bytes = len(json_bytes(record)) + len(json_bytes(raw_texts))
    rows = {}
    for name, view in views.items():
        summary = view if name.startswith("summary_") else None
        content_text = (summary_content_text(summary) if summary else
                        view_text(view) if name == "full" else
                        "\n".join((e.get("raw") or e.get("summary") or "")
                                  for e in view.get("events", [])))
        # "full" content coverage uses the raw evidence, not the JSON envelope.
        coverage_text = full_text if name == "full" else content_text
        row: dict[str, Any] = {
            "bytes": len(json_bytes(view)),
            "compression_ratio": len(json_bytes(view)) / max(full_bytes, 1),
            "estimated_tokens": view.get("meta", {}).get("estimated_tokens"),
            "process_recall": key_recall(known, view),
        }
        if summary is not None:
            sketch = summary["content_sketch"]
            n_prop = len(sketch.get("propositions", []))
            n_units = len(sketch.get("evidence_units", []))
            row["evidence"] = {
                "propositions": n_prop,
                "evidence_units": n_units,
                "supported": n_prop,
                "unsupported_claims": sketch.get("unsupported_claims", 0),
                "rejected_claims": sketch.get("rejected_claims", 0),
                "unknown_records": len(sketch.get("unknown_records", [])),
                "records_total": sketch.get("records_total", 0),
                "support_rate": 1.0 if n_prop else None,
                "unknown_rate": (len(sketch.get("unknown_records", [])) / max(sketch.get("records_total", 0), 1)),
            }
            row["live_state"] = live_state_consistency(known, summary)
            row["method"] = sketch["method"]
            replay = replay_summary(record, raw_texts=raw_texts,
                                    response_cache=response_cache or {},
                                    budgets=BUDGETS[name.removeprefix("summary_")])
            original = dict(summary)
            original.setdefault("meta", {}).pop("model_calls", None)
            replayed = dict(replay)
            replayed.setdefault("meta", {}).pop("model_calls", None)
            row["replay_equal"] = json_bytes(replayed) == json_bytes(original)
        else:
            row["live_state"] = live_state_consistency(known, view)
            row["evidence"] = {}
        row["content_coverage"] = content_retention(coverage_text, spans)
        rows[name] = row

    result: dict[str, Any] = {
        "family": family, "turn": turn,
        "full_bytes": full_bytes,
        "graph_bytes": len(json_bytes(record)),
        "raw_content_bytes": len(json_bytes(raw_texts)),
        "known_keys": {k: len(v) for k, v in known.items()},
        "gold_spans": spans,
        "views": rows,
    }
    if oracle is not None:
        result["usage"] = oracle_usage(oracle)
    if family_cls is not None and oracle is not None:
        task_root = replay_task_files(family_cls, oracle, turn)
        try:
            result["task_outcomes"] = family_cls().task_outcomes(task_root, turn)
        finally:
            shutil.rmtree(task_root, ignore_errors=True)
    if latency_seconds is not None:
        result["usage"] = {**(result.get("usage") or {}), "latency_seconds": round(latency_seconds, 3)}
    return result


# --------------------------------------------------------------------------- #
# Offline driver
# --------------------------------------------------------------------------- #

def find_families(input_root: Path) -> list[str]:
    return [d.name for d in sorted(input_root.iterdir())
            if (d / "oracle.json").exists() and (d / "graph.json").exists()]


def offline_main(args: argparse.Namespace) -> None:
    input_root = args.input_root
    output_root = args.output_root
    output_root.mkdir(parents=True, exist_ok=True)
    families = args.families.split(",") if args.families else find_families(input_root)

    results: dict[str, Any] = {}
    log_lines: list[str] = []
    completed: dict[str, Any] = {}
    for family in families:
        fam_dir = input_root / family
        oracle_path = fam_dir / "oracle.json"
        if not oracle_path.exists():
            log_lines.append(f"[{family}] missing oracle.json; skipped")
            continue
        oracle = json.loads(oracle_path.read_text(encoding="utf-8"))
        ran_turns = [s["session"] for s in oracle.get("sessions", [])
                     if not s.get("error")]
        max_turn = max(ran_turns, default=0)
        checkpoints = [t for t in CHECKPOINTS if t <= max_turn]
        if not checkpoints and max_turn > 0:
            checkpoints = [max_turn]
        family_results: dict[str, Any] = {"max_turn": max_turn, "checkpoints": {}}
        family_cls = FAMILIES[family]
        for turn in checkpoints:
            started = time.perf_counter()
            truncated = truncate_oracle(oracle, turn)
            record, raw_texts = rebuild_at_turn(oracle, turn)
            metrics = evaluate_checkpoint(
                family, turn, record, raw_texts,
                oracle=truncated, family_cls=family_cls,
                save_views_path=output_root / family / "views" / f"turn_{turn:03d}.json",
            )
            metrics["rebuild_seconds"] = round(time.perf_counter() - started, 3)
            write_json(output_root / family / "checkpoints" / f"turn_{turn:03d}.json", metrics)
            write_json(output_root / family / f"graph_{turn:03d}.json", record)
            write_json(output_root / family / f"content_{turn:03d}.json", raw_texts)
            family_results["checkpoints"][str(turn)] = metrics
            log_lines.append(f"[{family}] turn {turn} rebuilt+summarized "
                             f"({metrics['rebuild_seconds']}s, "
                             f"full={metrics['full_bytes']}B)")
        results[family] = family_results
        completed[family] = max_turn
        write_json(output_root / "status.json", {
            "phase": "offline", "family": family, "input_root": str(input_root),
            "completed_turns": {family: max_turn}, "updated_at": now_iso(),
        })

    write_json(output_root / "results.json", {
        "mode": "offline", "input_root": str(input_root),
        "checkpoints": list(CHECKPOINTS), "budgets": {k: b.as_dict() for k, b in BUDGETS.items()},
        "fixed_window_events": FIXED_WINDOW_EVENTS, "families": results,
    })
    (output_root / "run.log").write_text("\n".join(log_lines) + "\n", encoding="utf-8")
    print(json.dumps({"phase": "offline_done", "families": {k: v["max_turn"] for k, v in results.items()}},
                     ensure_ascii=False, indent=2))


# --------------------------------------------------------------------------- #
# Live driver (real OpenClaw/AgentLAB turns, tight caps)
# --------------------------------------------------------------------------- #

def live_main(args: argparse.Namespace) -> None:
    from run_real_agent_validation import _load_agentlab, _load_env

    output_root = args.output_root
    output_root.mkdir(parents=True, exist_ok=True)
    families = [f for f in args.families.split(",") if f]
    budget_path = output_root / "budget.json"

    # --- a single connectivity probe before committing to a run ------------ #
    _load_env()
    try:
        Agent, model, _, _ = _load_agentlab()
        from src.llm import LLMClient
        client = LLMClient(model=model)
        probe = client.chat([{"role": "user", "content": "ping"}], temperature=0, max_tokens=4)
        probe_ok = True
        probe_note = f"probe ok (model={probe.get('model')})"
    except Exception as exc:  # noqa: BLE001
        probe_ok = False
        probe_note = f"probe failed: {type(exc).__name__}: {str(exc)[:200]}"

    status = {"phase": "live", "probe_ok": probe_ok, "probe_note": probe_note,
              "families": {}, "updated_at": now_iso(),
              "caps": LIVE_CAPS, "error_or_stop_reason": None}
    if not probe_ok:
        status["phase"] = "stopped"
        status["error_or_stop_reason"] = probe_note
        write_json(output_root / "status.json", status)
        write_json(output_root / "results.json", {"mode": "live", "stopped": probe_note})
        print(json.dumps(status, ensure_ascii=False, indent=2))
        return

    from longrun_driver import (BudgetTracker, RealFileEnvironment, make_usage_client,  # noqa: F401
                                TrackedRecordingClient, budget_reason, save_budget)
    from longrun_tasks import FAMILIES
    from greatwallguard.agentlab_recorder import AgentLabGraphRecorder
    from greatwallguard.content import ContentIndex
    from greatwallguard.model import EffectType, TaskScope
    from real_process_support import snapshot
    import tempfile

    tracker = BudgetTracker()
    started = time.perf_counter()

    def reason() -> str | None:
        if time.perf_counter() - started >= LIVE_CAPS["wall_seconds"]:
            return "wall_clock"
        if tracker.requests_attempted >= LIVE_CAPS["llm_requests"]:
            return "llm_requests"
        if tracker.input_tokens >= LIVE_CAPS["input_tokens"]:
            return "input_tokens"
        if tracker.output_tokens >= LIVE_CAPS["output_tokens"]:
            return "output_tokens"
        return None

    results = {}
    checkpoint_turns = sorted({t for t in CHECKPOINTS if t <= args.max_turns} |
                              {args.max_turns})
    for family_name in families:
        family = FAMILIES[family_name]()
        fam_dir = output_root / family_name
        fam_dir.mkdir(parents=True, exist_ok=True)
        task_root = Path(tempfile.mkdtemp(prefix="task-files-", dir=fam_dir))
        scope = TaskScope("graph-summary-live", "normal local graph-summary tasks", frozenset(EffectType))
        index = ContentIndex()
        recorder = AgentLabGraphRecorder(scope, content_index=index)
        oracle: dict[str, Any] = {"initial_files": {}, "model_calls": [], "tool_calls": [], "sessions": []}
        env = RealFileEnvironment(task_root, recorder, oracle, state_evidence="snapshot")
        for name, text in family.initial_files().items():
            p = task_root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text, encoding="utf-8")
        oracle["initial_files"] = snapshot(task_root)

        base_client = make_usage_client(model, tracker)
        turns_done = 0
        stop = None
        turn_latencies: list[dict[str, Any]] = []
        for turn in range(1, args.max_turns + 1):
            r = reason()
            if r:
                stop = r
                break
            turn_started = time.perf_counter()
            task = family.task(turn)
            env.session = turn
            agent = Agent(model=model, temperature=0.2, env=env, enable_flush=False)
            agent.base_prompt = family.base_prompt
            agent.llm = TrackedRecordingClient(base_client, env, recorder, oracle, tracker)
            agent.max_rounds = family.max_rounds
            agent.reset(env)
            recorder.begin_session(env, task, phase="normal_task")
            try:
                agent.run(task)
            except Exception as exc:  # noqa: BLE001
                tracker.mark_error(exc)
                oracle["sessions"].append({
                    "session": turn, "user": task, "error": str(exc),
                    "files": snapshot(task_root),
                })
                write_json(fam_dir / "oracle.json", oracle)
                if tracker.consecutive_api_errors >= 3:
                    stop = "api_errors"
                else:
                    stop = stop or "runtime_error"
                break
            turns_done = turn
            latency = time.perf_counter() - turn_started
            turn_latencies.append({"turn": turn, "seconds": round(latency, 3)})
            oracle["sessions"].append({
                "session": turn, "user": task,
                "last_reply": agent.messages[-1] if agent.messages else None,
                "files": snapshot(task_root),
            })
            write_json(fam_dir / "oracle.json", oracle)
            if turn in checkpoint_turns:
                record = recorder.runtime.trace_dict()
                raw_texts = index.export(include_raw=True)["raw_texts"]
                truncated = truncate_oracle(oracle, turn)
                metrics = evaluate_checkpoint(
                    family_name, turn, record, raw_texts,
                    oracle=truncated, family_cls=FAMILIES[family_name],
                    latency_seconds=latency,
                    save_views_path=fam_dir / "views" / f"turn_{turn:03d}.json",
                )
                metrics["turn_latencies"] = list(turn_latencies)
                write_json(fam_dir / "checkpoints" / f"turn_{turn:03d}.json", metrics)
                write_json(fam_dir / f"graph_{turn:03d}.json", record)
                write_json(fam_dir / f"content_{turn:03d}.json", raw_texts)
            save_budget(budget_path, tracker, time.perf_counter() - started)
            write_json(fam_dir / "progress.json", {
                "family": family_name, "completed_turns": turns_done,
                "task_root": str(task_root), "updated_at": now_iso(),
            })
            print(f"[{family_name}] turn {turn}/{args.max_turns} "
                  f"req={tracker.requests_attempted} in={tracker.input_tokens} "
                  f"out={tracker.output_tokens}", flush=True)
        results[family_name] = {
            "completed_turns": turns_done, "stop_reason": stop,
            "turn_latencies": turn_latencies,
            "task_root": str(task_root),
        }
        status["families"][family_name] = results[family_name]
        write_json(output_root / "status.json", status)
        if stop in {"api_errors"}:
            break

    status["phase"] = "completed" if all(r["stop_reason"] is None for r in results.values()) else "stopped"
    status["error_or_stop_reason"] = next((r["stop_reason"] for r in results.values() if r.get("stop_reason")), None)
    write_json(output_root / "status.json", status)
    write_json(output_root / "results.json", {"mode": "live", "families": results})
    print(json.dumps(status, ensure_ascii=False, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode")
    offline = sub.add_parser("offline", help="matrix from saved audit graphs (no API)")
    offline.add_argument("--input-root", type=Path,
                         default=GUARD_ROOT / "experiments" / "longrun_20260907")
    offline.add_argument("--output-root", type=Path,
                         default=GUARD_ROOT / "experiments" / f"graph_summary_{datetime.now(timezone.utc):%Y%m%d}")
    offline.add_argument("--families", default="")
    live = sub.add_parser("live", help="real OpenClaw/AgentLAB turns, tight caps")
    live.add_argument("--output-root", type=Path,
                      default=GUARD_ROOT / "experiments" / f"graph_summary_{datetime.now(timezone.utc):%Y%m%d}")
    live.add_argument("--families", default="multifile,revision,recovery")
    live.add_argument("--max-turns", type=int, default=30)
    args = parser.parse_args()
    if args.mode == "live":
        live_main(args)
    else:
        offline_main(args)


if __name__ == "__main__":
    main()
