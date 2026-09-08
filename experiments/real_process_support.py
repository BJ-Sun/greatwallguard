"""Real file tools and an independent, snapshot-based evaluation oracle.

No shell/network/send tools. Agent chooses calls; files live in a fresh directory.
Oracle values come from requests, returns and disk, never graph counters.
"""
from __future__ import annotations

import copy
import hashlib
import json
from collections import Counter
from pathlib import Path
from greatwallguard.model import StateTransition


def tools_schema():
    definitions = [
        ("read_file", "Read a UTF-8 file relative to the workspace; missing files return an error.", {"path": {"type": "string"}}, ["path"]),
        ("write_file", "Write UTF-8 content to a workspace-relative file, creating or replacing it.", {"path": {"type": "string"}, "content": {"type": "string"}}, ["path", "content"]),
        ("list_files", "List files relative to the workspace.", {}, []),
    ]
    return [{"type": "function", "function": {"name": name, "description": desc,
             "parameters": {"type": "object", "properties": props, "required": required,
                            "additionalProperties": False}}} for name, desc, props, required in definitions]


def snapshot(root: Path):
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.rglob("*")) if p.is_file()}


class RealFileEnvironment:
    def __init__(self, root, recorder, oracle, *, state_evidence="receipt"):
        self.root = Path(root).resolve()
        self.recorder = recorder
        self.oracle = oracle
        self.pending = []
        self.session = 0
        self.state_evidence = state_evidence

    def get_tool_config(self):
        return tools_schema()

    def _perform(self, name, args):
        if name == "list_files":
            return json.dumps(sorted(snapshot(self.root))), True
        if name not in {"read_file", "write_file"}:
            return "Error: unknown tool", False
        path = (self.root / args["path"]).resolve()
        if not path.is_relative_to(self.root) or path == self.root:
            return "Error: path is outside the workspace", False
        if name == "read_file":
            return path.read_text(encoding="utf-8"), True
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(args["content"], encoding="utf-8")
        return "File written successfully.", True

    def execute_tool(self, name, args):
        pending = self.pending.pop(0)
        if pending["function"]["name"] != name:
            raise RuntimeError("Tool order differs from model response")
        call_id = pending["id"]
        before = snapshot(self.root)
        self.recorder.before_tool_call(self, name, args, call_id=call_id)
        try:
            result, success = self._perform(name, args)
        except (OSError, KeyError, TypeError, ValueError) as exc:
            result, success = "Error: " + type(exc).__name__, False
        after = snapshot(self.root)
        # Append independent values BEFORE recorder result processing.
        self.oracle["tool_calls"].append({
            "call_id": call_id, "session": self.session, "name": name,
            "args": copy.deepcopy(args), "result": result, "success": success,
            "before": before, "after": after,
            "changed": sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k)),
        })
        transition, read_fingerprint = None, None
        if self.state_evidence == "snapshot" and "path" in args:
            path = args["path"]
            if name == "write_file" and success:
                transition = StateTransition("file://workspace/" + path, before.get(path), after.get(path))
            elif name == "read_file" and success:
                read_fingerprint = before.get(path)
        self.recorder.after_tool_call(self, name, result, success=success,
                                     transition=transition, read_fingerprint=read_fingerprint)
        return result


class RecordingClient:
    def __init__(self, client, env, recorder, oracle):
        self.client, self.env, self.recorder, self.oracle = client, env, recorder, oracle

    def chat(self, messages, **kwargs):
        call_id = f"llm-{len(self.oracle['model_calls']) + 1}"
        request = copy.deepcopy({"messages": messages, "tools": kwargs.get("tools")})
        self.recorder.record_model_boundary(self.env, phase="input", payload=request, call_id=call_id)
        response = self.client.chat(messages, **kwargs)
        # Namespace the remote IDs across model calls; preserve remote IDs in
        # the raw response. Tool IDs only correlate messages, not task content.
        remote_response = copy.deepcopy(response)
        for tool_call in response["tool_calls"]:
            tool_call["id"] = call_id + ":" + tool_call["id"]
        self.oracle["model_calls"].append({"call_id": call_id, "session": self.env.session,
                                           "request": request, "response": copy.deepcopy(response),
                                           "remote_response": remote_response})
        self.recorder.record_model_boundary(self.env, phase="output", payload=response, call_id=call_id)
        self.env.pending = copy.deepcopy(response["tool_calls"])
        return response


def evaluate_process(graph, raw_texts, oracle):
    nodes = graph["nodes"]
    by_id = {n["id"]: n for n in nodes}
    actions = [n for n in nodes if n["node_type"] == "action"]
    returns = [n for n in nodes if n["data"].get("source") == "tool_return"]
    action_by_call = {n["data"].get("call_id"): n for n in actions}
    returns_by_call = {n["data"].get("call_id"): n for n in returns}
    effect_to_action = {e["target"]: e["source"] for e in graph["edges"] if e["edge_type"] == "causes"}
    effects_by_action = {}
    for eff, act in effect_to_action.items():
        effects_by_action.setdefault(act, []).append(by_id[eff])
    state_writer = {}
    actual_updates = []
    for n in nodes:
        if n["node_type"] == "state":
            action = by_id.get(effect_to_action.get(n["data"]["effect_id"]))
            writer = action["data"].get("call_id") if action else None
            state_writer[n["id"]] = writer
            actual_updates.append((writer, n["data"]["object_id"]))
    actual_reads = []
    for e in graph["edges"]:
        if e["edge_type"] == "reads":
            obs = by_id[e["target"]]
            actual_reads.append((state_writer.get(e["source"]), obs["data"].get("call_id"), obs["data"].get("object_id")))

    def payload(node):
        descriptor = node["data"].get("content", {})
        raw = raw_texts.get(descriptor.get("ref"))
        if raw is None:
            return None
        return raw if descriptor.get("encoding") == "text" else json.loads(raw)

    exact_calls = exact_returns = exact_effects = 0
    failures = []
    expected_updates, expected_reads = [], []
    last_writer = {}
    for call in oracle["tool_calls"]:
        cid = call["call_id"]
        action, obs = action_by_call.get(cid), returns_by_call.get(cid)
        if action and action["data"]["tool"] == call["name"] and payload(action) == call["args"] and action["data"]["execution_status"] == ("succeeded" if call["success"] else "failed"):
            exact_calls += 1
        else:
            failures.append({"call_id": cid, "issue": "action/arguments/status mismatch"})
        if obs and payload(obs) == call["result"]:
            exact_returns += 1
        effects = effects_by_action.get(action["id"], []) if action else []
        expected_kind = "write" if call["name"] == "write_file" else "read"
        target = "file://workspace/" + call["args"]["path"] if "path" in call["args"] else None
        if len(effects) == 1 and effects[0]["data"]["kind"] == expected_kind and (target is None or effects[0]["data"]["target"] == target) and effects[0]["data"]["status"] == ("succeeded" if call["success"] else "failed"):
            exact_effects += 1
        if call["name"] == "read_file" and call["success"] and call["args"]["path"] in last_writer:
            expected_reads.append((last_writer[call["args"]["path"]], cid, target))
        for path in call["changed"]:
            expected_updates.append((cid, "file://workspace/" + path))
            last_writer[path] = cid
    exact_model_inputs = exact_model_outputs = 0
    for call in oracle["model_calls"]:
        for source, expected in (("model_input", call["request"]), ("assistant_output", call["response"])):
            matches = [n for n in nodes if n["data"].get("source") == source and n["data"].get("model_call_id") == call["call_id"]]
            correct = len(matches) == 1 and payload(matches[0]) == expected
            if source == "model_input":
                exact_model_inputs += correct
            else:
                exact_model_outputs += correct

    def compare(expected, actual):
        exp, act = Counter(expected), Counter(actual)
        tp = sum((exp & act).values())
        return {"matched": tp, "expected": sum(exp.values()), "recorded": sum(act.values()),
                "precision": tp / sum(act.values()) if act else None,
                "recall": tp / sum(exp.values()) if exp else None,
                "missing": list((exp - act).elements()), "extra": list((act - exp).elements())}

    return {
        "scope": "sequential read_file/write_file/list_files and visible model boundaries; actual local disk",
        "tool_calls": {"matched": exact_calls, "expected": len(oracle["tool_calls"]), "recorded": len(actions)},
        "tool_returns": {"matched": exact_returns, "expected": len(oracle["tool_calls"]), "recorded": len(returns)},
        "tool_effects": {"matched": exact_effects, "expected": len(oracle["tool_calls"])},
        "model_inputs": {"matched": exact_model_inputs, "expected": len(oracle["model_calls"])},
        "model_outputs": {"matched": exact_model_outputs, "expected": len(oracle["model_calls"])},
        "content_state_transitions": compare(expected_updates, actual_updates),
        "state_reads": compare(expected_reads, actual_reads),
        "tool_failures": sum(not c["success"] for c in oracle["tool_calls"]),
        "successful_no_change_writes": sum(c["name"] == "write_file" and c["success"] and not c["changed"] for c in oracle["tool_calls"]),
        "failures": failures,
        "causal_use_accuracy": "unmeasured; model context exposure does not establish causal use",
        "model_requested_tools": sum(len(c["response"]["tool_calls"]) for c in oracle["model_calls"]),
        "requested_but_not_executed": [tc["id"] for c in oracle["model_calls"] for tc in c["response"]["tool_calls"]
                                      if tc["id"] not in {t["call_id"] for t in oracle["tool_calls"]}],
    }
