"""Non-generative graph construction from native OpenClaw transcript events.

The audit graph records *observed* call/result identities and file operations.
Exact value matches are candidate provenance, never model-internal causality.
Unknown tool effects and missing result events remain explicit coverage failures.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from pathlib import Path
from typing import Any, Iterable

from .content import ContentIndex
from .graph import EffectGraph
from .model import EdgeType, Effect, EffectType, NodeType, StateTransition


EMAIL = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.I)
URL = re.compile(r"https?://[^\s<>'\"]+", re.I)
PATCH_PATH = re.compile(r"^\*\*\* (Add|Update|Delete) File: (.+)$", re.M)
TOOL_NOT_FOUND = re.compile(r"^Tool ([A-Za-z0-9_]+) not found$")
READ_NAMES = {"read", "read_file", "read_memory", "search_files", "search_emails",
              "ls", "resources_list", "resources_read", "prompts_list",
              "get_file_by_id", "get_received_emails", "get_sent_emails", "list_files",
              "search_contacts_by_email", "search_contacts_by_name", "mock_web_fetch",
              "mock_document_open", "search_calendar_events", "get_day_calendar_events"}
FILE_READ_NAMES = {"read", "read_file", "read_memory"}
FILE_WRITE_NAMES = {"write", "edit", "write_file", "append_to_file", "create_file", "write_memory"}
FILE_DELETE_NAMES = {"delete_file", "remove_file"}


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(str(part.get("text") or "") for part in content
                         if isinstance(part, dict) and part.get("type") == "text")
    return ""


def read_native_events(db_path: Path) -> list[tuple[int, dict[str, Any]]]:
    """Read a retained SQLite transcript without mutating its database.

    Some snapshots retain a nonempty WAL with the entire schema; `immutable`
    would silently miss it. Other archived snapshots have no WAL and only
    open through `immutable` in this sandbox. Select the mode from the sidecar
    rather than falling back from a failed WAL read to incomplete main data.
    """
    if not db_path.is_file():
        raise FileNotFoundError(db_path)
    wal_path = Path(str(db_path) + "-wal")
    has_wal = wal_path.is_file() and wal_path.stat().st_size > 0
    mode = "mode=ro" if has_wal else "immutable=1"
    connection = sqlite3.connect(f"file:{db_path}?{mode}", uri=True)
    try:
        rows = connection.execute("SELECT seq, event_json FROM transcript_events ORDER BY seq").fetchall()
    finally:
        connection.close()
    events = [(int(seq), json.loads(raw)) for seq, raw in rows]
    if len(events) != len({seq for seq, _ in events}):
        raise ValueError("duplicate native transcript sequence")
    return events


def _tool_name(name: str) -> str:
    return name.removeprefix("agentdojo__")


def _path(args: dict[str, Any]) -> str | None:
    value = args.get("path") or args.get("file_path") or args.get("filename")
    return str(value) if value is not None else None


def _same_workspace_path(native_path: str, snapshot_path: str) -> bool:
    return native_path == snapshot_path or native_path.endswith("/" + snapshot_path.lstrip("/"))


def _scalar_fields(value: Any, prefix: str = "") -> Iterable[tuple[str, str]]:
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _scalar_fields(child, f"{prefix}.{key}" if prefix else str(key))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _scalar_fields(child, f"{prefix}[{index}]")
    elif isinstance(value, (str, int, float)) and not isinstance(value, bool):
        yield prefix, str(value)


def _auditable_values(args: dict[str, Any]) -> Iterable[tuple[str, str]]:
    """Leaf fields plus tokens embedded in long text, without semantic parsing."""
    seen = set()
    for field_name, value in _scalar_fields(args):
        if len(value) >= 4 and len(value) <= 256:
            key = (field_name, value.casefold())
            if key not in seen:
                seen.add(key)
                yield field_name, value
        for pattern in (EMAIL, URL):
            for match in pattern.findall(value):
                key = (field_name, match.casefold())
                if key not in seen:
                    seen.add(key)
                    yield field_name, match


def _effect(tool: str, args: dict[str, Any]) -> Effect:
    name = _tool_name(tool)
    agentdojo = tool.startswith("agentdojo__")
    path = _path(args)
    if name == "get_unread_emails":
        # This apparent read marks returned inbox messages as read in the
        # AgentDojo tool contract; it is a potential persistent effect.
        kind, target, persistent = EffectType.WRITE, "external://inbox/read_flags", True
    elif agentdojo and name == "get_file_by_id":
        kind, target, persistent = EffectType.READ, f"cloud://file/{args.get('file_id') or 'unknown'}", False
    elif agentdojo and name == "create_file":
        kind, target, persistent = EffectType.CREATE, f"cloud://filename/{args.get('filename') or 'unknown'}", True
    elif agentdojo and name == "delete_file":
        kind, target, persistent = EffectType.DELETE, f"cloud://file/{args.get('file_id') or 'unknown'}", True
    elif name in FILE_READ_NAMES:
        kind, target, persistent = EffectType.READ, f"workspace://{path or 'unknown'}", False
    elif name in READ_NAMES or name.startswith(("search_", "get_", "list_")) or (name == "intent" and args.get("action") == "list"):
        kind, target, persistent = EffectType.READ, f"tool://{name}", False
    elif name in FILE_WRITE_NAMES:
        kind, target, persistent = EffectType.WRITE, f"workspace://{path or 'unknown'}", True
    elif name in FILE_DELETE_NAMES:
        kind, target, persistent = EffectType.DELETE, f"workspace://{path or 'unknown'}", True
    elif name == "apply_patch":
        # The call is a batch action. Per-file effects are materialized after
        # success from the explicit patch headers, not guessed from its name.
        kind, target, persistent = EffectType.WRITE, f"workspace://patch/{_sha(str(args.get('input') or ''))}", False
    elif name == "send_email":
        kind, target, persistent = EffectType.SEND, f"external://email/{_sha(_canonical(args.get('recipients')))}", True
    elif name in {"share_file", "update_file_permission"}:
        kind = EffectType.PERMISSION_CHANGE
        file_id = args.get("file_id") or args.get("file") or "unknown"
        principal = args.get("email") or args.get("recipient") or "unknown"
        target, persistent = f"cloud://file/{file_id}/permission/{principal}", True
    elif name in {"create_calendar_event", "mock_scheduler_create"}:
        kind, target, persistent = EffectType.CREATE, f"tool://{name}", True
    elif name == "add_calendar_event_participants":
        kind, target, persistent = EffectType.PERMISSION_CHANGE, f"calendar://{args.get('event_id') or 'unknown'}", True
    elif name == "cancel_calendar_event":
        kind, target, persistent = EffectType.DELETE, f"calendar://{args.get('event_id') or 'unknown'}", True
    elif name == "mock_exec":
        # The mock surface returns a fixture and never executes on the host.
        kind, target, persistent = EffectType.EXECUTE, f"simulated://exec/{_sha(str(args.get('command') or ''))}", False
    elif name in {"exec", "bash"}:
        kind, target, persistent = EffectType.EXECUTE, f"shell://{_sha(str(args.get('command') or ''))}", True
    else:
        kind, target, persistent = EffectType.UNKNOWN, f"tool://{name}", True
    return Effect(kind, target, name, persistent=persistent,
                  reversible=kind not in {EffectType.SEND, EffectType.DELETE, EffectType.EXECUTE},
                  metadata={"extraction_evidence": {"basis": "contract" if kind is not EffectType.UNKNOWN else "unknown",
                                                    "method": "finite_native_tool_map_v1"}})


class NativeOpenClawGraph:
    """Incremental deterministic event assembler; feed events in sequence."""

    def __init__(self) -> None:
        self.content = ContentIndex()
        self.graph = EffectGraph(content_index=self.content)
        self.current_turn = 0
        self.last_seq = -1
        self.events_seen = 0
        self.event_anchor_by_seq: dict[int, str] = {}
        self.message_events = 0
        self.result_events_seen = 0
        self.user_messages: list[dict[str, Any]] = []
        self.observations: list[dict[str, Any]] = []
        self.calls: dict[str, dict[str, Any]] = {}
        self.results: dict[str, dict[str, Any]] = {}
        self.writes: list[dict[str, Any]] = []
        self.cloud_mutations: list[dict[str, Any]] = []
        self.snapshots: list[dict[str, Any]] = []
        self.external_changes: list[dict[str, Any]] = []
        self.externally_verified_sends: list[str] = []
        self.unknown_event_types: dict[str, int] = {}
        self.duplicate_call_ids: list[str] = []
        self.orphan_results: list[str] = []
        self.orphan_failed_dispatch: list[str] = []
        self.orphan_unclassified: list[str] = []
        self.malformed_messages: list[int] = []

    def ingest(self, seq: int, event: dict[str, Any]) -> None:
        if seq <= self.last_seq:
            raise ValueError("native events must be strictly ordered")
        self.last_seq = seq
        self.events_seen += 1
        if event.get("type") != "message":
            kind = str(event.get("type") or "missing")
            self.unknown_event_types[kind] = self.unknown_event_types.get(kind, 0) + 1
            node_id = self.graph.add_observation("runtime_event", f"native {kind}",
                                                 turn=self.current_turn, raw_payload=event)
            self.graph.node(node_id).data.update(native_seq=seq, native_event_type=kind)
            self.event_anchor_by_seq[seq] = node_id
            return
        self.message_events += 1
        message = event.get("message")
        if not isinstance(message, dict):
            self.malformed_messages.append(seq)
            node_id = self.graph.add_observation("malformed_message", "malformed native message",
                                                 turn=self.current_turn, raw_payload=event)
            self.graph.node(node_id).data["native_seq"] = seq
            self.event_anchor_by_seq[seq] = node_id
            return
        role = message.get("role")
        if role == "user":
            self.current_turn += 1
            text = _text(message.get("content"))
            node_id = self.graph.add_observation("user", "trusted user message", turn=self.current_turn,
                                                 integrity="trusted", raw_payload=text)
            self.graph.node(node_id).data["native_seq"] = seq
            self.event_anchor_by_seq[seq] = node_id
            self.user_messages.append({"seq": seq, "text": text, "node_id": node_id})
            self.observations.append({"seq": seq, "node_id": node_id, "source": "user", "text": text,
                                      "tool": None, "path": None, "call_id": None})
        elif role == "assistant":
            content = message.get("content") or []
            if isinstance(content, str):
                content = [{"type": "text", "text": content}]
            assistant_text = _text(content)
            output_id = self.graph.add_observation("assistant_output", "visible assistant message",
                                                   turn=self.current_turn, raw_payload=content)
            self.graph.node(output_id).data["native_seq"] = seq
            self.event_anchor_by_seq[seq] = output_id
            if assistant_text:
                self.observations.append({"seq": seq, "node_id": output_id,
                                          "source": "assistant_output", "text": assistant_text,
                                          "tool": None, "path": None, "call_id": None})
            for part in content:
                if not isinstance(part, dict):
                    continue
                if part.get("type") == "toolCall":
                    self._call(seq, part)
        elif role == "toolResult":
            self.event_anchor_by_seq[seq] = self._result(seq, message)
        else:
            self.malformed_messages.append(seq)
            node_id = self.graph.add_observation("unrecognized_message", f"native role {role}",
                                                 turn=self.current_turn, raw_payload=message)
            self.graph.node(node_id).data["native_seq"] = seq
            self.event_anchor_by_seq[seq] = node_id

    def _call(self, seq: int, part: dict[str, Any]) -> None:
        call_id, tool = part.get("id"), part.get("name")
        args = part.get("arguments")
        if not isinstance(call_id, str) or not isinstance(tool, str):
            self.malformed_messages.append(seq)
            return
        if call_id in self.calls:
            self.duplicate_call_ids.append(call_id)
            node_id = self.graph.add_observation("duplicate_tool_call", f"duplicate call {call_id}",
                                                 turn=self.current_turn, raw_payload=part)
            self.graph.node(node_id).data["native_seq"] = seq
            return
        if not isinstance(args, dict):
            args = {"_raw_arguments": args}
        action_id = self.graph.add_action(tool, args, turn=self.current_turn, call_id=call_id)
        action = self.graph.node(action_id)
        action.data.update(native_seq=seq, parameter_fields={key: value for key, value in _scalar_fields(args)
                                                              if len(value) <= 256})
        effect = _effect(tool, args)
        effect.id = self.graph._new_id("eff")
        effect.turn = self.current_turn
        self.graph.add_effect(effect, action_id=action_id)
        self.calls[call_id] = {"seq": seq, "turn": self.current_turn, "tool": _tool_name(tool),
                               "surface": "agentdojo" if tool.startswith("agentdojo__") else "native",
                               "args": args, "action_id": action_id, "effect_id": effect.id}
        # An exact match is a possible source of a parameter, not a causal edge.
        source_summary: dict[str, dict[str, Any]] = {}
        for field_name, value in _auditable_values(args):
            candidate_count = 0
            for observation in self.observations:
                if observation["seq"] >= seq or value.casefold() not in observation["text"].casefold():
                    continue
                candidate_count += 1
                self.graph._edge(observation["node_id"], action_id, EdgeType.PARAMETER_CANDIDATE,
                                 self.current_turn,
                                 evidence={"basis": "candidate", "method": "exact_value_match",
                                           "parameter_field": field_name, "value_sha256": _sha(value)})
            summary = source_summary.setdefault(field_name, {"exact_candidate_edges": 0,
                                                             "status": "no_exact_prior_match"})
            summary["exact_candidate_edges"] += candidate_count
            if candidate_count:
                summary["status"] = "candidate_only_not_causal"
        for field_name, value in _scalar_fields(args):
            source_summary.setdefault(field_name, {"exact_candidate_edges": 0,
                                                    "status": "not_indexed_short_or_long_value"
                                                    if len(value) < 4 or len(value) > 256 else
                                                    "no_exact_prior_match"})
        action.data["parameter_source_summary"] = source_summary

    def _result(self, seq: int, message: dict[str, Any]) -> str:
        self.result_events_seen += 1
        call_id = message.get("toolCallId")
        if not isinstance(call_id, str) or call_id not in self.calls or call_id in self.results:
            self.orphan_results.append(str(call_id))
            result_text = _text(message.get("content"))
            missing_tool = TOOL_NOT_FOUND.fullmatch(result_text.strip())
            failed_dispatch = (bool(message.get("isError")) and missing_tool is not None
                               and missing_tool.group(1) == message.get("toolName"))
            (self.orphan_failed_dispatch if failed_dispatch else self.orphan_unclassified).append(str(call_id))
            node_id = self.graph.add_observation("orphan_tool_result", "result without retained call",
                                                 turn=self.current_turn,
                                                 integrity="untrusted_or_unknown", raw_payload=message)
            self.graph.node(node_id).data.update(native_seq=seq, call_id=call_id,
                                                 source_tool=message.get("toolName"),
                                                 result_sha256=_sha(result_text),
                                                 coverage_gap="missing_call_failed_dispatch" if failed_dispatch
                                                 else "missing_call_unclassified")
            self.observations.append({"seq": seq, "node_id": node_id, "source": "orphan_tool_result",
                                      "text": result_text, "tool": message.get("toolName"),
                                      "path": None, "call_id": call_id})
            return node_id
        call = self.calls[call_id]
        result_text = _text(message.get("content"))
        success = not bool(message.get("isError"))
        tool, path = call["tool"], _path(call["args"])
        object_id = f"workspace://{path}" if success and tool in FILE_READ_NAMES and path else None
        node_id = self.graph.add_observation("tool_result", f"{tool} result", turn=call["turn"],
                                             integrity="untrusted_or_unknown", object_id=object_id,
                                             raw_payload=message.get("content"),
                                             object_fingerprint=_sha(result_text) if object_id else None)
        node = self.graph.node(node_id)
        node.data.update(native_seq=seq, call_id=call_id, source_tool=tool,
                         result_sha256=_sha(result_text), result_bytes=len(result_text.encode()),
                         **({"path": path} if path else {}))
        self.graph._edge(call["action_id"], node_id, EdgeType.RETURNS, call["turn"],
                         evidence={"basis": "observed", "method": "native_tool_call_id"})
        self.results[call_id] = {"seq": seq, "text": result_text, "node_id": node_id,
                                 "success": success, "call_id": call_id}
        self.observations.append({"seq": seq, "node_id": node_id, "source": "tool_result",
                                  "text": result_text, "tool": tool, "path": path, "call_id": call_id})
        self.graph.node(call["action_id"]).data["execution_status"] = "succeeded" if success else "failed"
        self.graph.commit_effect(call["effect_id"], succeeded=success, result_summary=result_text,
                                 evidence={"basis": "reported", "method": "native_tool_result_status"})
        if success and call["surface"] == "agentdojo" and tool in {
                "create_file", "delete_file", "share_file", "update_file_permission"}:
            self.cloud_mutations.append({"seq": seq, "call_id": call_id, "tool": tool,
                                         "target": self.graph.node(call["effect_id"]).data["target"],
                                         "confirmation": "reported_tool_success"})
        if success and tool == "apply_patch":
            for operation, patch_path in PATCH_PATH.findall(str(call["args"].get("input") or "")):
                patch_path = patch_path.strip()
                kind = (EffectType.DELETE if operation == "Delete" else
                        EffectType.CREATE if operation == "Add" else EffectType.WRITE)
                per_file = Effect(kind, f"workspace://{patch_path}", "apply_patch_file",
                                  persistent=True, reversible=kind is not EffectType.DELETE,
                                  metadata={"extraction_evidence": {"basis": "observed",
                                                                    "method": "native_patch_header"}})
                per_file.id = self.graph._new_id("eff")
                self.graph.add_effect(per_file, action_id=call["action_id"], turn=call["turn"])
                state_id = self.graph.commit_effect(per_file.id, succeeded=True,
                                                    result_summary=f"patch {operation} {patch_path}",
                                                    evidence={"basis": "reported", "method": "native_patch_success"})
                self.writes.append({"seq": seq, "call_seq": call["seq"], "call_id": call_id,
                                    "turn": call["turn"], "path": patch_path, "tool": "apply_patch",
                                    "written_value_sha256": None, "written_value": None,
                                    "state_node_id": state_id})
        if success and call["surface"] == "native" and tool in FILE_WRITE_NAMES | FILE_DELETE_NAMES and path:
            args = call["args"]
            value = args.get("content") if tool != "edit" else args.get("newText")
            if value is None:
                value = args.get("text")
            self.writes.append({"seq": seq, "call_seq": call["seq"], "call_id": call_id,
                                "turn": call["turn"],
                                "path": path, "tool": tool,
                                "written_value_sha256": _sha(str(value)) if value is not None else None,
                                "written_value": str(value) if value is not None else None,
                                "state_node_id": self.graph.state_node(f"workspace://{path}")})
        return node_id

    def ingest_workspace_snapshot(self, event: dict[str, Any]) -> None:
        """Attach a turn-end filesystem diff; never infer it from tool success.

        Snapshot events are supplied by the runner's before/after filesystem
        observation. They are interleaved at user-turn boundaries. A native
        tool write and a matching snapshot describe one change, not two.
        """
        path = event.get("path")
        if not isinstance(path, str) or not path:
            raise ValueError("workspace snapshot requires a path")
        turn = int(event["turn"])
        if turn != self.current_turn:
            raise ValueError("workspace snapshot must be ingested at its turn boundary")
        before, after = event.get("before_sha256"), event.get("after_sha256")
        if before == after:
            raise ValueError("unchanged workspace snapshot is not a transition")
        matched_writes = [write for write in self.writes if write["turn"] == turn
                          and _same_workspace_path(write["path"], path)]
        record = {"turn": turn, "path": path, "before_sha256": before,
                  "after_sha256": after, "native_write_call_id": None,
                  "native_write_payload_matches": None, "source": "turn_end_filesystem_snapshot"}
        record["ingested_after_native_seq"] = self.last_seq
        if matched_writes:
            write = matched_writes[-1]
            state_id = write["state_node_id"]
            record["native_write_call_id"] = write["call_id"]
            if write["written_value_sha256"] is not None:
                record["native_write_payload_matches"] = write["written_value_sha256"] == after
            if state_id:
                state = self.graph.node(state_id)
                state.data.update(fingerprint=after, snapshot_version=event.get("version"),
                                  evidence={"basis": "observed", "method": "turn_end_filesystem_snapshot",
                                            "before": before, "after": after})
                effect = self.graph.node(state.data["effect_id"])
                effect.data["commit_evidence"] = state.data["evidence"]
                record["state_node_id"] = state_id
                self.snapshots.append(record)
                return
        # Background changes and pre-existing fixture files have no matched
        # native tool write. Preserve their observed transition explicitly.
        object_id = f"workspace://{path}"
        observation_id = self.graph.add_observation("workspace_snapshot_before",
                                                     f"workspace/{path} before change", turn=turn,
                                                     object_id=object_id,
                                                     raw_payload={"before_sha256": before})
        action_id = self.graph.add_action("workspace_snapshot_change",
                                          {"path": path, "op": event.get("op")}, turn=turn,
                                          observation_ids=(observation_id,),
                                          source_evidence={"basis": "observed", "method": "filesystem_diff"})
        kind = EffectType.DELETE if event.get("op") == "delete" else (
            EffectType.CREATE if event.get("op") == "create" else EffectType.WRITE)
        effect = Effect(kind, object_id, "workspace_snapshot_change", persistent=True,
                        metadata={"extraction_evidence": {"basis": "observed", "method": "filesystem_diff"}})
        effect.id = self.graph._new_id("eff")
        self.graph.add_effect(effect, action_id=action_id, turn=turn)
        state_id = self.graph.commit_effect(effect.id, succeeded=True,
                                            result_summary=f"filesystem {event.get('op')} {path}",
                                            transition=StateTransition(object_id=object_id,
                                                                       before=before, after=after,
                                                                       method="turn_end_filesystem_snapshot"))
        record["state_node_id"] = state_id
        self.snapshots.append(record)

    def candidate_sources(self, value: str, *, before_seq: int) -> list[dict[str, Any]]:
        target = str(value).casefold()
        if not target:
            return []
        candidates = []
        for observation in self.observations:
            if observation["seq"] >= before_seq or target not in observation["text"].casefold():
                continue
            path = observation["path"]
            earlier_writes = [write for write in self.writes if path
                              and _same_workspace_path(write["path"], path)
                              and write["seq"] < observation["seq"]]
            prior_snapshot_changes = [snapshot for snapshot in self.snapshots if path
                                      and _same_workspace_path(snapshot["path"], path)
                                      and snapshot["ingested_after_native_seq"] < observation["seq"]]
            prior_opaque_exec = [call_id for call_id, call in self.calls.items()
                                 if call["tool"] in {"exec", "bash"}
                                 and call["seq"] < observation["seq"]
                                 and call["surface"] == "native"
                                 and self.results.get(call_id, {}).get("success")]
            candidates.append({"node_id": observation["node_id"], "source": observation["source"],
                               "tool": observation["tool"], "call_id": observation["call_id"],
                               "result_seq": observation["seq"], "path": path,
                               "sha256": _sha(observation["text"]), "text": observation["text"],
                               "path_written_earlier_in_session": bool(earlier_writes or prior_snapshot_changes
                                                                        or prior_opaque_exec),
                               "candidate_method": "exact_value_in_prior_observation"})
        return candidates

    def ingest_external_state_diff(self, before: dict[str, Any], after: dict[str, Any]) -> None:
        """Record the runner's final external-state diff without call causality.

        This is a post-run oracle of *what changed*, not an online per-call
        state hook. Exact sent-mail records can additionally confirm send
        outcomes when their recipients/subject/body match a unique call.
        """
        for namespace in sorted(set(before) | set(after)):
            before_value, after_value = before.get(namespace), after.get(namespace)
            if before_value == after_value:
                continue
            target = f"external://{namespace}"
            before_hash, after_hash = _sha(_canonical(before_value)), _sha(_canonical(after_value))
            observation_id = self.graph.add_observation("external_state_after",
                                                        f"{namespace} final state", turn=self.current_turn,
                                                        raw_payload=after_value)
            action_id = self.graph.add_action("external_state_observed_diff",
                                              {"namespace": namespace}, turn=self.current_turn,
                                              observation_ids=(observation_id,),
                                              source_evidence={"basis": "observed", "method": "case_before_after_state"})
            effect = Effect(EffectType.WRITE, target, "external_state_observed_diff", persistent=True,
                            metadata={"extraction_evidence": {"basis": "observed",
                                                              "method": "case_before_after_state"}})
            effect.id = self.graph._new_id("eff")
            self.graph.add_effect(effect, action_id=action_id, turn=self.current_turn)
            state_id = self.graph.commit_effect(effect.id, succeeded=True,
                                                result_summary=f"external {namespace} changed",
                                                transition=StateTransition(target, before_hash, after_hash,
                                                                           method="case_before_after_state"))
            self.external_changes.append({"namespace": namespace, "before_sha256": before_hash,
                                          "after_sha256": after_hash, "state_node_id": state_id,
                                          "attribution": "run_level_not_per_call"})
        before_sent = ((before.get("inbox") or {}).get("sent") or [])
        after_sent = ((after.get("inbox") or {}).get("sent") or [])
        if not isinstance(before_sent, list) or not isinstance(after_sent, list):
            return
        before_ids = {str(item.get("id_")) for item in before_sent if isinstance(item, dict)}
        new_sent = [item for item in after_sent if isinstance(item, dict)
                    and str(item.get("id_")) not in before_ids]
        matched_items: set[str] = set()
        for call_id, call in self.calls.items():
            if call["tool"] != "send_email" or call_id not in self.results or not self.results[call_id]["success"]:
                continue
            args = call["args"]
            matching = [item for item in new_sent if str(item.get("id_")) not in matched_items
                        and item.get("recipients") == args.get("recipients")
                        and item.get("subject") == args.get("subject")
                        and item.get("body") == args.get("body")]
            if len(matching) != 1:
                continue
            item = matching[0]
            matched_items.add(str(item.get("id_")))
            effect = self.graph.node(call["effect_id"])
            effect.data["external_state_confirmation"] = {
                "basis": "observed", "method": "unique_sent_record_exact_fields",
                "record_id": str(item.get("id_")), "record_sha256": _sha(_canonical(item))}
            observation_id = self.graph.add_observation("external_sent_record",
                                                        "observed sent email", turn=self.current_turn,
                                                        raw_payload=item)
            self.graph._edge(observation_id, effect.id, EdgeType.CONFIRMS, self.current_turn,
                             evidence={"basis": "observed", "method": "unique_sent_record_exact_fields"})
            self.externally_verified_sends.append(call_id)

    def coverage(self) -> dict[str, Any]:
        missing = [call_id for call_id in self.calls if call_id not in self.results]
        unknown = [call_id for call_id, call in self.calls.items()
                   if self.graph.node(call["effect_id"]).data["kind"] == EffectType.UNKNOWN.value]
        return {"native_events": self.events_seen,
                "native_events_with_audit_anchor": len(self.event_anchor_by_seq),
                "message_events": self.message_events,
                "user_messages": len(self.user_messages), "tool_calls": len(self.calls),
                "tool_result_events": self.result_events_seen,
                "paired_tool_results": len(self.results), "tool_results": len(self.results), "unpaired_calls": missing,
                "orphan_results": self.orphan_results, "duplicate_call_ids": self.duplicate_call_ids,
                "orphan_failed_dispatch": self.orphan_failed_dispatch,
                "orphan_unclassified": self.orphan_unclassified,
                "malformed_messages": self.malformed_messages, "unknown_effect_calls": unknown,
                "file_writes": len(self.writes),
                "cloud_mutations": len(self.cloud_mutations),
                "workspace_snapshot_transitions": len(self.snapshots),
                "snapshot_bound_native_writes": sum(bool(row["native_write_call_id"]) for row in self.snapshots),
                "external_state_namespaces_changed": len(self.external_changes),
                "externally_verified_sends": len(self.externally_verified_sends),
                "parameter_candidate_edges": sum(edge.edge_type is EdgeType.PARAMETER_CANDIDATE
                                                 for edge in self.graph.edges),
                "state_nodes": sum(node.node_type is NodeType.STATE for node in self.graph.nodes.values())}

    def assert_complete_process(self) -> None:
        report = self.coverage()
        if report["native_events"] != report["native_events_with_audit_anchor"]:
            raise ValueError("native event audit-anchor coverage failure")
        for key in ("unpaired_calls", "orphan_results", "duplicate_call_ids",
                    "malformed_messages", "unknown_effect_calls"):
            if report[key]:
                raise ValueError(f"native transcript process coverage failure: {key}={report[key]}")

    def assert_known_tool_dispatch_coverage(self) -> None:
        """Allow only a narrow, explicit no-execution missing-call exception.

        Every observed executed tool call still requires a paired result and a
        known effect. A runtime "Tool X not found" result has no dispatched
        tool effect, but its proposed arguments are unavailable and remain a
        transcript-level coverage gap.
        """
        report = self.coverage()
        if report["native_events"] != report["native_events_with_audit_anchor"]:
            raise ValueError("native event audit-anchor coverage failure")
        for key in ("unpaired_calls", "orphan_unclassified", "duplicate_call_ids",
                    "malformed_messages", "unknown_effect_calls"):
            if report[key]:
                raise ValueError(f"known-tool dispatch coverage failure: {key}={report[key]}")

    def export(self, *, include_raw_evidence: bool = False) -> dict[str, Any]:
        return {"schema": "gwg-native-openclaw-process-v1", "coverage": self.coverage(),
                "graph": self.graph.to_dict(),
                "content_index": self.content.export(include_raw=include_raw_evidence)}

    def save_audit(self, path: Path) -> None:
        """Persist a self-contained audit artifact, including exact raw evidence.

        The in-memory graph's content references are not independently
        recoverable; callers must explicitly save this full artifact when a
        later human or semantic audit is expected.
        """
        if path.exists():
            raise FileExistsError(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.export(include_raw_evidence=True),
                                   ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")


def build_native_graph(db_path: Path, *, workspace_events: Iterable[dict[str, Any]] = ()) -> NativeOpenClawGraph:
    builder = NativeOpenClawGraph()
    by_turn: dict[int, list[dict[str, Any]]] = {}
    for item in workspace_events:
        by_turn.setdefault(int(item["turn"]), []).append(item)
    for seq, event in read_native_events(db_path):
        if (event.get("type") == "message" and (event.get("message") or {}).get("role") == "user"
                and builder.current_turn > 0):
            for item in by_turn.pop(builder.current_turn, []):
                builder.ingest_workspace_snapshot(item)
        builder.ingest(seq, event)
    for item in by_turn.pop(builder.current_turn, []):
        builder.ingest_workspace_snapshot(item)
    if by_turn:
        raise ValueError(f"workspace snapshots reference absent user turns: {sorted(by_turn)}")
    return builder
