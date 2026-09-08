"""Passive AgentLAB trace recorder.

The recorder observes an existing AgentLAB/AgentDojo run without changing its
decision path.  It is deliberately separate from :class:`GreatWallGuardRuntime`:
experiments need to compare successful and failed attacks even when the guard
would have blocked the action.  The same finite Effect vocabulary and graph
serialization are used, but authorization is labelled ``observe_only``.
"""

from __future__ import annotations

import re
from contextlib import contextmanager
from dataclasses import asdict
from typing import Any, Iterator

from .graph import EffectGraph, compact_summary, digest
from .content import ContentIndex
from .metrics import summarize_runtime
from .model import Effect, EffectType, GraphEdge, GraphNode, NodeType, StateTransition
from .runtime import GreatWallGuardRuntime
from .trace import TraceEventType


def _text(value: Any) -> str:
    return value if isinstance(value, str) else str(value)


class AgentLabGraphRecorder:
    """Collect user/tool/background events into one cross-session graph."""

    def __init__(self, scope, *, content_index: ContentIndex | None = None) -> None:
        self.runtime = GreatWallGuardRuntime(scope, graph=EffectGraph(content_index=content_index))
        self._latest_observation: dict[int, str] = {}
        self._session_for_env: dict[int, int] = {}
        self._env_for_workspace: dict[int, int] = {}
        self._action_for_env: dict[int, tuple[str, str, Effect]] = {}
        self._context_snapshot_by_env: dict[int, str] = {}
        self._model_boundary_by_env: dict[int, tuple[str, ...]] = {}
        self._session_counter = 0
        self._step = 0
        self.raw_payload_chars = 0
        self.sessions: list[dict[str, Any]] = []

    @property
    def graph(self):
        return self.runtime.graph

    def _turn(self) -> int:
        self._step += 1
        self.runtime.turn = max(self.runtime.turn, self._step)
        return self._step

    def begin_session(self, env: Any, user_message: str, *, phase: str = "unknown") -> str:
        """Record one user turn and bind subsequent tool calls for ``env``."""
        env_key = id(env)
        self._model_boundary_by_env.pop(env_key, None)
        turn = self._turn()
        self._session_counter += 1
        session_id = self._session_counter
        node_id = self.graph.add_observation(
            "user",
            "user message",
            turn=turn,
            integrity="user",
            object_id=f"session://{session_id}",
            raw_payload=user_message,
        )
        self.runtime.trace.record(
            TraceEventType.OBSERVATION,
            turn=turn,
            node_id=node_id,
            summary="user message",
            payload=user_message,
            data={"source": "user", "integrity": "user", "phase": phase},
        )
        self._latest_observation[env_key] = node_id
        self._session_for_env[env_key] = session_id
        workspace = getattr(env, "workspace", None)
        if workspace is not None:
            self._env_for_workspace[id(workspace)] = env_key
        self.raw_payload_chars += len(_text(user_message))
        self.sessions.append(
            {
                "session_id": session_id,
                "env_id": env_key,
                "phase": phase,
                "turn": turn,
                "message_digest": digest(user_message),
                "message_chars": len(_text(user_message)),
                "user_node_id": node_id,
            }
        )
        return node_id

    def record_context_load(self, env: Any, workspace: Any) -> None:
        """Record files loaded into the system prompt at session start.

        OpenClaw reads MEMORY.md and other bootstrap files outside the tool
        loop.  Without this hook, a cross-session state update would appear in
        the graph but its later activation would be invisible.
        """
        env_key = id(env)
        files = getattr(workspace, "files", {}) or {}
        snapshot = digest({name: getattr(value, "content", "") for name, value in files.items() if getattr(value, "exists", False)})
        if self._context_snapshot_by_env.get(env_key) == snapshot:
            return
        self._context_snapshot_by_env[env_key] = snapshot
        for name, file_obj in files.items():
            if not getattr(file_obj, "exists", False):
                continue
            turn = self._turn()
            object_id = f"file://workspace/{name}"
            previous_state_id = self.graph.state_node(object_id)
            node_id = self.graph.add_observation(
                "workspace_bootstrap",
                f"load {name}",
                turn=turn,
                integrity="file" if name == "MEMORY.md" else "system",
                object_id=object_id,
                raw_payload=getattr(file_obj, "content", ""),
            )
            self.runtime.trace.record(
                TraceEventType.OBSERVATION,
                turn=turn,
                node_id=node_id,
                summary=f"load {name}",
                payload=getattr(file_obj, "content", ""),
                data={
                    "source": "workspace_bootstrap",
                    "file": name,
                    "integrity": "file" if name == "MEMORY.md" else "system",
                    "session_id": self._session_for_env.get(env_key),
                },
            )
            if previous_state_id:
                self.runtime.trace.record(
                    TraceEventType.STATE_READ,
                    turn=turn,
                    node_id=node_id,
                    related_ids=(previous_state_id,),
                    summary=f"load state {object_id}",
                    data={"object_id": object_id, "source": "workspace_bootstrap"},
                )
            self._latest_observation[env_key] = node_id
            self.raw_payload_chars += len(_text(getattr(file_obj, "content", "")))

    def record_model_boundary(self, env: Any, *, phase: str, payload: Any,
                              call_id: str) -> str:
        """Record observable model I/O without claiming internal dependence.

        An input payload contains the actual messages and tool schemas; an
        output payload contains the visible response. One context reference
        avoids connecting every historical observation to every new action.
        The full context remains in the optional evidence index, not graph text.
        """
        if phase not in {"input", "output"}:
            raise ValueError("model phase must be input or output")
        env_key = id(env)
        turn = self._turn()
        source = "model_input" if phase == "input" else "assistant_output"
        node_id = self.graph.add_observation(
            source, f"model {phase}", turn=turn, integrity="unknown",
            object_id=f"model://{call_id}/{phase}", raw_payload=payload,
        )
        self.graph.node(node_id).data.update(
            model_call_id=call_id, session_id=self._session_for_env.get(env_key))
        self.runtime.trace.record(
            TraceEventType.OBSERVATION, turn=turn, node_id=node_id,
            summary=f"model {phase}", payload=payload,
            data={"source": source, "model_call_id": call_id},
        )
        previous = self._model_boundary_by_env.get(env_key, ())
        self._model_boundary_by_env[env_key] = (node_id,) if phase == "input" else (*previous[:1], node_id)
        self._latest_observation[env_key] = node_id
        self.raw_payload_chars += len(_text(payload))
        return node_id

    def _source_ids(self, env: Any) -> tuple[str, ...]:
        if id(env) in self._model_boundary_by_env:
            return self._model_boundary_by_env[id(env)]
        node_id = self._latest_observation.get(id(env))
        return (node_id,) if node_id else ()

    def _source_evidence(self, env: Any) -> dict[str, Any]:
        if id(env) in self._model_boundary_by_env:
            return {"basis": "observed", "method": "model_call_boundary",
                    "meaning": "context_and_response_association_not_causal_use"}
        return {"basis": "inferred", "method": "latest_observation_proxy"}

    @staticmethod
    def _target(tool: str, args: dict[str, Any], kind: EffectType) -> str:
        def first(*keys: str) -> str:
            for key in keys:
                value = args.get(key)
                if value is not None and _text(value):
                    return _text(value)
            return ""

        if kind is EffectType.SEND:
            value = first("to", "recipient", "recipients", "email", "cc")
            return "external://" + (compact_summary(value, 120) if value else "unknown")
        if kind is EffectType.EXECUTE:
            return "shell://" + digest(first("command", "cmd"))
        path = first("path", "filename", "file", "file_id", "id", "object")
        if path:
            # AgentLAB cases mix logical targets (``memory://...``) and
            # workspace-relative names (``MEMORY.md``).  Preserve an
            # already-qualified URI; otherwise normalize once so e.g.
            # ``file://workspace/report.md`` does not become
            # ``file://workspace/workspace/report.md``.
            if "://" in path:
                return path
            # ``MEMORY.md`` is a persistent workspace file, not a logical
            # memory URI.  Only memory-named tools or a memory/ path use the
            # memory:// namespace.
            normalized_path = path.lstrip("/")
            if "memory" in tool.lower() or normalized_path.lower().startswith("memory/"):
                return "memory://" + normalized_path
            return "file://workspace/" + normalized_path
        if kind is EffectType.READ:
            return "tool://" + tool + "/" + digest(args)
        return "tool://" + tool

    @staticmethod
    def infer_effect(tool: str, args: dict[str, Any]) -> Effect:
        name = tool.lower()
        # Prefer the operation verb over object nouns.  For example,
        # ``get_sent_emails`` is a read, not an external send merely because
        # the resource name contains ``email``.  This finite vocabulary is
        # intentionally conservative; unknown verbs remain ``unknown``.
        tokens = tuple(token for token in re.split(r"[^a-z0-9]+", name) if token)
        if any(token in tokens for token in ("delete", "remove", "cancel", "revoke")):
            kind = EffectType.DELETE
        elif any(token in tokens for token in ("read", "get", "search", "list", "fetch", "query", "current", "lookup", "find")):
            kind = EffectType.READ
        elif any(token in tokens for token in ("send", "post", "publish")):
            kind = EffectType.SEND
        elif any(token in tokens for token in ("share", "permission", "access", "participant")):
            kind = EffectType.PERMISSION_CHANGE
        elif any(token in tokens for token in ("exec", "shell", "bash", "command", "run", "script")):
            kind = EffectType.EXECUTE
        elif any(token in tokens for token in ("create", "append", "write", "edit", "update", "modify", "save", "draft")):
            kind = EffectType.CREATE if "create" in tokens else EffectType.WRITE
        else:
            # Unknown tools remain explicit in the graph; the recorder does
            # not silently coerce them into a safe read.
            kind = EffectType.UNKNOWN
        target = AgentLabGraphRecorder._target(tool, args, kind)
        return Effect(
            kind,
            target,
            operation=tool,
            persistent=kind is not EffectType.READ,
            reversible=kind not in {EffectType.DELETE, EffectType.SEND, EffectType.EXECUTE},
            metadata={"extraction_evidence": {"basis": "inferred", "method": "tool_name_tokens_v1"},
                      "source_evidence": {"basis": "inferred", "method": "latest_observation_proxy"}},
        )

    def before_tool_call(self, env: Any, tool: str, args: dict[str, Any], *,
                         call_id: str | None = None) -> str:
        """Record a proposed action before the original environment executes."""
        turn = self._turn()
        source_ids = self._source_ids(env)
        action_id = self.graph.add_action(tool, args, turn=turn, observation_ids=source_ids,
                                          source_evidence=self._source_evidence(env))
        # Malformed JSON tool arguments should not make passive telemetry
        # alter the original environment's exception/return path.  Keep the
        # raw value in the action digest and infer a conservative unknown
        # effect from a mapping wrapper.
        effect_args = args if isinstance(args, dict) else {"_raw_args": args}
        effect = self.infer_effect(tool, effect_args)
        effect.metadata["source_evidence"] = self._source_evidence(env)
        effect.source_node_ids = source_ids
        effect.turn = turn
        effect.id = self.graph._new_id("eff")
        self.graph.add_effect(effect, action_id=action_id, turn=turn)
        action = self.graph.node(action_id)
        if call_id is not None:
            action.data["call_id"] = call_id
        action.data.update({"decision": "observe_only", "reason": "passive trace capture"})
        self.runtime.trace.record(
            TraceEventType.ACTION_PROPOSED,
            turn=turn,
            node_id=action_id,
            related_ids=source_ids,
            summary=f"{tool}()",
            payload=args,
            data={"tool": tool, "decision": "observe_only"},
        )
        self.runtime.trace.record(
            TraceEventType.AUTHORIZATION,
            turn=turn,
            node_id=action_id,
            related_ids=(effect.id,),
            summary="passive trace capture",
            data={"decision": "observe_only"},
        )
        self._action_for_env[id(env)] = (action_id, effect.id, effect)
        self.raw_payload_chars += len(_text(args))
        return action_id

    def after_tool_call(
        self,
        env: Any,
        tool: str,
        result: Any,
        *,
        injected: bool = False,
        success: bool = True,
        transition: StateTransition | None = None,
        read_fingerprint: str | None = None,
    ) -> str:
        env_key = id(env)
        pending = self._action_for_env.pop(env_key, None)
        # The recorder is observational and must never change the outcome of
        # an AgentLAB run.  A custom bridge may bypass the patched
        # ``before_tool_call`` hook; retain the return observation instead of
        # raising a telemetry-only KeyError in that case.
        if pending is None:
            turn = self._turn()
            summary = compact_summary(result)
            node_id = self.graph.add_observation(
                "tool_return",
                f"{tool} result (orphan)",
                turn=turn,
                integrity="untrusted" if injected else "unknown",
                object_id=None,
                raw_payload=result,
            )
            self.runtime.trace.record(
                TraceEventType.OBSERVATION,
                turn=turn,
                node_id=node_id,
                summary=f"{tool} result (orphan)",
                payload=result,
                data={
                    "source": "tool_return",
                    "tool": tool,
                    "integrity": "untrusted" if injected else "unknown",
                    "orphan": True,
                },
            )
            self._latest_observation[env_key] = node_id
            self.raw_payload_chars += len(_text(result))
            return node_id

        action_id, effect_id, effect = pending
        action = self.graph.node(action_id)
        action.data["execution_status"] = "succeeded" if success else "failed"
        effect_node = self.graph.node(effect_id)
        effect_node.data["status"] = "authorized" if success else "failed"
        summary = compact_summary(result)
        effect_node.data["result_summary"] = summary

        # Materialize the returned observation before committing a write.  This
        # prevents a write's own return value from being counted as a read of
        # the state version it just created; only later observations should
        # activate a committed state.
        self.raw_payload_chars += len(_text(result))
        # A tool return is a state observation only for a successful read. A
        # write/send/execute acknowledgement must not look like a later read
        # of the state it changed; otherwise repeated writes create false
        # cross-turn activation edges.
        observation_object_id = effect.target if success and effect.kind is EffectType.READ else None
        previous_state_id = self.graph.state_node(observation_object_id) if observation_object_id else None
        node_id = self.graph.add_observation(
            "tool_return",
            f"{tool} result",
            turn=effect.turn,
            integrity="untrusted" if injected else "unknown",
            object_id=observation_object_id,
            raw_payload=result,
            object_fingerprint=read_fingerprint,
        )
        if action.data.get("call_id") is not None:
            self.graph.node(node_id).data["call_id"] = action.data["call_id"]
        self.runtime.trace.record(
            TraceEventType.OBSERVATION,
            turn=effect.turn,
            node_id=node_id,
            related_ids=(action_id,),
            summary=f"{tool} result",
            payload=result,
            data={"source": "tool_return", "tool": tool, "integrity": "untrusted" if injected else "unknown"},
        )
        if previous_state_id and self.graph.node(node_id).data.get("state_match") != "fingerprint_mismatch":
            self.runtime.trace.record(
                TraceEventType.STATE_READ,
                turn=effect.turn,
                node_id=node_id,
                related_ids=(previous_state_id,),
                summary=f"read state {effect.target}",
                data={"object_id": effect.target, "source": "tool_return"},
            )
        if success:
            self.runtime.trace.record(
                TraceEventType.EFFECT_COMMITTED,
                turn=effect.turn,
                node_id=effect_id,
                related_ids=(action_id,),
                summary=f"{effect.kind.value}:{effect.target}",
                data={"effect_kind": effect.kind.value, "target": effect.target, "passive": True},
            )
            # ``commit_effect`` marks even read effects as succeeded; it only
            # materializes a State node for persistent effects.
            self.graph.commit_effect(effect_id, succeeded=True, result_summary=summary,
                                     evidence={"basis": "reported", "method": "tool_return_status"},
                                     transition=transition)
        else:
            self.runtime.trace.record(
                TraceEventType.EFFECT_FAILED,
                turn=effect.turn,
                node_id=effect_id,
                related_ids=(action_id,),
                summary=summary,
                data={"effect_kind": effect.kind.value, "target": effect.target, "passive": True},
            )
            self.graph.commit_effect(effect_id, succeeded=False, result_summary=summary)

        self._latest_observation[env_key] = node_id
        return node_id

    def background_effect(
        self,
        workspace: Any,
        *,
        operation: str,
        target: str,
        kind: EffectType = EffectType.WRITE,
        summary: str = "background persistence",
    ) -> None:
        """Record Flush/Dreaming writes that bypass the tool boundary."""
        # Flush/Dreaming receive a workspace rather than the environment. Map
        # it back to the current env so the background effect inherits the
        # latest tool-return source instead of falling back to only the user
        # message.
        env_key = self._env_for_workspace.get(id(workspace), id(workspace))
        source_id = self._latest_observation.get(env_key)
        source_ids = (source_id,) if source_id else ()
        if not source_ids and self.sessions:
            source_ids = (self.sessions[-1]["user_node_id"],)
        turn = self._turn()
        source_evidence = {"basis": "inferred", "method": "latest_observation_proxy"}
        action_id = self.graph.add_action(operation, {"target": target}, turn=turn,
                                         observation_ids=source_ids, source_evidence=source_evidence)
        effect = Effect(kind, target, operation, persistent=True, reversible=True, source_node_ids=source_ids, turn=turn)
        effect.metadata.update(source_evidence=source_evidence,
                               extraction_evidence={"basis": "declared", "method": "background_adapter"})
        effect.id = self.graph._new_id("eff")
        self.graph.add_effect(effect, action_id=action_id, turn=turn)
        self.graph.node(action_id).data.update({"decision": "observe_only", "execution_status": "succeeded"})
        self.graph.commit_effect(effect.id, succeeded=True, result_summary=summary,
                                 evidence={"basis": "reported", "method": "background_hook_return"})
        self.runtime.trace.record(
            TraceEventType.ACTION_PROPOSED,
            turn=turn,
            node_id=action_id,
            related_ids=source_ids,
            summary=operation,
            data={"tool": operation, "background": True},
        )
        self.runtime.trace.record(
            TraceEventType.EFFECT_COMMITTED,
            turn=turn,
            node_id=effect.id,
            related_ids=(action_id,),
            summary=f"{kind.value}:{target}",
            data={"effect_kind": kind.value, "target": target, "background": True},
        )

    def export(self, *, label: str, result: dict[str, Any] | None = None) -> dict[str, Any]:
        report = summarize_runtime(self.runtime, raw_payload_chars=self.raw_payload_chars)
        return {
            "label": label,
            "result": result or {},
            "sessions": self.sessions,
            "metrics": report,
            "compact_view": self.runtime.compact_context(),
            "minimal_graph": self.runtime.minimal_graph(),
            **self.runtime.trace_dict(),
        }


def _looks_injected(env: Any, tool: str) -> bool:
    if f"__tool__:{tool}" in (getattr(env, "injections", {}) or {}):
        return True
    bridge = getattr(env, "skill_bridge", None)
    return bool(bridge is not None and tool in (getattr(bridge, "_injections", {}) or {}))


def _phase_for_message(message: str) -> str:
    lower = message.lower()
    if "pending" in lower or "standing instruction" in lower:
        return "activation"
    if "summar" in lower and ("today" in lower or "reminder" in lower):
        return "filler"
    if "reminder_" in lower or "earlier i saved" in lower:
        return "activation"
    return "task_or_carrier"


@contextmanager
def patch_agentlab(recorder: AgentLabGraphRecorder) -> Iterator[None]:
    """Temporarily patch AgentLAB boundaries for passive capture."""
    from src import agent as agent_module
    from src import environment as environment_module
    from src import workspace as workspace_module

    original_run = agent_module.VictimAgent.run
    original_execute = environment_module.OpenClawEnvironment.execute_tool
    original_flush = workspace_module.FlushSimulator.flush
    original_dream = workspace_module.DreamingSimulator.run

    def run(agent, user_task: str, *args, **kwargs):
        phase = _phase_for_message(user_task)
        flush_date = kwargs.get("flush_date")
        if args and flush_date is None:
            flush_date = args[0]
        recorder.begin_session(agent.env, user_task, phase=phase)
        if getattr(agent, "workspace", None) is not None:
            recorder.record_context_load(agent.env, agent.workspace)
        return original_run(agent, user_task, *args, **kwargs)

    def execute(env, tool_name: str, args: dict[str, Any], *call_args, **call_kwargs):
        recorder.before_tool_call(env, tool_name, args)
        injected = _looks_injected(env, tool_name)
        try:
            result = original_execute(env, tool_name, args, *call_args, **call_kwargs)
        except Exception as exc:  # preserve original exception semantics
            recorder.after_tool_call(env, tool_name, str(exc), injected=injected, success=False)
            raise
        success = not _text(result).startswith(("Error:", "Tool execution failed:"))
        recorder.after_tool_call(env, tool_name, result, injected=injected, success=success)
        return result

    def flush(workspace, conversation_summary: str, *call_args, **call_kwargs):
        result = original_flush(workspace, conversation_summary, *call_args, **call_kwargs)
        date = call_kwargs.get("date")
        if call_args and date is None:
            date = call_args[0]
        day = date or "current"
        recorder.background_effect(
            workspace,
            operation="memory_flush",
            target=f"memory://daily/{day}",
            summary=conversation_summary,
        )
        return result

    def dream(dreamer, workspace, *call_args, **call_kwargs):
        result = original_dream(dreamer, workspace, *call_args, **call_kwargs)
        memory = workspace.get_file("MEMORY.md")
        if memory and memory.exists:
            recorder.background_effect(
                workspace,
                operation="dreaming",
                target="file://workspace/MEMORY.md",
                summary=memory.content,
            )
        return result

    agent_module.VictimAgent.run = run
    environment_module.OpenClawEnvironment.execute_tool = execute
    workspace_module.FlushSimulator.flush = staticmethod(flush)
    workspace_module.DreamingSimulator.run = dream
    try:
        yield
    finally:
        agent_module.VictimAgent.run = original_run
        environment_module.OpenClawEnvironment.execute_tool = original_execute
        workspace_module.FlushSimulator.flush = staticmethod(original_flush)
        workspace_module.DreamingSimulator.run = original_dream
