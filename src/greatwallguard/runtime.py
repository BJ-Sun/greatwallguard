"""Runtime hooks for an OpenClaw-style tool loop."""

from __future__ import annotations

from typing import Any, Callable, Iterable

from .authorizer import EffectAuthorizer
from .contracts import ToolContractRegistry
from .graph import EffectGraph
from .model import Decision, DecisionKind, Effect, EffectType, StateTransition
from .trace import TraceEventType, TraceRecorder


class GreatWallGuardRuntime:
    """Collect observations, gate tool calls, and commit allowed Effects."""

    def __init__(self, scope, *, contracts: ToolContractRegistry | None = None, graph: EffectGraph | None = None) -> None:
        self.scope = scope
        self.graph = graph or EffectGraph()
        self.contracts = contracts or ToolContractRegistry()
        self.authorizer = EffectAuthorizer(scope)
        self.turn = 0
        self.user_observation_ids: list[str] = []
        self.trace = TraceRecorder()

    def observe_user(self, message: str) -> str:
        node_id = self.graph.add_observation("user", "user task", turn=0, integrity="trusted", raw_payload=message)
        self.user_observation_ids.append(node_id)
        self.trace.record(
            TraceEventType.OBSERVATION,
            turn=0,
            node_id=node_id,
            summary="user task",
            payload=message,
            data={"source": "user", "integrity": "trusted"},
        )
        return node_id

    def observe(
        self,
        source: str,
        summary: str,
        *,
        integrity: str = "unknown",
        turn: int | None = None,
        object_id: str | None = None,
        object_fingerprint: str | None = None,
        raw_payload: Any = None,
    ) -> str:
        node_id = self.graph.add_observation(
            source,
            summary,
            turn=self.turn if turn is None else turn,
            integrity=integrity,
            object_id=object_id,
            raw_payload=raw_payload,
            object_fingerprint=object_fingerprint,
        )
        self.trace.record(
            TraceEventType.OBSERVATION,
            turn=self.turn if turn is None else turn,
            node_id=node_id,
            summary=summary,
            payload=raw_payload,
            data={"source": source, "integrity": integrity, "object_id": object_id},
        )
        if object_id and self.graph.state_node(object_id):
            self.trace.record(
                TraceEventType.STATE_READ,
                turn=self.turn if turn is None else turn,
                node_id=node_id,
                related_ids=(self.graph.state_node(object_id),),
                summary=f"read state {object_id}",
                data={"object_id": object_id},
            )
        return node_id

    def before_tool_call(
        self,
        tool: str,
        arguments: dict[str, Any],
        *,
        source_node_ids: Iterable[str] = (),
        turn: int | None = None,
        call_id: str | None = None,
        execute: Callable[[], Any] | None = None,
    ) -> tuple[Decision, Any | None]:
        current_turn = self.turn if turn is None else turn
        source_node_ids = tuple(source_node_ids)
        action_id = self.graph.add_action(
            tool, arguments, turn=current_turn, observation_ids=source_node_ids,
            call_id=call_id)
        self.trace.record(
            TraceEventType.ACTION_PROPOSED,
            turn=current_turn,
            node_id=action_id,
            related_ids=source_node_ids,
            summary=f"{tool}()",
            payload=arguments,
            data={"tool": tool, **({"call_id": call_id} if call_id is not None else {})},
        )
        effects = self.contracts.infer(tool, arguments)
        for effect in effects:
            effect.source_node_ids = tuple(source_node_ids)
            effect.turn = current_turn
            effect.id = self.graph._new_id("eff")

        decision = self.authorizer.check(effects, self.graph, action_id=action_id)
        self.graph.node(action_id).data["decision"] = decision.kind.value
        self.graph.node(action_id).data["reason"] = decision.reason
        self.trace.record(
            TraceEventType.AUTHORIZATION,
            turn=current_turn,
            node_id=action_id,
            related_ids=tuple(effect.id for effect in effects if effect.id),
            summary=decision.reason,
            data={"decision": decision.kind.value},
        )
        if decision.kind is not DecisionKind.ALLOW:
            return decision, None

        for effect in effects:
            self.graph.add_effect(effect, action_id=action_id, turn=current_turn)
        if execute is None:
            self.graph.node(action_id).data["execution_status"] = "not_executed"
            return decision, None

        try:
            result = execute()
        except Exception as exc:
            self.graph.node(action_id).data["execution_status"] = "failed"
            self.graph.node(action_id).data["execution_error"] = type(exc).__name__
            for effect in effects:
                self.graph.commit_effect(effect.id, succeeded=False, result_summary=str(exc))
                self.trace.record(
                    TraceEventType.EFFECT_FAILED,
                    turn=current_turn,
                    node_id=effect.id,
                    related_ids=(action_id,),
                    summary=str(exc),
                    data={"effect_kind": effect.kind.value, "target": effect.target},
                )
            self.turn = max(self.turn, current_turn + 1)
            raise

        self.graph.node(action_id).data["execution_status"] = "succeeded"
        for effect in effects:
            state_id = self.graph.commit_effect(effect.id, succeeded=True, result_summary=str(result))
            self.trace.record(
                TraceEventType.EFFECT_COMMITTED,
                turn=current_turn,
                node_id=effect.id,
                related_ids=tuple(identifier for identifier in (action_id, state_id) if identifier),
                summary=f"{effect.kind.value}:{effect.target}",
                data={"effect_kind": effect.kind.value, "target": effect.target, "state_id": state_id},
            )
        self.turn = max(self.turn, current_turn + 1)
        return decision, result

    def observe_tool_return(self, summary: str, *, tool: str, integrity: str = "untrusted", turn: int | None = None, raw_payload: Any = None) -> str:
        return self.observe(
            "tool_return",
            summary,
            integrity=integrity,
            turn=turn,
            object_id=f"tool://{tool}",
            raw_payload=raw_payload,
        )

    def observe_workspace_read(
        self,
        *,
        path: str,
        fingerprint: str | None,
        turn: int,
        evidence_level: str = "observed",
        evidence_method: str = "workspace_snapshot_or_runtime_context",
        version: int | None = None,
    ) -> str:
        """Add a file read as an evidence-labelled observation.

        Native OpenClaw filesystem arguments are not always present in the
        headless JSON envelope.  Callers must therefore pass the evidence
        level explicitly when a path was inferred from visible context.
        """
        return self.observe(
            "workspace_read",
            f"read workspace/{path}" + (f"@v{version}" if version is not None else ""),
            integrity=evidence_level,
            turn=turn,
            object_id=f"workspace://{path}",
            object_fingerprint=fingerprint,
            raw_payload={
                "path": path,
                "sha256": fingerprint,
                "version": version,
                "evidence_method": evidence_method,
            },
        )

    def record_workspace_change(self, event: dict[str, Any], *, call_id: str | None = None) -> str:
        """Record a workspace write/create/delete and its version transition."""
        operation = str(event.get("op", "update")).lower()
        path = str(event.get("path", ""))
        if not path:
            raise ValueError("workspace change requires a path")
        turn = int(event.get("turn", self.turn))
        target = f"workspace://{path}"
        kind = {
            "create": EffectType.CREATE,
            "update": EffectType.WRITE,
            "write": EffectType.WRITE,
            "replace": EffectType.WRITE,
            "delete": EffectType.DELETE,
        }.get(operation, EffectType.UNKNOWN)
        observation_id = self.observe(
            "workspace_state",
            f"workspace/{path} before {operation}",
            integrity=str(event.get("evidence_level", "observed")),
            turn=turn,
            object_id=target,
            object_fingerprint=event.get("before_sha256"),
            raw_payload={
                "path": path,
                "sha256": event.get("before_sha256"),
                "version": max(int(event.get("version", 1)) - 1, 0),
            },
        )
        action_id = self.graph.add_action(
            f"workspace_{operation}",
            {
                "path": path,
                "version": event.get("version"),
                "before_sha256": event.get("before_sha256"),
                "after_sha256": event.get("after_sha256"),
            },
            turn=turn,
            observation_ids=(observation_id,),
            call_id=call_id,
        )
        self.trace.record(
            TraceEventType.ACTION_PROPOSED,
            turn=turn,
            node_id=action_id,
            related_ids=(observation_id,),
            summary=f"workspace_{operation}({path})",
            payload=event,
            data={"workspace": True, "path": path, "operation": operation},
        )
        effect = Effect(
            kind=kind,
            target=target,
            operation=f"workspace_{operation}",
            persistent=True,
            reversible=kind is not EffectType.DELETE,
            source_node_ids=(observation_id,),
            metadata={
                "workspace_path": path,
                "version": event.get("version"),
                "evidence_level": event.get("evidence_level", "observed"),
                "evidence_method": event.get("evidence_method"),
            },
            turn=turn,
        )
        effect.id = self.graph._new_id("eff")
        decision = self.authorizer.check((effect,), self.graph, action_id=action_id)
        self.graph.node(action_id).data["decision"] = decision.kind.value
        self.graph.node(action_id).data["reason"] = decision.reason
        self.trace.record(
            TraceEventType.AUTHORIZATION,
            turn=turn,
            node_id=action_id,
            related_ids=(effect.id,),
            summary=decision.reason,
            data={"decision": decision.kind.value, "workspace": True},
        )
        if decision.kind is not DecisionKind.ALLOW:
            return action_id
        effect_id = self.graph.add_effect(effect, action_id=action_id, turn=turn)
        state_id = self.graph.commit_effect(
            effect_id,
            succeeded=True,
            result_summary=f"workspace {operation} {path}",
            transition=StateTransition(
                object_id=target,
                before=event.get("before_sha256"),
                after=event.get("after_sha256"),
                method=event.get("evidence_method") or "workspace_snapshot_sha256",
            ),
        )
        self.trace.record(
            TraceEventType.EFFECT_COMMITTED,
            turn=turn,
            node_id=effect_id,
            related_ids=tuple(value for value in (action_id, state_id) if value),
            summary=f"workspace {operation}:{path}",
            data={"workspace": True, "path": path, "state_id": state_id, "version": event.get("version")},
        )
        return action_id

    def trace_dict(self) -> dict[str, Any]:
        """Export the graph plus the event envelope used for coverage metrics."""
        return {
            "task_scope": {
                "task_id": self.scope.task_id,
                "intent": self.scope.intent,
                "allowed_effects": sorted(effect.value for effect in self.scope.allowed_effects),
                "allowed_resources": list(self.scope.allowed_resources),
                "allowed_destinations": list(self.scope.allowed_destinations),
            },
            "events": self.trace.to_dict(),
            "graph": self.graph.to_dict(),
        }

    def compact_context(
        self,
        *,
        recent_actions: int = 8,
        max_states: int = 32,
        max_sources_per_state: int = 4,
    ) -> dict[str, Any]:
        """Return the bounded semantic context intended for runtime checks."""
        return {
            "task_scope": {
                "task_id": self.scope.task_id,
                "intent": self.scope.intent,
                "allowed_effects": sorted(effect.value for effect in self.scope.allowed_effects),
            },
            **self.graph.compact_view(
                recent_actions=recent_actions,
                max_states=max_states,
                max_sources_per_state=max_sources_per_state,
            ),
        }

    def minimal_graph(self) -> dict[str, Any]:
        return self.graph.project_minimal(self.scope)
