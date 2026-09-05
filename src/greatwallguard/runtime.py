"""Runtime hooks for an OpenClaw-style tool loop."""

from __future__ import annotations

from typing import Any, Callable, Iterable

from .authorizer import EffectAuthorizer
from .contracts import ToolContractRegistry
from .graph import EffectGraph
from .model import Decision, DecisionKind, Effect


class GreatWallGuardRuntime:
    """Collect observations, gate tool calls, and commit allowed Effects."""

    def __init__(self, scope, *, contracts: ToolContractRegistry | None = None, graph: EffectGraph | None = None) -> None:
        self.scope = scope
        self.graph = graph or EffectGraph()
        self.contracts = contracts or ToolContractRegistry()
        self.authorizer = EffectAuthorizer(scope)
        self.turn = 0
        self.user_observation_ids: list[str] = []

    def observe_user(self, message: str) -> str:
        node_id = self.graph.add_observation("user", "user task", turn=0, integrity="trusted", raw_payload=message)
        self.user_observation_ids.append(node_id)
        return node_id

    def observe(
        self,
        source: str,
        summary: str,
        *,
        integrity: str = "unknown",
        turn: int | None = None,
        object_id: str | None = None,
        raw_payload: Any = None,
    ) -> str:
        return self.graph.add_observation(
            source,
            summary,
            turn=self.turn if turn is None else turn,
            integrity=integrity,
            object_id=object_id,
            raw_payload=raw_payload,
        )

    def before_tool_call(
        self,
        tool: str,
        arguments: dict[str, Any],
        *,
        source_node_ids: Iterable[str] = (),
        turn: int | None = None,
        execute: Callable[[], Any] | None = None,
    ) -> tuple[Decision, Any | None]:
        current_turn = self.turn if turn is None else turn
        source_node_ids = tuple(source_node_ids)
        action_id = self.graph.add_action(tool, arguments, turn=current_turn, observation_ids=source_node_ids)
        effects = self.contracts.infer(tool, arguments)
        for effect in effects:
            effect.source_node_ids = tuple(source_node_ids)
            effect.turn = current_turn
            effect.id = self.graph._new_id("eff")

        decision = self.authorizer.check(effects, self.graph, action_id=action_id)
        self.graph.node(action_id).data["decision"] = decision.kind.value
        self.graph.node(action_id).data["reason"] = decision.reason
        if decision.kind is not DecisionKind.ALLOW:
            return decision, None

        for effect in effects:
            self.graph.add_effect(effect, action_id=action_id, turn=current_turn)
        result = execute() if execute else None
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
