"""Small integration shim for OpenClaw AgentLAB call hooks.

The adapter deliberately has no dependency on AgentLAB.  A VictimAgent or
DojoSkillBridge can call these two hooks around its existing tool loop; the
defense repository remains usable with other OpenAI-compatible agents.
"""

from __future__ import annotations

from typing import Any, Iterable

from ..runtime import GreatWallGuardRuntime


class AgentLabTraceAdapter:
    def __init__(self, runtime: GreatWallGuardRuntime) -> None:
        self.runtime = runtime
        self._latest_return_by_tool: dict[str, str] = {}

    def on_user_message(self, message: str) -> str:
        return self.runtime.observe_user(message)

    def on_tool_return(
        self,
        tool: str,
        summary: str,
        *,
        injected: bool = False,
        raw_payload: Any = None,
    ) -> str:
        integrity = "untrusted" if injected else "unknown"
        node_id = self.runtime.observe_tool_return(
            summary,
            tool=tool,
            integrity=integrity,
            raw_payload=raw_payload,
        )
        self._latest_return_by_tool[tool] = node_id
        return node_id

    def before_tool_call(
        self,
        tool: str,
        arguments: dict[str, Any],
        *,
        source_node_ids: Iterable[str] = (),
        call_id: str | None = None,
        execute=None,
    ):
        """Return the gate decision; call ``execute`` only when allowed."""
        if not tuple(source_node_ids) and tool in self._latest_return_by_tool:
            source_node_ids = (self._latest_return_by_tool[tool],)
        return self.runtime.before_tool_call(
            tool,
            arguments,
            source_node_ids=source_node_ids,
            call_id=call_id,
            execute=execute,
        )
