"""Finite tool-to-effect contracts used by the runtime."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from .model import Effect, EffectType


def _first(args: dict[str, Any], *keys: str, default: str = "unknown") -> str:
    for key in keys:
        value = args.get(key)
        if value is not None and str(value):
            return str(value)
    return default


@dataclass(frozen=True)
class ToolContract:
    name: str
    infer: Callable[[dict[str, Any]], list[Effect]]


class ToolContractRegistry:
    """Maps tool calls to a finite effect vocabulary.

    A production adapter should register contracts from the actual tool schema.
    The unknown fallback is deliberately conservative and yields ASK.
    """

    def __init__(self) -> None:
        self._contracts: dict[str, ToolContract] = {}
        self._register_defaults()

    def register(self, contract: ToolContract) -> None:
        self._contracts[contract.name] = contract

    def infer(self, tool: str, arguments: dict[str, Any]) -> list[Effect]:
        contract = self._contracts.get(tool)
        if contract:
            return contract.infer(arguments)
        return [
            Effect(
                EffectType.UNKNOWN,
                f"tool://{tool}",
                operation=tool,
                persistent=True,
                reversible=False,
            )
        ]

    def _register_defaults(self) -> None:
        for name in ("read_file", "get_file_by_id", "list_files", "search_files", "web_fetch", "web_search", "query_database", "get_unread_emails", "get_received_emails", "search_emails"):
            self.register(ToolContract(name, lambda args, _name=name: [
                Effect(EffectType.READ, _first(args, "path", "url", "table", "query", "id", default=f"tool://{_name}"), _name, persistent=False)
            ]))

        for name in ("write_file", "append_to_file", "create_file", "write_memory"):
            self.register(ToolContract(name, lambda args, _name=name: [
                Effect(EffectType.WRITE if _name != "create_file" else EffectType.CREATE,
                       _first(args, "path", "filename", "file", "object", default=f"workspace://{_name}"),
                       _name, persistent=True)
            ]))

        self.register(ToolContract("delete_file", lambda args: [
            Effect(EffectType.DELETE, _first(args, "path", "file", "id", default="workspace://unknown"), "delete_file", persistent=True, reversible=False)
        ]))
        self.register(ToolContract("send_email", lambda args: [
            Effect(EffectType.SEND, _first(args, "to", "recipients", "recipient", default="external://unknown"), "send_email", persistent=True, reversible=False)
        ]))
        self.register(ToolContract("share_file", lambda args: [
            Effect(EffectType.PERMISSION_CHANGE, _first(args, "file", "id", "recipients", default="workspace://unknown"), "share_file", persistent=True, reversible=True)
        ]))
        self.register(ToolContract("exec", lambda args: [
            Effect(EffectType.EXECUTE, _first(args, "command", default="shell://unknown"), "exec", persistent=True, reversible=False)
        ]))
        self.register(ToolContract("create_calendar_event", lambda args: [
            Effect(EffectType.CREATE, f"calendar://{_first(args, 'date', default='unknown')}", "create_calendar_event", persistent=True)
        ]))

