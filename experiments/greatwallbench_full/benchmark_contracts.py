"""Benchmark-agnostic contracts derived from embedded deployment schemas."""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from greatwallguard import EffectContract, ObservationContract, ObservationTool


EFFECTS = {
    "send_email": "external_message",
    "create_calendar_event": "calendar_create",
    "reschedule_calendar_event": "calendar_reschedule",
    "add_calendar_event_participants": "calendar_participant_add",
    "create_file": "file_create",
    "append_to_file": "file_update",
    "delete_file": "file_delete",
    "share_file": "file_share",
    "mock_scheduler_create": "scheduled_task_create",
    "mock_scheduler_advance": "scheduled_task_execute",
    "mock_network_scan": "network_probe",
    "mock_network_connect": "network_connect",
    "mock_shell_plan": "process_plan",
    "mock_shell_spawn": "process_spawn",
    "mock_exec": "local_command",
    "mock_process_stop": "process_stop",
    # Host-observed persistent writes are part of the Agent execution
    # environment even when the model-facing tool API performs them
    # implicitly (for example OpenClaw workspace memory updates).
    "workspace_state_change": "persistent_state_update",
}


def _schema(tool: Mapping[str, Any]) -> Mapping[str, Any]:
    value = tool.get("input_schema") or tool.get("parameters") or {}
    return value if isinstance(value, Mapping) else {}


def _fields(tool: Mapping[str, Any]) -> tuple[str, ...]:
    properties = _schema(tool).get("properties") or {}
    if not isinstance(properties, Mapping):
        return ()
    return tuple(str(key) for key in properties)


def contracts(tool_contracts: Iterable[Mapping[str, Any]]):
    """Build finite contracts only from stable tool metadata.

    All effect arguments are initially security-relevant.  Later experiments
    may relax fields only through a tool-level deployment contract, never from
    observed benchmark outcomes.
    """
    by_name: dict[str, Mapping[str, Any]] = {}
    for contract in tool_contracts:
        for tool in contract.get("tools") or []:
            if not isinstance(tool, Mapping):
                continue
            name = str(tool.get("canonical_name") or tool.get("name") or "")
            if name:
                by_name.setdefault(name, tool)

    effects = []
    observations = []
    runtime_observations = []
    for name, tool in sorted(by_name.items()):
        fields = _fields(tool)
        description = str(tool.get("description") or "")
        if name in EFFECTS:
            required = _schema(tool).get("required") or []
            effects.append(EffectContract(
                tool=name,
                effect=EFFECTS[name],
                critical_fields=fields,
                required_fields=tuple(
                    str(field) for field in required if str(field) in fields
                ),
                description=description,
            ))
        else:
            observations.append(ObservationTool(
                name=name, output_fields=(), description=description,
            ))
            # Reads that can transmit query data or contact a supplied URL are
            # outbound observations; simple local/mock lookups are passive.
            mode = "outbound" if (
                any(token in name for token in ("web_fetch", "download"))
                and any(field in fields for field in ("url", "query"))
            ) else "passive"
            runtime_observations.append(ObservationContract(name, mode))
    effects.append(EffectContract(
        tool="workspace_state_change",
        effect="persistent_state_update",
        critical_fields=("path", "operation"),
        required_fields=("path", "operation"),
        description=(
            "Persistently create, update, or delete a workspace file or Agent memory object."
        ),
    ))
    observations.append(ObservationTool(
        name="workspace_state_read",
        output_fields=("path", "sha256"),
        description="Read a specific version of a workspace file or Agent memory object.",
    ))
    runtime_observations.append(ObservationContract("workspace_state_read", "passive"))
    return tuple(effects), tuple(observations), tuple(runtime_observations)
