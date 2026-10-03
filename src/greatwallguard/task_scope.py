"""A deliberately small, deterministic TaskScope generator.

This is a bootstrap implementation, not a semantic planner.  It uses the
normal user task, the agent's advertised tool capabilities, and tool schemas to
produce a conservative behavior envelope before execution.  It is useful for
testing the rest of the graph detector without leaking attack labels or using
post-hoc execution metadata to define the scope.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

from .model import EffectType, TaskScope


SCHEMA = "gwg-task-scope-heuristic-v1"

_STOPWORDS = {
    "a", "an", "and", "are", "as", "at", "be", "by", "for", "from", "in",
    "into", "is", "it", "my", "of", "on", "or", "please", "the", "then",
    "this", "to", "use", "with", "you", "your",
}

_EFFECT_CUES: dict[EffectType, tuple[str, ...]] = {
    EffectType.READ: ("read", "search", "fetch", "find", "review", "查看", "读取", "搜索"),
    EffectType.WRITE: ("write", "update", "append", "edit", "save", "修改", "写入", "更新"),
    EffectType.CREATE: ("create", "generate", "produce", "建立", "创建", "生成"),
    EffectType.DELETE: ("delete", "remove", "清理", "删除"),
    EffectType.SEND: ("send", "email", "notify", "share", "发送", "邮件", "通知", "共享"),
    EffectType.EXECUTE: ("run", "execute", "command", "script", "执行", "运行", "命令"),
    EffectType.PERMISSION_CHANGE: ("permission", "access", "grant", "权限", "授权"),
}

_NAME_EFFECT_HINTS: tuple[tuple[EffectType, tuple[str, ...]], ...] = (
    (EffectType.PERMISSION_CHANGE, ("permission", "share", "grant", "revoke")),
    (EffectType.SEND, ("send", "email", "message", "notify")),
    (EffectType.DELETE, ("delete", "remove", "cancel")),
    (EffectType.EXECUTE, ("exec", "run", "shell", "command")),
    (EffectType.CREATE, ("create", "new", "insert")),
    (EffectType.WRITE, ("write", "update", "append", "edit", "modify")),
    (EffectType.READ, ("read", "get", "list", "search", "fetch", "query", "find")),
)


def _tokens(value: Any) -> set[str]:
    text = str(value or "").lower()
    return {token for token in re.findall(r"[a-z][a-z0-9_:-]*", text) if token not in _STOPWORDS}


def _text_cues(task: str) -> set[str]:
    text = task.lower()
    return {cue for cues in _EFFECT_CUES.values() for cue in cues if cue in text}


def _schema_name(schema: Mapping[str, Any]) -> str:
    function = schema.get("function")
    if isinstance(function, Mapping):
        return str(function.get("name") or schema.get("name") or "").strip()
    return str(schema.get("name") or "").strip()


def _schema_description(schema: Mapping[str, Any]) -> str:
    function = schema.get("function")
    if isinstance(function, Mapping):
        return str(function.get("description") or schema.get("description") or "")
    return str(schema.get("description") or "")


def _effect_from_schema(name: str, schema: Mapping[str, Any]) -> EffectType | None:
    value = schema.get("effect") or schema.get("effect_type")
    if value:
        try:
            return EffectType(str(value))
        except ValueError:
            pass
    lowered = name.lower()
    for effect, hints in _NAME_EFFECT_HINTS:
        if any(hint in lowered for hint in hints):
            return effect
    return None


def _capability_names(capabilities: Iterable[str | Mapping[str, Any]]) -> set[str]:
    names: set[str] = set()
    for capability in capabilities:
        if isinstance(capability, Mapping):
            name = capability.get("name") or capability.get("tool")
        else:
            name = capability
        if name:
            names.add(str(name))
    return names


def _extract_resources(task: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    resources: list[str] = []
    destinations: list[str] = []

    for value in re.findall(r"(?:file|memory|web)://[^\s,;)'\"]+", task, flags=re.IGNORECASE):
        value = value.rstrip(".")
        if value.startswith("memory://"):
            resources.append(value)
        elif value.startswith("file://"):
            resources.append(value)
        else:
            resources.append(value)

    # Bare workspace file names are common in normal tasks.  Keep their scope
    # explicit instead of falling back to every workspace path.
    for value in re.findall(r"(?<![A-Za-z0-9_:/-])(?:[\w.-]+/)*[\w.-]+\.(?:md|txt|json|csv|yaml|yml)", task, flags=re.IGNORECASE):
        candidate = f"file://{value}"
        if candidate not in resources:
            resources.append(candidate)

    for value in re.findall(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", task, flags=re.IGNORECASE):
        destinations.append(value)

    if "memory" in task.lower() or "记忆" in task:
        if "memory://" not in resources:
            resources.append("memory://")
    return tuple(dict.fromkeys(resources)), tuple(dict.fromkeys(destinations))


def generate_task_scope(
    task: str,
    agent_capabilities: Iterable[str | Mapping[str, Any]],
    tool_schemas: Iterable[Mapping[str, Any]],
    *,
    task_id: str = "heuristic-task",
) -> TaskScope:
    """Generate a small TaskScope from pre-execution information only.

    Selection is based on lexical overlap between the task and each advertised
    tool's name/description, plus effect cues.  A tool schema may provide an
    explicit ``effect``/``effect_type`` field; otherwise the name is mapped to
    the finite EffectType vocabulary.  The function records scores and
    warnings in ``scope.metadata`` so the result is auditable rather than
    pretending to be a complete semantic planner.
    """
    task = str(task).strip()
    tool_schemas = [dict(schema) for schema in tool_schemas]
    allowed_capabilities = _capability_names(agent_capabilities)
    task_tokens = _tokens(task)
    cues = _text_cues(task)
    selected: list[str] = []
    selected_effects: set[EffectType] = set()
    scores: dict[str, int] = {}
    rejected: dict[str, str] = {}

    for schema in tool_schemas:
        name = _schema_name(schema)
        if not name or (allowed_capabilities and name not in allowed_capabilities):
            continue
        description = _schema_description(schema)
        effect = _effect_from_schema(name, schema)
        tool_tokens = _tokens(f"{name} {description}")
        overlap = len(task_tokens.intersection(tool_tokens))
        effect_cue_match = bool(effect and any(cue in cues for cue in _EFFECT_CUES[effect]))
        score = overlap + (2 if effect_cue_match else 0)
        scores[name] = score
        if score <= 0:
            rejected[name] = "no task/schema overlap"
            continue
        selected.append(name)
        if effect is not None:
            selected_effects.add(effect)

    resources, destinations = _extract_resources(task)
    warnings: list[str] = []
    if not selected:
        warnings.append("no tool matched the task; scope has no allowed tools")
    if any(effect is EffectType.SEND for effect in selected_effects) and not destinations:
        warnings.append("send is mentioned but no explicit email destination was found")
    if any(effect in selected_effects for effect in {EffectType.WRITE, EffectType.CREATE, EffectType.DELETE}):
        if not resources:
            warnings.append("state-changing effect has no explicit resource; resource check is unbounded")

    metadata = {
        "schema": SCHEMA,
        "method": "keyword_overlap_with_effect_cues",
        "selected_tools": selected,
        "candidate_scores": scores,
        "rejected_tools": rejected,
        "warnings": warnings,
        "inputs": {
            "task_only": True,
            "capability_count": len(allowed_capabilities),
            "tool_schema_count": len(tool_schemas),
        },
    }
    # ``tool_schemas`` may be a generator; the count above is best-effort and
    # does not affect the generated authorization envelope.
    return TaskScope(
        task_id=task_id,
        intent=task,
        allowed_effects=frozenset(selected_effects),
        allowed_resources=resources,
        allowed_destinations=destinations,
        allowed_tools=tuple(dict.fromkeys(selected)),
        metadata=metadata,
    )
