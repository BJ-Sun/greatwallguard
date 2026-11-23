"""Bounded derivation of persistent intermediate effects."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Iterable, Mapping

from .authorization_dag import AuthorizationDAG, DagDecision


@dataclass(frozen=True)
class DerivedEffectCandidate:
    tool: str
    object_id: str | None
    operation: str
    content_present: bool
    parent_effect_ids: tuple[str, ...]
    protected_object: bool


class BoundedDerivedEffectPolicy:
    """Recognize local persistent writes without silently authorizing them.

    Writes to Agent control state are rejected. Other writes remain REVIEW
    until their parent effect, object scope, content provenance, visibility,
    and lifetime are proved.
    """

    DEFAULT_PROTECTED_OBJECTS = frozenset({
        "agents.md", "bootstrap.md", "identity.md", "memory.md", "soul.md",
        "user.md", ".env", "settings.json", "config.json",
    })

    def __init__(
        self,
        *,
        write_tools: Iterable[str] = (
            "create_file", "append_to_file", "write_file", "edit_file",
            "workspace_state_change",
        ),
        protected_objects: Iterable[str] = DEFAULT_PROTECTED_OBJECTS,
    ) -> None:
        self.write_tools = frozenset(str(item) for item in write_tools)
        self.protected_objects = frozenset(
            str(item).casefold() for item in protected_objects
        )

    @staticmethod
    def _object_id(arguments: Mapping[str, Any]) -> str | None:
        for field in ("path", "filename", "file_path", "object_id"):
            value = arguments.get(field)
            if value is not None and str(value).strip():
                return str(value).strip()
        return None

    @staticmethod
    def _operation(tool: str, arguments: Mapping[str, Any]) -> str:
        explicit = arguments.get("operation")
        if explicit:
            return str(explicit).casefold()
        if "append" in tool:
            return "append"
        if "create" in tool:
            return "create"
        return "update"

    def inspect(
        self, tool: str, arguments: Mapping[str, Any], graph: AuthorizationDAG,
    ) -> DerivedEffectCandidate | None:
        if tool not in self.write_tools:
            return None
        object_id = self._object_id(arguments)
        basename = (
            PurePosixPath(object_id.replace("\\", "/")).name.casefold()
            if object_id else ""
        )
        parents = tuple(
            node.id for node in graph.nodes.values()
            if node.kind == "effect" and node.status != "revoked"
            and not bool(node.attrs.get("revoked"))
        )
        return DerivedEffectCandidate(
            tool=tool,
            object_id=object_id,
            operation=self._operation(tool, arguments),
            content_present=any(
                arguments.get(field) is not None
                for field in ("content", "text", "patch", "data")
            ),
            parent_effect_ids=parents,
            protected_object=basename in self.protected_objects,
        )

    def derive(
        self, tool: str, arguments: Mapping[str, Any], graph: AuthorizationDAG,
    ) -> DagDecision | None:
        candidate = self.inspect(tool, arguments, graph)
        if candidate is None:
            return None
        if candidate.protected_object:
            return DagDecision(
                "alert", "protected_persistent_object_requires_explicit_authorization",
                missing_evidence=("explicit_object_authorization",),
            )
        return DagDecision(
            "review", "bounded_derived_effect_requires_proof",
            proof_nodes=candidate.parent_effect_ids,
            missing_evidence=(
                "parent_effect_link", "object_scope", "content_provenance",
                "visibility", "lifetime",
            ),
        )
