"""Derive auditable relation facts from the existing EffectGraph.

This is a query/adapter over the behavior graph, not a second execution graph.
Only directly observed structured fields and explicitly labelled parser outputs
are promoted to facts.
"""

from __future__ import annotations

import json
import re
from typing import Any, Mapping

from .graph import EffectGraph
from .model import EdgeType, NodeType
from .relation_proof import ProofGraph


CLIENT_LINE = re.compile(r"(?im)^\s*Attendees?\s+from\s+client\s*:\s*([^\n]+)$")
EMAIL = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.I)


def _payload(graph: EffectGraph, node_id: str) -> Any | None:
    node = graph.node(node_id)
    content = node.data.get("content")
    if graph.content_index is None or not isinstance(content, Mapping) or not content.get("ref"):
        return None
    text = graph.content_index.text(str(content["ref"]))
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def _normalized_person(value: str) -> str:
    return " ".join(re.sub(r"[^a-z0-9]+", " ", value.casefold()).split())


def _email_identity(email: str) -> str:
    return _normalized_person(email.split("@", 1)[0])


class BehaviorGraphRelationAdapter:
    """Project relevant structured evidence into relation-proof facts."""

    def __init__(self, graph: EffectGraph) -> None:
        self.graph = graph

    def build(self) -> ProofGraph:
        proof = ProofGraph()
        returns = [edge for edge in self.graph.edges if edge.edge_type is EdgeType.RETURNS]
        for edge in returns:
            action = self.graph.node(edge.source)
            result = self.graph.node(edge.target)
            if action.node_type is not NodeType.ACTION or result.node_type is not NodeType.OBSERVATION:
                continue
            tool = str(action.data.get("tool") or "")
            arguments = _payload(self.graph, action.id)
            payload = _payload(self.graph, result.id)
            if tool == "search_files_by_filename":
                self._files(proof, payload, result.id)
            elif tool == "search_contacts_by_name":
                self._contacts(proof, arguments, payload, result.id)
            else:
                self._generic_sources(proof, tool, payload, result.id)
        return proof

    @staticmethod
    def _files(proof: ProofGraph, payload: Any, result_node: str) -> None:
        if not isinstance(payload, list):
            return
        for item in payload:
            if not isinstance(item, Mapping):
                continue
            filename = item.get("filename")
            if not isinstance(filename, str):
                continue
            document = f"file:{filename}"
            proof.add("document", document, evidence=f"observed:{result_node}:filename")
            shared = item.get("shared_with")
            shared_emails = list(shared) if isinstance(shared, Mapping) else []
            for email in shared_emails:
                if isinstance(email, str):
                    proof.add("value_source", email, document,
                              evidence=f"observed:{result_node}:shared_with")
            content = item.get("content")
            if not isinstance(content, str):
                continue
            match = CLIENT_LINE.search(content)
            if match is None:
                continue
            quote = match.group(0)
            for person in (part.strip() for part in match.group(1).split(",")):
                if not person:
                    continue
                proof.add("document_role_entity", document, "client", person,
                          evidence=f"parser_candidate:{result_node}:{quote}",
                          basis="candidate")
                identity = _normalized_person(person)
                for email in shared_emails:
                    if isinstance(email, str) and _email_identity(email) == identity:
                        proof.add("document_role_value", document, "client", email,
                                  evidence=f"derived:{result_node}:role_plus_shared_identity",
                                  basis="candidate")

    @staticmethod
    def _contacts(proof: ProofGraph, arguments: Any, payload: Any, result_node: str) -> None:
        query = arguments.get("query") if isinstance(arguments, Mapping) else None
        values = payload if isinstance(payload, list) else [payload]
        for item in values:
            if not isinstance(item, Mapping):
                continue
            email = item.get("email") or item.get("email_address")
            name = item.get("name") or query
            if isinstance(name, str) and isinstance(email, str):
                proof.add("contact_email", name, email,
                          evidence=f"observed:{result_node}:contact")
                proof.add("value_source", email, f"contacts:{name}",
                          evidence=f"observed:{result_node}:contact")

    @staticmethod
    def _generic_sources(proof: ProofGraph, tool: str, payload: Any, result_node: str) -> None:
        text = payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False, default=str)
        for email in sorted(set(EMAIL.findall(text))):
            proof.add("value_source", email.casefold(), f"tool:{tool}:{result_node}",
                      evidence=f"observed:{result_node}:exact_email")
