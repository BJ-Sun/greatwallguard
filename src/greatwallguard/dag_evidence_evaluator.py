"""Deterministic evaluation of bindings compiled into an Authorization DAG."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
import re
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit

from .authorization_dag import AuthorizationDAG
from .runtime_relation_resolver import RuntimeRelationResolver


@dataclass(frozen=True)
class DAGEvidenceResult:
    proved: bool
    source_call_ids: tuple[str, ...] = ()
    operators: tuple[str, ...] = ()
    evidence_paths: tuple[str, ...] = ()


@dataclass(frozen=True)
class DAGConstraintResult:
    status: str
    source_call_ids: tuple[str, ...] = ()
    operators: tuple[str, ...] = ()


def _normal(value: Any) -> str:
    return " ".join(str(value).strip().casefold().split())


def _children(value: Any) -> Iterable[Any]:
    if isinstance(value, Mapping):
        yield from value.values()
    elif isinstance(value, (list, tuple)):
        yield from value


def _field_values(value: Any, field: str) -> list[Any]:
    """Collect a named field recursively from JSON-like runtime results."""
    found = []
    if isinstance(value, Mapping):
        for key, child in value.items():
            if _normal(key).replace(" ", "_") == _normal(field).replace(" ", "_"):
                found.append(child)
            found.extend(_field_values(child, field))
    elif isinstance(value, (list, tuple)):
        for child in value:
            found.extend(_field_values(child, field))
    return found


def _flatten(value: Any) -> list[Any]:
    if isinstance(value, Mapping):
        result = []
        for child in value.values():
            result.extend(_flatten(child))
        return result
    if isinstance(value, (list, tuple, set)):
        result = []
        for child in value:
            result.extend(_flatten(child))
        return result
    return [value]


class DAGEvidenceEvaluator:
    """Replay finite DAG expressions over already observed tool results.

    Source aliases are defender-owned capability equivalence classes.  They
    tolerate interchangeable read tools without treating arbitrary sources as
    equivalent.
    """

    def __init__(self, graph: AuthorizationDAG, resolver: RuntimeRelationResolver,
                 *, source_aliases: Mapping[str, Iterable[str]] | None = None) -> None:
        self.graph = graph
        self.resolver = resolver
        self.source_aliases = {
            tool: frozenset({tool, *aliases})
            for tool, aliases in (source_aliases or {}).items()
        }

    def prove_binding(self, node_id: str, actual: Any) -> DAGEvidenceResult | None:
        evaluated = self._evaluate(node_id, set())
        if evaluated is None:
            return None
        values, calls, operators = evaluated
        expected_values = [item for value in values for item in _flatten(value)]
        observed_values = list(_flatten(actual))
        field = self._binding_field(node_id)
        if not observed_values or not all(
                any(self._value_in_scope(field, item, allowed)
                    for allowed in expected_values)
                for item in observed_values):
            return None
        observed = {_normal(item) for item in observed_values}
        accepted_calls = set(calls)
        accepted_values = observed
        evidence_paths = tuple(dict.fromkeys(
            f"{fact.call_id}:{fact.path}"
            for fact in self.resolver.facts
            if fact.call_id in accepted_calls
            and _normal(fact.value) in accepted_values
        ))
        return DAGEvidenceResult(
            True, tuple(dict.fromkeys(calls)), tuple(operators), evidence_paths,
        )

    def _binding_field(self, node_id: str) -> str | None:
        node = self.graph.nodes[node_id]
        field = node.attrs.get("field")
        if isinstance(field, str):
            return field
        edges = [
            edge for edge in self.graph.edges
            if edge.source == node_id and edge.kind == "binds"
        ]
        if len(edges) == 1 and isinstance(edges[0].attrs.get("field"), str):
            return str(edges[0].attrs["field"])
        return None

    @staticmethod
    def _value_in_scope(field: str | None, actual: Any, allowed: Any) -> bool:
        if _normal(actual) == _normal(allowed):
            return True
        if (isinstance(actual, (int, float)) and not isinstance(actual, bool)
                and isinstance(allowed, (int, float)) and not isinstance(allowed, bool)):
            return float(actual) == float(allowed)
        normalized = (field or "").casefold()
        if any(token in normalized for token in ("path", "directory", "dir")):
            actual_path = str(actual).rstrip("/")
            allowed_path = str(allowed).rstrip("/")
            return actual_path.startswith(allowed_path + "/")
        if "url" in normalized:
            def parts(value: Any):
                text = str(value).strip()
                parsed = urlsplit(
                    text if "://" in text else f"https://{text}"
                )
                return (
                    (parsed.hostname or "").casefold().removeprefix("www."),
                    parsed.path.rstrip("/"),
                )
            actual_host, actual_path = parts(actual)
            allowed_host, allowed_path = parts(allowed)
            return bool(actual_host) and actual_host == allowed_host and (
                not allowed_path or actual_path == allowed_path
                or actual_path.startswith(allowed_path + "/")
            )
        return False

    def evaluate_constraint(self, node_id: str) -> DAGConstraintResult:
        """Evaluate one compiled Boolean constraint without guessing semantics."""
        node = self.graph.nodes.get(node_id)
        if node is None or node.kind != "constraint":
            return DAGConstraintResult("unknown")
        by_role = {
            edge.attrs.get("role"): edge.source
            for edge in self.graph.incoming(node_id, "data_dep")
        }
        if "left" not in by_role or "right" not in by_role:
            return DAGConstraintResult("unknown")
        left = self._evaluate(by_role["left"], set())
        right = self._evaluate(by_role["right"], set())
        if left is None or right is None:
            return DAGConstraintResult("unknown")
        left_values, left_calls, left_ops = left
        right_values, right_calls, right_ops = right
        left_flat = [item for value in left_values for item in _flatten(value)]
        right_flat = [item for value in right_values for item in _flatten(value)]
        if not left_flat or not right_flat:
            return DAGConstraintResult("unknown")
        comparator = node.attrs.get("comparator")
        if not isinstance(comparator, str):
            return DAGConstraintResult("unknown")
        satisfied = any(
            self._compare(left_item, comparator, right_item)
            for left_item in left_flat for right_item in right_flat
        )
        return DAGConstraintResult(
            "proved" if satisfied else "contradicted",
            tuple(dict.fromkeys([*left_calls, *right_calls])),
            tuple([*left_ops, *right_ops]),
        )

    def _evaluate(self, node_id: str, visiting: set[str]
                  ) -> tuple[list[Any], list[str], list[str]] | None:
        if node_id in visiting:
            return None
        visiting = {*visiting, node_id}
        node = self.graph.nodes[node_id]
        source_type = node.attrs.get("source_type")
        if source_type == "trusted_literal":
            return list(node.attrs.get("values", [])), [], []
        if source_type == "runtime_deferred":
            tool = node.attrs.get("tool")
            if not isinstance(tool, str) or not tool:
                return None
            accepted = self.source_aliases.get(tool, frozenset({tool}))
            observations = [
                item for item in self.resolver.observations if item.tool in accepted
            ]
            if not observations:
                return None
            path = node.attrs.get("path")
            values = []
            calls = []
            for observation in observations:
                current = [observation.value]
                if isinstance(path, str) and path:
                    if path.startswith("/"):
                        argument_path = (observation.arguments or {}).get("path")
                        if not isinstance(argument_path, str) or not (
                                argument_path == path or argument_path.startswith(path.rstrip("/") + "/")):
                            current = []
                    else:
                        for segment in path.split("."):
                            segment = segment.removesuffix("[]")
                            next_values = []
                            for value in current:
                                next_values.extend(_field_values(value, segment))
                            current = next_values
                            if not current:
                                break
                values.extend(current)
                calls.append(observation.call_id)
            return (values, calls, []) if values else None
        if node.kind != "transform":
            return None
        inputs = []
        input_groups: list[list[Any]] = []
        calls: list[str] = []
        operators: list[str] = []
        for edge in self.graph.incoming(node_id, "data_dep"):
            child = self._evaluate(edge.source, visiting)
            if child is None:
                return None
            values, child_calls, child_ops = child
            input_groups.append(values)
            inputs.extend(values)
            calls.extend(child_calls)
            operators.extend(child_ops)
        if not inputs:
            return None
        op = node.op
        field = node.attrs.get("field")
        if op == "project":
            if not isinstance(field, str):
                return None
            projected = []
            for value in inputs:
                projected.extend(_field_values(value, field))
            # A source path may already have projected the requested field.
            values = projected or inputs
        elif op == "select":
            if not isinstance(field, str):
                return None
            comparator = node.attrs.get("comparator")
            target = node.attrs.get("value")
            if comparator is None and "value" not in node.attrs:
                projected = []
                for value in inputs:
                    projected.extend(_field_values(value, field))
                return (projected, calls, [*operators, str(op)]) if projected else None
            values = []
            for value in inputs:
                rows = list(value.values()) if isinstance(value, Mapping) else (
                    list(value) if isinstance(value, (list, tuple)) else []
                )
                for row in rows:
                    candidates = _field_values(row, field)
                    if any(self._compare(item, comparator, target) for item in candidates):
                        values.append(row)
        elif op == "aggregate":
            if not isinstance(field, str):
                return None
            rows = []
            for value in inputs:
                if isinstance(value, Mapping):
                    rows.extend(value.values())
                elif isinstance(value, (list, tuple)):
                    rows.extend(value)
            function = node.attrs.get("function")
            if function == "count":
                values = [len(rows)]
                return values, calls, [*operators, str(op)]
            scored = []
            for row in rows:
                candidates = _field_values(row, field)
                if candidates:
                    try:
                        scored.append((float(candidates[0]), row))
                    except (TypeError, ValueError):
                        pass
            if not scored:
                return None
            if function == "sum":
                values = [sum(score for score, _ in scored)]
            elif function == "max":
                values = [max(score for score, _ in scored)]
            elif function == "min":
                values = [min(score for score, _ in scored)]
            elif function == "argmax":
                values = [max(scored, key=lambda item: item[0])[1]]
            elif function == "argmin":
                values = [min(scored, key=lambda item: item[0])[1]]
            else:
                return None
        elif op == "normalize":
            kind = node.attrs.get("kind") or node.attrs.get("format")
            if kind not in {"strip", "casefold", "url_host", "iso_date"}:
                return None
            values = []
            for value in inputs:
                for item in _flatten(value):
                    if kind == "strip":
                        values.append(str(item).strip())
                    elif kind == "casefold":
                        values.append(str(item).strip().casefold())
                    elif kind == "url_host":
                        parsed = urlsplit(
                            str(item) if "://" in str(item) else f"https://{item}"
                        )
                        if parsed.hostname:
                            values.append(parsed.hostname.casefold().removeprefix("www."))
                    elif kind == "iso_date":
                        try:
                            values.append(datetime.fromisoformat(str(item)).date().isoformat())
                        except ValueError:
                            continue
            if not values:
                return None
        elif op == "compute":
            expression = node.attrs.get("expression")
            flat = [item for value in inputs for item in _flatten(value)]
            if not isinstance(expression, str) or not flat:
                return None
            if expression == "sum":
                try:
                    values = [sum(float(item) for item in flat)]
                except (TypeError, ValueError):
                    return None
            else:
                match = re.fullmatch(
                    r"(?:x|[A-Za-z_][A-Za-z0-9_]*)\s*([+-])\s*"
                    r"(\d+(?:\.\d+)?)\s*(day|days)?",
                    expression.strip(), re.I,
                )
                if match is None or len(flat) != 1:
                    return None
                sign, amount, unit = match.groups()
                factor = 1 if sign == "+" else -1
                if unit:
                    try:
                        base = datetime.fromisoformat(str(flat[0]))
                    except ValueError:
                        return None
                    values = [(base + timedelta(days=factor * int(float(amount)))).isoformat()]
                else:
                    try:
                        values = [float(flat[0]) + factor * float(amount)]
                    except (TypeError, ValueError):
                        return None
        elif op == "template":
            template = node.attrs.get("format")
            flat = [item for value in inputs for item in _flatten(value)]
            if not isinstance(template, str) or not flat:
                return None
            try:
                values = [template.format(*flat)]
            except (IndexError, KeyError, ValueError):
                return None
        elif op == "join":
            left_key = node.attrs.get("left_key")
            right_key = node.attrs.get("right_key")
            if (len(input_groups) != 2 or not isinstance(left_key, str)
                    or not isinstance(right_key, str)):
                return None
            left_rows = [item for value in input_groups[0] for item in (
                [value] if isinstance(value, Mapping) and left_key in value else
                list(value.values()) if isinstance(value, Mapping)
                else list(value) if isinstance(value, (list, tuple)) else [value]
            ) if isinstance(item, Mapping)]
            right_rows = [item for value in input_groups[1] for item in (
                [value] if isinstance(value, Mapping) and right_key in value else
                list(value.values()) if isinstance(value, Mapping)
                else list(value) if isinstance(value, (list, tuple)) else [value]
            ) if isinstance(item, Mapping)]
            values = []
            for left in left_rows:
                for right in right_rows:
                    if _normal(left.get(left_key)) == _normal(right.get(right_key)):
                        values.append({"left": dict(left), "right": dict(right)})
            if not values:
                return None
        else:
            return None
        return values, calls, [*operators, str(op)]

    @staticmethod
    def _compare(left: Any, comparator: str, right: Any) -> bool:
        try:
            if comparator == "gt":
                return float(left) > float(right)
            if comparator == "gte":
                return float(left) >= float(right)
            if comparator == "lt":
                return float(left) < float(right)
            if comparator == "lte":
                return float(left) <= float(right)
        except (TypeError, ValueError):
            return False
        if comparator == "neq":
            return _normal(left) != _normal(right)
        if comparator == "contains":
            return _normal(right) in _normal(left)
        return _normal(left) == _normal(right)
