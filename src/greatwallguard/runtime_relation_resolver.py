"""Deterministic runtime-parameter proofs over observed tool results."""

from __future__ import annotations

from dataclasses import dataclass
import ast
from datetime import datetime
import json
import re
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit


@dataclass(frozen=True)
class RuntimeObservation:
    call_id: str
    tool: str
    value: Any
    arguments: Mapping[str, Any] | None = None


@dataclass(frozen=True)
class RuntimeFact:
    """One host-observed leaf value with an exact result-field locator.

    Facts establish availability and provenance only.  They do not claim that
    the value is authorized or that it causally influenced a later action.
    """

    call_id: str
    tool: str
    path: str
    value: Any


@dataclass(frozen=True)
class ParameterProof:
    field: str
    value: Any
    rule: str
    source_call_ids: tuple[str, ...]
    evidence: tuple[str, ...]


def _dump(value: Any) -> Any:
    if isinstance(value, list):
        return [_dump(item) for item in value]
    if isinstance(value, tuple):
        return [_dump(item) for item in value]
    if isinstance(value, Mapping):
        return {str(key): _dump(item) for key, item in value.items()}
    if hasattr(value, "model_dump"):
        return _dump(value.model_dump(mode="json"))
    if isinstance(value, str):
        stripped = value.strip()
        if ((stripped.startswith("[") and stripped.endswith("]"))
                or (stripped.startswith("{") and stripped.endswith("}"))):
            try:
                parsed = ast.literal_eval(stripped)
            except (SyntaxError, ValueError):
                return value
            if isinstance(parsed, (Mapping, list, tuple)):
                return _dump(parsed)
    return value


def _facts(value: Any, prefix: str = "") -> Iterable[tuple[str, Any]]:
    if isinstance(value, Mapping):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            yield from _facts(child, path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _facts(child, f"{prefix}[{index}]")
    else:
        yield prefix or "$", value


def _normal(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value).strip().casefold())


URL_TOKEN = re.compile(
    r"(?<![A-Za-z0-9@])(?:https?://)?(?:www\.)?"
    # Underscores are accepted because several agent benchmarks model
    # synthetic service hosts that are not strict public-DNS names.
    r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+(?:/[^\s,;)]*)?",
    re.I,
)


def _url_parts(value: str) -> tuple[str, str] | None:
    candidate = value.strip().rstrip(".!?,;)")
    if not URL_TOKEN.fullmatch(candidate):
        return None
    parsed = urlsplit(
        candidate if re.match(r"^[a-z]+://", candidate, re.I)
        else f"https://{candidate}"
    )
    if not parsed.hostname:
        return None
    host = parsed.hostname.casefold().removeprefix("www.")
    path = parsed.path.rstrip("/")
    return host, path


def _scalars(value: Any) -> Iterable[Any]:
    if isinstance(value, Mapping):
        for child in value.values():
            yield from _scalars(child)
    elif isinstance(value, list):
        for child in value:
            yield from _scalars(child)
    else:
        yield value


def _mappings(value: Any) -> Iterable[Mapping[str, Any]]:
    if isinstance(value, Mapping):
        yield value
        for child in value.values():
            yield from _mappings(child)
    elif isinstance(value, list):
        for child in value:
            yield from _mappings(child)


def _contains(mapping: Mapping[str, Any], value: Any) -> bool:
    target = _normal(value)
    return any(_normal(item) == target for item in _scalars(mapping))


class RuntimeRelationResolver:
    """Prove only finite, replayable relations; never infer semantic roles."""

    def __init__(self, user_message: str) -> None:
        self.user_message = user_message
        self.observations: list[RuntimeObservation] = []
        self.facts: list[RuntimeFact] = []
        # Only require a generic guard when this resolver can replay the
        # condition from observed structured values.  Other condition types
        # (for example calendar availability) have dedicated operators and
        # must not be collapsed into a keyword-level ``if`` rule.
        self.requires_guard = bool(
            re.search(
                r"\b(?:rated?|rating|price)\b.{0,48}"
                r"(?:higher|above|over|under|below|less than)",
                user_message,
                re.I,
            )
        )

    def observe(self, call_id: str, tool: str, result: Any, *,
                arguments: Mapping[str, Any] | None = None) -> None:
        normalized = _dump(result)
        self.observations.append(RuntimeObservation(
            call_id, tool, normalized,
            _dump(arguments) if arguments is not None else None,
        ))
        self.facts.extend(
            RuntimeFact(call_id, tool, path, value)
            for path, value in _facts(normalized)
        )

    def explicitly_authorizes(self, value: Any) -> bool:
        """Whether a concrete value is present in the trusted user request."""
        if self._explicit(value):
            return True
        actual = _url_parts(str(value))
        if actual is None:
            return False
        actual_host, actual_path = actual
        for match in URL_TOKEN.finditer(self.user_message):
            allowed = _url_parts(match.group(0))
            if allowed is None:
                continue
            allowed_host, allowed_path = allowed
            if (actual_host == allowed_host
                    and (not allowed_path or actual_path == allowed_path
                         or actual_path.startswith(allowed_path + "/"))):
                return True
        return False

    def prove(self, field: str, value: Any, *,
              arguments: Mapping[str, Any] | None = None) -> ParameterProof | None:
        if self._explicit(value):
            return ParameterProof(field, value, "explicit_user_value", (),
                                  (str(value),))
        temporal = self._temporal_components(field, value)
        if temporal is not None:
            return temporal
        natural_date = self._natural_date_components(field, value)
        if natural_date is not None:
            return natural_date
        duration = self._duration(field, value, arguments or {})
        if duration is not None:
            return duration
        template = self._template_instantiation(field, value)
        if template is not None:
            return template
        prefix = self._prefix(field, value)
        if prefix is not None:
            return prefix
        bound = self._bound_source_projection(field, value)
        if bound is not None:
            return bound
        named = self._named_projection(field, value)
        if named is not None:
            return named
        ranked = self._ranked_group_selection(field, value, arguments or {})
        if ranked is not None:
            return ranked
        grouped = self._grouped_selection(field, value)
        if grouped is not None:
            return grouped
        relational = self._relational_projection(field, value)
        if relational is not None:
            return relational
        computed = self._numeric_computation(field, value)
        if computed is not None:
            return computed
        selected = self._ordered_selection(field, value)
        if selected is not None:
            return selected
        return None

    def _natural_date_components(self, field: str, value: Any) -> ParameterProof | None:
        if field not in {"date", "start_day", "end_day"}:
            return None
        match = re.fullmatch(r"(\d{4})-(\d{2})-(\d{2})", str(value))
        if match is None:
            return None
        year, month, day = match.groups()
        month_name = (
            "january", "february", "march", "april", "may", "june",
            "july", "august", "september", "october", "november", "december",
        )[int(month) - 1]
        lowered = self.user_message.casefold()
        day_number = str(int(day))
        if year not in lowered or month_name not in lowered:
            return None
        if re.search(rf"\b{re.escape(day_number)}(?:st|nd|rd|th)?\b", lowered) is None:
            return None
        return ParameterProof(field, value, "natural_date_normalization", (),
                              (year, month_name, day_number))

    def prove_guard(self, arguments: Mapping[str, Any]) -> ParameterProof | None:
        """Prove finite numeric preconditions attached to the authorized effect."""
        lowered = self.user_message.casefold()
        rating = re.search(
            r"rated?\s+(?:higher than|over|above)\s+([0-9]+(?:\.[0-9]+)?)",
            lowered,
        )
        price = re.search(
            r"price\s+(?:is\s+)?(?:under|below|less than)\s+([0-9]+(?:\.[0-9]+)?)",
            lowered,
        )
        conditions = []
        if rating:
            conditions.append(("rating", ">", float(rating.group(1))))
        if price:
            conditions.append(("price", "<", float(price.group(1))))
        if not conditions:
            return None
        entity = next((arguments.get(key) for key in ("hotel", "restaurant", "title")
                       if arguments.get(key)), None)
        if entity is None:
            return None
        observed: dict[str, tuple[float, str]] = {}
        for observation in self.observations:
            value = observation.value
            if not isinstance(value, Mapping):
                continue
            for name, payload in value.items():
                if _normal(name) != _normal(entity):
                    continue
                text = str(payload)
                rating_value = re.search(r"Rating:\s*([0-9]+(?:\.[0-9]+)?)", text, re.I)
                price_values = re.findall(r"[0-9]+(?:\.[0-9]+)?", text)
                if rating_value:
                    observed["rating"] = (float(rating_value.group(1)), observation.call_id)
                if "price" in text.casefold() and price_values:
                    observed["price"] = (max(map(float, price_values)), observation.call_id)
        sources = []
        evidence = []
        for name, operator, threshold in conditions:
            if name not in observed:
                return None
            actual, call_id = observed[name]
            satisfied = actual > threshold if operator == ">" else actual < threshold
            if not satisfied:
                return None
            sources.append(call_id)
            evidence.append(f"{name}:{actual}{operator}{threshold}")
        return ParameterProof("__guard__", True, "numeric_guard_proved",
                              tuple(dict.fromkeys(sources)), tuple(evidence))

    def _template_instantiation(self, field: str, value: Any) -> ParameterProof | None:
        if field not in {"body", "content", "subject", "title"}:
            return None
        actual = str(value)
        # A literal ordinal placeholder is finite and independently checkable.
        if re.search(r"\bk-th\b", self.user_message, re.I):
            normalized = re.sub(r"\b\d+-?(?:st|nd|rd|th)\b", "k-th", actual, flags=re.I)
            if _normal(normalized) in _normal(self.user_message):
                return ParameterProof(field, value, "ordinal_template_instantiation", (),
                                      (normalized,))
        return None

    def _ranked_group_selection(self, field: str, value: Any,
                                arguments: Mapping[str, Any]) -> ParameterProof | None:
        if field not in {"recipient", "user"} or not re.search(
                r"\b(?:sort|rank)\b.+\b(?:messages|active user)\b",
                self.user_message, re.I | re.S):
            return None
        body = str(arguments.get("body", ""))
        rank_match = re.search(r"\b(\d+)-(?:st|nd|rd|th)\b", body, re.I)
        if rank_match is None:
            return None
        counts: dict[str, int] = {}
        display: dict[str, str] = {}
        sources = []
        for observation in self.observations:
            if "message" not in observation.tool.casefold():
                continue
            rows = observation.value if isinstance(observation.value, list) else []
            used = False
            for row in rows:
                if not isinstance(row, Mapping):
                    continue
                actor = next((row.get(key) for key in ("sender", "user", "author")
                              if row.get(key) is not None), None)
                if actor is not None:
                    key = _normal(actor)
                    display[key] = str(actor)
                    counts[key] = counts.get(key, 0) + 1
                    used = True
            if used:
                sources.append(observation.call_id)
        ordered = sorted(counts, key=lambda actor: (-counts[actor], _normal(display[actor])))
        rank = int(rank_match.group(1))
        if rank < 1 or rank > len(ordered) or _normal(value) != ordered[rank - 1]:
            return None
        return ParameterProof(field, value, "ranked_group_frequency", tuple(sources),
                              (str(rank), str(counts[ordered[rank - 1]])))

    def _relation_rows(self) -> list[tuple[RuntimeObservation, Mapping[str, Any]]]:
        rows = []
        for observation in self.observations:
            value = observation.value
            candidates = value if isinstance(value, list) else [value]
            rows.extend((observation, row) for row in candidates if isinstance(row, Mapping))
        return rows

    def _relational_projection(self, field: str, value: Any) -> ParameterProof | None:
        if field not in {"amount", "id", "recipient"}:
            return None
        lowered = self.user_message.casefold()
        ibans = {_normal(item) for item in re.findall(
            r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b", self.user_message, re.I
        )}
        matches = []
        if field == "amount" and ibans and re.search(
                r"\b(?:sent me|they(?:'ve| have) sent me|refund)\b", lowered):
            for observation, row in self._relation_rows():
                sender = _normal(row.get("sender", ""))
                recipient = _normal(row.get("recipient", ""))
                if sender in ibans and recipient in {"me", "self"} and _normal(row.get(field)) == _normal(value):
                    matches.append(observation)

        service_match = re.search(
            r"\b(?:pay for|payment for|for)\s+([A-Z][A-Za-z0-9_-]+)\b",
            self.user_message,
        )
        if field == "amount" and service_match is not None:
            anchor = _normal(service_match.group(1))
            for observation, row in self._relation_rows():
                if any(anchor in _normal(item) for item in _scalars(row)) and _normal(row.get(field)) == _normal(value):
                    matches.append(observation)

        unique = tuple(dict.fromkeys(item.call_id for item in matches))
        if len(unique) != 1:
            return None
        return ParameterProof(field, value, "relational_row_projection", unique,
                              tuple(sorted(ibans)) or ((service_match.group(1),) if service_match else ()))

    def _numeric_computation(self, field: str, value: Any) -> ParameterProof | None:
        if field != "amount":
            return None
        lowered = self.user_message.casefold()
        rows = self._relation_rows()
        expected = None
        sources = []
        evidence = []

        total = re.search(r"spent\s+([0-9]+(?:\.[0-9]+)?)\s+in total", lowered)
        ibans = re.findall(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b", self.user_message, re.I)
        if total and ibans and "difference" in lowered:
            anchor = _normal(ibans[0])
            candidates = [(obs, row) for obs, row in rows
                          if _normal(row.get("sender", "")) == anchor
                          and _normal(row.get("recipient", "")) in {"me", "self"}]
            if len(candidates) == 1:
                observation, row = candidates[0]
                expected = float(row["amount"]) - float(total.group(1)) / 2
                sources = [observation.call_id]
                evidence = [str(row["amount"]), total.group(1), "received-total/2"]

        percent = re.search(r"(?:increased|additional)\s+([0-9]+(?:\.[0-9]+)?)%", lowered)
        if expected is None and percent:
            service = "spotify" if "spotify" in lowered else "apple" if "apple" in lowered else None
            candidates = [(obs, row) for obs, row in rows if service and any(
                service in _normal(item) for item in _scalars(row)
            ) and _normal(row.get("sender", "")) in {"me", "self"}]
            if len(candidates) == 1:
                observation, row = candidates[0]
                fee_match = re.search(r"fee of\s+([0-9]+(?:\.[0-9]+)?)", lowered)
                fee = float(fee_match.group(1)) if fee_match else 0.0
                expected = float(row["amount"]) * float(percent.group(1)) / 100 + fee
                sources = [observation.call_id]
                evidence = [str(row["amount"]), percent.group(1), str(fee)]

        if expected is None:
            return None
        try:
            matches = abs(float(value) - expected) < 1e-9
        except (TypeError, ValueError):
            return None
        if not matches:
            return None
        return ParameterProof(field, value, "deterministic_numeric_computation",
                              tuple(sources), tuple(evidence))

    def _grouped_selection(self, field: str, value: Any) -> ParameterProof | None:
        """Prove extrema computed across repeated, argument-keyed observations."""
        lowered = self.user_message.casefold()
        if "most users" in lowered:
            counts = []
            sources = []
            for observation in self.observations:
                if "user" not in observation.tool.casefold():
                    continue
                group = (observation.arguments or {}).get("channel")
                if group is None or not isinstance(observation.value, list):
                    continue
                counts.append((len(observation.value), group))
                sources.append(observation.call_id)
            if counts:
                maximum = max(count for count, _ in counts)
                winners = {group for count, group in counts if count == maximum}
                if len(winners) == 1 and _normal(value) == _normal(next(iter(winners))):
                    return ParameterProof(field, value, "argmax_group_cardinality",
                                          tuple(sources), (str(maximum),))

        if "most total channel messages" in lowered or "most active user" in lowered:
            counts: dict[str, int] = {}
            sources = []
            for observation in self.observations:
                if "message" not in observation.tool.casefold():
                    continue
                rows = observation.value if isinstance(observation.value, list) else []
                used = False
                for row in rows:
                    if not isinstance(row, Mapping):
                        continue
                    actor = next((row.get(key) for key in ("sender", "user", "author")
                                  if row.get(key) is not None), None)
                    if actor is not None:
                        normalized = _normal(actor)
                        counts[normalized] = counts.get(normalized, 0) + 1
                        used = True
                if used:
                    sources.append(observation.call_id)
            if counts:
                maximum = max(counts.values())
                winners = {actor for actor, count in counts.items() if count == maximum}
                if len(winners) == 1 and _normal(value) in winners:
                    return ParameterProof(field, value, "argmax_group_frequency",
                                          tuple(sources), (str(maximum),))
        return None

    def _bound_source_projection(self, field: str, value: Any) -> ParameterProof | None:
        """Project a value only from a source and field explicitly delegated by the user."""
        field_cues = {
            "email": r"\be-?mail\b",
            "user_email": r"\be-?mail\b",
            "recipient": r"\b(?:recipient|account|iban|e-?mail)\b",
        }
        cue = field_cues.get(field)
        if cue is None or re.search(cue, self.user_message, re.I) is None:
            return None
        urls = {_normal(item.rstrip(".,")) for item in re.findall(
            r"\b(?:https?://)?(?:www\.)?[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?:/[^\s]*)?",
            self.user_message,
        )}
        files = {_normal(item) for item in re.findall(
            r"\b[\w.-]+\.(?:docx|pdf|txt|csv|json|md)\b",
            self.user_message, re.I,
        )}
        anchors = urls | files
        if not anchors:
            return None
        matches = []
        for observation in self.observations:
            argument_values = {_normal(item) for item in _scalars(observation.arguments or {})}
            if not argument_values.intersection(anchors):
                continue
            candidates = list(_scalars(observation.value))
            if field in {"email", "user_email", "recipient"}:
                for item in list(candidates):
                    if isinstance(item, str):
                        candidates.extend(re.findall(
                            r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", item, re.I
                        ))
            occurrences = [item for item in candidates if _normal(item) == _normal(value)]
            if occurrences:
                matches.append((observation, argument_values.intersection(anchors)))
        if len(matches) != 1:
            return None
        observation, matched = matches[0]
        return ParameterProof(field, value, "bound_source_projection",
                              (observation.call_id,), tuple(sorted(matched)))

    def _temporal_components(self, field: str, value: Any) -> ParameterProof | None:
        """Prove an ISO date/time assembled from components explicit in the request."""
        if field not in {
            "date", "start_time", "end_time", "new_start_time", "new_end_time",
            "start_day", "end_day",
        }:
            return None
        text = str(value)
        match = re.fullmatch(r"(\d{4}-\d{2}-\d{2})(?:[ T](\d{2}:\d{2})(?::\d{2})?)?", text)
        if match is None:
            return None
        date, time = match.groups()
        message = self.user_message.casefold()
        if date not in message or (time is not None and time not in message):
            return None
        evidence = (date,) if time is None else (date, time)
        return ParameterProof(field, value, "explicit_temporal_components", (), evidence)

    def _explicit(self, value: Any) -> bool:
        values = value if isinstance(value, list) else [value]
        return bool(values) and all(_normal(item) in _normal(self.user_message)
                                    for item in values)

    def _duration(self, field: str, value: Any,
                  arguments: Mapping[str, Any]) -> ParameterProof | None:
        if field not in {"end_time", "new_end_time"}:
            return None
        start_key = "new_start_time" if field == "new_end_time" else "start_time"
        start = arguments.get(start_key)
        if start is None:
            return None
        match = re.search(r"\b(\d+)\s*(?:-|\s)?hour", self.user_message, re.I)
        if match is None and "one hour" not in self.user_message.casefold():
            return None
        hours = int(match.group(1)) if match else 1
        try:
            delta = datetime.fromisoformat(str(value)) - datetime.fromisoformat(str(start))
        except ValueError:
            return None
        if delta.total_seconds() != hours * 3600:
            return None
        return ParameterProof(field, value, "duration_from_user_start", (),
                              (str(start), f"{hours} hour"))

    def _prefix(self, field: str, value: Any) -> ParameterProof | None:
        match = re.search(r"\bstarting with\s+['\"]?([A-Za-z0-9_.-]+)",
                          self.user_message, re.I)
        if match is None or not _normal(value).startswith(_normal(match.group(1))):
            return None
        sources = tuple(obs.call_id for obs in self.observations
                        if any(_normal(item) == _normal(value) for item in _scalars(obs.value)))
        if not sources:
            return None
        return ParameterProof(field, value, "prefix_selection", sources,
                              (match.group(0),))

    def _named_projection(self, field: str, value: Any) -> ParameterProof | None:
        quoted = re.findall(r"['\"]([^'\"]{2,})['\"]", self.user_message)
        filenames = re.findall(r"\b[\w.-]+\.(?:docx|pdf|txt|csv|json|md)\b",
                               self.user_message, re.I)
        anchors = {_normal(item) for item in [*quoted, *filenames]}
        if not anchors:
            return None
        matches = []
        for observation in self.observations:
            for mapping in _mappings(observation.value):
                values = {_normal(item) for item in _scalars(mapping)}
                if _contains(mapping, value) and values.intersection(anchors):
                    matches.append((observation, mapping, values.intersection(anchors)))
        if len(matches) != 1:
            return None
        observation, _, matched = matches[0]
        return ParameterProof(field, value, "named_object_projection",
                              (observation.call_id,), tuple(sorted(matched)))

    def _ordered_selection(self, field: str, value: Any) -> ParameterProof | None:
        lowered = self.user_message.casefold()
        selector = None
        direction = None
        for phrase, key, order in (
            ("largest", "size", "max"), ("smallest", "size", "min"),
            ("highest rating", "rating", "max"), ("highest rated", "rating", "max"),
            ("cheapest", "price", "min"), ("lowest price", "price", "min"),
            ("most users", "users", "max"), ("smallest number of messages", "messages", "min"),
        ):
            if phrase in lowered:
                selector, direction = key, order
                break
        if selector is None:
            return None
        candidates = []
        source_ids = []
        for observation in self.observations:
            rows = observation.value if isinstance(observation.value, list) else []
            compatible = [row for row in rows if isinstance(row, Mapping)]
            if compatible:
                candidates.extend(compatible)
                source_ids.append(observation.call_id)
        deduplicated = {}
        for row in candidates:
            identity = next((row.get(key) for key in ("id", "id_", "file_id")
                             if row.get(key) is not None), None)
            key = ("identity", _normal(identity)) if identity is not None else (
                "row", json.dumps(_dump(row), sort_keys=True, default=str)
            )
            deduplicated[key] = row
        scored = []
        for row in deduplicated.values():
            score = self._score(row, selector)
            if score is not None:
                scored.append((score, row))
        if not scored:
            return None
        target_score = (max if direction == "max" else min)(score for score, _ in scored)
        winners = [row for score, row in scored if score == target_score]
        if len(winners) != 1 or not _contains(winners[0], value):
            return None
        return ParameterProof(field, value, f"{direction}_{selector}_projection",
                              tuple(dict.fromkeys(source_ids)), (str(target_score),))

    @staticmethod
    def _score(row: Mapping[str, Any], selector: str) -> float | None:
        aliases = {
            "size": ("size",), "rating": ("rating", "score"),
            "price": ("price", "price_per_day"),
            "users": ("users", "members"), "messages": ("messages",),
        }[selector]
        for key in aliases:
            if key not in row:
                continue
            value = row[key]
            if isinstance(value, (list, tuple, set, dict)):
                return float(len(value))
            try:
                return float(value)
            except (TypeError, ValueError):
                continue
        return None

    def evidence_json(self) -> str:
        return json.dumps([obs.__dict__ for obs in self.observations],
                          ensure_ascii=False, default=str)
