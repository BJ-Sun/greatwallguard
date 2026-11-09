"""Schema-grounded deterministic authorization compiler.

The compiler is benchmark-agnostic: a deployment supplies finite defender
contracts (effect class and critical fields) for its tools.  Shared effect
semantics and parameter types are compiled from trusted user text without
task IDs, attack examples, or tool-result contents.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Iterable, Mapping

from .structured_effect_authorization import (
    EMAIL, IBAN, URL, ParameterAuthorization, StructuredEffectDecision,
    StructuredEffectGrant,
)


@dataclass(frozen=True)
class EffectContract:
    tool: str
    effect: str
    critical_fields: tuple[str, ...]
    description: str = ""
    required_fields: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        unknown = set(self.required_fields) - set(self.critical_fields)
        if unknown:
            raise ValueError(f"required fields are not critical fields: {sorted(unknown)}")


# This ontology describes stable user-visible effects, not benchmark tasks.
# New tools reuse one of these classes instead of adding prompt-specific rules.
EFFECT_LANGUAGE: Mapping[str, tuple[str, ...]] = {
    "external_message": ("send", "email", "message", "write", "reply", "notify"),
    "channel_message": ("post", "write", "reply", "message", "channel"),
    "delete_message": ("delete email", "remove email", "delete message"),
    "calendar_create": ("create event", "add event", "schedule", "calendar", "reminder"),
    "calendar_cancel": ("cancel", "remove event", "delete event"),
    "calendar_reschedule": ("reschedule", "move appointment", "change appointment"),
    "calendar_participant_add": ("add participant", "invite participant"),
    "file_update": ("append", "add", "update", "adjust", "file", "list"),
    "file_create": ("create file", "new file", "save file"),
    "file_delete": ("delete file", "remove file"),
    "file_share": ("share", "grant access", "permission"),
    "membership_add": ("add", "join", "channel", "member"),
    "workspace_invite": ("invite", "workspace", "slack", "colleague"),
    "workspace_remove": ("remove", "workspace", "slack", "user"),
    "web_publish": ("post", "publish", "website", "webpage"),
    "reservation": ("reserve", "reservation", "book", "hotel", "restaurant", "rental"),
    # Generic "send" and "refund" are intentionally excluded: they collide
    # with messages and purchase refunds. Currency/recipient fields and the
    # more specific transfer vocabulary distinguish actual fund movement.
    "funds_transfer": ("pay", "transfer", "bill", "money", "difference"),
    "shopping_cart_update": ("add to cart", "remove from cart", "clear cart"),
    "purchase": ("buy", "purchase", "place the order", "checkout"),
    "purchase_refund": ("request a refund", "refund order", "refund purchase"),
    "filesystem_update": ("download", "save file", "copy file", "move file"),
    "repository_update": ("create repository", "delete repository", "upload to", "sync repository"),
    "scheduled_funds_transfer": ("schedule", "recurring", "transaction", "payment"),
    "scheduled_funds_update": ("update", "adjust", "change", "rent", "payment", "standing order"),
    "credential_update": ("update password", "change password", "reset password"),
    "account_profile_update": ("update", "account information", "user info", "address"),
}

ACTION_WORDS = frozenset({
    "send", "email", "message", "write", "reply", "notify", "post", "delete",
    "remove", "cancel", "create", "add", "schedule", "reschedule", "move",
    "change", "append", "update", "adjust", "share", "grant", "invite",
    "publish", "reserve", "reservation", "book", "pay", "refund", "transfer",
    "reset", "save",
})
NEGATED = re.compile(r"\b(?:do not|don't|never|without)\b[^.!?]{0,50}$", re.I)
DELEGATION = re.compile(
    r"\b(?:actions?|tasks?)\s+(?:specified|listed|recorded)\s+in\b"
    r"|\bdo all the tasks\b.+\bTODO list\b|\bfollow the instructions\b",
    re.I | re.S,
)


def _tokens(text: str) -> set[str]:
    values = set(re.findall(r"[a-z][a-z0-9_-]*", text.casefold()))
    # Lightweight normalization is intentionally finite and auditable.
    for token in list(values):
        if token.endswith("ies") and len(token) > 4:
            values.add(token[:-3] + "y")
        elif token.endswith("s") and len(token) > 3:
            values.add(token[:-1])
    return values


def _effect_match(effect: str, text: str) -> str | None:
    language = EFFECT_LANGUAGE.get(effect)
    if language is None:
        return None
    lowered = text.casefold()
    text_tokens = _tokens(lowered)
    matched = []
    for phrase in language:
        phrase_tokens = _tokens(phrase)
        if ((len(phrase_tokens) == 1 and phrase_tokens.issubset(text_tokens))
                or (len(phrase_tokens) >= 2 and (
                    phrase in lowered or phrase_tokens.issubset(text_tokens)))):
            matched.append(phrase)
    if not matched:
        if (effect == "funds_transfer" and "refund" in text_tokens
                and (IBAN.search(text) is not None
                     or re.search(r"\b(?:sent me|got from|received)\b", lowered))):
            matched.append("refund_funds")
        else:
            return None
    action_present = bool(_tokens(lowered).intersection(ACTION_WORDS))
    if not action_present:
        return None
    positions = [lowered.find(phrase) for phrase in matched if phrase in lowered]
    first = min(positions) if positions else 0
    prefix = text[max(0, first - 55):first]
    if NEGATED.search(prefix):
        return None
    return ",".join(sorted(matched))


def _values(field: str, text: str) -> tuple[str, ...]:
    normalized = field.casefold()
    if any(key in normalized for key in ("recipient", "email", "participant")):
        found = list(EMAIL.findall(text))
        if normalized == "recipient":
            found.extend(IBAN.findall(text))
        return tuple(dict.fromkeys(item.casefold() for item in found))
    if "url" in normalized:
        return tuple(dict.fromkeys(item.casefold().rstrip(".,") for item in URL.findall(text)))
    if "password" in normalized:
        found = re.search(r"password\s+(?:to|as)\s+['\"]([^'\"]+)['\"]", text, re.I)
        return (found.group(1),) if found else ()
    if normalized in {"filename", "file_name"}:
        found = re.search(r"file\s+named\s+['\"]([^'\"]+)['\"]", text, re.I)
        return (found.group(1),) if found else ()
    if "permission" in normalized:
        if re.search(r"\bread(?:-only)? permissions?\b", text, re.I):
            return ("r",)
        if re.search(r"\b(?:write|edit|read-write) permissions?\b", text, re.I):
            return ("rw",)
    return ()


class SchemaGroundedAuthorization:
    """Compile and check effect grants from one trusted user message."""

    def __init__(self, user_message: str, contracts: Iterable[EffectContract]) -> None:
        self.user_message = user_message
        self.delegated = bool(DELEGATION.search(user_message))
        self.grants = self._compile(tuple(contracts))

    def _compile(self, contracts: tuple[EffectContract, ...]) -> tuple[StructuredEffectGrant, ...]:
        grants = []
        for contract in contracts:
            evidence = _effect_match(contract.effect, self.user_message)
            if evidence is None:
                continue
            parameters = {}
            for field in contract.critical_fields:
                values = _values(field, self.user_message)
                # Role-based recipients cannot be reduced to another explicit
                # account appearing elsewhere in the same multi-effect task.
                if (field == "recipient" and re.search(
                        r"\b(?:friend|them|their)\b", self.user_message, re.I)):
                    values = ()
                parameters[field] = (
                    ParameterAuthorization("literal_set", values)
                    if values else ParameterAuthorization(
                        "deferred", reason="runtime operand requires provenance proof"
                    )
                )
            grants.append(StructuredEffectGrant(
                contract.tool, contract.effect, parameters, evidence
            ))
        return tuple(grants)

    def check(self, tool: str, arguments: Mapping[str, Any]) -> StructuredEffectDecision:
        grants = [grant for grant in self.grants if grant.tool == tool]
        if not grants:
            if self.delegated:
                return StructuredEffectDecision("review", "effect_delegated_to_external_content")
            return StructuredEffectDecision("alert", "effect_not_authorized")
        unresolved = None
        for field, rule in grants[0].parameters.items():
            if field not in arguments:
                # A critical field is checked when this concrete partial-update
                # call actually writes it; absent optional fields have no effect.
                continue
            if rule.kind == "deferred":
                unresolved = unresolved or field
                continue
            actual = arguments.get(field)
            actual_values = actual if isinstance(actual, list) else [actual]
            observed = {self._normalize(field, item) for item in actual_values if item is not None}
            expected = {self._normalize(field, item) for item in rule.values}
            if not observed or not observed.issubset(expected):
                return StructuredEffectDecision("alert", "explicit_parameter_mismatch", field)
        if unresolved:
            return StructuredEffectDecision(
                "review", "authorized_effect_has_deferred_parameter", unresolved
            )
        return StructuredEffectDecision("allow", "effect_and_parameters_authorized")

    @staticmethod
    def _normalize(field: str, item: Any) -> str:
        value = str(item).casefold()
        if "url" in field.casefold():
            value = re.sub(r"^https?://", "", value)
            value = re.sub(r"^www\.", "", value).rstrip("/")
        return value
