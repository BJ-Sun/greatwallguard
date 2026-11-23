import unittest

from greatwallguard import (
    AuthorizationDAG, AuthorizationRuntime, AuthorizationTimeline,
    ConstrainedAuthorizationUpdateCompiler, ConstrainedIntentDAGCompiler,
    EffectContract, IntentCompilationError,
)


CONTRACTS = (
    EffectContract("send_email", "external_message", ("recipients",), ("recipients",)),
    EffectContract("delete_file", "file_delete", ("file_id",), ("file_id",)),
)


class StaticBackend:
    def __init__(self, value):
        self.value = value

    def generate(self, **_kwargs):
        return self.value


def ir(tool="send_email", value="alice@example.com"):
    contract = CONTRACTS[0] if tool == "send_email" else CONTRACTS[1]
    field = contract.critical_fields[0]
    return {
        "schema": "authorization_ir_v1", "review_reasons": [],
        "delegations": [], "grants": [{
            "grant_id": "g", "tool": tool, "effect": contract.effect,
            "bindings": {field: {"op": "literal", "value": value}},
            "constraints": [], "budget": 1,
        }],
    }


def compiler(value):
    backend = StaticBackend(value)
    intent = ConstrainedIntentDAGCompiler(
        CONTRACTS, (), backend, check_explicit_effect_completeness=False,
        allow_partial=True,
    )
    return ConstrainedAuthorizationUpdateCompiler(intent, backend)


class AuthorizationUpdateCompilerTests(unittest.TestCase):
    def test_add_creates_first_authorization(self):
        value = {
            "schema": "authorization_update_v1", "operation": "ADD",
            "target_effect_ids": [], "evidence": "Send to Alice",
            "authorization_ir": ir(),
        }
        update = compiler(value)
        runtime = AuthorizationRuntime(AuthorizationDAG())
        timeline = AuthorizationTimeline(runtime)
        plan = update.compile(
            trusted_message="Send to Alice", runtime=runtime, turn=1,
        )
        update.apply(plan=plan, timeline=timeline, turn=1,
                     trusted_message="Send to Alice")
        self.assertEqual(
            runtime.authorize_tool_call(
                "c", "send_email", {"recipients": "alice@example.com"},
            ).verdict,
            "allow",
        )

    def test_replace_revokes_named_old_effect(self):
        runtime = AuthorizationRuntime(AuthorizationDAG())
        timeline = AuthorizationTimeline(runtime)
        add = compiler({
            "schema": "authorization_update_v1", "operation": "ADD",
            "target_effect_ids": [], "evidence": "Send to Alice",
            "authorization_ir": ir(),
        })
        first = add.compile(trusted_message="Send to Alice", runtime=runtime, turn=1)
        first_record = add.apply(plan=first, timeline=timeline, turn=1,
                                 trusted_message="Send to Alice")
        old = first_record.added_effect_ids[0]
        replace = compiler({
            "schema": "authorization_update_v1", "operation": "REPLACE",
            "target_effect_ids": [old], "evidence": "change it to Bob",
            "authorization_ir": ir(value="bob@example.com"),
        })
        plan = replace.compile(
            trusted_message="Wait, change it to Bob", runtime=runtime, turn=2,
        )
        replace.apply(plan=plan, timeline=timeline, turn=2,
                      trusted_message="Wait, change it to Bob")
        self.assertIn(old, runtime.revoked)
        self.assertEqual(
            runtime.authorize_tool_call(
                "bob", "send_email", {"recipients": "bob@example.com"},
            ).verdict,
            "allow",
        )

    def test_refine_that_changes_concrete_value_is_normalized_to_replace(self):
        runtime = AuthorizationRuntime(AuthorizationDAG())
        timeline = AuthorizationTimeline(runtime)
        add = compiler({
            "schema": "authorization_update_v1", "operation": "ADD",
            "target_effect_ids": [], "evidence": "Send to Alice",
            "authorization_ir": ir(),
        })
        record = add.apply(
            plan=add.compile(trusted_message="Send to Alice", runtime=runtime, turn=1),
            timeline=timeline, turn=1, trusted_message="Send to Alice",
        )
        update = compiler({
            "schema": "authorization_update_v1", "operation": "REFINE",
            "target_effect_ids": [record.added_effect_ids[0]],
            "evidence": "change it to Bob",
            "authorization_ir": ir(value="bob@example.com"),
        })
        plan = update.compile(
            trusted_message="change it to Bob", runtime=runtime, turn=2,
        )
        self.assertEqual(plan.kind.value, "REPLACE")

    def test_replace_cannot_change_effect_tool(self):
        runtime = AuthorizationRuntime(AuthorizationDAG())
        timeline = AuthorizationTimeline(runtime)
        add = compiler({
            "schema": "authorization_update_v1", "operation": "ADD",
            "target_effect_ids": [], "evidence": "Send to Alice",
            "authorization_ir": ir(),
        })
        record = add.apply(
            plan=add.compile(trusted_message="Send to Alice", runtime=runtime, turn=1),
            timeline=timeline, turn=1, trusted_message="Send to Alice",
        )
        bad = compiler({
            "schema": "authorization_update_v1", "operation": "REPLACE",
            "target_effect_ids": [record.added_effect_ids[0]],
            "evidence": "change the recipient", "authorization_ir": ir("delete_file", "x"),
        })
        with self.assertRaisesRegex(IntentCompilationError, "different effect tool"):
            bad.compile(
                trusted_message="change the recipient", runtime=runtime, turn=2,
            )

    def test_context_only_cannot_expand_authority(self):
        update = compiler({
            "schema": "authorization_update_v1", "operation": "CONTEXT_ONLY",
            "target_effect_ids": [], "evidence": "The status is pending",
            "authorization_ir": None,
        })
        runtime = AuthorizationRuntime(AuthorizationDAG())
        plan = update.compile(
            trusted_message="The status is pending", runtime=runtime, turn=1,
        )
        self.assertFalse(plan.delta.nodes)


if __name__ == "__main__":
    unittest.main()
