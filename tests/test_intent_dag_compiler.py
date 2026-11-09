import unittest

from greatwallguard import (
    AuthorizationDAGVerifier,
    ConstrainedIntentDAGCompiler,
    EffectContract,
    IntentCompilationError,
    ObservationTool,
    RuntimeRelationResolver,
)


CONTRACTS = (
    EffectContract("reserve_hotel", "reservation", ("hotel", "start_day", "end_day")),
    EffectContract("send_email", "external_message", ("recipients", "subject", "body")),
)
OBSERVATIONS = (
    ObservationTool("search_hotels", ("name", "rating", "price")),
    ObservationTool("read_report", ("recipient", "summary")),
)


class StaticBackend:
    def __init__(self, value):
        self.value = value
        self.system_prompt = None

    def generate(self, *, system_prompt, user_prompt):
        self.system_prompt = system_prompt
        return self.value


class SequenceBackend:
    def __init__(self, values):
        self.values = iter(values)
        self.prompts = []

    def generate(self, *, system_prompt, user_prompt):
        self.prompts.append(user_prompt)
        return next(self.values)


def hotel_ir():
    hotels = {"op": "tool_result", "tool": "search_hotels"}
    selected = {
        "op": "aggregate", "function": "argmax", "field": "rating",
        "source": {
            "op": "select", "field": "rating", "comparator": "gt", "value": 4,
            "source": hotels,
        },
    }
    return {
        "schema": "authorization_ir_v1",
        "review_reasons": [],
        "grants": [{
            "grant_id": "book-best-rated",
            "tool": "reserve_hotel",
            "effect": "reservation",
            "bindings": {
                "hotel": {"op": "project", "field": "name", "source": selected},
                "start_day": {"op": "literal", "value": "next Monday"},
                "end_day": {
                    "op": "compute", "expression": "start_day + 1 day",
                    "source": {"op": "literal", "value": "next Monday"},
                },
            },
            "constraints": [{
                "left": {"op": "project", "field": "rating", "source": selected},
                "comparator": "gt",
                "right": {"op": "literal", "value": 4},
            }],
            "budget": 1,
        }],
    }


class IntentDAGCompilerTests(unittest.TestCase):
    def test_complex_dynamic_authorization_is_explicit_in_dag(self):
        backend = StaticBackend(hotel_ir())
        graph = ConstrainedIntentDAGCompiler(CONTRACTS, OBSERVATIONS, backend).compile(
            "Book the highest-rated hotel above 4 for next Monday night."
        )
        self.assertTrue(graph.is_acyclic())
        self.assertIn("EFFECT_CONTRACTS", backend.system_prompt)
        self.assertEqual(
            {node.op for node in graph.nodes.values() if node.kind == "transform"},
            {"select", "aggregate", "project", "compute"},
        )
        effect = next(node for node in graph.nodes.values() if node.kind == "effect")
        self.assertEqual(effect.attrs["tool"], "reserve_hotel")
        self.assertEqual(len(graph.incoming(effect.id, "binds")), 3)
        self.assertEqual(len(graph.incoming(effect.id, "guards")), 1)

    def test_per_binding_budget_is_validated_and_lowered(self):
        value = hotel_ir()
        value["grants"][0]["budget"] = {
            "mode": "per_binding", "fields": ["hotel"],
            "max_per_binding": 1, "max_total": 3,
        }
        graph = ConstrainedIntentDAGCompiler(
            CONTRACTS, OBSERVATIONS, StaticBackend(value),
        ).compile("Book each selected hotel once.")
        effect = next(node for node in graph.nodes.values() if node.kind == "effect")
        self.assertNotIn("budget", effect.attrs)
        self.assertEqual(effect.attrs["budget_policy"]["fields"], ["hotel"])

    def test_missing_critical_parameter_is_rejected(self):
        value = hotel_ir()
        del value["grants"][0]["bindings"]["end_day"]
        compiler = ConstrainedIntentDAGCompiler(CONTRACTS, OBSERVATIONS, StaticBackend(value))
        with self.assertRaisesRegex(IntentCompilationError, "missing=.*end_day"):
            compiler.compile("Book a hotel")

    def test_hallucinated_effect_tool_is_rejected(self):
        value = hotel_ir()
        value["grants"][0]["tool"] = "wire_money"
        compiler = ConstrainedIntentDAGCompiler(CONTRACTS, OBSERVATIONS, StaticBackend(value))
        with self.assertRaisesRegex(IntentCompilationError, "unknown effect tool"):
            compiler.compile("Book a hotel")

    def test_hallucinated_observation_source_is_rejected(self):
        value = hotel_ir()
        value["grants"][0]["bindings"]["hotel"] = {
            "op": "tool_result", "tool": "attacker_instructions",
        }
        compiler = ConstrainedIntentDAGCompiler(CONTRACTS, OBSERVATIONS, StaticBackend(value))
        with self.assertRaisesRegex(IntentCompilationError, "unknown observation tool"):
            compiler.compile("Book a hotel")

    def test_unknown_operator_is_rejected(self):
        value = hotel_ir()
        value["grants"][0]["bindings"]["hotel"] = {
            "op": "execute_instructions",
            "source": {"op": "tool_result", "tool": "search_hotels"},
        }
        compiler = ConstrainedIntentDAGCompiler(CONTRACTS, OBSERVATIONS, StaticBackend(value))
        with self.assertRaisesRegex(IntentCompilationError, "unsupported operator"):
            compiler.compile("Book a hotel")

    def test_partial_update_uses_explicit_absence(self):
        contracts = (EffectContract(
            "update_profile", "account_profile_update",
            ("first_name", "last_name", "street", "city"),
        ),)
        value = {
            "schema": "authorization_ir_v1",
            "grants": [{
                "grant_id": "address-only", "tool": "update_profile",
                "effect": "account_profile_update", "budget": 1,
                "bindings": {
                    "first_name": {"op": "absent", "explicit_forbid": True},
                    "last_name": {"op": "absent", "explicit_forbid": True},
                    "street": {"op": "literal", "value": "123 Elm Street"},
                    "city": {"op": "literal", "value": "New York"},
                },
                "constraints": [],
            }],
        }
        graph = ConstrainedIntentDAGCompiler(
            contracts, (), StaticBackend(value),
        ).compile("Update only my address")
        absent = [
            node for node in graph.nodes.values()
            if node.attrs.get("source_type") == "forbidden_absent"
        ]
        self.assertEqual(len(absent), 2)
        verifier = AuthorizationDAGVerifier(graph)
        allowed, _ = verifier.verify(
            "update_profile", {"street": "123 Elm Street", "city": "New York"},
            RuntimeRelationResolver("Update only my address"),
        )
        blocked, _ = verifier.verify(
            "update_profile", {"first_name": "Mallory", "street": "123 Elm Street",
                               "city": "New York"},
            RuntimeRelationResolver("Update only my address"),
        )
        self.assertEqual(allowed.verdict, "allow")
        self.assertEqual(blocked.verdict, "alert")
        self.assertEqual(blocked.reason, "parameter_not_authorized")

    def test_unmentioned_optional_parameter_reviews_instead_of_false_alert(self):
        contracts = (EffectContract(
            "checkout", "purchase", ("product_ids", "discount_code"),
        ),)
        value = {
            "schema": "authorization_ir_v1", "review_reasons": [],
            "grants": [{
                "grant_id": "purchase", "tool": "checkout", "effect": "purchase",
                "bindings": {
                    "product_ids": {"op": "literal", "value": ["P1"]},
                    "discount_code": {"op": "absent"},
                },
                "constraints": [], "budget": 1,
            }],
        }
        graph = ConstrainedIntentDAGCompiler(
            contracts, (), StaticBackend(value),
        ).compile("Buy product P1")
        decision, _ = AuthorizationDAGVerifier(graph).verify(
            "checkout", {"product_ids": ["P1"], "discount_code": "SAVE10"},
            RuntimeRelationResolver("Buy product P1"),
        )
        self.assertEqual(decision.verdict, "review")
        self.assertEqual(decision.reason, "unspecified_parameter_requires_review")

    def test_invalid_candidate_gets_one_bounded_repair(self):
        invalid = hotel_ir()
        del invalid["grants"][0]["bindings"]["end_day"]
        backend = SequenceBackend([invalid, hotel_ir()])
        graph = ConstrainedIntentDAGCompiler(CONTRACTS, OBSERVATIONS, backend).compile(
            "Book the highest-rated hotel above 4 for next Monday night."
        )
        self.assertEqual(len(backend.prompts), 2)
        self.assertIn("Validation error", backend.prompts[1])
        effect = next(node for node in graph.nodes.values() if node.kind == "effect")
        self.assertEqual(len(graph.incoming(effect.id, "binds")), 3)

    def test_external_content_cannot_create_effect_authority(self):
        value = {
            "schema": "authorization_ir_v1",
            "review_reasons": ["external_action_delegation"],
            "grants": [],
        }
        graph = ConstrainedIntentDAGCompiler(
            CONTRACTS, OBSERVATIONS, StaticBackend(value),
        ).compile("Do all the tasks listed in Alice's email")
        self.assertTrue(graph.delegated)
        self.assertFalse(any(node.kind == "effect" for node in graph.nodes.values()))

    def test_independent_check_rejects_omitted_explicit_effect(self):
        value = {
            "schema": "authorization_ir_v1",
            "review_reasons": [],
            "grants": [],
        }
        compiler = ConstrainedIntentDAGCompiler(
            CONTRACTS, OBSERVATIONS, StaticBackend(value), max_repair_attempts=0,
        )
        with self.assertRaisesRegex(IntentCompilationError, "omitted explicit"):
            compiler.compile("Send an email to alice@example.com")


if __name__ == "__main__":
    unittest.main()
