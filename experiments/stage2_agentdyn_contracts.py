"""Deployment-level AgentDyn contracts used by the Stage-2 evaluation.

These declarations describe stable tool semantics.  They must not contain
task IDs, attack labels, prompt fragments, or values learned from benchmark
outcomes.
"""

from greatwallguard import CapabilityLink, CapabilityRule


EMAIL_READERS = frozenset({
    "search_emails", "get_received_emails", "get_unread_emails", "get_sent_emails",
    "get_shopping_linked_received_emails", "get_shopping_linked_unread_emails",
    "get_github_linked_unread_emails",
})
GITHUB_ACCOUNT_READERS = frozenset({
    "get_logged_in_github_user_information",
    "get_github_account_user_information",
})

SOURCE_ALIASES = {
    tool: tuple(sorted(EMAIL_READERS - {tool})) for tool in EMAIL_READERS
} | {
    tool: tuple(sorted(GITHUB_ACCOUNT_READERS - {tool}))
    for tool in GITHUB_ACCOUNT_READERS
}

# A missing link never grants execution.  It only states that the prerequisite
# can be instrumental to the terminal effect, changing an otherwise explicit
# conflict into REVIEW until an object-level relation is proved.
CAPABILITY_RULES = (
    CapabilityRule("cart_add_product", "checkout_selected_cart", (
        CapabilityLink("product_id", "product_ids"),
    )),
    CapabilityRule("create_dir", "download_file_through_url", (
        CapabilityLink("path", "save_dir"),
    )),
    CapabilityRule("create_dir", "download_file_through_id", (
        CapabilityLink("path", "save_dir"),
    )),
    CapabilityRule("git_pull", "git_push", (
        CapabilityLink("local_path", "local_path"),
    )),
    CapabilityRule("git_clone", "git_push"),
    CapabilityRule("move_node", "git_push"),
    CapabilityRule("move_node", "git_create_repo"),
    CapabilityRule("git_push", "git_create_repo"),
    CapabilityRule("input_to_webpage", "checkout_selected_cart"),
    CapabilityRule("input_to_webpage", "send_money"),
    CapabilityRule("input_to_webpage", "download_file_through_url"),
    CapabilityRule("input_to_webpage", "send_email"),
    CapabilityRule("download_file_through_id", "refund_order"),
)

PROVISIONAL_EFFECT_TOOLS = frozenset(
    rule.prerequisite_tool for rule in CAPABILITY_RULES
)
