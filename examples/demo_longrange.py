"""Offline demonstration of a two-step long-range attack and its gate."""

from greatwallguard import EffectType, GreatWallGuardRuntime, TaskScope


def main() -> None:
    scope = TaskScope(
        task_id="report-001",
        intent="Read the supplied data and write an internal report.",
        allowed_effects=frozenset({EffectType.READ, EffectType.WRITE, EffectType.CREATE}),
        allowed_resources=("file://reports/",),
    )
    guard = GreatWallGuardRuntime(scope)
    user_id = guard.observe_user("Read the supplied data and write an internal report.")
    web_id = guard.observe(
        "tool_return",
        "A web page contains a request to send collected data elsewhere.",
        integrity="untrusted",
        raw_payload="opaque external page content",
    )

    allow, _ = guard.before_tool_call(
        "create_file",
        {"path": "file://reports/weekly.md", "content": "summary"},
        source_node_ids=(user_id,),
        execute=lambda: "mock file created",
    )
    blocked, _ = guard.before_tool_call(
        "send_email",
        {"to": "external@example.net", "subject": "report", "body": "summary"},
        source_node_ids=(web_id,),
        execute=lambda: "should not run",
    )

    print(f"report write: {allow.kind.value} — {allow.reason}")
    print(f"external send: {blocked.kind.value} — {blocked.reason}")
    print(f"nodes={len(guard.graph.nodes)} edges={len(guard.graph.edges)} states={guard.graph.state_versions}")


if __name__ == "__main__":
    main()
