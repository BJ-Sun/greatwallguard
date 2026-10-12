# CaMeL baseline reproduction

The official [CaMeL research artifact](https://github.com/google-research/camel-prompt-injection) is pinned as the `camel-prompt-injection` Git submodule at commit `f083b6b396399d3b3c7f2ddaf613a5945eaf32d8`. The upstream license is Apache-2.0. We have not modified its source.

## What was reproduced

On 2026-10-08, the locked runtime dependencies were installed in the submodule's isolated `.venv` with Python 3.12.14. The official test suite ran with `pytest`: **126 passed**. The official `main.py --help` entry point also ran successfully. These checks reproduce the interpreter, value-provenance, and tool-wrapper tests; they **do not** reproduce the paper's AgentDojo attack/utility numbers or a live model execution. The upstream README calls this an unsupported research artifact and warns that its interpreter may contain bugs.

To repeat the local checks after cloning GreatWallGuard:

```bash
git submodule update --init baselines/camel-prompt-injection
cd baselines/camel-prompt-injection
uv run --python python3.12 --no-dev --with pytest pytest -q
uv run --python python3.12 --no-dev main.py --help
```

The upstream `.python-version` requests 3.10.12. We used an available compatible 3.12.14 interpreter without changing the lockfile. A machine with 3.10.12 can use the upstream default instead.

## How the implementation works

1. `src/camel/pipeline_elements/privileged_llm.py`: a privileged LLM sees the trusted query and tool API, generates restricted Python-like code, and sends that code to the interpreter. Tool-return text is not simply appended to its planning context.
2. `src/camel/pipeline_elements/agentdojo_function.py` and `src/camel/interpreter/value.py`: tool outputs become wrapped values carrying sources, readers, and dependency links. The interpreter propagates this metadata as values are transformed.
3. `src/camel/quarantined_llm.py`: untrusted material can be processed by a quarantined LLM, but its output remains data with tracked dependencies rather than a new privileged instruction.
4. `src/camel/security_policy.py` plus `src/camel/pipeline_elements/security_policies/`: the interpreter has a pre-call hook that can check argument metadata and control dependencies. Read-only tools are separately enumerated. The workspace policies include rules for email, calendar, and file operations. **The default CaMeL pipeline selects `ADNoSecurityPolicyEngine`; the provided CLI activates these application policies through `--replay-with-policies` on a previously saved trace.** Thus the published artifact's default generation run is not itself an online policy-enforced run.

Thus CaMeL's central enforcement point is **execution of generated code with information-flow metadata and explicit tool policies**, not a post-hoc graph detector. Its AgentDojo policy files encode application-specific assumptions; the tests passing does not establish that these policies fit OpenClaw or long-lived cross-task state.

For our research question, the important implementation boundary is temporal: `PrivilegedLLM.query()` creates a fresh interpreter namespace for each query, while continuing a generated-code attempt inside that query. A file or memory item later read from the environment receives metadata from the current tool wrapper. The implementation does not, by itself, retain a version chain saying which earlier user request authorized each prior write to that item. This is a concrete hypothesis to test with matched cross-task cases, not a claim that CaMeL fails on all such cases.

## What is needed for a comparable baseline

The official `main.py` supports the paper's configured OpenAI, Anthropic, and Google model paths, not a ready-made DeepSeek/OpenClaw path. No relevant model API key is configured in this environment, so no live AgentDojo run has been claimed here. A fair comparison first needs a pinned model/provider adapter and matched task/attack cases, then separate reporting of task utility, attack success, policy denials, and cost. CaMeL changes the Agent's execution architecture; GreatWallGuard observes an existing black-box Agent, so this is a **system-level comparison**, not a drop-in detector swap.
