# GreatWallGuard

GreatWallGuard 是一个最小可运行的运行时防御原型，验证论文中的核心假设：

> 长程攻击的单步动作可能看起来合理，但攻击成功必须留下可被后续步骤利用的持久 Effect。防御系统不保存全部长上下文，而是把“观测 → 行为 → Effect → 状态变化”压缩成跨轮图，并在副作用提交前执行任务级授权。

## 当前研究目标

本阶段先验证正常 OpenClaw 任务中的图表征能力，不加入攻击样例。目标有两个：

1. **运行时提取能力**：在不依赖完整上下文的情况下，稳定捕获用户 / 系统输入、工具 schema、tool call 与参数、工具返回、文件 / 记忆读写、实际副作用和授权结果，并保留它们的来源与跨轮因果关系。
2. **复杂过程压缩能力**：将多轮、多工具、跨状态的正常任务压缩为少量可解释节点和边，同时保留任务意图、持久状态变化、Effect 类型和后续激活关系。

这里的“完整”指对后续执行有影响的行为—状态因果链完整，而不是保存每个 token 或模型的全部思维过程。图的效果将从以下维度验证：事件覆盖率、来源 / 因果链完整率、状态版本一致性、Effect 与实际副作用一致性、图压缩率、运行时延迟和未知 Effect 比例。

验证顺序是：离线确定性任务 → AgentLAB mock 长时任务 → 可选的本地真实 OpenClaw 任务 → 150 轮压力测试。攻击生成与攻击—防御对比不属于当前阶段。

## 非目标与安全边界

- 不把图当作单独的恶意意图分类器；任务语义模型只负责生成或辅助校验 `TaskScope`。
- 不保存原始长上下文、完整密钥或模型隐藏状态；仅保留摘要、哈希、版本和结构化标签。
- 所有当前验证均在 AgentLAB / AgentDojo mock 或隔离环境中完成，不连接真实生产系统，不执行真实外部发送。

## 原型做什么

1. 将用户输入、工具返回、文件 / 记忆读取等信息记录为带来源标签的观测节点。
2. 将 tool call 记录为行为节点，将工具调用映射为有限的 Effect 类型：`read`、`write`、`create`、`delete`、`send`、`execute`、`permission_change`、`unknown`。
3. 只有实际提交的持久 Effect 才生成状态版本节点；原始长文本只保存摘要和哈希，不进入跨轮状态。
4. 用 `TaskScope` 定义任务级最小权限。权限来自用户 / 系统授权，不从工具返回、文件或记忆内容中自动升级。
5. 在 tool call 执行前返回 `ALLOW`、`ASK` 或 `BLOCK`，并保留可审计的图。

它不是一个完整的恶意意图分类器，也不假设“所有外部数据都恶意”。语义模型可以作为 TaskScope 生成器或风险探针，但最终副作用的提交由结构化 Effect 和确定性策略控制。

运行时同时保留三种视图：

```text
完整审计图       保存全部节点、来源边和状态版本，用于离线复盘
论文最小图       投影为 Entity / Action + consume / produce / authorize / precede
有界运行时视图   只保留持久状态、Effect 聚合计数和最近动作，用于每轮检查
```

三者不是三套语义：前两者保证可解释和可审计，最后一者控制 150 轮长任务中的上下文与延迟。

## 最小流转

```text
用户输入 / 工具返回
          │
          ▼
    观测节点（来源、完整性、摘要）
          │
          ▼
    行为节点（工具、参数摘要）
          │  infer
          ▼
    Effect 节点（类型、目标、是否持久）
          │  commit only after authorization
          ▼
    状态版本（文件、记忆、配置、外部副作用）
          │
          └──── 下一轮读取 / 规划
```

## 运行验证

无需 API key：

```bash
python -m unittest discover -s tests -v
python examples/demo_longrange.py
# Optional: requires the AgentLAB clone and AgentDojo dependencies.
python examples/agentlab_hook_smoke.py
```

预期行为：报告文件写入被允许；外部工具返回不能授予外发权限；后续 `send_email` 在任务范围外被阻断；图中保留跨轮的 `write → state` 传播链。

### 正常长时任务基线

运行不需要 LLM 的确定性任务：

```bash
PYTHONPATH=src python examples/normal_long_task.py --turns 150 \
  --output /tmp/greatwallguard_normal_150.json
```

该基线会生成 200 个 Agent action、25 个持久状态更新和 25 条跨状态读取边；动作捕获率和 Effect 提交率均为 100%。完整审计图约 484KB，但有界运行时视图约 1.7KB，后者只保留持久状态、Effect 聚合计数和最近 8 个动作。

运行一个 DeepSeek 驱动的 AgentDojo 正常任务：

```bash
PYTHONPATH=src python examples/run_agentlab_normal.py \
  --workflow read --max-rounds 4 \
  --output /tmp/greatwallguard_agentlab_normal.json
```

该任务只在 AgentDojo mock 环境中执行。当前观察到的结果是：工具调用能够 100% 进入图，但模型可能在限定轮数内持续搜索而没有完成文件 / 记忆写入。因此，真实 LLM 任务的“任务完成率”和图的“事件捕获率”需要分开评估；持久 Effect 目前先用确定性基线验证。

## 与 OpenClaw AgentLAB 对接

防御原型已用 `BJ-Sun/openclaw-agentlab` 的最新分支 `openclaw-agent-ljh`（commit `d10cbdd`）做过受控回放。AgentLAB 的 `VictimAgent` / `DojoSkillBridge` 只需要在工具返回和工具调用边界接入两个 hook：

```python
from greatwallguard import EffectType, GreatWallGuardRuntime, TaskScope
from greatwallguard.adapters import AgentLabTraceAdapter

guard = GreatWallGuardRuntime(TaskScope(
    task_id="agentlab-case-001",
    intent="Read the event data and prepare an internal report.",
    allowed_effects=frozenset({EffectType.READ, EffectType.WRITE, EffectType.CREATE}),
    allowed_resources=("file://reports/",),
))
hook = AgentLabTraceAdapter(guard)
hook.on_user_message(user_task)
poison_id = hook.on_tool_return("search_calendar_events", "opaque result", injected=True)
decision, _ = hook.before_tool_call(
    "send_email", {"to": "external@example.net", "body": "..."},
    source_node_ids=(poison_id,), execute=lambda: bridge.call(...),
)
```

这次回放使用 AgentDojo `workspace/user_task_0+injection_task_0` seed，跨会话链路包含污染、`MEMORY.md` 生成和后续激活；结果和完整日志保存在攻击仓库的 `results/repro_workspace_s2_cross_short.json` 与 `.log` 中。

## 与现有 CFG / DFG / provenance 图的关系

现有图方法主要表示当前动作由什么来源、控制流或数据依赖驱动，并据此做局部异常或白名单检查。本原型不替代这些图，而是在其上增加一层跨轮的持久状态压缩：图的安全对象不是“某个来源天然恶意”，而是“某次行为实际改变了什么，以及该改变是否被当前任务授权”。

## 当前边界

- 工具语义通过显式 `ToolContractRegistry` 提供；未知工具默认产生 `unknown` Effect 并进入 `ASK`。
- 目标匹配使用前缀和显式目的地策略，尚未接入白盒 hidden-state probe 或 LLM 意图模型。
- 该仓库只在沙箱和离线 trace 上验证防御逻辑，不连接真实生产系统。
