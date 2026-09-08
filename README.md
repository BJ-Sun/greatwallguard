# GreatWallGuard

GreatWallGuard 当前研究重点是：对 Agent 长程活动进行中立、可回查的压缩表征，为后续防御监控提供输入。仓库同时保留早期任务授权原型。

> 多步影响可以通过文件、记忆、环境以及保留在上下文中的信息延续。图记录可观测的过程与对象关联，内容索引保留带证据的语义；尚未观测或未验证的信息显式保留不确定性。

统一定义和实现边界见 [图表征规范](docs/REPRESENTATION_SPEC.md)。本轮仍沿用四类节点，通过统一证据属性区分观测、回执与推断；可选内容索引用带原文位置的完整命题表征事实、要求和约束。它们尚不构成完整防御器。

研究交接入口见 [研究推进索引](docs/INDEX.md)：其中包含 [图设计说明](docs/GRAPH_DESIGN.md) 和 [当前进展](docs/PROGRESS.md)。

最新实验见 [过程与内容双维度验证](experiments/TWO_AXIS_VALIDATION.md)：三次真实模型自主执行、真实本地文件读写；按独立调用记录和磁盘快照评估过程，以预设问题评估内容压缩。回执版多记一次无变化写入，快照版已消除该虚增；关键片段压缩在本轮保留了八个问题所需的信息。

之前的命题式抽取及其失败见 [首轮验证](experiments/EVIDENCE_CONTENT_VALIDATION.md)。现阶段以原文片段为内容压缩基线，保留来源、顺序和限制语境，不将格式校验当作语义正确。

## 当前研究目标

本阶段先验证正常 OpenClaw 任务中的图表征能力，不加入攻击样例。目标有两个：

1. **运行时提取能力**：在不依赖完整上下文的情况下，稳定捕获用户 / 系统输入、工具 schema、tool call 与参数、工具返回、文件 / 记忆读写、实际副作用和授权结果，并保留它们的来源与跨轮因果关系。
2. **复杂过程压缩能力**：将多轮、多工具、跨状态的正常任务压缩为少量可解释节点和边，同时保留任务意图、持久状态变化、Effect 类型和后续激活关系。

这些是研究目标，尚未全部实现。“完整”须相对于观测边界和评估问题定义，不能由事件数量一致推出因果或语义完整。图的效果将从以下维度验证：事件覆盖率、来源关联精确率与召回率、状态版本一致性、Effect 与实际副作用一致性、图压缩率、运行时延迟和未知 Effect 比例。

验证顺序是：离线确定性任务 → AgentLAB mock 长时任务 → 可选的本地真实 OpenClaw 任务 → 150 轮压力测试。攻击生成与攻击—防御对比不属于当前阶段。

## 非目标与安全边界

- 不把图当作单独的恶意意图分类器；任务语义模型只负责生成或辅助校验 `TaskScope`。
- 图默认仅保留摘要、哈希、版本和结构化标签；内容实验可显式启用独立原文索引，用于核查压缩损失，不把原文放入图或默认运行时视图。
- 当前验证包括 AgentLAB / AgentDojo mock，以及隔离目录中的真实文件工具；不连接真实生产系统，不执行真实外部发送。

## 原型做什么

1. 将用户输入、工具返回、文件 / 记忆读取等信息记录为带来源标签的观测节点。
2. 将 tool call 记录为行为节点，将工具调用映射为有限的 Effect 类型：`read`、`write`、`create`、`delete`、`send`、`execute`、`permission_change`、`unknown`。
3. 根据提交报告生成状态版本节点；被动采集器主要依据工具回执，尚未独立核验全部实际副作用。节点和边标明证据来源。
4. 用 `TaskScope` 定义任务级最小权限。权限来自用户 / 系统授权，不从工具返回、文件或记忆内容中自动升级。
5. 在 tool call 执行前返回 `ALLOW`、`ASK` 或 `BLOCK`，并保留可审计的图。

它不是一个完整的恶意意图分类器，也不假设“所有外部数据都恶意”。语义模型可以作为 TaskScope 生成器或风险探针，但最终副作用的提交由结构化 Effect 和确定性策略控制。

运行时同时保留三种视图：

```text
完整审计图       保存全部节点、来源边和状态版本，用于离线复盘
论文最小图       投影为 Entity / Action + consume / produce / authorize / precede
有界运行时视图   只保留持久状态、Effect 聚合计数和最近动作，用于每轮检查
```

三者是同一记录的不同视图。完整图随执行增长；有界视图会丢失细节，必须单独评估保真度。内容索引目前供离线评估使用，尚未进入运行时视图的全局检索预算。

本轮新增第 4 种视图：`src/greatwallguard/state_summary.py` 提供**有界图状态摘要**，从已保存的审计图和内容索引离线重建，不替代完整审计图。它包含三个有界组件：

- `recent_trace`：最近若干进程事件及其 ID（数量有界，事件原文按字符截断或整条省略）；
- `effect_ledger`：去重后的最新持久状态 / 副作用（文件、记忆、配置、权限、外部副作用），带版本、哈希和证据引用；
- `content_sketch`：任务相关事实、约束、条件、修订和撤回，带来源引用；预算为字节数。

摘要支持 `small` / `medium` / `large` 三档预算，并保证整个 `content_sketch`（含元数据）不超过其字节预算。内容摘要默认使用确定性的原文片段兜底；可选 LLM 模式要求每个命题引用可验证的原文片段，拒绝无据声明，失败记为 `unknown`。LLM 原始响应按语料摘要缓存，因此可从保存的审计图回放摘要而不再调用 API。

限制：有界摘要会丢失窗口外的旧事件；当前摘要不是攻击检测器，也不对内容做良性 / 恶意分类。公开结果见 [图状态摘要公开实验摘要](docs/GRAPH_SUMMARY_RESULTS.md)，实现方案见 `experiments/GRAPH_SUMMARY_PLAN.md`。

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

## 图验证实验

实验脚本把正常基线和 AgentLAB 攻击回放统一保存为完整图、论文最小图、
有界运行时视图及指标。攻击侧是被动采集，不改变原有 AgentLAB 的 judge 或
mock 工具执行路径；`--replay-success-case` 生成的是 ground-truth 工具调用的
确定性成功路径，不计入 LLM ASR。

```bash
PYTHONPATH=src python experiments/run_graph_experiments.py \
  --normal-turns 50 150 300 \
  --direct-cases LONG-001 LONG-004 \
  --replay-success-case LONG-001 \
  --output-root experiments/results_runtime
```

需要真实 DeepSeek 回放时，使用攻击仓库已有 `.env`，并确保网络代理可用；
结果写入指定的 `--output-root`。三类图的差异和当前缺口见
[experiments/GRAPH_COMPARISON.md](experiments/GRAPH_COMPARISON.md)，完整结果目录见
[experiments/RESULTS_MANIFEST.md](experiments/RESULTS_MANIFEST.md)。

真实 Agent 的跨会话结构验证见
[experiments/REAL_AGENT_VALIDATION.md](experiments/REAL_AGENT_VALIDATION.md)，原始图位于
`experiments/real_agent/real_normal_validation.json`；固定预算压力样本位于
`experiments/real_agent_budget2/real_normal_validation.json`。

采集器有单元测试，并以 2-turn smoke 验证正常路径、注入返回和
持久状态读取；攻击回放仍是离线 mock，不会触发真实外部副作用。
