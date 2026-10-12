# 在线建图实验 v0：一次真实 Agent 运行中，图何时、怎样长出来

## 实验问题与边界

本实验只验证**建图过程**，不检测攻击，也不生成 TaskScope：图能否在 Agent 执行的当下，依次从输入、调用和副作用形成，而不是依赖结束后的完整 trace 补画？

受害者是 `VictimAgent`，实际调用 `deepseek-chat`；工具是隔离的 AgentLAB/OpenClaw 模拟工具，工作区和两条用户任务均为脚本内的虚构数据。记录器通过 AgentLAB 的用户消息、上下文加载、工具调用前、工具返回后和后台记忆写入钩子同步运行。**这不是原生 OpenClaw 的生产集成，也不是离线 case 回放。**

每个钩子结束时，实验立即保存图增量：`input` 是此刻可见事件，`process` 是提取规则，`output` 是本步新增/更新的节点与边。后续事件不能回填较早快照。逐步记录见 [`output/online_timeline.json`](output/online_timeline.json)，代码见 [`run.py`](run.py)。

## 真实执行：输入 → 过程 → 输出

| 时刻 | 当时的输入 | 建图动作 | 本步输出 |
|---|---|---|---|
| 1 | 用户要求把“项目评审在周五”写入 `MEMORY.md` | 记录用户 Observation | 1 个 Observation |
| 2 | Agent 会加载的工作区文件 | 每个实际加载的文件记录为 Observation，原文只在独立内容索引中保留引用 | 5 个 Observation |
| 3，工具**执行前** | `write_file(path=MEMORY.md, content=...)` | 记录 Action；依据工具名与参数推断“写这个文件”的候选 Effect | 1 个 Action、1 个 Effect；**此时还没有 State** |
| 4，工具**返回后** | 写入成功；文件内容指纹从不存在变为一个 SHA-256 值 | 更新 Action/Effect 状态，并以实际文件变化确认写入 | 返回 Observation、`MEMORY.md@v1` State、`updates` 边 |
| 5 | Agent 后台写入每日记忆 | 后台钩子记录额外写入 | Action、Effect、State；这一步目前只有钩子报告，未校验前后指纹 |
| 6 | 第一轮结束的可见答复 | 记录输出 Observation | 1 个 Observation |
| 7–8 | 下一轮用户要求读取 `MEMORY.md`；工作区重新加载该文件 | 记录新用户消息与加载 Observation，按对象 ID 连接先前的状态版本 | `MEMORY.md@v1 → 加载 Observation`；这条边目前仅为推断 |
| 9–10 | `read_file(path=MEMORY.md)` 及返回的文件内容 | 先记读取 Action/Effect；返回后比较读取文件的 SHA-256 与先前版本 | `MEMORY.md@v1 → 读取结果 Observation`，指纹匹配、版本已核实 |
| 11–12 | 第二轮后台记忆写入和可见答复 | 分别记录后台副作用与 Agent 输出 | 新的每日记忆 State、输出 Observation |

实际运行共 2 个会话、2 次工具调用、12 个在线记录边界，形成 28 个节点、26 条边。工具执行前/后各 2 次；仅按这 12 次保存的增量重建最终图，节点和边均完全一致。跨轮 `MEMORY.md` 读取中有 1 条经过内容指纹核实的 `reads` 边。

## 这次实验确认了什么，没确认什么

**确认：** O/A/E/S 的过程骨架可以在真实模型执行时增量生成；工具调用前能先表征“拟做什么”，执行后能用状态变化确认“实际做了什么”；后续读取可以连接到先前的持久状态。图不需要预先知道整条轨迹或攻击标签。

**没有确认：** 从非结构化内容准确提取语义、再证明内容如何影响具体参数。内容索引在线保存了原文引用，但本实验的语义摘要数为 0。当前 `derived_from` 可使用“最近一次 Observation”代理：第 3 步的写入动作被连到刚加载的 `USER.md`，并非有证据证明 `USER.md` 导致了写入。时间/上下文关联不应被称为语义因果。背景记忆写入也缺少内容前后指纹。上述两项是下一版建图方法要解决的实质问题，而不是检测器调参问题。

## 可复现方式

在 `greatwallguard` 目录，用已配置的 AgentLAB Python 环境运行：

```bash
PYTHONPATH=src:../attack-generation/openclaw-agentlab-upstream \
  ../attack-generation/openclaw-agentlab/.venv/bin/python \
  experiments/online_graph_construction_v0/run.py --max-rounds 2
```

运行依赖已配置的模型 API。任务、隔离工作区和模型回复可能影响具体节点数量；`timeline_reconstructs_final_nodes/edges`、调用前后配对和每条边的证据级别才是建图正确性的检查项。
