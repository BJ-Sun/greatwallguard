# 多级图设计（v0）

更新时间：2026-09-08

## 核心原则

GreatWallGuard 不把“全面”理解为“为每个工具增加一种节点”。底层图只记录
观测边界内的事件、对象、证据和关系；上层图是同一批事件的标准化、聚合和有界
投影。

```text
L0  全量审计图       保留每次观测、调用、Effect、State 和证据回指
 ↓  通用字段归一化
L1  规范化过程图     用工具无关的 operation / target / payload / outcome 表达
 ↓  跨轮对象聚合
L2  状态传播图       保留对象版本、产生过程、读取/激活链和会话传播
 ↓  预算化投影
L3  运行时检测图     保留当前检测所需的有限路径、摘要和计数
```

每一级都必须保留 `children_ids` 或等价的回指信息；压缩只影响当前级别，不修改
L0。无法归一化的工具进入 `operation=unknown` 并保留 schema/参数 digest，不通过
新增工具节点“修复”语义。

## L0：全量审计图

L0 是全面但不一定把原文放进图的审计层。它继续使用现有四类节点：
`Observation`、`Action`、`Effect`、`State`，并为每个节点保存统一事件包络：

| 字段 | 含义 |
|---|---|
| `event_id` / `turn` / `timestamp` | 可排序的事件身份 |
| `session_id` / `phase` | 会话、bootstrap、model boundary、tool loop、background 等阶段 |
| `source` / `integrity` | 来源和完整性，不直接等于恶意标签 |
| `operation` / `target` | 规范化操作和对象；无法判断时为 `unknown` |
| `payload_ref` / `arguments_digest` | 参数、返回或文件的证据引用/摘要 |
| `status` / `commit_evidence` | proposed、succeeded、failed、blocked、no-op 及其依据 |
| `parent_ids` / `source_node_ids` | 候选来源、调用、返回和 State 的回指 |

L0 的“全量”指：只要在适配器观测边界内，就保留每次发生的事件，包括失败、
重复写入、未知工具、未提交 Effect 和没有 State 的尝试。原始内容仍放在独立
证据索引中，由权限和存储策略决定是否保存全文。

### 工具无关的 Effect IR

工具适配器只提供声明式字段选择器，把工具调用归一化为：

```json
{
  "operation": "send",
  "targets": [{"role": "to", "value_ref": "…"}],
  "payload_fields": [{"role": "body", "value_ref": "…"}],
  "persistent": true,
  "reversible": false,
  "evidence": {"basis": "declared", "method": "tool_contract"}
}
```

不同工具只改变字段选择器和能力声明，不改变节点类型、边类型或检测器。未知
工具至少保留原始工具名、参数 digest 和 `unknown` Effect。

## L1：规范化过程图

L1 不再关心具体工具的参数命名，而关心通用过程元组：

```text
(source, operation, target[s], payload field[s], authority, outcome, persistence)
```

它仍保留一条 Action/Effect 对应一条或多条 L0 事件的映射。典型归一化包括：

- `send_email`、Slack 发消息、HTTP POST → `operation=send`；
- `write_file`、数据库 update、memory flush → `operation=write`；
- `exec` → `operation=execute`，其内部影响暂记为未知；
- 多收件人、CC、body URL → `targets[]` 和 `payload_fields[]`，而不是新增邮件节点；
- 不同工具的 `file_id`、`path`、URL → 统一的 `target` 引用和对象命名空间。

L1 的目标是让一个检测规则可以跨工具复用。例如检测器检查“外部来源是否影响
高影响 operation”，不检查工具名称。

## L2：状态传播图

L2 以对象和过程为中心，把重复的 L1 Effect 聚合成跨轮传播链：

```text
State(v1) → read Observation → Action → Effect → State(v2)
                    ↑
             argument provenance
```

L2 至少保留：

- 每个对象的最新版本和历史版本摘要；
- `effect_process_ledger`：Effect → Action/call → source → result → State；
- 跨轮/跨会话的 `session_id`、phase 和 bridge evidence；
- 可选字段级来源：`argument_path → source observation/content ref`；
- 被聚合事件的数量、ID digest 和证据完整度。

L2 允许把十次相同的 memory flush 聚合成一个对象历史，但不能把失败调用和
成功提交混为一谈。它回答的是：

```text
什么对象被改变？改变由哪个过程造成？之后在哪里被重新读取或激活？
```

## L3：运行时检测图

L3 是按预算生成的运行时投影，不是新的事实层。根据检测任务保留：

- 最近 Action tail；
- 活跃 State 和重要历史版本；
- 高影响 Effect 的过程账本行；
- `untrusted → high-impact`、`State → activation → high-impact` 等候选路径；
- omitted counts/digests 和证据缺失标记。

L3 可以有 small/medium/large 三档预算，但任何报警都必须回指 L2/L1/L0 的
节点或证据。如果上层没有足够信息，应输出 `unknown` 或 `insufficient_evidence`，
而不是猜测。

## 压缩与回指规则

| 转换 | 可以聚合什么 | 不能丢失什么 |
|---|---|---|
| L0 → L1 | 工具名、参数别名、操作同义词 | 原始 Action、参数 digest、契约证据 |
| L1 → L2 | 同一对象的连续版本和重复操作 | 版本顺序、失败/成功区别、来源回指 |
| L2 → L3 | 旧版本、低风险读操作、重复过程 | 高影响路径、最新 State、证据缺失和 omitted digest |

任何聚合行都应包含：

```text
aggregate_id, child_count, child_ids_or_digest, first_turn, last_turn,
evidence_completeness, omitted_fields
```

这样可以测量压缩造成的真实信息损失，而不是把丢失的事件误认为从未发生。

## 当前实现的对应关系

| 设计层 | 当前实现状态 |
|---|---|
| L0 | `EffectGraph` 的 O/A/E/S 审计图，已记录证据和 State 版本 |
| L1 | `multi_level_graph.py::build_level1_process_graph`，从现有 O/A/E/S 投影为工具无关 operation/target/outcome |
| L2 | `multi_level_graph.py::build_level2_state_graph`，按对象聚合版本、激活链并嵌入 `effect_process_ledger` |
| L3 | `multi_level_graph.py::build_multi_level_graph`，组合有界 `state_summary` 与图检测基线 |

当前实现仍有意保持保守：L1 尚未臆造字段级 payload 来源，L2 的 activation chain 只使用
图中已经存在的 `reads → derived_from → causes` 证据；缺失信息继续显式保留为 unknown。
真实 Agent 验证脚本会从同一份执行轨迹一次性落盘四级结果，便于比较压缩和回查。

2026-09-08 已用真实 DeepSeek AgentLAB 执行验证：4 个连续会话、5 个工具 Action、5
个持久 State，恢复 3 条跨轮激活链；L1/L2/L3 的体积分别为 L0 的 62.9%/18.1%/31.9%，
且未产生检测报警。结果文件位于 `experiments/real_agent_multilevel_live/`。

因此下一步不是继续增加基础节点，而是补 L0 的通用事件字段，再验证 L1–L3 在
未参与设计的工具和任务上是否仍能工作。

## 泛化验收标准

一次新增能力只有同时满足以下条件才进入主干：

1. 新样例可以只通过数据/契约配置完成标注，不需要新增节点类型；
2. 同一字段或关系至少适用于两个不同工具和两个不同任务；
3. 规则检测器不引用具体工具名、域名或攻击字符串；
4. 在留出的工具/任务上能回放、归一化、聚合并保留证据回指；
5. 压缩后无法判断时显式报告 unknown，而不是用启发式补全。
