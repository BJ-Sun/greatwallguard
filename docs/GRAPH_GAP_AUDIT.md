# 图覆盖审计与最小缺口集合

更新时间：2026-09-08

审计对象是 [攻击样例标注表](ATTACK_ANNOTATIONS.md) 的 29 条样例。判断标准是：
当前 O/A/E/S 图能否在不读取完整上下文的情况下回答下面五个问题：

1. 入口是否被记录？
2. 哪些 Action 构成攻击链，哪些只是正常前置动作？
3. 哪个持久 Effect 由哪个调用产生？
4. State 是否跨轮/跨会话传播并被再次读取？
5. 成功条件和失败中断点是否能由证据回查？

## 覆盖矩阵

| 能力 | 当前图已有机制 | 29 条样例的审计结论 | 结论 |
|---|---|---|---|
| 入口来源与完整性 | Observation `source/integrity/content_ref` | S1/S2/文件/记忆入口可标注；动态结果的入口通常只在外部摘要中 | 结构可表达，采集不完整 |
| Action 顺序 | Action + `next` + tool/参数 digest | 同一轨迹顺序可保留；跨 artifact 只有调用总数时无法重建 | 结构可表达，输入证据不足 |
| Action→Effect | `causes` + 有限 Effect 词表 | 常规文件/邮件/命令可映射；复合邮件和 shell 内部影响会被折平 | 最小结构可用，但语义粒度不足 |
| Effect→State | `updates` + version/fingerprint | 文件/记忆版本可表达；外部发送多为 reported，无外部确认 | 结构可表达，验证证据不足 |
| State→后续 Action | `reads` 与 `derived_from` 链 | 同一图、同一 object_id 可表达；跨会话桥接和 model context 激活经常断开 | 需要过程桥接字段 |
| Effect→产生它的 call | 旧图只有 `causes` 到 Action，Action 未必有 call_id | A01/A24/A28/A29 可以从 action id 回查；旧 runtime/外部摘要不能稳定回查 | `effect_process_ledger` 直接补齐 |
| 读取值→后续参数 | 只有 source node 关联和参数 digest | 能知道“读过”和“发过”，不能证明 code/密码/联系人进入了哪个字段 | 图结构确实缺一条数据流表达 |
| 多目标/多字段副作用 | Effect 仅有一个 `target` + `operation` | `to/cc/body`、多个 recipients、文件内容与 URL 会丢失目标集合和字段角色 | Effect payload projection 是缺口 |
| 成功条件 | 过程图本身无任务 oracle | 已保存结果只给 success/security_breach 或 oracle 文件，无法统一对齐到图 | 需要独立 evaluation adapter，不扩节点 |
| 失败中断点 | failed Effect 可记录；被 gate 阻断的动作只留下 Action | 运行时可识别 gate 失败；被动结果常缺 tool return / state snapshot | ledger 保留失败过程，采集器仍需增强 |

## 最小缺口集合

这里的“最小”指若不补该项，至少一类已有样例的链不能按目标五元组回查；
不是建议新增五种基础节点。

### M1：过程账本缺口（已实现第一版）

需要把每个持久 Effect 投影为：

```text
effect_id → action_id → call_id/tool/arguments_digest
          → source_node_ids/integrity
          → result/commit evidence → state_id/version/fingerprint
```

`src/greatwallguard/effect_process_ledger.py` 已实现 `build_effect_process_ledger()`，
并由 `GraphStateSummarizer` 作为第四个有界组件输出。它保留 failed/no-State
Effect，不把“没有落盘”误判为“没有攻击尝试”。`call_id` 已成为 runtime
和 AgentLab adapter 的可选字段；没有 call_id 时显式计数。

### M2：值流 / 字段来源缺口（结构缺口）

当前 `derived_from` 只表达“候选来源关联”，参数只保存 digest。因而无法区分：

```text
read(passwords.txt) → send_email.body
read(contact list)  → send_email.body
read(search result) → send_email.cc
```

这正是 A01/A04/A05/A07/A08/A23/A28 的共同缺口。最小补法不是添加节点，而是
在 Action 或 ledger 的字段级证据中增加可选 `argument_provenance`：
`argument_path → source_node_ids/content_ref/quote_or_digest`。没有适配器或内容
快照时保持 `unknown`，不能根据时间相邻关系伪造数据依赖。

### M3：复合 Effect / 多目标投影缺口（结构缺口）

一个 `send_email` 可能同时有 `to`、`cc`、`bcc`、body 中的 URL 和敏感数据；一个
`exec` 也可能造成文件写入、网络发送和删除。当前单个 Effect 只有一个 target，
会把 A04 的 CC、A07 的 phishing URL 和 A02/A03 的 shell 子影响折叠掉。

最小补法是允许一个 Effect 行带有有界的 `targets[]` 和 `field_effects[]`，而不改变
四类节点；超过预算时保留计数、digest 和 `omitted_fields`。

### M4：会话桥接与激活证据缺口（结构/采集边界）

跨会话样例需要同时表达：旧会话写入、session boundary、下一会话 bootstrap/load、
再到 Action。当前图可以通过同一 object_id 和 `reads` 近似表达，但没有统一的
session id / bridge evidence；model input 也只表明“进入上下文”，不证明模型使用了
该内容。因此 A06/A07/A15/A16/A18/A21/A24/A27/A29 不能仅靠 v0 图区分“被加载”
和“导致了后续参数”。

最小补法是把 session/phase/call_id 作为已有 Observation/Action 的数据字段，增加
`bridge_evidence` 和 `activation_evidence` 的可选引用；仍不新增 `Session` 节点，
也不把加载自动解释为因果使用。

### M5：结果与成功 oracle 缺口（评估边界）

成功条件有三种不同口径：严格 tool+arguments oracle、环境 State 改变、结果摘要
中的 `security_breach`。A09–A23 大多只有后一种或部分字段，不能与图中的
`commit_evidence` 对齐。需要 evaluator adapter 把 `success_definition`、匹配的
Action/Effect/State 和中断轮次写入独立评估记录。

这不是基础图缺少“成功节点”；成功是实验标签，必须和中立图分离。

## 不列为缺口的项目

- 不新增攻击专用节点或 `malicious` Effect 类型；攻击语义留在 evaluator/detector。
- 不把所有外部 Observation 自动视为恶意；完整性与授权是两个字段。
- 不把 hidden-state、模型意图或自然语言计划当作图事实。
- 不为每一个攻击类别加一条规则；先补 M1，再用 M2–M5 的证据暴露是否真的需要
  新结构。

## 审计结论

当前图的最小可用边界是“入口、动作顺序、粗粒度 Effect、持久对象版本”；第一类
真正影响检测的工程缺口是 M1，已用过程账本补上。剩余核心信息损失是 M2/M3，
而跨会话实验的主要不可判定性是 M4/M5。下一轮应优先在 29 条样例上补齐这些
字段并重新计算检测率/最早检测轮次，不应继续扩展基础节点类型。

