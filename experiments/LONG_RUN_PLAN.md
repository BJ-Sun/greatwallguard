# 长时正常 Agent 图表征实验 — 实施计划

## 目标

把 `experiments/run_two_axis_validation.py` 的五轮验证扩展为可断点续跑的长时正常任务：三个任务族各 150 个真实用户轮次，总量 ≥450。沿用现有分层：过程图 + 内容索引 + 原始证据；沿用四类节点 O/A/E/S 与统一证据属性，不新增攻击规则或节点类型。

模型仍为 `.env` 中的真实 DeepSeek；驱动器为 AgentLAB `VictimAgent`，工具为隔离目录内的真实 `read_file` / `write_file` / `list_files`。保持此口径。

## 三个任务族

| 族 | 会话模式 | 验证重点 | 对应任务要求 |
|---|---|---|---|
| `multifile` | 连续对话（单 agent，消息累积） | 多文件报告与事实维护；成本随轮次增长 | 任务 1、连续对话轨迹 |
| `revision` | 每轮新上下文（读 MEMORY.md 恢复） | 目标/接收人/条件/撤回旧要求 | 任务 2 |
| `recovery` | 每轮新上下文 | 跨会话恢复、失败恢复、重复写入、多对象增长 | 任务 3、上下文重建与跨会话恢复 |

每轮 = 一次 `agent.run(task)`（一个真实用户消息），模型自主生成工具调用，不重放预设调用。每轮限制 `max_rounds`（3–4），并给模型明确的单轮工具循环上限。

## 确定性任务脚本与 gold

每个族有一个确定性脚本：`task(turn)` 生成该轮用户指令，`checkpoint_state(turn)` 生成该检查点下“脚本真实要求”的 gold（事实、接收人、条件、撤回、对象内容、计数），`task_outcomes(turn, root)` 用磁盘实际文件比对脚本要求。内容 QA 的 gold 只来自脚本要求，与 agent 实际任务完成质量分开报告。

- `multifile`：事实按 `turn % 3` 分派到 `facts_a/b/c.txt`，`report.md` 汇总全部事实与计数；禁止修改其他文件。
- `revision`：确定性状态机改变接收人（Alice/Bob/Carol/Dave/Eve）、审批、条件，并逐轮“撤回上一要求”。
- `recovery`：每轮读 `MEMORY.md` 恢复计数，读 `objects/obj_NNN.txt`（首次缺失→恢复写），部分轮重复写入相同内容，多对象增长。

## 测量与落盘

每轮原子更新 `oracle.json`（model_calls / tool_calls / sessions，含请求、可见响应、调用 ID、参数、返回、前后 SHA-256 快照）、`graph.json`、`content_evidence.json`。检查点 10/25/75/150：

- 过程：`evaluate_process` 按调用 ID/参数/对象/版本逐项匹配，报告精确率/召回率与错误实例；保留失败、无变化写入、多对象版本、历史读取关联。
- 内容：`extractive.py` 原文片段基线；比较原文 / 同预算前缀截断 / 抽取式视图；预先确定的问题与 gold 不泄漏给选择器；选择按 `ref` 缓存。
- 规模：用户轮次、LLM 请求数、工具调用数、完整图字节、内容索引、原文存储、运行时视图、内容视图、延迟、API usage（能取到 usage 记真实值，否则记录估算方法）。所有统计可从 `oracle.json` 重算。

## 断点续跑

`oracle.json` 保存全部 model_calls/tool_calls 与快照。恢复时**不重跑**已完成前缀，而是把已落盘 oracle 重放进一个新 recorder（纯 Python、无 API 调用）重建图与内容索引，再继续下一轮。连续族另存 `agent_messages.json` 恢复对话。因此指标可证明从落盘证据重算。

## 资源硬上限（全局，串行执行）

4 小时 / 1,500 次实验 LLM 请求 / 12,000,000 输入 tokens / 1,000,000 输出 tokens，任一达到即保存并停止。连续 3 次 API 错误即检查点退出。不打印凭据。CLI 编码调用与实验 API 调用分开计数。

## 执行顺序

1. 单元测试：确定性脚本 gold 生成、恢复重放、预算与 usage 计数。
2. smoke（≤10 轮总量）：验证事件映射、状态指纹、预算、恢复。
3. 串行跑三个族到 150 轮或硬预算。
4. 写 `SUMMARY.md`（准确/遗漏/失真、成本增长、最优先改进点）。

结果根目录 `experiments/longrun_20260907/`，含 `status.json`、各族子目录、日志与 `SUMMARY.md`。
