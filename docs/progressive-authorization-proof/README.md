# Progressive Authorization Proof 文档索引

本目录是当前方法、设计细节与实验结论的唯一入口。建议按以下顺序阅读：

1. [方法总览](METHOD_OVERVIEW.md)：研究问题、核心观察、三阶段流程与贯穿案例。
2. [阶段一：授权编译](STAGE1_AUTHORIZATION_COMPILATION_DETAILS.md)：将可信用户请求与工具契约编译为 Authorization DAG。
3. [阶段二：确定性运行时证明](STAGE2_RUNTIME_AUTHORIZATION_PROOF_DETAILS.md)：用真实工具返回求值授权关系，并检查候选工具、参数、条件、版本与预算。
4. [阶段三：语义证明补全](STAGE3_SEMANTIC_PROOF_COMPLETION_DETAILS.md)：仅对程序无法闭合的局部关系构造最小证据包并完成终局裁决。

两个通用扩展处理长程执行中的授权变化与持久状态：

- [逐轮授权时间线](MULTITURN_AUTHORIZATION_TIMELINE.md)：维护多轮用户指令对授权的新增、收窄、撤销和替换。
- [受限派生 Effect](BOUNDED_DERIVED_EFFECT.md)：允许服务于已授权终端目标的必要中间文件，同时约束对象、内容来源、可见性和生命周期。

实验结果分为两组：

- [AgentDojo 与 AgentDyn 实验](EXPERIMENT_RESULTS.md)：跨 benchmark 的冻结轨迹授权回放，以及各阶段的增量作用。
- [GreatWallBench 三阶段全量结果](GREATWALLBENCH_FULL_RESULTS.md)：240 条正常任务与 405 条严格双成功攻击上的当前最佳结果。
- [GreatWallBench 阶段一、二结果](GREATWALLBENCH_STAGE12_RESULTS.md)：引入阶段三和受限派生 Effect 前的中间结果，用于说明方法增量。

GreatWallBench 的适配器、评估脚本和机器可读结果保存在 `experiments/greatwallbench_full/`。该目录只承担复现，不再保存面向读者的结果说明。
