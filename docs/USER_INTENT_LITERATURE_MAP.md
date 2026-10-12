# 用户意图如何变成 Agent 的运行时授权：相关研究与我们的切入点

## 摘要

本次调研回答三个问题：**RQ1** 研究中“用户意图”究竟指目标、对话状态还是授权边界？**RQ2** 自然语言如何变成可执行约束？**RQ3** 多轮变化和运行时才知道的参数如何处理？检索覆盖对话语义解析、任务级授权和 Agent 安全三个方向，以下只纳入核对过原文或正式论文页面、且与这些问题直接相关的工作；截至 2026-10-05。核心判断是：文献已有分别解决“意图状态更新”“授权精度”“参数来源”的方法，但这些问题常在不同实验设定中被独立处理。我们的工作如果继续推进，不能笼统声称“首次从用户意图生成权限”；应检验三者在真实长程、多次用户输入和持久副作用中的组合是否仍然准确、可用。

## 1. 三种不同的“意图”

| 研究线 | 意图的表示 | 主要解决 | 对我们最重要的边界 |
| --- | --- | --- | --- |
| 对话语义解析与状态跟踪 [1, 2, 3] | 当前函数/目标、槽位、指代、修订 | 用户说的任务现在是什么 | 表达任务，不直接证明某个副作用被授权 |
| 任务对齐 [4] | 用户消息中提取的任务指令集合；其他指令是否对其有贡献 | 运行中的指令/工具调用是否偏离目标 | 贡献关系由 LLM 判断；没有精确表示参数的来源与有效期 |
| 任务级授权 [5, 6, 7, 8] | 权限策略、工具调用及参数条件、短时证书/租约 | 具体调用是否被这次任务允许 | 编译正确性、模糊任务、多轮更新仍是关键困难 |

这里的关键区别是：**任务目标不是执行计划，执行计划也不是授权。** 用户说“给项目负责人发总结”，可能授权一个发送效果，但没有固定具体的邮件正文；工具返回可以提供负责人地址的候选值，却不能因此自行授权第二封邮件。

## 2. 怎样表示不断变化的用户任务

早期 Conversational Semantic Parsing [1] 把多轮请求转成可组合的语义表示，在表示中直接处理指代和上下文承接；Dynamic Context Graphs [2] 用动态子图建模对话上下文，目标仍是生成可执行逻辑形式。这些工作说明“同一个人”“那个文件”应作为可解析的引用，而不是缺失参数，但其语义解析正确并不等于安全授权正确。

更近的 Evolving User Intent [3] 把意图写成函数和参数状态，显式区分参数逐步揭示、旧参数修订和任务切换；IntentFlux/StateForge [9] 进一步将用户的添加、删除、替换折叠成**当前有效状态**，并删除依赖于已失效意图的中间结论。两篇互补：前者给了可控制的转移分类，后者表明“把所有历史压缩进摘要”仍可能保留失效的要求。它们主要以任务完成为指标，而非外部效果的越权率。[3, 9]

对我们而言，这意味着 TaskScope 不能只是历次用户消息的并集。至少要有 `add / refine / replace / revoke / switch` 的更新语义；“这一步不要发”与“此任务永远不要发”的有效期也不能混同。我们目前的增量草稿只覆盖 `grant / this_step constraint / unresolved`，撤销和依赖失效仍未实现。

## 3. 怎样把任务转成可检查的授权

Task Shield [4] 以用户指令集合为目标，提取各层消息里的可执行指令，用 `ContributesTo` 判断它们是否服务于用户目标；这适合捕捉显著的任务偏离，却把难点放在 LLM 的贡献判断上。PAuth [5] 走得更具体：把用户自然语言任务先翻译成受限命令式程序，再对目标工具求 NL slice，保留调用参数的符号表达式和前置条件；运行时通过来源 envelope 检查实际参数。它明确区分 operator 与 operation，正好击中“同一工具、不同收件人”的问题。但其论文将自然语言歧义视为互补问题，假设任务本身无歧义，并要求服务端提供可验证的来源值。[4, 5]

另一种轻量方向是先编译权限证书。IBAC [6] 从单次用户请求提取最小工具/资源权限并逐次检查，扩权需用户确认；IGAC [7] 把可信请求变成短期证书，再限制工具清单和实际 payload 的效果，对复合请求也提出拆成逐效果证书。IGAC 同时指出：系统可以确定证书**不超过静态权限**，却仍可能因为证书不忠实于用户请求而过度授权。与 PAuth 的精确符号求值相比，这类证书更容易接到现有黑盒 Agent，但也更依赖提取的粒度与正确性。[5, 6, 7]

Yan 等的 AuthBench [8]（与 PAuth 论文中同名的 AuthBench 并非同一数据集）从另一个角度验证了这一瓶颈：让模型仅凭任务和环境直接生成文件级最小权限，会同时漏掉完成任务必需的权限、又给出多余权限；它采用先保证充分性、再逐项审查紧致性的两阶段生成。这提示 TaskScope 的评估不能只看“越窄越安全”，还必须同时量化正常任务的欠授权。[8]

## 4. 运行时参数究竟由谁决定

PAuth [5] 把参数表示为任务所要求的计算，envelope 绑定具体值与上游服务返回的符号来源。IntentCap [10] 则把决策字段分配给用户、工作流、工具 schema 和运行环境，并要求后续租约只在用户授权内收窄；例如外部 PDF 可以填表格内容，却不能改写用户指定的输出仓库。两者的共同点是**值可以在执行时产生，但决定该值可用于哪个字段的权力不能从不可信内容获得**。不同点是 PAuth 聚焦每个操作数的精确计算，IntentCap 聚焦字段所有权与来源组合。[5, 10]

这里必须避免过度声称：IntentCap 已非常接近我们讨论的“来源决定参数权限”，PAuth 已覆盖复杂的同工具不同参数攻击，也讨论了多调用任务；IGAC 还提出复合请求的逐效果证书。AGATE [11] 更已在组合攻击中联合授权、来源和效果账本，并接入 OpenClaw。IntentCap 是短篇预印本、仅报告初步评估；PAuth 的原文假设无歧义、足够自包含的用户任务及可靠来源服务。PAuth 在 100 条原始任务中自动授权 71 条，经过补全、消除歧义的任务则为 100 条；AGATE 报告 11 个良性文件处理场景中有 6 个出现拒绝。这些不同设定的结果都表明授权精度与良性可用性需要共同评估，而不能据此断言某篇论文在我们的场景下失效。[5, 7, 10, 11]

## 5. 研究判断与可验证的切口

已有研究给出了一条较清晰的组合路线：

```text
用户消息序列
   └─ 解析为带证据的意图更新（含撤销、有效期） [1,3,9]
       └─ 编译为效果 + 参数约束的当前授权 [5,6,7,8]
           └─ 运行时用来源/依赖证据实例化参数 [5,10]
               └─ 与行为图中的实际持久 Effect 对照
```

我们可能的研究问题不是“能否提取一个 TaskScope”，而是：**在用户逐轮调整任务、参数从外部资料中得到、Agent 中途产生持久副作用时，能否维持既不过度授权也不妨碍正常工作的当前授权状态？** 这将任务状态、授权边界和参数来源三种不同语义分开，又给行为图一个明确用途：图记录实际效果及来源证据，TaskScope 提供独立于 Agent 轨迹的用户侧约束。

最小实验应使用同一批真实执行，同时比较三种基线：`静态单轮权限`、`多轮意图状态但只约束工具名`、`多轮效果/参数约束 + 图上的来源核实`。标注必须在看 trace 前独立完成，分别报告授权提取的过宽/过窄、正常任务误阻断、攻击越权漏检和无法判定比例。我们的 8 组手写参考样本只能用来发现表示缺口，不能为论文提供准确率证据。

## 参考文献

[1] Aghajanyan et al., “Conversational Semantic Parsing,” EMNLP, 2020. https://aclanthology.org/2020.emnlp-main.408/

[2] Jain and Lapata, “Conversational Semantic Parsing using Dynamic Context Graphs,” EMNLP, 2023. https://aclanthology.org/2023.emnlp-main.535/

[3] Tack et al., “LLMs Get Lost in Evolving User Intent,” arXiv:2607.20734, 2026. https://arxiv.org/abs/2607.20734

[4] Jia et al., “The Task Shield: Enforcing Task Alignment to Defend Against Indirect Prompt Injection in LLM Agents,” ACL, 2025. https://aclanthology.org/2025.acl-long.1435/

[5] Sharma et al., “Beyond OAuth: Task-Scoped Authorization for AI Agents via Natural Language Slices,” arXiv:2603.17170v2, 2026. https://arxiv.org/abs/2603.17170

[6] Potti, “Intent-Based Access Control: Securing Agentic AI Through Fine-Grained Authorization of User Intent,” preprint, 2026. https://ibac.dev/ibac-paper.pdf

[7] Zhu and Wang, “Intent-Governed Tool Authorization for AI Agents,” arXiv:2606.22916v4, 2026. https://arxiv.org/abs/2606.22916

[8] Yan et al., “Do Coding Agents Understand Least-Privilege Authorization?,” arXiv:2605.14859v2, 2026. https://arxiv.org/abs/2605.14859

[9] Zhang et al., “When Users Change Their Minds: Measuring and Repairing Intent Drift in LLM Agents,” arXiv:2609.32520, 2026. https://arxiv.org/abs/2609.32520

[10] Zheng et al., “LLM Agent Capabilities Should Follow Task Intent and Context Source,” arXiv:2609.14631, 2026. https://arxiv.org/abs/2609.14631

[11] Zhang et al., “AGATE: Provenance-Based Runtime Defense Against Compositional Attacks on LLM Agents,” arXiv:2609.30830, 2026. https://arxiv.org/abs/2609.30830
