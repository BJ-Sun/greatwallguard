# 方法设计动机：从实验失败到方法原则

本目录记录 GreatWallGuard 方法如何由具体实验问题逐步形成。这里不重复完整实验细节，也不把暂未验证的构想写成结论；每份文档只回答五个问题：

1. 原先采用了什么合理但不足的假设；
2. 哪个对照实验暴露了问题；
3. 问题如何被形式化；
4. 方法因此必须增加什么能力；
5. 解决后又暴露出什么新难点。

## 演进链

```text
工具与字面参数白名单
        │
        │ 正常参数需要由运行时结果计算
        ▼
动态参数授权
用户授权“参数如何得到”，而非只授权具体参数值
        │
        │ 同一任务存在多条合理执行路径
        ▼
计划无关的关系型授权
验证执行事实能否证明任务关系，而非匹配唯一计划
        │
        │ 关系事实并不会自动可靠地出现
        ▼
运行时关系证明
从真实工具返回证明筛选、排序、投影、计算和时间归一化
        │
        │ 内容语义、外部委托与跨轮版本形成仍不可直接证明
        ▼
下一问题：状态版本与局部语义
判断某个后来被使用的状态版本，其形成过程是否得到当时授权
```

## 文档顺序

1. [动态参数授权](01_DYNAMIC_PARAMETER_AUTHORIZATION.md)：解释为什么静态工具/参数白名单在 AgentDojo 动态正常任务中必然面临误报与漏报两难。
2. [计划无关的关系型授权](02_PLAN_INVARIANT_RELATIONAL_AUTHORIZATION.md)：解释为什么授权不能等同于一条预测计划，以及如何用不同证明路径支持正常执行变化。
3. [计划无关的正向证明算子](03_PLAN_INVARIANT_POSITIVE_PROOFS.md)：定义如何在不预测工具顺序的情况下，用有限可重放算子证明正常动态参数，并给出全量验证结果。
4. [类型化来源、跨调用连接与版本化证据](04_TYPED_SOURCE_AND_VERSIONED_EVIDENCE.md)：说明如何避免无关来源误绑定，并区分 AgentDojo 已验证的来源收益与仍需长程 case 验证的版本能力。
5. [由复核归因驱动通用算子完善](05_REVIEW_DRIVEN_OPERATOR_REFINEMENT.md)：说明如何从失败分类中选择可重放关系与条件守卫，并将正常自动放行提升到61/97而不新增攻击证明。
6. [从任务适配转向冻结算子泛化](06_FROZEN_OPERATOR_GENERALIZATION.md)：明确现有结果不能视为未见任务泛化，并冻结“取值—变换—约束”关系语言用于前瞻测试。

## 当前收敛出的研究层次

三个阶段不能混写成同一个已经完成的方法：

1. **基础机制已经实现：**从可信用户请求识别允许的效果，程序化检查候选工具调用，并对显式参数和部分动态参数给出可重放证明；
2. **AgentDojo 已验证的能力：**动态参数不必全部交给 LLM，有限关系算子能在不新增攻击放行的情况下提高正常任务自动放行率；
3. **长程论文仍待实现的贡献：**把授权和证明扩展到跨轮状态版本，判断某次写入是否有权形成后来被使用的文件、记忆或环境状态。

因此，AgentDojo 实验是长程方法的基础验证，不是长程状态版本问题已经解决的证据。

## 与详细材料的关系

本目录用于论文故事线和方法动机。代码、完整实验口径与结构化结果仍以以下文档为准：

- [阶段一：授权编译](../progressive-authorization-proof/STAGE1_AUTHORIZATION_COMPILATION_DETAILS.md)
- [阶段二：运行时授权证明](../progressive-authorization-proof/STAGE2_RUNTIME_AUTHORIZATION_PROOF_DETAILS.md)
- [阶段三：语义证明补全](../progressive-authorization-proof/STAGE3_SEMANTIC_PROOF_COMPLETION_DETAILS.md)
- [AgentDojo 阶段 A](../AGENTDOJO_SYMBOLIC_STAGE_A.md)
- [AgentDojo 阶段 B](../AGENTDOJO_SYMBOLIC_STAGE_B.md)
- [邮件计划无关实验](../AGENTDOJO_EMAIL_PLAN_INVARIANCE.md)
- [运行时参数溯源 v1.1](../RUNTIME_PARAMETER_PROVENANCE_V09.md)
