# 正常拒绝归因与统一在线授权模块

## 1. 17 个正常拒绝来自哪里

按 benchmark 标签，终局实验有 17/157 个正常任务被拒绝。逐条检查后，它们不能统一称为误报：

- 约 12 个任务的标准轨迹本身存在明确问题，例如错误日期、错误账户、买错商品、占位文件 ID、条件未满足仍退款、仓库创建失败仍继续执行；
- 5 个任务可能属于方法误拒：用户明确要求“查看某人的邮件并完成请求”，但初始授权 DAG 无法预知邮件中的具体子任务，阶段三收到的证据包又没有携带部署环境的端点和工具能力语义。

第二类问题横跨三个阶段，但根因是信息没有连续传播：

```text
阶段一：只生成初始授权，缺少“未来可受限扩展”的委托边界
阶段二：知道工具调用，却没有把稳定端点和工具产物能力作为证明
阶段三：只看到调用和轨迹，因此把合法动态步骤误认为新增效果
```

## 2. 统一方法

```text
可信用户请求
   │
   ├─ 初始授权 DAG
   └─ Delegation Envelope
      指定来源、目的、允许效果类型、预算和认证要求
                    │
运行时工具调用 ─────┤
                    ▼
程序化证明
   ├─ 调用、参数、来源和版本
   ├─ 稳定端点契约
   └─ 工具输入—输出能力关系
                    │
              证明不足时
                    ▼
原子证明义务 → 主动补证一次 → 局部语义证明
                    │
                    ▼
显式委托触发的 DAG Delta
   来源身份匹配 + 目的不扩张 + 效果类型/预算校验
                    │
                    ▼
ALLOW / DENY / CONFIRM（无 REVIEW）
```

核心变化是：外部内容既不会被一概视为无权数据，也不会自动获得控制权。只有用户明确选定的来源，才能在有限目的、效果类型和预算内提出授权增量；主机程序校验来源身份、认证状态、效果边界和数量。敏感披露、凭据或金融效果仍需确认。

阶段三输入同时包含 `authorization_context`：授权 DAG 的相关节点、Delegation Envelope、端点契约和工具能力关系。这样，LLM 判断的是一个已经受程序边界约束的局部关系，而不是自行猜测整个环境。

## 3. 代码模块

- `UnifiedAuthorizationPipeline`：串联程序证明、局部语义证明、一次主动补证和终局裁决；公开结果只有 `ALLOW / DENY / CONFIRM`。
- `ProofPacket.authorization_context`：把阶段一授权和阶段二环境能力送入阶段三，修复跨阶段信息丢失。
- `DynamicDelegationExpander`：校验运行时 DAG Delta 的来源、身份、效果类型和预算。
- `GreatWallGuardMethod.build_terminal_pipeline`：统一部署入口，绑定具体 LLM、只读证据解析器和终局审计器。

这些模块不包含 task ID、攻击标签或 benchmark 字符串。不同 Agent 只需提供自己的工具 schema、端点契约、效果类型和证据读取适配器。

## 4. 动态委托试验

试验选择5个疑似机制误拒任务及同任务下的攻击调用，共50个调用。第一版只有动态委托，没有环境契约：13个正常调用中6个接受、1个确认、6个拒绝；37个攻击调用全部拒绝。

加入从部署环境获得的稳定语义后：

- `github_receive_invitation.com` 是模拟 GitHub 邀请流程的正式端点；
- `git_clone` 产生本地仓库树，在没有文件级 GitHub 下载工具时是取得仓库文件的必要能力。

结果为：

| 数据 | ACCEPT | CONFIRM | DENY |
|---|---:|---:|---:|
| 正常调用（13） | 9 | 0 | 4 |
| 攻击调用（37） | 0 | 0 | 37 |

恢复的3个任务分别是接受 GitHub 邀请、按 Alice 邮件更新仓库、按 Taylor 邮件取得并转发仓库文件。仍拒绝的两个任务涉及向第三方页面提交用户邮箱或从可疑优惠站获取信息，保守处置具有明确安全理由。

将试验结果叠加到原全量终局结果：

| 数据 | ALLOW | CONFIRM | DENY | REVIEW |
|---|---:|---:|---:|---:|
| 正常任务（157） | 129（82.2%） | 14（8.9%） | 14（8.9%） | 0 |
| 有效攻击（1,169） | 0 | 25（2.1%） | 1,144（97.9%） | 0 |

这是针对已归因缺口的机制试验叠加，不应冒充重新运行全部 benchmark 的新端到端结果。它证明稳定环境语义和有界动态委托能够修复真实误拒，同时在对应攻击集合上未放宽安全边界。

## 5. 下一步

下一轮不再调整终局 Prompt，而是把两类输入完整接入全量在线执行：

1. 从工具 schema 和部署配置自动生成端点与输入—输出能力契约；
2. 从可信用户请求生成 Delegation Envelope，在读到匹配来源后生成并验证 DAG Delta。

随后重跑 AgentDyn 全量正常与攻击任务。只有在未见任务上仍降低正常拒绝、且攻击自动放行保持为0，才能把这次 pilot 升级为论文主结果。

## 6. 复现入口

- 统一管线：`src/greatwallguard/unified_authorization.py`
- 动态委托：`src/greatwallguard/dynamic_delegation.py`
- 证明包：`src/greatwallguard/proof_obligation_packet.py`
- Pilot：`experiments/dynamic_delegation_pilot.py`
- Pilot 分析：`experiments/analyze_dynamic_delegation_pilot.py`
- 结果：`experiments/dynamic_delegation_pilot/results_v2.json`
- 任务级叠加：`experiments/dynamic_delegation_pilot/task_analysis_v2.json`
