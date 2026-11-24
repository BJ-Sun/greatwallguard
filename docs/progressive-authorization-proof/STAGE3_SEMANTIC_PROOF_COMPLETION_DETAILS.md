# 阶段三：Semantic Proof Completion

阶段二已经程序化验证工具、参数、来源、条件、版本和使用次数，并将尚未闭合的调用标记为 `REVIEW`。这些未决调用主要来自三种情况：现有事实充足，但用户语义无法由有限算子计算；执行证据仍有缺失；用户是否授予某项权限本身不明确。本阶段的目标是补全前两类证据与语义缺口，并把第三类问题交还用户决定。为此，**Semantic Proof Completion** 由程序根据阶段二定位的失败关系生成原子证明问题并切取局部证据；审计模型只判断这条关系是得到支持、存在冲突还是证据不足；程序再校验证据引用并将结果收敛为 `ALLOW / DENY / CONFIRM`。受限自动补证是下一步需要接入的闭环，当前全量实验对证据不足的样本采用终局拒绝或用户确认。

一个自然的问题是：既然最终仍需要模型理解语义，为什么不直接让它审计完整轨迹？完整轨迹会使成本和延迟随任务长度增长，更根本的困难在于，可信用户请求、外部不可信内容和大量中间返回混在一起，模型需要同时恢复授权边界、寻找待审查行为、追踪参数来源并作出判断，任何一步出错都难以复核。前两阶段已经把这些工作转化为结构化证明：DAG 固定允许的 Effect、字段和关系，运行时证明定位尚未闭合的关系及其来源路径。阶段三因此只解释一个明确问题，例如“证据中的 `project owner` 是否满足用户所说的项目负责人”，并且结论只能作用于指定的 Effect、字段和值。这样既缩短审计输入，也使模型判断可以沿证据引用被程序复核。

```text
阶段二未闭合的关系
        ↓
局部问题与最小证据
        ↓
受约束的语义审计
        ↓
程序校验与终局处置
        ↓
ALLOW / DENY / CONFIRM
```

## 1. 构造局部问题与最小证据

阶段二通常已经确定候选 Effect、发生问题的字段、Agent 实际使用的值及其运行时来源，只剩一条关系无法由程序判断。为了把这条关系转化为边界稳定、可以复核的审计任务，程序首先将阶段二的 `REVIEW reason` 映射为有限的证明类型，例如参数绑定、条件满足、委托范围或生成内容一致性；再把候选字段和值代入固定问题模板。审计问题的边界因此由阶段二和 Authorization DAG 决定，不需要额外的大模型自由生成。

以“给项目负责人发送项目完成通知”为例，阶段一规定：

```text
Effect       = external_message
recipients   = 项目负责人的邮箱
使用次数     = 1
```

阶段二随后观察到：

```text
候选调用：send_email(recipients=[alice@example.com])

成员资料：
name  = Alice
role  = project owner
email = alice@example.com
```

程序已经证明邮箱来自允许的成员资料，也已经确认 `send_email` 是用户授权的 Effect；有限算子无法判断 `project owner` 是否满足用户所说的“项目负责人”。阶段二据此输出 `parameter_binding / recipients / alice@example.com`，程序用固定模板生成下面的证明问题；`project owner` 与“项目负责人”的语义对应关系由审计模型结合用户请求和 E0 判断，而不是再调用一个模型改写问题。

```text
现有证据能否证明 alice@example.com
是 send_email 的授权 recipients？
```

局部审计输入包含：

```text
可信用户请求        用户实际授权了什么
已授权 Effect       本次调用允许产生哪类后果
候选工具与参数      Agent 当前准备执行什么
未决字段和值        哪一项关系尚未证明
直接相关证据        值的来源、字段和上下文
允许影响的范围      本次结论只能作用于哪个 Effect 和字段
```

对应的紧凑表示为：

```json
{
  "trusted_request": "给项目负责人发送项目完成通知",
  "authorized_effect": "external_message",
  "candidate_call": {
    "tool": "send_email",
    "recipients": ["alice@example.com"]
  },
  "question": "现有证据能否证明 alice@example.com 是 send_email 的授权 recipients？",
  "evidence": [{
    "ref": "E0",
    "source": "read_project_members",
    "value": {
      "role": "project owner",
      "email": "alice@example.com"
    }
  }],
  "scope": {
    "effect": "external_message",
    "field": "recipients",
    "value": "alice@example.com"
  }
}
```

局部证据同样由程序整理。网关保留候选调用之前的工具调用、参数、真实返回和状态事件；证据切片器使用候选值、问题字段、来源工具和时间邻近性对这些事件评分，优先保留包含 `alice@example.com`、`recipients` 及其同一对象字段的记录，当前最多选择六条。完整轨迹仍保留在主机侧。该实现已经避免把整条长轨迹交给模型，但当前证据排序仍以值匹配、字段匹配和邻近性为主；后续可进一步沿执行图中的 Binding 和字段依赖反向切片。审计模型不会接收 Agent 隐藏推理，也不能改变问题中的 Effect、字段和候选值。

## 2. 受约束审计、校验与补证

局部问题仍可能得到三种不同结论：证据支持当前授权关系、证据明确反驳当前授权关系、现有证据不足。若把后两者都视为拒绝，会误拦缺少日志或字段的正常任务；若把证据不足视为允许，又会让未获证明的调用通过。为此，审计模型必须返回三态结果：

```text
SUPPORTED
现有证据支持当前 Effect、字段和候选值之间的授权关系。

CONTRADICTED
现有证据明确反驳这条局部授权关系。

NEED_EVIDENCE
现有证据不足以判断支持或冲突。
```

`SUPPORTED` 必须引用具体证据，并且只对输入中规定的 Effect、字段和值生效。在上述案例中，`E0.role=project owner` 与 `E0.email=alice@example.com` 可以支持当前邮件的收件人；该结论不授权附件、其他收件人或后续任务。

`CONTRADICTED` 必须指出冲突的实际值、授权要求和证据引用。程序重新读取这些引用并验证比较关系，只有冲突确实成立时才输出 `DENY`。审计模型仅给出“看起来异常”或引用不存在的证据时，结论转为证据不足。

`NEED_EVIDENCE` 必须说明缺少什么事实。完整的补证闭环应由程序把该事实规范化为有限证据槽，例如 `project_member.role(email=alice@example.com)`，再根据工具契约选择部署方允许的只读查询；新返回写入证据图后，系统重建同一个证明问题并只重试一次。审计模型可以描述缺失事实，但不能自由选择或执行工具，也不能改变用户请求、Effect、字段和候选值。若缺少的是用户授权，环境查询和模型推断都无法补齐，只能请求用户确认。

当前代码已经定义补证计划与终局网关，但 GreatWallBench 全量实验尚未真正执行“新查询—新证据—重新审计”。实验中的 `NEED_EVIDENCE` 会连同原证据包进入终局裁决：缺少授权时转为 `CONFIRM`，其他无法闭合的高风险调用转为 `DENY`。因此，下面的自动补证流程描述的是待完成的方法闭环，而不是当前实验已经使用的额外查询。

最终处置为：

```text
SUPPORTED
→ ALLOW

经程序验证的 CONTRADICTED
→ DENY

NEED_EVIDENCE
→ 当前实现：终局 DENY 或 CONFIRM
→ 完整闭环：一次受限补证并重新审计

补证后仍缺少事实
→ 根据风险 DENY 或 CONFIRM

授权范围本身不明确
→ CONFIRM
```

阶段三的模型只解释一条局部语义关系；问题的选择、初始证据范围、冲突校验和最终处置均由程序控制。完整版本还将由程序控制补证工具、查询参数和最多一次的重试次数。

## 3. 贯穿案例

继续使用“给项目负责人发送项目完成通知”的任务。阶段二已经确认：

```text
send_email 属于已授权 external_message
alice@example.com 来自允许的成员资料
邮件次数尚未超过限制

未决关系：
role=project owner 是否满足“项目负责人”
```

若成员资料为：

```text
E0.role  = project owner
E0.email = alice@example.com
```

审计模型引用 E0 返回 `SUPPORTED`，当前调用获得仅限 `external_message.recipients=alice@example.com` 的语义证明，最终输出 `ALLOW`。

若资料明确显示：

```text
E0.role  = external visitor
E0.email = alice@example.com
```

审计模型返回 `CONTRADICTED` 并引用 E0；程序确认角色与用户条件冲突后输出 `DENY`。

若成员资料没有角色字段，审计模型返回 `NEED_EVIDENCE` 并声明缺少 Alice 的项目角色。当前实现将其路由到终局 `DENY` 或 `CONFIRM`；完整补证闭环会把该事实映射为受限的成员角色查询，取得新证据后重建同一问题并重新审计一次。审计模型没有权限自行补全缺失事实或执行工具。

阶段三解决的是前两阶段留下的局部语义缺口。它可以判断候选值是否满足用户的开放描述，但不能新增终端 Effect、扩大字段和对象范围，也不能代替用户授予权限。当前实现已包含程序化问题生成、相关证据筛选、三态审计、证据引用校验和终局处置；尚未完成的是把 `NEED_EVIDENCE` 接入真实只读工具，形成一次受限的自动补证闭环。语义结论只对本次调用有效，也尚未自动写回 Authorization DAG 成为可复用授权。
