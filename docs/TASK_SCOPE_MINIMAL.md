# 简易 TaskScope 原型

## 目的

在不读取攻击结果、不使用 case 标签、也不调用外部 LLM 的情况下，先验证一个最小问题：

> 仅凭正常用户任务、Agent 声明的能力和工具 schema，能否生成一个初步的行为范围，并用于阻止明显的计划外高影响动作？

这个原型不是最终的语义规划器，而是 TaskScope 的可运行基线。

## 输入与输出

输入只有三类：

```text
正常用户任务
Agent 可用工具名称
工具 schema（名称、描述、Effect 类型）
```

输出为 `TaskScope`：

```text
allowed_tools          任务相关的工具集合
allowed_effects        允许的 Effect 类型
allowed_resources      任务中明确出现的文件、记忆或 URL
allowed_destinations   任务中明确出现的邮件地址
metadata               选择分数、拒绝原因和生成警告
```

生成方法是确定性的关键词重叠加 Effect 线索匹配：

1. 从工具名称和描述中抽取词；
2. 与用户任务计算重叠；
3. 根据 `read/write/send/execute` 等语义线索增加分数；
4. 只保留 Agent 已声明且与任务相关的工具；
5. 从任务文本中提取显式资源和收件人；
6. 在执行开始前冻结结果。

实现入口：

```python
from greatwallguard import generate_task_scope

scope = generate_task_scope(
    task,
    agent_capabilities,
    tool_schemas,
    task_id="normal-report",
)
```

## 一个离线例子

任务：

```text
Read file://workspace/notes.md and create file://workspace/report.md with a summary.
```

生成结果：

```text
allowed_tools:    read_file, create_file
allowed_effects:  read, create
resources:        file://workspace/notes.md
                  file://workspace/report.md
```

在同一个运行时中：

```text
read_file(notes.md)       → ALLOW
create_file(report.md)    → ALLOW
send_email(attacker, ...) → BLOCK
```

这里的阻断不是因为检测到了“恶意文本”，而是因为 `send_email` 不在任务范围内，且它会产生任务没有声明的外部持久 Effect。

## 当前原型能验证什么

- 能从正常任务自动产生一个可审计的 Scope，而不是从攻击 trace 反推 Scope；
- 能拦截明显的计划外工具和 Effect；
- 能为后续运行时图检测提供一个明确的比较对象；
- 生成过程记录了匹配分数和警告，便于分析 Scope 过窄或过宽的原因。

## 明确的局限

这个版本还不能处理：

- 同一工具不同参数的语义约束；
- “参会者”“我的团队”等需要上下文解析的目标集合；
- 多步条件、部分顺序和合法动态扩展；
- 正常任务中隐含但未写出的资源；
- 中文复杂语义和跨轮任务目标修订。

因此它只能作为第一版基线。后续应逐步替换：

```text
关键词匹配
  → 结构化任务解析
  → 受约束的轻量 LLM 规划
  → TaskScope 人工/自动一致性评估
```

评估时必须把 Scope 生成和图检测分开报告，不能把已有 case 元数据直接当作自动生成结果。
