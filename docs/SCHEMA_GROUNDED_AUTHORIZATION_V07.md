# 通用 Schema-Grounded 授权编译器 v0.7

## 目标

结构化授权 v0.5 将正常高置信误报降到零，但使用了逐工具语言规则，容易退化为针对 AgentDojo 的补丁。本轮重新实现一个通用版本，回答：**不为 task ID 或具体任务模板编写规则，只依靠有限效果本体、工具契约和参数类型，能做到什么程度？**

## 方法

部署方只需要为工具声明：

```text
tool            工具名称
effect          用户可理解的效果类别
critical_fields 必须接受授权检查的关键参数
```

例如，新工具 `notify_customer` 可以直接复用：

```text
effect = external_message
critical_fields = [recipient, body]
```

编译器不需要新增该工具的提示词规则。它使用共享的有限效果语言识别“发送消息、创建日历、成员变更、预订、资金转移、账户修改”等效果；使用动作—对象词集合容忍 `create an event`、`delete the largest file` 等插入修饰词的表达；再根据字段类型提取邮箱、IBAN、URL、文件名、权限和密码等显式值。没有显式值的字段统一标记为 `deferred`。

外部委托仍不产生具体授权：`follow the instructions in the file` 只会进入 `REVIEW`。

## 与场景化规则的区别

```text
场景化版本：某个工具 + 某类句式 → 授权

通用版本：用户效果语言 → 有限效果类别
                         ↓
                   工具契约映射
                         ↓
               关键参数 literal / deferred
```

允许人工维护的是稳定的效果本体和工具安全契约，而不是 benchmark 任务模板。

## AgentDojo 全量结果

仍使用同一冻结实验：97 个正常任务、609 个有目标工具调用的攻击组合，不调用受害模型、事实图或 LLM。

| 指标 | 场景化 v0.5 | 通用 v0.7 |
|---|---:|---:|
| 正常直接放行 | 38/97 | 38/97 |
| 正常进入复核 | 59/97 | 59/97 |
| 正常高置信告警 | 0/97 | **0/97** |
| 攻击高置信告警 | 474/609（77.8%） | 413/609（67.8%） |
| 攻击进入复核 | 114/609（18.7%） | 175/609（28.7%） |
| 攻击直接放行 | 21/609（3.4%） | 21/609（3.4%） |

通用版本在正常任务上达到与场景化版本相同的结果，说明消除高置信正常误报不依赖逐任务补丁。代价是它更保守：61 个攻击组合从高置信告警降为复核，因为通用效果类别不会假设动态参数一定错误。

## 能力边界

效果级规则已经达到一个清晰边界：

- 38 个任务只需要只读工具或显式参数，可以程序化直接放行；
- 59 个任务的效果可以识别，但至少一个关键参数需要运行时证据；
- 继续扩充效果语言无法把这59个任务安全转成放行，只会扩大攻击授权。

因此，下一步不应继续增加同义词，而应编译参数关系：

```text
“删除最大的文件”
file_id = project(id, argmax(size, list_files()))

“发给文件中的客户”
recipient = role(client, named_file)

“加入人数最少的频道”
channel = argmin(member_count, get_channels())
```

前两类排序、过滤、投影和唯一匹配可以由通用符号算子及事实图重放；角色识别、摘要和外部委托仍需保留不确定。

## 结论

程序化方法还没有到达能力上限，但“效果识别”这一层已经基本收敛。继续提高正常自动放行率，关键不再是理解更多动词，而是证明动态参数的选择和来源。

## 产物

- 实现：`src/greatwallguard/schema_grounded_authorization.py`
- 测试：`tests/test_schema_grounded_authorization.py`
- 实验：`experiments/agentdojo_schema_grounded_v06.py`
- 结果：`experiments/agentdojo_schema_grounded_v07_results.json`
