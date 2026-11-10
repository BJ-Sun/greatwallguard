# 新 Benchmark 与真实 Agent 接入规范

## 1. 新 Benchmark

适配层只允许提供环境事实，不允许包含 task ID、攻击标签或样本答案。

必须实现：

1. 将轨迹转换为 `user message / tool call / tool result / state change`；
2. 从工具 schema 生成 `EffectContract` 和 `ObservationContract`；
3. 声明稳定端点、来源别名和工具输入—输出能力；
4. 提供正常任务 utility 和攻击目标 oracle，仅用于事后评估；
5. 分别报告 `ALLOW / DENY / CONFIRM`，不得把确认或拒绝直接计为攻击检出。

禁止：

- 根据攻击 case 添加工具、域名或参数规则；
- 用完整轨迹反向修改初始授权；
- 把正常标签自动当作每个调用都得到授权；
- 把安全替代计作原任务完成。

## 2. 真实 Agent

建议在工具网关接入：

```text
on_user_message(message, identity)
before_tool_call(call_id, tool, arguments)
after_tool_result(call_id, result, state_changes)
on_task_end()
```

部署顺序：

1. `observe-only`：记录决策，不影响 Agent；
2. `confirm-only`：只对敏感未知调用询问用户；
3. `high-confidence block`：仅阻断程序冲突和已校验证书；
4. 完整 `ALLOW / DENY / CONFIRM` 网关。

## 3. 三个部署回调

```python
JsonProofAuditor(complete, validate_conflict=...)
CallableEvidenceResolver(fetch)
JsonTerminalAuditor(complete)
```

`complete(system_prompt, payload)` 可以连接任意支持 JSON 输出的黑盒云端模型。`fetch(query, packet)` 必须由宿主实现，并限制为受控只读动作。

## 4. 配置审查

上线前至少确认：

- 哪些工具会产生外部提交效果；
- 哪些参数可能携带敏感数据；
- 哪些读取会产生网络出站流量；
- 哪些域名或资源标识属于稳定业务端点；
- 工具返回的对象类型与可供后续工具消费的字段；
- 用户确认如何写回授权 DAG；
- LLM 超时、格式错误和不可用时默认拒绝还是确认。

示例配置见 `config/contracts.example.json`。
