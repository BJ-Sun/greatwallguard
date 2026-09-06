# 真实 Agent 图结构验证

## 设置

使用攻击仓库的真实 `VictimAgent + DeepSeek API`，连续运行 4 个正常会话，所有会话共享同一个 `WorkspaceState`。工具仍是 AgentLAB 的本地模拟工具，不产生真实外部副作用。

```text
会话 1：web_fetch → 摘要
会话 2：write_file(MEMORY.md)
会话 3：read_file(MEMORY.md)
会话 4：web_search → 摘要
```

## 结果

| 会话 | Agent 工具调用 | 图动作（含后台） | 状态节点 | 状态读取边 | compact_view |
|---:|---:|---:|---:|---:|---:|
| 1 | 1 | 2 | 1 | 0 | 739 B |
| 2 | 1 | 4 | 3 | 0 | 1,258 B |
| 3 | 1 | 6 | 4 | 2 | 1,654 B |
| 4 | 2 | 9 | 5 | 3 | 2,053 B |

最终覆盖指标：

- 会话捕获率：`4 / 4 = 100%`
- 工具动作捕获率：`5 / 5 = 100%`
- 工具返回捕获率：`5 / 5 = 100%`
- 工作区持久变更与 State 节点：`5 / 5 = 100%`
- `MEMORY.md` 后续上下文加载：2 次
- `state_read` 边与事件：3 / 3

## 对图设计的结论

1. **信息覆盖可行**：用户输入、workspace bootstrap、工具调用、工具返回、文件写入、Flush 和后续状态读取均能进入同一张图。
2. **跨会话保真成立**：会话 2 写入 `MEMORY.md`，会话 3/4 重新加载该文件；图中产生版本节点和读取边，且不需要保存原始文件内容。
3. **摘要不是绝对常数**：4 个会话中 `compact_view` 从 739 B 增至 2,053 B，增长来自新增持久对象和状态版本，而不是历史消息本身。当前设计是“与持久对象数相关、与历史长度无关”的压缩；若要严格有界，需要增加对象 TTL、按对象聚合或滑动窗口。
4. **当前盲区**：尚未记录完整 assistant 思考、工具 schema 的版本变化和一个动作的多源依赖；这些应作为下一轮图字段扩展，而不是在图构建阶段做攻击判断。

完整原始图和指标保存在 [real_normal_validation.json](real_agent/real_normal_validation.json)，可用以下命令重跑：

```bash
env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY \
  PYTHONPATH=src:../attack-generation/openclaw-agentlab-upstream \
  ../attack-generation/openclaw-agentlab/.venv/bin/python \
  experiments/run_real_agent_validation.py --output-root experiments/real_agent
```
