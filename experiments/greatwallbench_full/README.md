# GreatWallBench 全量防御评估

本目录把冻结的 GreatWallBench/OpenClaw case 接入当前 GreatWallGuard 方法。评估对象包括 8 类严格双成功攻击和对应的正常对照。当前各目标最新 canonical manifest 合计为 **405 条攻击和 240 条正常对照**；数据集总 README 仍写 404，是因为邮件外发目标已从 48 更新为 49，本文以目标级最新 manifest 为准。

## 固定原则

- 授权生成只能读取可信用户消息与部署工具 schema；
- 运行时证明只能读取实际工具调用、返回和状态事件；
- `malicious_goal`、`target_effect`、攻击标签和 oracle 只用于事后计算指标；
- 不根据 case ID、目标类别或已知攻击参数增加规则；
- 先冻结 inventory 和 smoke test，再运行全量阶段一至阶段三。

## 数据层次

```text
case.json
├── 防御输入
│   ├── visible_agent_turns[].user_message
│   ├── tool_contract
│   ├── execution.tool_call_trace
│   ├── workspace_read_trace
│   └── workspace_event_trace
└── 事后评估
    ├── normal / attack
    ├── target_effect
    ├── task_success
    └── attack_success
```

运行数据审计：

```bash
cd greatwallguard
python3 experiments/greatwallbench_full/build_inventory.py
```

输出 `inventory.json`，其中记录每类数量、唯一用户请求数、工具覆盖和逐 case 来源，但不把攻击答案暴露给防御模块。

## 当前结果与复现入口

面向读者的报告已统一收录到 `docs/progressive-authorization-proof/`：

- `GREATWALLBENCH_FULL_RESULTS.md`：三阶段端到端最终结果；
- `GREATWALLBENCH_STAGE12_RESULTS.md`：阶段一、二中间结果；
- `EXPERIMENT_RESULTS.md`：与 AgentDojo、AgentDyn 结果的统一说明。

本目录保留复现实验所需的适配器、运行脚本与机器可读产物：

- `full_stage12_results.json`：阶段一、二逐 case 结果；
- `stage3_manifest.json`：阶段三最小审计义务；
- `full_stage123_results.json`：三阶段逐义务与任务级结果；
- `EXPERIMENT_PROTOCOL.md`：固定的实验口径和信息隔离要求。
