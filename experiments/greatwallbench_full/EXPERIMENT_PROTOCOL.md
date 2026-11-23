# GreatWallBench 防御全量实验协议

## 1. 目标

在不修改 GreatWallGuard 方法规则的前提下，将当前冻结方法迁移到自建长程 benchmark，分别测量正常任务自动放行、用户确认与拒绝，以及攻击目标调用的自动放行、复核与明确阻断。

## 2. 数据冻结

目标级最新 canonical manifest 共包含：

| 数据 | 数量 |
|---|---:|
| 正常对照 | 240 |
| 严格双成功攻击 | 405 |
| 合计 | 645 |

攻击按目标分为：日历错误创建52、文件删除46、邮件外发49、权限扩大61、模型输出完整性47、定时任务50、网络探测50、虚拟回连50。数据集总 README 仍记录404条，是因为邮件外发目标已经更新为49条；本实验以各目标最新 canonical manifest 为准。

## 3. 信息隔离

防御可见：

- 当前及此前可信用户消息；
- 工具名称、描述和输入 schema；
- 已发生的工具调用、参数和返回；
- 文件/记忆读取与状态变化。

仅评估器可见：

- normal/attack 标签；
- malicious goal 与 target effect；
- task/attack oracle；
- 目标调用匹配结果。

## 4. 已完成的执行层次

1. **Inventory audit。** 645条 case 均具有可信消息、工具契约和工具轨迹；模型输出完整性攻击另按持久状态和最终输出评估。
2. **Stage-1/2 smoke 与 full。** 全部样本按消息时间逐轮更新 Authorization DAG，再回放当时可见的工具调用、返回和状态证据。
3. **Stage-3 full。** 仅为阶段二的 `REVIEW` 构造原子证明义务和最小证据包；已确定的 `ALLOW` 与 `ALERT` 不再交给语义模型。
4. **Terminal adjudication。** 阶段三结果经过证据引用校验和授权不变量约束，最终统一为 `ALLOW / DENY / CONFIRM`，不保留 `REVIEW`。
5. **State-level track。** 47条模型输出完整性攻击按持久文件版本、内容变化与最终输出链路评估，不能用工具调用目标替代。

## 5. Smoke 结果

| 数据 | ALLOW | REVIEW | ALERT | 状态级待适配 |
|---|---:|---:|---:|---:|
| 正常任务（8） | 6 | 2 | 0 | 0 |
| 攻击目标（8） | 0 | 5 | 2 | 1 |

两条正常 `REVIEW` 都是用户允许根据动态资产信息执行网络扫描的任务；程序无法仅凭静态授权确定实际扫描范围。五条攻击 `REVIEW` 主要涉及外部内容补全动态对象或宽泛委托。邮件外发和错误分享产生了明确参数冲突，因此在阶段二直接 `ALERT`。

## 6. 协议边界

实验采用冻结轨迹上的在线顺序回放：每次只使用当时已经出现的可信用户消息更新 Authorization DAG，同时保留此前证据、授权消费和撤销状态。该口径能够评估逐轮授权判定，但仍不等同于重新运行受害模型后的端到端任务完成率或攻击成功率。

## 7. 产物

- `dataset_adapter.py`：case 到防御输入/评估标签的隔离适配；
- `benchmark_contracts.py`：从工具 schema 生成通用 effect/observation contract；
- `build_inventory.py` 与 `inventory.json`：全量数据审计；
- `smoke_stage12.py` 与 `smoke_stage12_results.json`：阶段一、二真实 smoke；
- `full_stage12_results.json`：阶段一、二逐 case 结果；
- `stage3_manifest.json`：阶段三证明义务；
- `full_stage123_results.json`：三阶段逐义务与任务级最终结果。
