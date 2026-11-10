# GreatWallGuard v0.1 交付包

这是当前最佳实测版本的唯一交付入口。核心源码位于仓库的 `src/greatwallguard/`，本目录固定方法、公开接口、配置模板、实验快照和集成步骤，避免从历史实验脚本中拼装系统。

## 交付状态

- 版本：`0.1.0-research`
- 固定提交：以本目录所在 Git commit 为准
- 支持：冻结轨迹回放、新 benchmark 适配、真实 Agent 旁路监控
- 暂不承诺：未经旁路验证直接用于生产阻断；完整多轮用户授权修改尚未进入 v0.1

## 目录

```text
greatwallguard-v0.1/
├── README.md                 使用入口
├── METHOD.md                 完整方法说明
├── INTEGRATION.md            新 benchmark / Agent 接入规范
├── MANIFEST.md               固定代码与实验文件清单
├── config/
│   └── contracts.example.json
├── examples/
│   └── minimal_pipeline.py
└── results/
    └── best_results.json
```

## 安装与测试

在仓库根目录运行：

```bash
python3 -m pip install -e .
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:experiments \
python3 -m unittest discover -s tests -p 'test_*.py'
python3 deliverables/greatwallguard-v0.1/examples/minimal_pipeline.py
```

## 最小在线流程

```text
可信用户请求
  → 授权 DAG + Delegation Envelope
  → before_tool_call：程序化运行时证明
  → 证明不足：原子 Proof Obligation
  → 最多一次受限补证
  → 局部 LLM 证明
  → 动态委托 DAG Delta 校验
  → ALLOW / DENY / CONFIRM
```

## 公开代码入口

```python
from greatwallguard import (
    GreatWallGuardMethod,
    JsonProofAuditor,
    JsonTerminalAuditor,
    CallableEvidenceResolver,
    ProofPacketBuilder,
)
```

完整调用示例见 `examples/minimal_pipeline.py`。方法原理见 `METHOD.md`，适配要求见 `INTEGRATION.md`。
