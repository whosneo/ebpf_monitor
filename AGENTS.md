# eBPF 监控系统 — Agent 指南

面向在本仓库中编码的 agent。人读说明见 `README.md` 与 `docs/`。

## 硬约束

1. **BCC only**：持续使用 BCC + kprobe/tracepoint（`ufunc` 允许 BCC uprobe attach）。**禁止**迁移 CO-RE / libbpf。见 `docs/adr/0001-documentation-strategy-and-core-constraints.md`。
2. **文档卫生**：只写**当前真实事实**或**有明确验收标准的短期目标**。禁止未来愿景、长期规划、业界最佳实践空谈。见 ADR 0001。
3. **规划与决策**：下一阶段工作的唯一真相是 `docs/ROADMAP.md`。策略/硬约束/重大能力变更须更新 ROADMAP 或新增 `docs/adr/`。

## 必读文档（按需打开）

| 文档 | 何时读 |
|------|--------|
| `docs/ROADMAP.md` | 动手前：当前状态与可验收目标 |
| `docs/adr/` | 涉及约束或已决架构取舍 |
| `docs/ARCHITECTURE.md` | 组件职责与扩展监控器流程 |
| `docs/design/trading-server-stability-and-process-targeting.md` | ProcessTarget、pid_allow、ufunc、稳定性 |
| `docs/USER_GUIDE.md` | 运行方式、配置、分析入口 |
| `CONTEXT.md` | 领域用词（勿自造同义词） |

## 验证

- **默认**：`source .venv/bin/activate && python -m pytest tests/ -q`
- **Full**：任务需要端到端/真机时，可执行 `sudo python main.py …`（或等价）。执行前在回复中说明命令与影响；优先保证 unit 绿。无 root / 无 BCC 能力时记录失败原因并降级为 unit，勿假装已验证内核路径。

## 改哪里读哪份

| 工作面 | 必读 |
|--------|------|
| Python 监控器 | `src/monitors/AGENTS.md` |
| eBPF C | `src/ebpf/AGENTS.md` |
| 离线分析 | `analysis/AGENTS.md` |
| 测试 | `tests/AGENTS.md` |

## 文档义务（Strict）

- **新监控器或行为/配置语义变化** → 更新 `docs/ROADMAP.md`「当前真实状态」（及必要时 `ARCHITECTURE.md`）。
- **策略、硬约束、不可逆架构取舍** → 新增或修订 ADR。
- **纯 bugfix / 仅测试 / 无用户可见语义变化** → 不强制改 docs。

## 领域词表

术语以 `CONTEXT.md` 为准。尤其：**kfunc**（内核 kprobe）与 **ufunc**（用户态 uprobe）不得混称；代码注册名与领域名均为 `kfunc`，见 `src/monitors/AGENTS.md`。
