# analysis — Agent 指南

改离线分析、预处理或 nic 验证文档时读本文件。全局约束见根目录 `AGENTS.md`。

## 职责边界

- 消费 `output/`（或约定数据目录）中的 CSV，做排名、分布、专项报告。
- **不是**运行时监控进程；不在此实现 eBPF 加载或常驻采集。
- 依赖见本目录 `requirements.txt`；入口以 `analyzer.py`、`data_utils.py`、`USAGE.md` 为准。

## 文档卫生

- 遵守 ADR 0001：只写当前事实与可验收目标。
- **禁止**在 `analysis/` 下新增「愿景 / 长期规划 / 业界启示」类报告。
- nic 真机量化结果写入或更新 `nic_spike_verification.md`，不另起空泛规划文档。

## 接入新监控类型

1. 确认运行时已稳定产出该类型 CSV（列语义清楚）。
2. 在 `analyzer.py` 的 `monitor_types`（或等价列表）中登记类型名。
3. 提供至少一条分析路径（专用 `analyze_*` 或可复用的通用统计）。
4. 与 `docs/ROADMAP.md` 目标 C 对齐：写明已支持类型，勿夸大「深度分析已全覆盖」。
5. 类型名与运行时/CSV 前缀一致。内核 kprobe 监控器类型为 **`kfunc`**（`analyze_kfunc`，CSV 前缀 `kfunc_`）。

## 常用入口

```bash
cd analysis
# 见 USAGE.md；按日期与类型分析
python analyzer.py --date YYYYMMDD --type <monitor>
```

辅助采集（如 nic）：`collect_nic_metrics.py` —— 改动时注明适用网卡/产品，默认勿假设 SWIFT-2200N 已在本机。

## 不要做

- 假设本机正在跑 `main.py` 或已有 root eBPF。
- 把 Grafana/Prometheus 部署说明复制成新的分析「架构愿景」；展示侧指针指向 `docs/USER_GUIDE.md` 与 `config/`。
