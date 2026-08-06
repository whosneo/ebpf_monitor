# eBPF 系统监控工具用户指南

## 当前能力概述

本工具是 eBPF 监控系统，基于 eBPF + BCC，支持 12 个监控器（详见 docs/ROADMAP.md；含 nic 低延时网卡针对 SWIFT-2200N）。以聚合统计模式为主（数据量大幅减少），支持控制台、CSV、Prometheus 输出。兼容 Python 2.7+/3.7+ 与内核 3.10+。

**已支持监控器**（当前真实状态）：
- exec、open、bio、syscall、func、interrupt、page_fault、context_switch、udp（方向/延迟/端口过滤）、shm（竞争率）、特定进程（process_trade，专用）、nic（低延时网卡）。

**nic（低延时网卡）**：已实现（队列深度相关统计、缓冲区、延迟），针对 SWIFT-2200N。默认 `enabled: false`（driver-specific 符号为占位，待真实硬件验证后启用），可用 `-m nic` 显式运行。辅助采集工具 collect_nic_metrics.py 已支持 SWIFT-2200N。

## 快速运行

```bash
# 推荐使用项目 venv
source .venv/bin/activate

# 默认运行 config/monitor_config.yaml 中 enabled 的监控器
sudo python main.py

# 只跑特定监控器
sudo python main.py -m nic,udp,process_trade

# 守护进程模式 + 日志
sudo python main.py -d
```

配置文件：`config/monitor_config.yaml`（每监控器可配 enabled、interval、target_* 过滤、min_* 阈值等）。

## Prometheus + Grafana + 告警

- Prometheus：config/prometheus.yml + 代码中 declarative PROMETHEUS_CONFIG（默认端口 9200，可在 prometheus: 节下配置 enabled/port）。
- Grafana：config/grafana/ 下的 dashboards 与 provisioning。
- 告警规则：config/alert_rules.yml（当前包含 bio、syscall、shm、process_trade、nic 等）。

运行 Prometheus：
```bash
prometheus --config.file=config/prometheus.yml
```

详细集成步骤与示例面板见本指南后续或 ROADMAP #5 相关内容。

## 数据输出与分析

- CSV 默认输出到 output/ 或 daily_data/（按主机名分目录）。
- 预处理脚本：analysis/preprocess_data.sh。
- 深度分析：
  ```bash
  cd analysis
  python analyzer.py --date 20260615 --type nic
  ```
  analyzer 支持 exec/bio/syscall/open/func/interrupt/page_fault/nic 的完整排名、延迟分布等（每次 `--type` 只能指定单个监控器，或用 `--type all` 分析全部；nic 当前为基础统计，队列深度分析与 spike 报告自动集成计划在 Phase 5 进一步增强；udp/process_trade 暂未接入 analyzer，仅有 CSV/Prometheus 输出）。

报告默认保存到 reports/<hostname>/。

## 配置与过滤示例（nic）

```yaml
monitors:
  nic:
    enabled: false          # 硬件验证完成后改为 true，或用 -m nic 显式运行
    interval: 2
    target_interfaces: []   # e.g. ["eth0"]
    target_processes: []    # e.g. ["zmb"]
    min_queue_depth: 0
    min_latency_us: 0
```

类似配置适用于 udp（target_ports、min_packet_size）、shm、process_trade 等。

## 低延时网卡（nic）专项（SWIFT-2200N）

- 独立监控器，系统级全量。
- 核心指标：硬件队列深度、缓冲区占用、收发延迟（与 socket 层对比）。
- 实现：通用 netdev/napi + tracepoint/kprobe（driver specific 符号为占位；待真实硬件验证后填充）。
- 验证：已完成 ROADMAP Phase 2 spike（见 analysis/nic_spike_verification.md），推荐统计聚合模式。辅助使用 analysis/collect_nic_metrics.py --product SWIFT-2200N。
- 分析：analyzer 已有 analyze_nic 基础统计；queue_depth_analysis + spike 报告自动集成计划在 Phase 5 进一步增强。
- 当前状态：nic.py + nic.c 已实现并集成到主流程/配置/Prometheus/告警；默认禁用，等待真实硬件上验证后再默认启用。

## 注意事项与限制

- 必须 root 或具备 CAP_BPF 能力。
- 集成测试（tests/ 中的 integration）需真实 Linux + bcc + 对应硬件，默认 skip。
- 任何新能力必须遵守硬约束（BCC 路线、无愿景文档）。
- 下一阶段工作唯一来源：docs/ROADMAP.md（执行顺序 1-2-4-5-3；当前正按顺序推进 Phase 2 spike + 测试框架 + nic 实现）。

更多细节与验收标准见 ROADMAP.md 和 docs/adr/0001-documentation-strategy-and-core-constraints.md。


## Trading server profile

```bash
sudo python main.py -c config/monitor_config.trading_server.yaml
```

- 减负：默认关闭多数系统级重监控器，启用 udp/shm/process_trade。
- `process_trade` 的 `zmb_processes` / `zme_processes` 在 trading profile 中为**非空**占位；请改为真实 comm。
- 主配置中二者皆空 = 监控全部进程（全机 `raw_syscalls`，开销大）。

## process_trade pre-fix note

修复前 Python 期望 map `process_trade_stats`，C 使用 `trade_syscall_stats`，CSV 可能一直为空。现已统一为 `process_trade_stats` / `process_trade_ipc_stats`。

## udp / nic filtering

- `target_processes`：已生效（空列表 = 全部）。
- `target_ports`（udp）、`target_interfaces`（nic）：**暂不支持**（C 侧 key 无字段）；非空配置会打 WARNING。

## ufunc（用户态函数）

- 默认 `enabled: false`。
- 配置 `targets[].binary` + `symbols[].name`（运维从有源码的构建提供；实现不臆造交易符号）。
- 使用 BCC uprobe；不宣称所有 3.10 内核可用；失败时该监控器 soft-fail，不影响其它监控器。

## Health / restart

- 进程内 watchdog 可按 app 配置自动 `restart_monitor`（Factory 新建，CSV 新文件）。
- `get_health()` 供运维/日志使用；**无**内置 Prometheus HTTP 服务（勿依赖 9200 端口 unless 自行接入）。

## CSV retention

见 `output.csv_retention`（max_age_days / max_total_bytes_mb / max_files_per_monitor）。
