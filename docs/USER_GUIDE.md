# eBPF 系统监控工具用户指南

## 当前能力概述

本工具是 eBPF 监控系统，基于 eBPF + BCC，支持 12 个监控器（详见 docs/ROADMAP.md）。以聚合统计模式为主（数据量大幅减少），支持控制台、CSV、Prometheus 输出。兼容 Python 2.7+/3.7+ 与内核 3.10+。

**已支持监控器**（当前真实状态）：
- exec、open、bio、syscall、func、interrupt、page_fault、context_switch、udp（方向/延迟/端口过滤）、shm（竞争率）、特定进程（专用）、nic（低延时网卡：队列深度、缓冲区、延迟）。

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
- 告警规则：config/alert_rules.yml（当前包含 bio、syscall、shm、process_trade 等；nic 规则可按需添加）。

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
  python analyzer.py --date 20260615 --monitor nic,udp
  ```
  analyzer 支持 exec/bio/syscall/.../nic 的完整排名、延迟分布、队列深度（P50/P95/P99）、spike 报告集成等。

报告默认保存到 reports/<hostname>/。

## 配置与过滤示例（nic）

```yaml
monitors:
  nic:
    enabled: false          # 硬件就绪后改为 true
    interval: 2
    target_interfaces: []   # e.g. ["eth0"]
    target_processes: []    # e.g. ["zmb"]
    min_queue_depth: 0
    min_latency_us: 0
```

类似配置适用于 udp（target_ports、min_packet_size）、shm、process_trade 等。

## 低延时网卡（nic）专项

- 独立监控器，系统级全量。
- 核心指标：硬件队列深度、缓冲区占用、收发延迟（与 socket 层对比）。
- 实现：通用 netdev/napi + tracepoint/kprobe（driver specific 符号为占位，需提供中科驭数型号后填充）。
- 验证：使用 temp/nic_latency_spike/ 进行 spike（量化数据量，决定聚合 vs 事件模式）。
- 分析：analyzer 的 analyze_nic + queue_depth_analysis + spike 报告。

## 注意事项与限制

- 必须 root 或具备 CAP_BPF 能力。
- 集成测试（tests/ 中的 integration）需真实 Linux + bcc + 对应硬件，默认 skip。
- 任何新能力必须遵守硬约束（BCC 路线、无愿景文档）。
- 下一阶段工作唯一来源：docs/ROADMAP.md（执行顺序 1-2-4-5-3，已完成文档 + nic 标准模板 + 测试骨架 + #5 部分）。

更多细节与验收标准见 ROADMAP.md 和 docs/adr/0001-documentation-strategy-and-core-constraints.md。
