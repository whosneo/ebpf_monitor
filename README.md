# eBPF 系统监控工具

[![Python Version](https://img.shields.io/badge/python-2.7%2B-blue)](https://www.python.org/)
[![Python Version](https://img.shields.io/badge/python-3.7%2B-blue)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Linux-orange)](https://www.kernel.org/)
[![Kernel](https://img.shields.io/badge/kernel-3.10%2B-orange)](https://www.kernel.org/)

基于 eBPF + BCC 的 eBPF 监控系统。当前支持 13 个监控器（含 ufunc 用户态函数、nic 低延时网卡 for SWIFT-2200N：exec、open、bio、syscall、func、interrupt、page_fault、context_switch、udp、shm、process_trade、nic、ufunc），以聚合统计模式为主，支持控制台/CSV 输出（PROMETHEUS_CONFIG 辅助；无内置 HTTP exporter）。

**nic（低延时网卡）**：已实现（针对 SWIFT-2200N 等中科驭数低延时卡），默认 `enabled: false`，driver-specific 符号为占位，待真实硬件上完成验证后启用。

## 当前真实状态

- **监控器**：见 docs/ROADMAP.md（13 个，含 ufunc、ProcessTargetManager、watchdog/CSV retention）。nic 已实现但默认禁用，见上。
- **输出**：单监控器支持控制台+CSV；多监控器以 CSV 为主。`PROMETHEUS_CONFIG` 声明式指标提取辅助；**无内置 Prometheus HTTP exporter**（勿依赖 9200 端口 unless 自行接入）。Grafana/alert 配置文件在 `config/` 供外部接入。
- **架构**：依赖注入（ApplicationContext），监控器通过 @register_monitor 自动注册，声明式 CONFIG_SCHEMA + CSV/CONSOLE/PROMETHEUS_CONFIG。
- **硬约束**：持续使用 BCC + kprobe/tracepoint（ufunc 为 BCC uprobe），兼容内核 3.10+ 路线；不迁移 CO-RE。
- **分析工具**：analysis/analyzer.py 支持 exec/bio/syscall/open/func/interrupt/page_fault/nic/udp/process_trade/ufunc 列表接入（深度分析因类型而异）。

## 快速开始

```bash
# 激活项目 venv（推荐）
source .venv/bin/activate

# 运行（需 root 或 CAP_BPF）
sudo python main.py

# 指定监控器（nic 针对 SWIFT-2200N 已可用）
sudo python main.py -m nic,udp,process_trade

# 后台守护
sudo python main.py -d
```

配置见 `config/monitor_config.yaml`；交易机减负可用 `config/monitor_config.trading_server.yaml`（各监控器 enabled、interval、过滤参数等）。

Grafana 仪表板与告警规则样例见 `config/` 及 docs/USER_GUIDE.md（需自行部署 Prometheus/Grafana；本程序不监听 9200）。

## 文档

- **唯一规划真相来源**：docs/ROADMAP.md（当前状态 + 下一阶段可验证目标，按 1-2-4-5-3 顺序执行）
- **决策记录**：docs/adr/0001-documentation-strategy-and-core-constraints.md
- **用户指南**（含 Prometheus 集成）：docs/USER_GUIDE.md
- **架构**：docs/ARCHITECTURE.md
- **设计（稳定性/多进程/ufunc）**：docs/design/trading-server-stability-and-process-targeting.md
- **ADR 0002**：docs/adr/0002-process-targeting-and-ufunc.md

## 代码质量与测试

- 测试：`source .venv/bin/activate && python -m pytest tests/ -q`
- 新监控器必须配套 unit + smoke 测试（使用 DI mock）。

所有变更必须符合 ADR 规则：只记录当前事实或有明确验收标准的短期目标，无愿景语言。
