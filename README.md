# eBPF 系统监控工具

[![Python Version](https://img.shields.io/badge/python-2.7%2B-blue)](https://www.python.org/)
[![Python Version](https://img.shields.io/badge/python-3.7%2B-blue)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Linux-orange)](https://www.kernel.org/)
[![Kernel](https://img.shields.io/badge/kernel-3.10%2B-orange)](https://www.kernel.org/)

基于 eBPF + BCC 的 eBPF 监控系统。当前支持 12 个监控器（exec、open、bio、syscall、func、interrupt、page_fault、context_switch、udp、shm、特定进程、nic），以聚合统计模式为主，支持控制台/CSV/Prometheus 输出。

## 当前真实状态

- **监控器**：见 docs/ROADMAP.md “当前支持的监控器（共 12 个）”。
- **输出**：单监控器支持控制台+CSV；多监控器以 CSV 为主。支持 Prometheus（默认 9200 端口，可配置）。
- **架构**：依赖注入（ApplicationContext），监控器通过 @register_monitor 自动注册，声明式 CONFIG_SCHEMA + CSV/CONSOLE/PROMETHEUS。
- **硬约束**：持续使用 BCC + kprobe/tracepoint，兼容内核 3.10+；不迁移 CO-RE。
- **分析工具**：analysis/analyzer.py 支持各监控器深度统计（含 nic 的队列深度、P99、spike 报告集成）。

## 快速开始

```bash
# 激活项目 venv（推荐）
source .venv/bin/activate

# 运行（需 root 或 CAP_BPF）
sudo python main.py

# 指定监控器
sudo python main.py -m nic,udp

# 后台守护
sudo python main.py -d
```

配置见 `config/monitor_config.yaml`（各监控器 enabled、interval、过滤参数等）。

Prometheus + Grafana + 告警规则见 config/ 目录及 docs/USER_GUIDE.md。

## 文档

- **唯一规划真相来源**：docs/ROADMAP.md（当前状态 + 下一阶段可验证目标，按 1-2-4-5-3 顺序执行）
- **决策记录**：docs/adr/0001-documentation-strategy-and-core-constraints.md
- **用户指南**（含 Prometheus 集成）：docs/USER_GUIDE.md
- **架构**：docs/ARCHITECTURE.md

## 代码质量与测试

- 测试：`source .venv/bin/activate && python -m pytest tests/ -q`
- 新监控器必须配套 unit + smoke 测试（使用 DI mock）。

所有变更必须符合 ADR 规则：只记录当前事实或有明确验收标准的短期目标，无愿景语言。
