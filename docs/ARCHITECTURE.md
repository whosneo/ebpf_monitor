# eBPF 系统监控工具架构设计文档

## 概述

本文档描述当前 eBPF 系统监控工具的实际架构。项目是 eBPF 监控系统，基于 eBPF + BCC 实现低开销监控，支持 12 个监控器，输出 CSV/控制台/Prometheus。

## 当前真实状态

**支持的监控器（12 个）**：
exec（事件）、open、bio、syscall、func、interrupt、page_fault、context_switch、udp、shm、process_trade、nic（低延时网卡，聚合统计，关注队列深度/缓冲区/延迟）。

**核心特性（已实现）**：
- 依赖注入（ApplicationContext + MonitorContext）替代单例，提升可测试性。
- 监控器自动注册（@register_monitor）。
- 声明式配置（CONFIG_SCHEMA）、输出（CSV_COLUMNS / CONSOLE_FORMAT / PROMETHEUS_CONFIG）。
- 统计聚合模式为主（内核 map 累积 + 定期 pop 输出），部分为事件模式。
- Python 侧使用 MonitorDataUtils 统一延迟/吞吐/大小计算。
- 测试框架：pytest + MagicMock bcc + DI fixtures（支持 macOS/CI）。

**硬约束**：
- 仅使用 BCC + kprobe/tracepoint，兼容 3.10+ 内核。
- 不迁移 CO-RE / libbpf。
- 文档只记录当前事实或有明确验收标准的短期目标（见 ROADMAP.md）。

## 主要组件

- **main.py / ebpf_monitor.py**：入口与主控制器，加载配置、创建 ApplicationContext、启动启用的监控器。
- **ApplicationContext**：依赖注入容器，管理 ConfigManager、LogManager、OutputController、MonitorRegistry 等。
- **BaseMonitor**：所有监控器的基类。负责 eBPF 加载（get_ebpf_code）、_collect_and_output（原子 pop）、格式化派发、should_collect 过滤。子类仅需声明 CONFIG_SCHEMA、CSV/CONSOLE/PROMETHEUS 及可选 should_collect/_initialize。
- **注册与发现**：decorators.register_monitor + monitor_registry 动态导入。
- **输出**：output_controller 统一处理 CSV/Console/Prometheus；prometheus_writer/metrics 支持 declarative 配置。
- **eBPF C 程序**：每个监控器对应 src/ebpf/<name>.c，使用 BCC 编译加载。通用探针优先，driver-specific 用 TODO 占位。
- **分析**：analysis/analyzer.py + data_utils.py（支持 nic 的 queue_depth_analysis、latency_histogram、spike 报告集成等）。

## 数据流

配置 → ApplicationContext → 各 Monitor（load_ebpf → run → 定时/事件 _collect_and_output → output_controller）→ CSV/Console/Prometheus。

内核 eBPF map（统计聚合）→ 用户态 pop → 过滤 → 格式化输出。

详见 ROADMAP.md “当前真实状态”与各监控器实现（src/monitors/*.py + src/ebpf/*.c）。

## 扩展新监控器

1. 在 src/ebpf/ 新增 <name>.c（统计模式推荐使用 BPF_HASH + update_nic_stats 风格的原子累积）。
2. 在 src/monitors/ 新增 <name>.py，继承 BaseMonitor，实现：
   - @register_monitor("name")
   - CONFIG_SCHEMA（声明式）
   - CSV_COLUMNS / CONSOLE_FORMAT / PROMETHEUS_CONFIG（优先使用声明式）
   - 可选：should_collect、_initialize、mode 重写。
3. 在 config/monitor_config.yaml 添加对应节。
4. 添加对应 unit 测试（tests/unit/test_<name>_monitor.py，使用 mock_monitor_context）。
5. 更新 ROADMAP.md “当前真实状态”与验收标准。
6. 如涉及新分析能力，扩展 analysis/analyzer.py + data_utils.py。

任何架构/策略变更必须先更新 ROADMAP 或新增 ADR。

参考实现：src/monitors/udp.py、src/monitors/nic.py、src/monitors/base.py。
