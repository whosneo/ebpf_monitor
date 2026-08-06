# eBPF 监控系统 - 当前状态与下一阶段工作

**最后更新**：2026-08-06（实现 design: 长期稳定 + 多进程目标 + ufunc）

本文档是项目下一阶段工作的**唯一真相来源**。只记录当前真实事实和有明确验收标准的短期目标，不包含任何未来愿景或长期规划。

## 当前真实状态

本项目是**eBPF 监控系统**，基于 eBPF + BCC 实现低开销系统监控。

**当前支持的监控器（共 13 个）**：
- **exec**：进程执行监控（事件模式）。
- **open / bio / syscall / interrupt / page_fault / context_switch**：系统级聚合统计。
- **func**：内核函数 kprobe（`/proc/kallsyms`），**不是**用户态 uprobe。
- **udp / shm / nic / process_trade**：可按进程名过滤（ProcessTargetManager）；udp/nic 的 `target_ports` / `target_interfaces` **未实现内核过滤**（非空配置打 WARNING）。
- **process_trade**：map 为 `process_trade_stats` + `process_trade_ipc_stats`；支持 `monitor_syscalls` / `monitor_ipc` 门控；**pre-fix 版本曾因 map 名不一致导致空 CSV**。
- **ufunc**（新建）：BCC uprobe/uretprobe 用户态函数统计；默认 `enabled: false`；符号/路径由运维提供；uprobe 不可用时软失败。
- **nic**：默认 `enabled: false`，driver-specific 占位。

**运行时稳定性（已实现）**：
- `restart_monitor`：Factory 新建实例（不复用 cleanup 后对象）。
- Watchdog：死线程 / stale success / error delta + 重启退避。
- `get_health()` + 日志；**无**内置 Prometheus HTTP exporter（文档不再宣称端口 9200 已实现）。
- CSV retention（可配置）；输出缓冲 drop 计数。
- `config/monitor_config.trading_server.yaml` 减负 profile（不改主 yaml 重监控默认）。

**输出**：控制台 / CSV / 声明式 PROMETHEUS_CONFIG 提取辅助（无 HTTP 服务）。

**硬约束**：
- 必须使用 root 或 CAP_BPF。
- 兼容 Linux 内核 3.10+（系统级 kprobe/tracepoint 路线）。
- **不迁移 CO-RE / libbpf**；ufunc 的 uprobe 为 BCC attach，不宣称全局 3.10 uprobe 可用。

## 硬约束

- 不迁移到 CO-RE。
- 文档中永远不写未来愿景、长期规划或宏大目标。
- 所有目标必须可验证（有明确的验收标准）。
- 新能力必须在现有 BCC + 统计/事件模式框架下务实实现。

## 下一阶段工作（短期可验证）

### A. 真机验证 ufunc / pid_allow
**目标**：在目标交易机上用运维提供的 binary+symbols 验证 ufunc 与 pid_allow。
**验收标准**：
- `ufunc` load/attach 成功或明确 soft-fail 原因记入日志。
- process_trade/udp 在非空 targets 下 cflags 含 `-DENABLE_PID_FILTER=1` 且开销可接受。

### B. nic 真机与 driver 符号
**目标**：SWIFT-2200N 上验证 nic 占位探针。
**验收标准**：验证报告更新 `analysis/nic_spike_verification.md` 量化数据。

### C. analyzer 扩展
**目标**：analyzer 接入 process_trade / udp / ufunc 基础统计。
**验收标准**：`analysis/analyzer.py` monitor_types 列表含上述类型且有至少一种分析路径。

## 已知限制与说明

- udp `target_ports`、nic `target_interfaces`：C key 无对应字段，配置非空仅 WARNING。
- 主配置 `process_trade` 空 zmb+zme = 全进程（开发语义）；交易机请用 trading_server profile 非空列表。
- 任何偏离本 ROADMAP 的工作，必须先更新本文档或新增 ADR。

**维护规则**：本文件是活文档。每次完成一项工作后，必须更新“当前真实状态”和相应目标的完成情况。
