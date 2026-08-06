# 0002: 按进程名目标、ufunc（BCC uprobe）与运行时稳定性

**状态**：接受

**日期**：2026-08-06

**决策者**：设计文档 Accepted r4 + 实现落地

## 背景

交易服务器需要：（1）按进程名过滤多监控器；（2）用户态函数调用统计；（3）长期常驻的故障隔离与磁盘保留。硬约束仍为 ADR 0001：BCC only，不迁 CO-RE。

## 决策

1. **新建 `ufunc` 监控器**，不把内核 `func` 改为 uprobe。
2. **BCC `attach_uprobe` / `attach_uretprobe` 允许**，作为 BCC 原生 attach；禁止为此引入 libbpf/CO-RE。
3. **ProcessTargetManager** 统一进程名匹配；空列表 = 全部允许。
4. **BPF `pid_allow`** 写新后删旧；`get_extra_cflags()` 返回 `-DENABLE_PID_FILTER=1`，禁止改共享 compile_flags。
5. **`restart_monitor` 永远 Factory 新建**；watchdog 双条件 + 退避；Phase 4 不实现 Prometheus HTTP exporter。
6. **process_trade** map 名为 `process_trade_stats` / `process_trade_ipc_stats`；CSV 行经 `_normalize_stat_row` 写平。
7. **符号列表由运维提供**（D26）；实现与测试仅用占位路径/符号。
8. **ufunc 不宣称全局 3.10 uprobe**；不可用时软失败。

## 结果

- `src/utils/process_target_manager.py`、`src/monitors/ufunc.py`、`src/ebpf/ufunc.c`
- BaseMonitor 多表 / health / extra cflags
- `config/monitor_config.trading_server.yaml`
- 设计文档：`docs/design/trading-server-stability-and-process-targeting.md`

## 参考

- ADR 0001
- `docs/design/trading-server-stability-and-process-targeting.md`
