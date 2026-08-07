# eBPF 监控系统

面向交易与系统侧可观测的 eBPF 监控上下文：按监控器采集、按进程目标过滤、以统计或事件方式输出。

## Language

**监控器 (Monitor)**：
一类可独立启停的 eBPF 采集单元（通常对应一对 Python 监控类与可选 C 程序）。
_Avoid_：探针包、采集器、插件、监控项

**统计模式 (STATISTICAL)**：
内核 map 累积指标，用户态按 interval 弹出并输出的采集方式。
_Avoid_：批量模式、轮询监控（泛称）

**事件模式 (EVENT)**：
经 perf buffer 等路径实时上报单条事件的采集方式。
_Avoid_：实时模式、流式监控（泛称）

**ProcessTarget**：
按进程名解析出的目标进程集合；**空集合表示全部允许**。
_Avoid_：进程白名单（易暗示「空=全拒绝」）、PID 列表（未强调按名）

**pid_allow**：
内核侧按 PID 放行的 BPF map 过滤约定（与 ProcessTarget 同步）。
_Avoid_：PID 黑名单、进程黑名单

**kfunc**：
内核函数 kprobe 类监控器；领域名与代码/配置/注册标识均为 `kfunc`（`kfunc.py` / yaml `kfunc` / map `kfunc_stats`）。
_Avoid_：func（旧注册名，已弃用）、用户态函数监控、与 ufunc 混称

**ufunc**：
用户态函数 uprobe/uretprobe 类监控器；与 kfunc 分立。
_Avoid_：func、kfunc 的旧称混用、用户态 kprobe、与 kfunc 混称

**process_trade**：
面向交易相关进程的 syscall/IPC 等专用监控器。
_Avoid_：通用进程监控、trade monitor（无定名时）

**输出通路**：
控制台、CSV，以及声明式 `PROMETHEUS_CONFIG` 指标提取辅助；**不**表示内置 Prometheus HTTP 导出服务。
_Avoid_：Prometheus 已集成、9200 端口导出器、完整 metrics endpoint
