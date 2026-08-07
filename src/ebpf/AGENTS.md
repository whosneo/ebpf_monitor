# src/ebpf — Agent 指南

改 BCC C 程序或新增 `*.c` 时读本文件。全局约束见根目录 `AGENTS.md`。

## 硬约束

- **仅 BCC 可加载的 C**：kprobe / tracepoint；用户态路径仅配合 Python 侧 BCC `attach_uprobe` / `attach_uretprobe`（见 `ufunc.c`）。
- **禁止** CO-RE、libbpf、BPF skeleton、依赖 BTF 的重写。
- 与 `src/monitors/<name>.py` **成对变更**；只改 C 或只改 Python 易导致空 CSV / attach 失败。

## Map 与命名

- 统计 map 名必须与 Python 侧读取名一致（`stats_name` / 多表名）。
- **教训**：`process_trade` 曾因 C/Python map 名不一致导致空 CSV；改名时两侧与测试一起改。
- 需要 PID 过滤时使用 map 名 **`pid_allow`**（`BPF_HASH(pid_allow, …)`），与 `ProcessTargetManager.sync_pid_allow_map(..., "pid_allow")` 对齐。
- 内核 kprobe 监控器文件为 **`kfunc.c`**，map 为 **`kfunc_stats`**（与 `@register_monitor("kfunc")` / `stats_name` 一致）。

## pid_allow 与编译开关

- 过滤逻辑用 `#ifdef ENABLE_PID_FILTER`（或项目既有宏）包起来。
- **启用方式**：监控器 `get_extra_cflags()` → `-DENABLE_PID_FILTER=1`。
- **禁止**修改全仓库共享的默认 compile_flags 来「顺手」打开过滤。
- 用户态同步策略：**先写入新 PID，再删除过期键**（写新后删旧），避免刷新窗口内全丢事件。

## 探针策略

- **优先**通用 tracepoint / 稳定 kprobe 符号。
- **driver-specific**（如 nic / SWIFT-2200N）用占位 + TODO，待真机符号验证后再填；默认勿假设硬件已验证。
- 保持低开销：统计聚合优于不必要的 per-event 海量输出。

## 不要做

- 引入需新内核特性且无法在 3.10+ 路线降级的写法，却不在 ROADMAP/日志中说明限制。
- 静默改变 map 值布局而不更新 Python 解析与单测。
