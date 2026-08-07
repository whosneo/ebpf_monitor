# src/monitors — Agent 指南

改 Python 监控器或新增监控类型时读本文件。全局约束见根目录 `AGENTS.md`；用词见 `CONTEXT.md`。

## 扩展新监控器

1. 在 `src/ebpf/` 增加 `<name>.c`（若需内核程序；约定见 `src/ebpf/AGENTS.md`）。
2. 本目录新增 `<name>.py`：
   - `@register_monitor("name")`
   - 继承 `BaseMonitor`
   - `CONFIG_SCHEMA`（声明式）
   - `CSV_COLUMNS` / `CONSOLE_FORMAT` / `PROMETHEUS_CONFIG`（优先声明式）
   - 可选：`should_collect`、`_initialize`、`mode`、`get_extra_cflags`
3. 在 `config/monitor_config.yaml`（及若适用 `monitor_config.trading_server.yaml`）增加对应节。
4. 单测：`tests/unit/test_<name>_monitor.py`（见 `tests/AGENTS.md`）。
5. **Strict**：更新 `docs/ROADMAP.md`「当前真实状态」；架构叙事变了则改 `docs/ARCHITECTURE.md`。

参考实现：`base.py`、`udp.py`、`nic.py`、`ufunc.py`、`kfunc.py`。

## kfunc 与 ufunc

| 领域名 | 含义 | 代码/配置/注册名 |
|--------|------|------------------|
| **kfunc** | 内核函数 **kprobe** | **`kfunc`**（`kfunc.py` / yaml `kfunc` / `@register_monitor("kfunc")` / map `kfunc_stats`） |
| **ufunc** | 用户态 **uprobe** | `ufunc` |

- 对话、文档与代码标识统一使用 **kfunc**（旧称 `func` 已弃用）。
- **禁止**把 kfunc 与 ufunc 合并为同一监控器；ufunc 默认 `enabled: false`，符号/路径由运维提供，不可用时软失败（ADR 0002）。

## ProcessTarget 与 pid_allow

- 进程名目标经 `ProcessTargetManager` 统一；**空列表 = 全部允许**（开发默认语义）。交易机减负用 `config/monitor_config.trading_server.yaml` 非空列表。
- 需要内核过滤时：`get_extra_cflags()` 返回 `-DENABLE_PID_FILTER=1`，**禁止**改共享全局 compile_flags。
- 运行时用 `sync_pid_allow_map`：**写新后删旧**。详见 ADR 0002 与 design 文档。
- 配置项若 schema 有、内核 key 无（如部分 `target_ports` / `target_interfaces`），保持诚实：WARNING 或文档标明未实现，勿假装已过滤。

## 实现约定

- 依赖注入：经 `MonitorContext` / `ApplicationContext`，避免新单例。
- 统计模式：内核 map 累积 + `_collect_and_output` 原子 pop；多表时 map 名必须与 C 一致。
- `restart_monitor` 由 Factory **新建**实例，勿假设 cleanup 后对象可复用。
- `PROMETHEUS_CONFIG` 仅为声明式提取辅助；**无**内置 HTTP exporter。

## 不要做

- 引入 libbpf / CO-RE / 非 BCC attach 路径。
- 在未更新 ROADMAP 的情况下宣称「新增第 N 个监控器」或改变项目身份。
- 用「白名单」描述空 ProcessTarget（空 = 全允许）。
