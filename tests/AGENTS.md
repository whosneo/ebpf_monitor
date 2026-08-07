# tests — Agent 指南

写或改测试时读本文件。全局约束见根目录 `AGENTS.md`。

## 原则

- **Unit 优先**：pytest + mock BCC，不依赖真机 eBPF / root 才能绿。
- 根目录 **Full** 验证（`sudo python main.py`）是额外层，**不能替代**本目录单测。
- DI：通过 `MonitorContext` / fixtures 注入，避免在测试里复活全局单例。

## 基础设施

- 共享夹具与 mock：`conftest.py`（`MockBPF`、`MockTable`、attach kprobe/tracepoint/uprobe 等）。
- 实例化监控器时使用项目约定的 mock context（如 `mock_monitor_context`），先看现有 `tests/unit/test_*_monitor.py`。
- 在 import 会拉 bcc 的模块之前，确保 mock 注入路径与 `conftest` 一致。

## 新监控器最低要求

1. `tests/unit/test_<name>_monitor.py`
2. 覆盖：配置校验 / 声明式列或格式、关键 `should_collect` 或过滤语义、map 名或 cflags（若涉及 pid 过滤）。
3. 不要求真实 `BPF()` 加载成功；断言 Python 契约与 mock 交互即可。

## 稳定性与运行时

- `restart_monitor`、watchdog、health、retention 等：测**控制路径与状态行为**，不测真实 probe 附着。
- Factory 新建实例、cleanup 后不可复用等约定应有回归覆盖（参考 `test_runtime_stability.py` 等现有用例）。

## 运行

```bash
source .venv/bin/activate
python -m pytest tests/ -q
# 或单文件
python -m pytest tests/unit/test_<name>_monitor.py -q
```

## 不要做

- 新增「必须 root + 真机网卡才收集」的默认 CI 测试。
- 为了测而复制整份生产 yaml 进断言而不说明空 ProcessTarget = 全允许的语义。
- 混用旧注册名 `func` 与当前名 `kfunc`（代码/配置/测试须一致为 `kfunc`）。
