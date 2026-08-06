#!/usr/bin/env python
# encoding: utf-8
"""
Pytest fixtures for eBPF monitor tests.

Provides:
- Mocked bcc.BPF with kprobe/tracepoint/uprobe attach
- MonitorContext mock
- ApplicationContext mock
- Sample configs
- Helper to instantiate monitors without real eBPF
"""

import sys
import types
from unittest.mock import MagicMock

try:
    import pytest
except ImportError:
    # pytest 未安装时允许基本 import/冒烟
    class _DummyPytest:
        def fixture(self, *a, **k):
            def deco(f): return f
            return deco
    pytest = _DummyPytest()


class MockTable(object):
    """Simple dict-backed BPF table mock supporting keys/pop/update/delete."""

    def __init__(self):
        self._data = {}

    def keys(self):
        return list(self._data.keys())

    def pop(self, key):
        if key not in self._data:
            raise KeyError(key)
        return self._data.pop(key)

    def update(self, key, val):
        self._data[key] = val

    def __setitem__(self, key, val):
        self._data[key] = val

    def __getitem__(self, key):
        return self._data[key]

    def __delitem__(self, key):
        del self._data[key]

    def __contains__(self, key):
        return key in self._data

    def delete(self, key):
        if key in self._data:
            del self._data[key]

    def clear(self):
        self._data.clear()

    def items(self):
        return list(self._data.items())


# 在会拉取真实 bcc 的 import 之前注入 Mock
class MockBPF:
    last_cflags = None  # type: ignore
    last_text = None  # type: ignore
    instances = []  # type: ignore

    def __init__(self, *args, **kwargs):
        self._tables = {}
        self._kprobes = []
        self._tracepoints = []
        self._uprobes = []
        self._uretprobes = []
        self.cflags = kwargs.get("cflags", [])
        self.text = kwargs.get("text", args[0] if args else None)
        if "text" in kwargs:
            self.text = kwargs["text"]
        MockBPF.last_cflags = list(self.cflags) if self.cflags is not None else []
        MockBPF.last_text = self.text
        MockBPF.instances.append(self)

    def get_table(self, name):
        if name not in self._tables:
            self._tables[name] = MockTable()
        return self._tables[name]

    def cleanup(self):
        pass

    def attach_kprobe(self, *a, **k):
        self._kprobes.append((a, k))

    def attach_tracepoint(self, *a, **k):
        self._tracepoints.append((a, k))

    def attach_uprobe(self, *a, **k):
        self._uprobes.append((a, k))

    def attach_uretprobe(self, *a, **k):
        self._uretprobes.append((a, k))


# 在 src 导入前把 mock bcc 注入 sys.modules。
# 防止双重加载（pytest 以 "conftest" 加载；测试也可能
# "import tests.conftest"），保证 BaseMonitor 的 `from bcc import BPF`
# 与测试断言使用同一 MockBPF 类。
def _install_bcc_mock():
    existing = sys.modules.get("bcc")
    if existing is not None and getattr(existing, "BPF", None) is not None:
        # 复用已安装的 mock 类
        return getattr(existing, "BPF")
    mock_bcc = types.ModuleType("bcc")
    mock_bcc.BPF = MockBPF
    sys.modules["bcc"] = mock_bcc
    mock_bpfcc = types.ModuleType("bpfcc")
    mock_bpfcc.BPF = MockBPF
    sys.modules["bpfcc"] = mock_bpfcc
    return MockBPF


_ActiveMockBPF = _install_bcc_mock()
# 双重加载后，测试若再 import MockBPF，与已安装类对齐
if _ActiveMockBPF is not MockBPF:
    # 优先使用首次安装的类（共享 last_cflags / instances）
    MockBPF = _ActiveMockBPF  # noqa: F811


@pytest.fixture
def mock_bpf():
    """Provide a fresh MockBPF instance."""
    MockBPF.instances = []
    MockBPF.last_cflags = None
    MockBPF.last_text = None
    return MockBPF()


@pytest.fixture
def monitor_context(mock_bpf):
    """Minimal MonitorContext substitute for unit tests."""
    from src.utils.monitor_context import MonitorContext

    # 构造最小 MonitorContext 替身
    ctx = MagicMock(spec=MonitorContext)
    ctx.logger = MagicMock()
    ctx.output_controller = MagicMock()
    ctx.ebpf_file_path = "src/ebpf/dummy.c"  # load 测试中可覆盖
    ctx.compile_flags = []
    # 部分测试注入假 bpf
    ctx.bpf = mock_bpf
    return ctx


@pytest.fixture
def sample_config():
    """Default sample config for a generic monitor."""
    return {
        "enabled": True,
        "interval": 2.0,
    }


@pytest.fixture
def full_app_context():
    """Mocked ApplicationContext for higher level tests."""
    from src.utils.application_context import ApplicationContext
    app = MagicMock(spec=ApplicationContext)
    app.get_logger.return_value = MagicMock()
    app.config_manager = MagicMock()
    app.output_controller = MagicMock()
    app.log_manager = MagicMock()
    app.log_manager.get_logger.return_value = MagicMock()
    return app


@pytest.fixture(autouse=True)
def reset_registry():
    """Ensure monitor registry is clean between tests.

    Snapshot the registry *before* the test runs (so decorator-based
    registrations done at module import time - e.g. NicMonitor - remain
    available to the test), then after the test undo anything the test
    itself registered by restoring the snapshot.
    """
    from src.utils.decorators import MONITOR_REGISTRY
    saved = MONITOR_REGISTRY.copy()
    yield
    MONITOR_REGISTRY.clear()
    MONITOR_REGISTRY.update(saved)


def make_monitor_instance(monitor_cls, context, config):
    """Helper to construct monitor bypassing some init checks."""
    # Most monitors read from CONFIG_SCHEMA in __init__ via base
    mon = monitor_cls(context, config)
    return mon
