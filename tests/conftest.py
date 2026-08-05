#!/usr/bin/env python
# encoding: utf-8
"""
Pytest fixtures for eBPF monitor tests.

Provides:
- Mocked bcc.BPF
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
    # Allow basic import/smoke when pytest not installed
    class _DummyPytest:
        def fixture(self, *a, **k):
            def deco(f): return f
            return deco
    pytest = _DummyPytest()

# Mock bcc before any real imports that pull it
class MockBPF:
    def __init__(self, *args, **kwargs):
        self._tables = {}
        self._kprobes = []
        self._tracepoints = []

    def get_table(self, name):
        if name not in self._tables:
            # return a mock table supporting pop/keys
            tbl = MagicMock()
            tbl.keys.return_value = []
            tbl.pop.side_effect = KeyError
            self._tables[name] = tbl
        return self._tables[name]

    def cleanup(self):
        pass

    # Simulate attach
    def attach_kprobe(self, *a, **k): self._kprobes.append((a, k))
    def attach_tracepoint(self, *a, **k): self._tracepoints.append((a, k))


# Inject mock bcc into sys.modules before src imports
mock_bcc = types.ModuleType("bcc")
mock_bcc.BPF = MockBPF
sys.modules["bcc"] = mock_bcc

# Also support bpfcc alias if used
mock_bpfcc = types.ModuleType("bpfcc")
mock_bpfcc.BPF = MockBPF
sys.modules["bpfcc"] = mock_bpfcc


@pytest.fixture
def mock_bpf():
    """Provide a fresh MockBPF instance."""
    return MockBPF()


@pytest.fixture
def monitor_context(mock_bpf):
    """Minimal MonitorContext substitute for unit tests."""
    from src.utils.monitor_context import MonitorContext

    # Patch the real load
    ctx = MagicMock(spec=MonitorContext)
    ctx.logger = MagicMock()
    ctx.output_controller = MagicMock()
    ctx.ebpf_file_path = "src/ebpf/dummy.c"  # will be overridden in load tests
    ctx.compile_flags = []
    # Inject a fake bpf for some tests
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
