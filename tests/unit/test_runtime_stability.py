#!/usr/bin/env python
# encoding: utf-8
"""Unit tests for restart/watchdog/retention/drop counters."""

import os
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.utils.csv_writer import select_files_for_retention, CsvWriter
from src.ebpf_monitor import eBPFMonitor, MonitorStatus
from src.monitors.base import BaseMonitor
from src.utils.decorators import register_monitor


@register_monitor("stab_dummy")
class StabDummy(BaseMonitor):
    CONFIG_SCHEMA = {}
    CSV_COLUMNS = [("x", "x")]


def test_select_files_retention_max_files(tmp_path):
    now = time.time()
    files = [
        (str(tmp_path / "m_20200101_000001.csv"), now - 100, 100),
        (str(tmp_path / "m_20200101_000002.csv"), now - 50, 100),
        (str(tmp_path / "m_20200101_000003.csv"), now - 10, 100),
    ]
    # keep only 2 newest
    deleted = select_files_for_retention(files, max_age_days=30, max_total_bytes=10**9, max_files=2)
    assert len(deleted) == 1
    assert deleted[0].endswith("000001.csv")


def test_select_files_retention_age():
    now = time.time()
    files = [
        ("old.csv", now - 10 * 86400, 10),
        ("new.csv", now - 1, 10),
    ]
    deleted = select_files_for_retention(files, max_age_days=7, max_total_bytes=10**9, max_files=100)
    assert "old.csv" in deleted
    assert "new.csv" not in deleted


def test_csv_writer_apply_retention_deletes(tmp_path):
    logger = MagicMock()
    # create files
    for i in range(5):
        p = tmp_path / "nic_2020010{}_120000.csv".format(i)
        p.write_text("a")
        os.utime(p, (time.time() - i * 100, time.time() - i * 100))
    w = CsvWriter(
        tmp_path,
        ",",
        True,
        logger,
        retention={
            "enabled": True,
            "max_age_days": 365,
            "max_total_bytes_mb": 4096,
            "max_files_per_monitor": 2,
        },
    )
    deleted = w.apply_retention(force=True)
    assert len(deleted) >= 3
    remaining = list(tmp_path.glob("*.csv"))
    assert len(remaining) <= 2


def test_output_drop_count():
    from src.utils.output_controller import OutputController
    from collections import deque

    oc = MagicMock(spec=OutputController)
    # drive real handle_data logic by constructing minimal object
    real = object.__new__(OutputController)
    real.running = True
    real.monitors = {"m": MagicMock()}
    real.buffer_size = 2
    real.buffer_lock = __import__("threading").Lock()
    real.data_buffer = {"m": deque(maxlen=2)}
    real.output_drop_count = __import__("collections").defaultdict(int)
    real.logger = MagicMock()
    # call real method
    OutputController.handle_data(real, "m", {"a": 1})
    OutputController.handle_data(real, "m", {"a": 2})
    OutputController.handle_data(real, "m", {"a": 3})  # should drop
    assert real.output_drop_count["m"] >= 1


def test_restart_monitor_factory_only():
    """restart_monitor must create via factory, never reuse cleaned instance."""
    context = MagicMock()
    logger = MagicMock()
    context.get_logger.return_value = logger
    context.output_controller = MagicMock()

    app_cfg = MagicMock()
    app_cfg.watchdog_enabled = False
    app_cfg.watchdog_interval = 10
    app_cfg.watchdog_stale_intervals = 5
    app_cfg.watchdog_error_delta = 50
    app_cfg.watchdog_max_restarts_per_window = 3
    app_cfg.watchdog_restart_window_s = 60
    context.config_manager.get_app_config.return_value = app_cfg
    context.config_manager.get_monitors_config.return_value = MagicMock(stab_dummy={
        "enabled": True, "interval": 1.0
    })

    registry = MagicMock()
    registry.get_registered_monitors.return_value = {"stab_dummy": StabDummy}
    registry.get_monitor_names.return_value = ["stab_dummy"]
    context.get_monitor_registry.return_value = registry

    old = MagicMock()
    old.is_running.return_value = True
    old.enabled = True
    created = []

    new = MagicMock()
    new.enabled = True
    new.load_ebpf_program.return_value = True
    new.run.return_value = True
    new.collect_error_count = 0

    factory = MagicMock()

    def create_monitor(cls, name, cfg):
        created.append((cls, name))
        return new

    factory.create_monitor.side_effect = create_monitor
    context.get_monitor_factory.return_value = factory

    mon = eBPFMonitor.__new__(eBPFMonitor)
    mon.context = context
    mon.logger = logger
    mon.monitor_registry = registry
    mon.output_controller = context.output_controller
    mon.monitors_config = context.config_manager.get_monitors_config()
    mon.all_monitors = {"stab_dummy": StabDummy}
    mon.selected_monitors = ["stab_dummy"]
    mon.monitors = {"stab_dummy": old}
    mon.monitor_status = {"stab_dummy": MonitorStatus("stab_dummy", loaded=True, running=True)}
    mon.running = True
    mon.state_lock = __import__("threading").RLock()
    mon.stats = {"start_time": time.time()}
    mon.watchdog_enabled = False
    mon.watchdog_interval = 10
    mon.watchdog_stale_intervals = 5
    mon.watchdog_error_delta = 50
    mon.watchdog_max_restarts_per_window = 3
    mon.watchdog_restart_window_s = 60
    mon._watchdog_thread = None
    mon._watchdog_stop = __import__("threading").Event()

    ok = mon.restart_monitor("stab_dummy", reason="test")
    assert ok is True
    old.stop.assert_called()
    old.cleanup.assert_called()
    factory.create_monitor.assert_called()
    assert mon.monitors["stab_dummy"] is new
    assert mon.monitors["stab_dummy"] is not old
    assert mon.monitor_status["stab_dummy"].restart_count == 1


def test_restart_backoff_degraded():
    context = MagicMock()
    logger = MagicMock()
    context.get_logger.return_value = logger
    mon = eBPFMonitor.__new__(eBPFMonitor)
    mon.logger = logger
    mon.context = context
    mon.all_monitors = {"stab_dummy": StabDummy}
    mon.monitors = {}
    mon.monitor_status = {
        "stab_dummy": MonitorStatus("stab_dummy")
    }
    mon.monitor_status["stab_dummy"].restart_timestamps = [time.time()] * 3
    mon.watchdog_max_restarts_per_window = 3
    mon.watchdog_restart_window_s = 60
    mon.state_lock = __import__("threading").RLock()
    mon.monitors_config = MagicMock()
    ok = mon.restart_monitor("stab_dummy", reason="storm")
    assert ok is False
    assert mon.monitor_status["stab_dummy"].degraded is True


def test_watchdog_triggers_on_dead_thread():
    mon = eBPFMonitor.__new__(eBPFMonitor)
    mon.logger = MagicMock()
    mon.watchdog_stale_intervals = 5
    mon.watchdog_error_delta = 50
    mon.stats = {"start_time": time.time()}
    mon.state_lock = __import__("threading").RLock()

    fake = MagicMock()
    fake.is_thread_alive.return_value = False
    fake.interval = 2
    fake.last_success_ts = time.time()
    fake.collect_error_count = 0

    mon.monitors = {"stab_dummy": fake}
    mon.monitor_status = {
        "stab_dummy": MonitorStatus("stab_dummy", running=True)
    }
    mon.monitor_status["stab_dummy"].last_error_count_snapshot = 0

    called = []

    def fake_restart(name, reason=""):
        called.append((name, reason))
        return True

    mon.restart_monitor = fake_restart
    mon._watchdog_tick()
    assert called and called[0][1] == "dead_thread"


def test_get_health_structure():
    mon = eBPFMonitor.__new__(eBPFMonitor)
    mon.running = True
    mon.watchdog_enabled = True
    mon.stats = {"start_time": 1.0}
    mon.state_lock = __import__("threading").RLock()
    fake = MagicMock()
    fake.get_health.return_value = {"type": "x", "running": True}
    mon.monitors = {"x": fake}
    st = MonitorStatus("x")
    st.restart_count = 2
    mon.monitor_status = {"x": st}
    h = mon.get_health()
    assert h["running"] is True
    assert "x" in h["monitors"]
    assert h["monitors"]["x"]["restart_count"] == 2


def test_health_log_rate_limited_60s():
    """Design §9.2: logger.info health_snapshot at most every 60s."""
    mon = eBPFMonitor.__new__(eBPFMonitor)
    mon.logger = MagicMock()
    mon._last_health_log_ts = 0.0
    mon._health_log_interval_s = 60.0
    mon.running = True
    mon.watchdog_enabled = True
    mon.stats = {"start_time": 1.0}
    mon.state_lock = __import__("threading").RLock()
    mon.monitors = {}
    mon.monitor_status = {}
    mon._maybe_log_health()
    mon._maybe_log_health()  # same window — should not log twice
    info_calls = [c for c in mon.logger.info.call_args_list if c[0] and "health_snapshot" in str(c[0][0])]
    assert len(info_calls) == 1
    # force next window
    mon._last_health_log_ts = time.time() - 61
    mon._maybe_log_health()
    info_calls = [c for c in mon.logger.info.call_args_list if c[0] and "health_snapshot" in str(c[0][0])]
    assert len(info_calls) == 2
