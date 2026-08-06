#!/usr/bin/env python
# encoding: utf-8
"""Unit tests for process_trade map names, normalize, and gates."""

from unittest.mock import MagicMock, patch

import pytest

from src.monitors.process_trade import (
    ProcessTradeMonitor,
    ipc_type_to_category,
    category_to_str,
)


@pytest.fixture
def pt_config():
    return {
        "enabled": True,
        "interval": 2.0,
        "zmb_processes": ["zmb"],
        "zme_processes": ["zme"],
        "monitor_syscalls": True,
        "monitor_ipc": True,
    }


def test_instance_stats_tables_both(monitor_context, pt_config):
    m = ProcessTradeMonitor(monitor_context, pt_config)
    assert m.STATS_TABLES == [
        ("process_trade_stats", "syscall"),
        ("process_trade_ipc_stats", "ipc"),
    ]


def test_instance_stats_tables_ipc_only(monitor_context, pt_config):
    pt_config["monitor_syscalls"] = False
    m = ProcessTradeMonitor(monitor_context, pt_config)
    assert m.STATS_TABLES == [("process_trade_ipc_stats", "ipc")]


def test_instance_stats_tables_syscall_only(monitor_context, pt_config):
    pt_config["monitor_ipc"] = False
    m = ProcessTradeMonitor(monitor_context, pt_config)
    assert m.STATS_TABLES == [("process_trade_stats", "syscall")]


def test_both_false_raises(monitor_context, pt_config):
    pt_config["monitor_syscalls"] = False
    pt_config["monitor_ipc"] = False
    with pytest.raises(ValueError):
        ProcessTradeMonitor.validate_config(pt_config)


def test_normalize_syscall_row(monitor_context, pt_config):
    m = ProcessTradeMonitor(monitor_context, pt_config)
    row = m._normalize_stat_row(
        {
            "comm": b"zmb\x00",
            "syscall_category": 2,
            "count": 10,
            "error_count": 2,
            "total_ns": 100000,  # 10us avg
            "min_ns": 1000,
            "max_ns": 50000,
        },
        "syscall",
    )
    assert row["record_type"] == "syscall"
    assert row["comm"] == "zmb"
    assert row["category"] == "NETWORK"
    assert row["error_count"] == 2
    assert row["error_rate"] == 20.0
    assert row["avg_latency_us"] == pytest.approx(10.0)
    assert row["min_latency_us"] == pytest.approx(1.0)
    assert row["max_latency_us"] == pytest.approx(50.0)


def test_normalize_ipc_row_zeros(monitor_context, pt_config):
    m = ProcessTradeMonitor(monitor_context, pt_config)
    row = m._normalize_stat_row(
        {
            "comm": b"zme",
            "ipc_type": 2,
            "count": 4,
            "total_ns": 40000,
        },
        "ipc",
    )
    assert row["record_type"] == "ipc"
    assert row["category"] == "IPC_SHM"
    assert row["error_count"] == 0
    assert row["min_latency_us"] == 0
    assert row["max_latency_us"] == 0
    assert row["avg_latency_us"] == pytest.approx(10.0)


def test_ipc_type_mapping():
    assert ipc_type_to_category(1) == "IPC_PIPE"
    assert ipc_type_to_category(3) == "IPC_FUTEX"
    assert ipc_type_to_category(99) == "IPC_UNKNOWN"


def test_should_collect_filters_process(monitor_context, pt_config):
    m = ProcessTradeMonitor(monitor_context, pt_config)
    key_ok = MagicMock()
    key_ok.comm = b"zmb"
    key_bad = MagicMock()
    key_bad.comm = b"other"
    assert m.should_collect(key_ok, MagicMock()) is True
    assert m.should_collect(key_bad, MagicMock()) is False


def test_empty_targets_allow_all(monitor_context, pt_config):
    pt_config["zmb_processes"] = []
    pt_config["zme_processes"] = []
    m = ProcessTradeMonitor(monitor_context, pt_config)
    key = MagicMock()
    key.comm = b"anything"
    assert m.should_collect(key, MagicMock()) is True


def test_collect_uses_real_map_names(monitor_context, pt_config):
    """_collect_and_output must pop process_trade_stats and process_trade_ipc_stats."""
    m = ProcessTradeMonitor(monitor_context, pt_config)
    bpf = MagicMock()
    t_sys = MagicMock()
    t_ipc = MagicMock()
    t_sys.keys.return_value = []
    t_ipc.keys.return_value = []

    def get_table(name):
        if name == "process_trade_stats":
            return t_sys
        if name == "process_trade_ipc_stats":
            return t_ipc
        raise KeyError(name)

    bpf.get_table.side_effect = get_table
    m.bpf = bpf
    m._collect_and_output()
    names = [c[0][0] for c in bpf.get_table.call_args_list]
    assert "process_trade_stats" in names
    assert "process_trade_ipc_stats" in names
    assert m.last_success_ts > 0


def test_c_file_map_names_agree():
    """Structural check: C source uses renamed maps matching Python."""
    from pathlib import Path
    text = Path("src/ebpf/process_trade.c").read_text()
    assert "BPF_HASH(process_trade_stats" in text
    assert "BPF_HASH(process_trade_ipc_stats" in text
    assert "trade_syscall_stats" not in text
    assert "trade_ipc_stats" not in text or "process_trade_ipc_stats" in text


def test_extra_cflags_when_targets(monitor_context, pt_config):
    m = ProcessTradeMonitor(monitor_context, pt_config)
    assert "-DENABLE_PID_FILTER=1" in m.get_extra_cflags()


def test_extra_cflags_empty_targets(monitor_context, pt_config):
    pt_config["zmb_processes"] = []
    pt_config["zme_processes"] = []
    m = ProcessTradeMonitor(monitor_context, pt_config)
    assert m.get_extra_cflags() == []


def test_extra_cflags_whitespace_only_names_no_filter(monitor_context, pt_config):
    """AC3: empty/whitespace names must not enable empty kernel whitelist."""
    pt_config["zmb_processes"] = ["", "  ", "\t"]
    pt_config["zme_processes"] = []
    m = ProcessTradeMonitor(monitor_context, pt_config)
    assert m._pid_filter_enabled is False
    assert m._pid_filter_targets_nonempty() is False
    assert "-DENABLE_PID_FILTER=1" not in m.get_extra_cflags()
    assert m.get_extra_cflags() == []


def test_extra_cflags_real_name_enables_filter(monitor_context, pt_config):
    pt_config["zmb_processes"] = ["", "zmb"]
    pt_config["zme_processes"] = ["  "]
    m = ProcessTradeMonitor(monitor_context, pt_config)
    assert m._pid_filter_enabled is True
    assert "-DENABLE_PID_FILTER=1" in m.get_extra_cflags()


def test_csv_columns_simple_pairs(monitor_context, pt_config):
    m = ProcessTradeMonitor(monitor_context, pt_config)
    for col in m.CSV_COLUMNS:
        assert len(col) == 2


def test_on_collect_tick_refreshes_pid_allow(monitor_context, pt_config):
    """Runtime refresh: new PIDs after load must be written to pid_allow."""
    m = ProcessTradeMonitor(monitor_context, pt_config)
    m.bpf = MagicMock()
    m._ptm.refresh = MagicMock()
    m._ptm.sync_pid_allow_map = MagicMock()
    m._on_collect_tick()
    m._ptm.refresh.assert_called()
    m._ptm.sync_pid_allow_map.assert_called_with(m.bpf, "pid_allow")
