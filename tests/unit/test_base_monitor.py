#!/usr/bin/env python
# encoding: utf-8
"""Unit tests for BaseMonitor core logic (config, formatting, should_collect etc)."""

import pytest
from unittest.mock import patch, MagicMock

from src.monitors.base import BaseMonitor, MonitorMode
from src.utils.decorators import register_monitor


@register_monitor("dummy_test")
class DummyTestMonitor(BaseMonitor):
    """Minimal concrete monitor for testing base behavior."""

    CONFIG_SCHEMA = {
        "target_interfaces": {"type": list, "required": False, "default": []},
        "min_latency_us": {"type": int, "required": False, "default": 0},
    }

    CSV_COLUMNS = [
        ("comm", "comm"),
        ("count", "count"),
    ]

    CONSOLE_FORMAT = (
        "{:<8} {:>6}",
        ["comm", "count"],
        ["COMM", "COUNT"],
    )

    PROMETHEUS_CONFIG = {
        "labels": [("comm", "comm")],
        "metrics": [
            ("nic_packet_count", "counter", "packet count", "count", None),
        ],
    }

    def should_collect(self, key, value):
        if hasattr(self, "min_latency_us") and self.min_latency_us > 0:
            # simplistic
            return getattr(value, "count", 0) > 0
        return True


class TestBaseMonitor:
    def test_default_config(self):
        cfg = DummyTestMonitor.get_default_config()
        assert cfg["enabled"] is True
        assert cfg["interval"] == 2
        assert "target_interfaces" in cfg

    def test_validate_config_ok(self):
        DummyTestMonitor.validate_config({"enabled": True, "interval": 1.0})

    def test_validate_config_disabled_ok(self):
        DummyTestMonitor.validate_config({"enabled": False})

    def test_validate_config_bad(self):
        with pytest.raises(ValueError):
            DummyTestMonitor.validate_config({"enabled": True})  # missing interval

    def test_mode_default_statistical(self, monitor_context, sample_config):
        m = DummyTestMonitor(monitor_context, sample_config)
        assert m.mode == MonitorMode.STATISTICAL

    def test_should_collect_default_true(self, monitor_context, sample_config):
        m = DummyTestMonitor(monitor_context, sample_config)
        key = MagicMock()
        val = MagicMock(count=10)
        assert m.should_collect(key, val) is True

    def test_csv_header(self, monitor_context, sample_config):
        m = DummyTestMonitor(monitor_context, sample_config)
        header = m.get_csv_header()
        assert "comm" in header
        assert "count" in header

    def test_prometheus_config_present(self, monitor_context, sample_config):
        m = DummyTestMonitor(monitor_context, sample_config)
        pcfg = m.get_prometheus_config()
        assert "labels" in pcfg
        assert len(pcfg.get("metrics", [])) > 0


class TestMultiTableCollect:
    """Drive real BaseMonitor._collect_and_output multi-table path."""

    def test_iter_stats_tables_default(self, monitor_context, sample_config):
        m = DummyTestMonitor(monitor_context, sample_config)
        tables = list(m._iter_stats_tables())
        assert tables == [("dummy_test_stats", "default")]

    def test_iter_stats_tables_instance_override(self, monitor_context, sample_config):
        m = DummyTestMonitor(monitor_context, sample_config)
        m.STATS_TABLES = [("a_stats", "syscall"), ("b_stats", "ipc")]
        assert list(m._iter_stats_tables()) == [
            ("a_stats", "syscall"),
            ("b_stats", "ipc"),
        ]

    def test_collect_pops_multiple_tables_and_normalize(self, monitor_context, sample_config):
        m = DummyTestMonitor(monitor_context, sample_config)
        m.STATS_TABLES = [("t1", "type_a"), ("t2", "type_b")]

        class Key(object):
            def __init__(self, comm):
                self.comm = comm
                self._fields_ = [("comm", None)]

        class Val(object):
            def __init__(self, count):
                self.count = count
                self._fields_ = [("count", None)]

        # real struct_to_dict needs _fields_ as list of (name, type)
        # Use simple namespace objects + patch DataProcessor.struct_to_dict
        from unittest.mock import patch

        bpf = MagicMock()
        t1 = MagicMock()
        t2 = MagicMock()
        k1, v1 = MagicMock(), MagicMock()
        k2, v2 = MagicMock(), MagicMock()
        t1.keys.return_value = [k1]
        t1.pop.return_value = v1
        t2.keys.return_value = [k2]
        t2.pop.return_value = v2

        def get_table(name):
            return {"t1": t1, "t2": t2}[name]

        bpf.get_table.side_effect = get_table
        m.bpf = bpf

        def fake_struct(obj):
            if obj is k1:
                return {"comm": b"p1"}
            if obj is v1:
                return {"count": 3}
            if obj is k2:
                return {"comm": b"p2"}
            if obj is v2:
                return {"count": 5}
            return {}

        normalized = []

        def norm(data, record_type):
            data = dict(data)
            data["record_type"] = record_type
            normalized.append(record_type)
            return data

        m._normalize_stat_row = norm
        with patch("src.monitors.base.DataProcessor.struct_to_dict", side_effect=fake_struct):
            m._collect_and_output()

        assert normalized == ["type_a", "type_b"]
        assert m.last_success_ts > 0
        assert m.output_controller.handle_data.call_count == 2

    def test_map_lookup_fail_increments(self, monitor_context, sample_config):
        m = DummyTestMonitor(monitor_context, sample_config)
        m.bpf = MagicMock()
        m.bpf.get_table.side_effect = RuntimeError("no table")
        m._collect_and_output()
        assert m.map_lookup_fail_count >= 1
        assert m.collect_error_count >= 1

    def test_get_extra_cflags_default_empty(self, monitor_context, sample_config):
        m = DummyTestMonitor(monitor_context, sample_config)
        assert m.get_extra_cflags() == []

    def test_load_concatenates_cflags(self, monitor_context, sample_config, tmp_path):
        import src.monitors.base as base_mod
        BPF = base_mod.BPF
        c_file = tmp_path / "dummy.c"
        c_file.write_text("int x;")
        monitor_context.ebpf_file_path = str(c_file)
        monitor_context.compile_flags = ["-DSHARED=1"]
        m = DummyTestMonitor(monitor_context, sample_config)
        m.ebpf_file = str(c_file)
        m.compile_flags = ["-DSHARED=1"]
        m.get_extra_cflags = lambda: ["-DEXTRA=1"]
        BPF.instances = []
        BPF.last_cflags = None
        assert m.load_ebpf_program() is True
        assert m.bpf is not None
        assert getattr(m.bpf, "cflags", None) is not None
        assert "-DSHARED=1" in list(m.bpf.cflags)
        assert "-DEXTRA=1" in list(m.bpf.cflags)
        # shared list not mutated
        assert monitor_context.compile_flags == ["-DSHARED=1"]

    def test_get_health(self, monitor_context, sample_config):
        m = DummyTestMonitor(monitor_context, sample_config)
        h = m.get_health()
        assert h["type"] == "dummy_test"
        assert "collect_error_count" in h
        assert "last_success_ts" in h
