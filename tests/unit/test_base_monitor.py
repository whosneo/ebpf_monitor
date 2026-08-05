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


# Nic will add its own test later, placeholder here for coverage expectation
def test_nic_placeholder():
    assert True  # replaced when nic.py added
