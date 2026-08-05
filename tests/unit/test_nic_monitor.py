#!/usr/bin/env python
# encoding: utf-8
"""Unit tests for NicMonitor (SWIFT-2200N target)."""

import pytest
from unittest.mock import MagicMock

from src.monitors.nic import NicMonitor, direction_to_str
from src.utils.decorators import MONITOR_REGISTRY


def test_nic_registered():
    assert "nic" in MONITOR_REGISTRY
    assert MONITOR_REGISTRY["nic"] is NicMonitor


def test_direction():
    assert direction_to_str(1) == "TX"
    assert direction_to_str(2) == "RX"


def test_nic_config_schema(monitor_context):
    cfg = {
        "enabled": True,
        "interval": 2,
        "target_interfaces": ["eth0"],
        "min_queue_depth": 5,
        "min_latency_us": 10,
    }
    m = NicMonitor(monitor_context, cfg)
    assert m.target_interfaces == ["eth0"]
    assert m.min_queue_depth == 5


def test_nic_should_collect(monitor_context):
    cfg = {"enabled": True, "interval": 2}
    m = NicMonitor(monitor_context, cfg)
    val = MagicMock(count=100, total_ns=500000, queue_events=3)  # 5us avg
    key = MagicMock()
    assert m.should_collect(key, val) is True

    m2 = NicMonitor(monitor_context, {**cfg, "min_latency_us": 100})
    assert m2.should_collect(key, val) is False   # avg 5us < 100


def test_nic_csv_prometheus(monitor_context):
    m = NicMonitor(monitor_context, {"enabled": True, "interval": 2})
    cols = m.get_csv_header()
    assert "packet_count" in cols
    assert "queue_events" in cols

    p = m.get_prometheus_config()
    assert any("nic_" in mm[0] for mm in p.get("metrics", []))
