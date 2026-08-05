#!/usr/bin/env python
# encoding: utf-8
"""Unit tests for MonitorDataUtils (used by all monitors incl. nic)."""

from src.utils.monitor_data_utils import MonitorDataUtils as U


def test_latency_calc():
    assert U.calc_avg_latency_us(1000000, 1) == 1000.0
    assert U.calc_avg_latency_us(0, 0) == 0.0
    assert U.calc_min_latency_us(500) == 0.5

def test_size_and_throughput():
    assert U.calc_size_mb(1048576) == 1.0
    # BYTES_TO_MB is binary (1024*1024), matching MonitorDataUtils convention
    mbps = U.calc_throughput_mbps(1048576, 1000000000)  # 1 MiB in 1s
    assert abs(mbps - 1.0) < 0.01

def test_formatters():
    assert "KB" in U.format_bytes(2048)
    assert "ms" in U.format_latency_ms(1500)
