#!/usr/bin/env python
# encoding: utf-8
"""Unit tests for udp/nic/shm target_processes filtering."""

from unittest.mock import MagicMock

from src.monitors.udp import UdpMonitor
from src.monitors.nic import NicMonitor
from src.monitors.shm import ShmMonitor


def test_udp_filters_target_processes(monitor_context):
    cfg = {
        "enabled": True,
        "interval": 2.0,
        "target_processes": ["zmb"],
        "target_ports": [8080],
        "min_packet_size": 0,
    }
    m = UdpMonitor(monitor_context, cfg)
    key_ok = MagicMock()
    key_ok.comm = b"zmb"
    key_bad = MagicMock()
    key_bad.comm = b"other"
    val = MagicMock(total_bytes=100, count=1)
    assert m.should_collect(key_ok, val) is True
    assert m.should_collect(key_bad, val) is False
    # unsupported ports warning
    assert any(
        "target_ports" in str(c) and "unsupported" in str(c).lower()
        for c in monitor_context.logger.warning.call_args_list
    ) or monitor_context.logger.warning.called


def test_udp_empty_targets_allow_all(monitor_context):
    cfg = {
        "enabled": True,
        "interval": 2.0,
        "target_processes": [],
        "min_packet_size": 0,
    }
    m = UdpMonitor(monitor_context, cfg)
    key = MagicMock()
    key.comm = b"any"
    val = MagicMock(total_bytes=10, count=1)
    assert m.should_collect(key, val) is True
    assert m.get_extra_cflags() == []


def test_udp_extra_cflags_with_targets(monitor_context):
    cfg = {
        "enabled": True,
        "interval": 2.0,
        "target_processes": ["zmb"],
        "min_packet_size": 0,
    }
    m = UdpMonitor(monitor_context, cfg)
    assert "-DENABLE_PID_FILTER=1" in m.get_extra_cflags()


def test_nic_filters_target_processes(monitor_context):
    cfg = {
        "enabled": True,
        "interval": 2.0,
        "target_processes": ["trade"],
        "target_interfaces": ["eth0"],
        "min_queue_depth": 0,
        "min_latency_us": 0,
    }
    m = NicMonitor(monitor_context, cfg)
    key_ok = MagicMock()
    key_ok.comm = b"trade"
    key_bad = MagicMock()
    key_bad.comm = b"x"
    val = MagicMock(queue_events=0, total_ns=0, count=1)
    assert m.should_collect(key_ok, val) is True
    assert m.should_collect(key_bad, val) is False
    assert monitor_context.logger.warning.called


def test_udp_on_collect_tick_syncs_pid_allow(monitor_context):
    cfg = {
        "enabled": True,
        "interval": 2.0,
        "target_processes": ["zmb"],
        "min_packet_size": 0,
    }
    m = UdpMonitor(monitor_context, cfg)
    m.bpf = MagicMock()
    m._ptm.refresh = MagicMock()
    m._ptm.sync_pid_allow_map = MagicMock()
    m._on_collect_tick()
    m._ptm.sync_pid_allow_map.assert_called_with(m.bpf, "pid_allow")


def test_shm_uses_ptm(monitor_context):
    cfg = {
        "enabled": True,
        "interval": 2.0,
        "target_processes": ["zmb"],
        "target_shmids": [],
        "monitor_contention": True,
        "monitor_barriers": False,
    }
    m = ShmMonitor(monitor_context, cfg)
    key_ok = MagicMock()
    key_ok.comm = b"zmb"
    key_ok.shmid = 1
    key_bad = MagicMock()
    key_bad.comm = b"nope"
    key_bad.shmid = 1
    assert m.should_collect(key_ok, MagicMock()) is True
    assert m.should_collect(key_bad, MagicMock()) is False
