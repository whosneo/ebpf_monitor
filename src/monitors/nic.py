#!/usr/bin/env python
# encoding: utf-8
"""
低延时网卡（nic）监控器

负责加载和管理低延时网卡 eBPF 程序。
统计聚合模式：硬件/软件队列深度相关、缓冲区、网卡级延迟。

支持 SWIFT-2200N 等中科驭数低延时 DPU 卡。
优先使用通用探针，driver specific 占位已注释于 nic.c。

统计维度：
- (comm, direction) -> 报文数、字节、延迟、队列事件

参考：ROADMAP Phase 2/3，USER_GUIDE nic 专项
"""

from .base import BaseMonitor
from ..utils.monitor_data_utils import MonitorDataUtils
from ..utils.decorators import register_monitor


def direction_to_str(direction):
    # type: (int) -> str
    if direction == 1:
        return "TX"
    elif direction == 2:
        return "RX"
    return "UNK"


@register_monitor("nic")
class NicMonitor(BaseMonitor):
    """低延时网卡监控器 - 统计聚合模式

    核心指标：
      - queue_depth（通过软件事件 + 外部 collect_nic_metrics 硬件数据关联）
      - 缓冲区/字节统计
      - 延迟（路径粗略配对）
    """

    CONFIG_SCHEMA = {
        "target_interfaces": {
            "type": list,
            "required": False,
            "default": [],
            "item_type": str,
        },
        "target_processes": {
            "type": list,
            "required": False,
            "default": [],
            "item_type": str,
        },
        "min_queue_depth": {
            "type": int,
            "required": False,
            "min": 0,
            "default": 0,
        },
        "min_latency_us": {
            "type": int,
            "required": False,
            "min": 0,
            "default": 0,
        },
    }

    CSV_COLUMNS = [
        ("comm", "comm"),
        ("direction", "direction", direction_to_str),
        ("packet_count", "count"),
        ("total_bytes", "total_bytes"),
        ("size_mb", "total_bytes", MonitorDataUtils.calc_size_mb),
        ("avg_latency_us", ("total_ns", "count"), MonitorDataUtils.calc_avg_latency_us),
        ("min_latency_us", "min_ns", MonitorDataUtils.calc_min_latency_us),
        ("max_latency_us", "max_ns", MonitorDataUtils.calc_max_latency_us),
        ("queue_events", "queue_events"),
    ]

    CONSOLE_FORMAT = (
        "{:<16} {:>6} {:>10} {:>10} {:>10} {:>10} {:>10} {:>8}",
        [
            "comm",
            ("direction", direction_to_str),
            "count",
            ("total_bytes", MonitorDataUtils.format_bytes),
            (("total_ns", "count"), lambda tn, c: MonitorDataUtils.format_latency_ms(MonitorDataUtils.calc_avg_latency_us(tn, c))),
            ("min_ns", lambda ns: MonitorDataUtils.format_latency_ms(MonitorDataUtils.calc_min_latency_us(ns))),
            ("max_ns", lambda ns: MonitorDataUtils.format_latency_ms(MonitorDataUtils.calc_max_latency_us(ns))),
            "queue_events",
        ],
        ["COMM", "DIR", "COUNT", "BYTES", "AVG_LAT", "MIN_LAT", "MAX_LAT", "Q_EV"],
    )

    PROMETHEUS_CONFIG = {
        "labels": [
            ("comm", "comm"),
            ("direction", ("direction", direction_to_str)),
        ],
        "metrics": [
            ("nic_packets", "counter", "NIC packet count", "count", None),
            ("nic_bytes", "counter", "NIC bytes", "total_bytes", None),
            ("nic_avg_latency_us", "gauge", "Avg latency us", ("total_ns", "count"), MonitorDataUtils.calc_avg_latency_us),
            ("nic_queue_events", "counter", "Queue related events", "queue_events", None),
        ],
    }

    def should_collect(self, key, value):
        # type: (Any, Any) -> bool
        """过滤逻辑"""
        if getattr(self, "min_queue_depth", 0) > 0:
            qe = getattr(value, "queue_events", 0)
            if qe < self.min_queue_depth:
                return False

        if getattr(self, "min_latency_us", 0) > 0:
            avg = MonitorDataUtils.calc_avg_latency_us(
                getattr(value, "total_ns", 0), getattr(value, "count", 0)
            )
            if avg < self.min_latency_us:
                return False
        return True

    def _initialize(self, config):
        # type: (dict) -> None
        """可选初始化"""
        self.target_interfaces = config.get("target_interfaces", [])
        self.target_processes = config.get("target_processes", [])
        # 更多过滤逻辑可在此扩展（如接口匹配）
