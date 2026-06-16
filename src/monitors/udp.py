#!/usr/bin/env python
# encoding: utf-8
"""
UDP网络通信监控器

负责加载和管理UDP网络通信监控eBPF程序，统计UDP收发速率、延迟分布。
采用统计模式，在内核态累积UDP统计，定期批量输出。

统计维度：
- (进程名, 方向) -> (报文数, 总字节, 延迟统计)

支持的监控场景：
- ZMB中间件UDP通信监控
- UDP报文延迟分析
- UDP收发速率统计

模式：STATISTICAL（统计聚合）
"""

# 标准库导入
import ctypes as ct

# 兼容性导入
try:
    from typing import Dict, List, Any
except ImportError:
    from ..utils.py2_compat import Dict, List, Any

# 本地模块导入
from .base import BaseMonitor
from ..utils.monitor_data_utils import MonitorDataUtils
from ..utils.decorators import register_monitor


# ==================== UDP常量定义 ====================

DIR_SEND = 1  # 发送方向
DIR_RECV = 2  # 接收方向


def direction_to_str(direction):
    # type: (int) -> str
    """将方向代码转换为字符串"""
    if direction == DIR_SEND:
        return "SEND"
    elif direction == DIR_RECV:
        return "RECV"
    return "UNKNOWN"


def calc_drop_rate(count, drop_count):
    # type: (int, int) -> float
    """计算丢包率（百分比）"""
    total = count + drop_count
    if total == 0:
        return 0.0
    return (drop_count * 100.0) / total


# ==================== UDP监控器 ====================


@register_monitor("udp")
class UdpMonitor(BaseMonitor):
    """UDP网络通信监控器 - 统计聚合模式
    
    监控UDP收发报文数、字节数和延迟。
    使用 MonitorDataUtils 进行通用的数据处理和格式化。
    """

    # 配置模式定义
    CONFIG_SCHEMA = {
        "target_ports": {
            "type": list,
            "required": False,
            "default": [],
            "item_type": int,
        },
        "target_processes": {
            "type": list,
            "required": False,
            "default": [],
            "item_type": str,
        },
        "min_packet_size": {
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
        ("throughput_mbps", ("total_bytes", "total_ns"), MonitorDataUtils.calc_throughput_mbps),
    ]

    CONSOLE_FORMAT = (
        "{:<16} {:>6} {:>10} {:>10} {:>10} {:>10} {:>10} {:>12}",
        [
            "comm",
            ("direction", direction_to_str),
            "count",
            ("total_bytes", MonitorDataUtils.format_bytes),
            (("total_ns", "count"), lambda tn, c: MonitorDataUtils.format_latency_ms(MonitorDataUtils.calc_avg_latency_us(tn, c))),
            ("min_ns", lambda ns: MonitorDataUtils.format_latency_ms(MonitorDataUtils.calc_min_latency_us(ns))),
            ("max_ns", lambda ns: MonitorDataUtils.format_latency_ms(MonitorDataUtils.calc_max_latency_us(ns))),
            (("total_bytes", "total_ns"), lambda tb, tn: MonitorDataUtils.format_throughput(MonitorDataUtils.calc_throughput_mbps(tb, tn))),
        ],
        ["COMM", "DIR", "COUNT", "BYTES", "AVG_LAT", "MIN_LAT", "MAX_LAT", "THROUGHPUT"],
    )

    def should_collect(self, key, value):
        # type: (Any, Any) -> bool
        """判断是否应该收集数据"""
        # 最小报文大小过滤
        if self.min_packet_size > 0:
            avg_bytes = value.total_bytes / value.count if value.count > 0 else 0
            if avg_bytes < self.min_packet_size:
                return False
        return True
