#!/usr/bin/env python
# encoding: utf-8
"""
BIO监控器（Block IO Monitor）

负责加载和管理BIO监控eBPF程序，统计Block层IO性能数据。
采用统计模式，在内核态累积IO统计，定期批量输出，避免高频IO导致的数据丢失。

监控层次：Block层（真实的磁盘IO，过滤了Page Cache命中的操作）

统计维度：
- (进程名, BIO类型) -> (次数, 字节数, 延迟统计)

支持的BIO类型：
- READ (0x1): 读操作
- WRITE (0x2): 写操作
- SYNC (0x4): 同步操作

模式：STATISTICAL（统计聚合）
"""

# 兼容性导入
try:
    from typing import Dict, List, Any
except ImportError:
    from ..utils.py2_compat import Dict, List, Any

# 本地模块导入
from .base import BaseMonitor
from ..utils.monitor_data_utils import MonitorDataUtils
from ..utils.decorators import register_monitor


# ==================== BIO常量定义 ====================

# IO类型常量（与C代码保持一致）
IO_TYPE_READ = 0x1       # R: Read
IO_TYPE_WRITE = 0x2      # W: Write
IO_TYPE_SYNC = 0x4       # S: Synchronous
IO_TYPE_FLUSH = 0x8      # F: Flush
IO_TYPE_DISCARD = 0x10   # D: Discard/TRIM
IO_TYPE_METADATA = 0x20  # M: Metadata
IO_TYPE_READAHEAD = 0x40 # A: Read-ahead
IO_TYPE_NONE = 0x80      # N: None (barrier/flush without data)


def io_type_to_str(io_type):
    # type: (int) -> str
    """将IO类型转换为字符串"""
    types = []
    if io_type & IO_TYPE_READ:
        types.append("READ")
    if io_type & IO_TYPE_WRITE:
        types.append("WRITE")
    if io_type & IO_TYPE_FLUSH:
        types.append("FLUSH")
    if io_type & IO_TYPE_DISCARD:
        types.append("DISCARD")
    if io_type & IO_TYPE_METADATA:
        types.append("META")
    if io_type & IO_TYPE_READAHEAD:
        types.append("READAHEAD")
    if io_type & IO_TYPE_NONE:
        types.append("NONE")
    if io_type & IO_TYPE_SYNC:
        types.append("SYNC")
    return "|".join(types) if types else "UNKNOWN"


def is_read(io_type):
    # type: (int) -> bool
    """判断是否为读操作"""
    return bool(io_type & IO_TYPE_READ)


def is_write(io_type):
    # type: (int) -> bool
    """判断是否为写操作"""
    return bool(io_type & IO_TYPE_WRITE)


def is_sync(io_type):
    # type: (int) -> bool
    """判断是否为同步操作"""
    return bool(io_type & IO_TYPE_SYNC)


# ==================== BIO监控器 ====================


@register_monitor("bio")
class BioMonitor(BaseMonitor):
    """BIO监控器 - 统计聚合模式
    
    监控Block层IO操作，统计读写次数、字节数和延迟。
    使用 MonitorDataUtils 进行通用的数据处理和格式化。
    """
    REQUIRED_TRACEPOINTS = [  # type: List[str]
        'block:block_rq_issue',
        'block:block_rq_complete'
    ]

    # 配置模式定义
    # min_latency_us: 最小延迟过滤阈值（微秒），低于此值的IO操作将被过滤
    CONFIG_SCHEMA = {
        "min_latency_us": {
            "type": (int, float),
            "required": True,
            "min": 0,
            "default": 0,  # 默认不过滤，记录所有IO操作
        }
    }

    CSV_COLUMNS = [
        ("comm", "comm"),
        ("io_type", "bio_type"),
        ("io_type_str", "bio_type", io_type_to_str),
        ("count", "count"),
        ("total_bytes", "total_bytes"),
        ("size_mb", "total_bytes", MonitorDataUtils.calc_size_mb),
        ("avg_latency_us", ("total_ns", "count"), MonitorDataUtils.calc_avg_latency_us),
        ("min_latency_us", "min_ns", MonitorDataUtils.calc_min_latency_us),
        ("max_latency_us", "max_ns", MonitorDataUtils.calc_max_latency_us),
        ("throughput_mbps", ("total_bytes", "total_ns"), MonitorDataUtils.calc_throughput_mbps),
    ]

    CONSOLE_FORMAT = (
        "{:<16} {:<18} {:>8} {:>10} {:>10} {:>10} {:>10} {:>12}",
        [
            "comm",
            ("bio_type", io_type_to_str),
            "count",
            ("total_bytes", MonitorDataUtils.format_bytes),
            (("total_ns", "count"), lambda tn, c: MonitorDataUtils.format_latency_ms(MonitorDataUtils.calc_avg_latency_us(tn, c))),
            ("min_ns", lambda ns: MonitorDataUtils.format_latency_ms(MonitorDataUtils.calc_min_latency_us(ns))),
            ("max_ns", lambda ns: MonitorDataUtils.format_latency_ms(MonitorDataUtils.calc_max_latency_us(ns))),
            (("total_bytes", "total_ns"), lambda tb, tn: MonitorDataUtils.format_throughput(MonitorDataUtils.calc_throughput_mbps(tb, tn))),
        ],
        ["COMM", "IO_TYPE", "COUNT", "SIZE", "AVG_LAT", "MIN_LAT", "MAX_LAT", "THROUGHPUT"],
    )

    def should_collect(self, key, value):
        # type: (Any, Any) -> bool
        """判断是否应该收集数据"""
        avg_ns = value.total_ns / value.count if value.count > 0 else 0
        if self.min_latency_us > 0:
            if avg_ns < self.min_latency_us * MonitorDataUtils.NS_TO_US:
                return False
        return True
