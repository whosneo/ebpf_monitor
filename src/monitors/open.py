#!/usr/bin/env python
# encoding: utf-8
"""
文件打开监控器（Open Monitor）

负责加载和管理文件打开监控eBPF程序，统计文件打开操作。
采用统计模式，在内核态累积打开统计，定期批量输出，避免高频操作导致的数据丢失。

监控机制：
- 使用 Syscalls Tracepoint 机制（稳定的内核ABI）
- 监控 sys_enter_open/openat（入口）和 sys_exit_open/openat（出口）
- 记录完整的文件路径、打开标志、延迟统计等信息

统计维度：
- (进程名, 操作类型, 文件路径) -> (次数, 错误次数, 延迟统计, 标志汇总)

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


# ==================== Open常量定义 ====================

# 操作类型常量（与C代码保持一致）
OP_OPEN = 0
OP_OPENAT = 1

# 文件打开标志常量
O_RDONLY = 0x0000
O_WRONLY = 0x0001
O_RDWR = 0x0002
O_CREAT = 0x0040
O_EXCL = 0x0080
O_TRUNC = 0x0200
O_APPEND = 0x0400
O_DIRECTORY = 0x10000
O_CLOEXEC = 0x80000


def operation_to_str(operation):
    # type: (int) -> str
    """将操作类型转换为字符串"""
    if operation == OP_OPEN:
        return "OPEN"
    elif operation == OP_OPENAT:
        return "OPENAT"
    else:
        return "UNKNOWN"


def parse_flags(flags):
    # type: (int) -> str
    """解析并显示文件打开标志位（显示主要标志）"""
    parts = []

    # 访问模式（互斥）
    access_mode = flags & 0x3
    if access_mode == O_RDONLY:
        parts.append("RD")
    elif access_mode == O_WRONLY:
        parts.append("WR")
    elif access_mode == O_RDWR:
        parts.append("RW")

    # 创建和修改标志
    if flags & O_CREAT:
        parts.append("CR")
    if flags & O_EXCL:
        parts.append("EX")
    if flags & O_TRUNC:
        parts.append("TR")
    if flags & O_APPEND:
        parts.append("AP")

    # 特殊行为标志
    if flags & O_DIRECTORY:
        parts.append("DIR")
    if flags & O_CLOEXEC:
        parts.append("CLO")

    return "|".join(parts) if parts else "0x{:X}".format(flags)


# ==================== Open监控器 ====================


@register_monitor("open")
class OpenMonitor(BaseMonitor):
    """文件打开监控器 - 统计聚合模式
    
    监控文件打开操作，统计打开次数、延迟和错误率。
    使用 MonitorDataUtils 进行通用的数据处理和格式化。
    """
    REQUIRED_TRACEPOINTS = [  # type: List[str]
        "syscalls:sys_enter_open",
        "syscalls:sys_exit_open",
        "syscalls:sys_enter_openat",
        "syscalls:sys_exit_openat",
    ]

    # 配置模式定义
    # min_count: 最小打开次数过滤，低于此值的文件路径统计将被忽略
    # show_errors_only: 仅显示错误的打开操作，为True时过滤掉成功的open调用
    CONFIG_SCHEMA = {
        "min_count": {
            "type": int,
            "required": True,
            "min": 0,
            "default": 1,  # 默认显示所有出现过的文件打开操作
        },
        "show_errors_only": {
            "type": bool,
            "required": True,
            "default": False  # 默认显示所有调用，包括成功的
        }
    }

    CSV_COLUMNS = [
        ("comm", "comm"),
        ("operation", "operation", operation_to_str),
        ("filename", "filename"),
        ("count", "count"),
        ("errors", "error_count"),
        ("error_rate", ("count", "error_count"), MonitorDataUtils.calc_error_rate),
        ("avg_lat_us", ("total_latency_ns", "count"), MonitorDataUtils.calc_avg_latency_us),
        ("min_lat_us", "min_latency_ns", MonitorDataUtils.calc_min_latency_us),
        ("max_lat_us", "max_latency_ns", MonitorDataUtils.calc_max_latency_us),
        ("flags", "flags_summary", parse_flags),
    ]

    CONSOLE_FORMAT = (
        "{:<16} {:<8} {:<40} {:>8} {:>8} {:>10} {:<10}",
        [
            "comm",
            ("operation", operation_to_str),
            ("filename", lambda v: v if len(v) <= 40 else v[:37] + "..."),
            "count",
            (("error_count", "count"), lambda ec, c: MonitorDataUtils.format_error_count(ec, MonitorDataUtils.calc_error_rate(c, ec))),
            (("total_latency_ns", "count"), lambda tln, c: MonitorDataUtils.format_latency_us(MonitorDataUtils.calc_avg_latency_us(tln, c))),
            ("flags_summary", parse_flags),
        ],
        ["COMM", "OP", "FILENAME", "COUNT", "ERRORS", "AVG_LAT", "FLAGS"],
    )

    def should_collect(self, key, value):
        # type: (Any, Any) -> bool
        """是否收集数据"""
        if value.count < self.min_count:
            return False
        if self.show_errors_only and value.error_count == 0:
            return False
        return True
