#!/usr/bin/env python
# encoding: utf-8
"""
交易进程级监控器

负责加载和管理交易进程级监控eBPF程序，对ZMB/ZME进程的系统调用模式进行专项分析。
采用统计模式，在内核态累积交易进程统计，定期批量输出。

统计维度：
- (进程名, 系统调用分类) -> (调用次数, 错误次数, 延迟统计)
- (进程名, IPC类型) -> (调用次数, 延迟统计)

支持的监控场景：
- ZMB中间件UDP包处理速率监控
- ZME撮合引擎系统调用模式分析
- 交易进程IPC通信统计
- 异常拒单检测（通过error_count统计）

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


# ==================== 系统调用分类常量 ====================

SCAT_FILE_IO = 1
SCAT_NETWORK = 2
SCAT_MEMORY = 3
SCAT_PROCESS = 4
SCAT_IPC = 5
SCAT_TIME = 6
SCAT_SIGNAL = 7
SCAT_OTHER = 0


def category_to_str(category):
    # type: (int) -> str
    """将系统调用分类转换为字符串"""
    categories = {
        SCAT_FILE_IO: "FILE_IO",
        SCAT_NETWORK: "NETWORK",
        SCAT_MEMORY: "MEMORY",
        SCAT_PROCESS: "PROCESS",
        SCAT_IPC: "IPC",
        SCAT_TIME: "TIME",
        SCAT_SIGNAL: "SIGNAL",
        SCAT_OTHER: "OTHER",
    }
    return categories.get(category, "UNKNOWN")


def calc_error_rate(count, error_count):
    # type: (int, int) -> float
    """计算错误率（百分比）"""
    if count == 0:
        return 0.0
    return (error_count * 100.0) / count


# ==================== 交易进程监控器 ====================


@register_monitor("process_trade")
class ProcessTradeMonitor(BaseMonitor):
    """交易进程级监控器 - 统计聚合模式
    
    监控ZMB/ZME进程的系统调用和IPC通信统计。
    使用 MonitorDataUtils 进行通用的数据处理和格式化。
    """

    # 配置模式定义
    CONFIG_SCHEMA = {
        "zmb_processes": {
            "type": list,
            "required": True,
            "item_type": str,
        },
        "zme_processes": {
            "type": list,
            "required": True,
            "item_type": str,
        },
        "monitor_syscalls": {
            "type": bool,
            "required": False,
            "default": True,
        },
        "monitor_ipc": {
            "type": bool,
            "required": False,
            "default": True,
        },
    }

    CSV_COLUMNS = [
        ("comm", "comm"),
        ("category", "syscall_category", category_to_str),
        ("count", "count"),
        ("error_count", "error_count"),
        ("error_rate", ("count", "error_count"), calc_error_rate),
        ("avg_latency_us", ("total_ns", "count"), MonitorDataUtils.calc_avg_latency_us),
        ("min_latency_us", "min_ns", MonitorDataUtils.calc_min_latency_us),
        ("max_latency_us", "max_ns", MonitorDataUtils.calc_max_latency_us),
    ]

    CONSOLE_FORMAT = (
        "{:<16} {:<10} {:>8} {:>8} {:>7.1f}% {:>10} {:>10} {:>10}",
        [
            "comm",
            ("syscall_category", category_to_str),
            "count",
            "error_count",
            (("count", "error_count"), lambda c, e: calc_error_rate(c, e)),
            (("total_ns", "count"), lambda tn, c: MonitorDataUtils.format_latency_ms(MonitorDataUtils.calc_avg_latency_us(tn, c))),
            ("min_ns", lambda ns: MonitorDataUtils.format_latency_ms(MonitorDataUtils.calc_min_latency_us(ns))),
            ("max_ns", lambda ns: MonitorDataUtils.format_latency_ms(MonitorDataUtils.calc_max_latency_us(ns))),
        ],
        ["COMM", "CATEGORY", "COUNT", "ERRORS", "ERR%", "AVG_LAT", "MIN_LAT", "MAX_LAT"],
    )

    def should_collect(self, key, value):
        # type: (Any, Any) -> bool
        """判断是否应该收集数据"""
        # 系统调用监控过滤
        if not self.monitor_syscalls:
            return False

        # 进程角色过滤：仅监控配置的ZMB/ZME进程
        comm_str = key.comm.decode('utf-8', errors='replace').rstrip('\x00')
        all_target = self.zmb_processes + self.zme_processes
        if all_target and comm_str not in all_target:
            return False

        return True
