#!/usr/bin/env python
# encoding: utf-8
"""
共享内存通信监控器

负责加载和管理共享内存通信监控eBPF程序，统计System V SHM操作统计。
采用统计模式，在内核态累积共享内存操作统计，定期批量输出。

统计维度：
- (shmid, 进程名) -> (操作次数, 操作耗时统计, 错误次数)
- shmid -> (操作次数, 附加次数, 分离次数) 跟踪活跃内存段

支持的监控场景：
- 共享内存段访问热点分析
- 锁竞争检测（通过操作耗时异常判断）
- 共享内存段生命周期跟踪

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


# ==================== SHM常量定义 ====================

SHMOP_GET = 1   # shmget
SHMOP_AT = 2    # shmat
SHMOP_DT = 3    # shmdt
SHMOP_CTL = 4   # shmctl


def op_type_to_str(op_type):
    # type: (int) -> str
    """将操作类型转换为字符串"""
    ops = {
        SHMOP_GET: "GET",
        SHMOP_AT: "AT",
        SHMOP_DT: "DT",
        SHMOP_CTL: "CTL",
    }
    return ops.get(op_type, "UNKNOWN")


def calc_contention_rate(count, min_ns, max_ns):
    # type: (int, int, int) -> float
    """计算竞争率（基于延迟方差，百分比）"""
    if count < 2 or min_ns == 0:
        return 0.0
    avg_ns = max_ns  # 简化：用max/avg比值近似竞争程度
    if avg_ns == 0:
        return 0.0
    # 竞争率 = (max - min) / max * 100
    return ((max_ns - min_ns) * 100.0) / max_ns if max_ns > 0 else 0.0


# ==================== SHM监控器 ====================


@register_monitor("shm")
class ShmMonitor(BaseMonitor):
    """共享内存通信监控器 - 统计聚合模式
    
    监控System V SHM操作统计，分析内存访问模式和竞争情况。
    使用 MonitorDataUtils 进行通用的数据处理和格式化。
    """

    # 配置模式定义
    CONFIG_SCHEMA = {
        "target_shmids": {
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
        "monitor_contention": {
            "type": bool,
            "required": False,
            "default": True,
        },
        "monitor_barriers": {
            "type": bool,
            "required": False,
            "default": False,
        },
    }

    CSV_COLUMNS = [
        ("shmid", "shmid"),
        ("comm", "comm"),
        ("access_count", "count"),
        ("err_count", "err_count"),
        ("err_rate", ("count", "err_count"), MonitorDataUtils.calc_error_rate),
        ("avg_latency_us", ("total_ns", "count"), MonitorDataUtils.calc_avg_latency_us),
        ("min_latency_us", "min_ns", MonitorDataUtils.calc_min_latency_us),
        ("max_latency_us", "max_ns", MonitorDataUtils.calc_max_latency_us),
        ("contention_rate", ("count", "min_ns", "max_ns"), calc_contention_rate),
    ]

    CONSOLE_FORMAT = (
        "{:>8} {:<16} {:>8} {:>6} {:>8.1f}% {:>10} {:>10} {:>10} {:>7.1f}%",
        [
            "shmid",
            "comm",
            "count",
            "err_count",
            (("count", "err_count"), lambda c, e: MonitorDataUtils.calc_error_rate(c, e)),
            (("total_ns", "count"), lambda tn, c: MonitorDataUtils.format_latency_ms(MonitorDataUtils.calc_avg_latency_us(tn, c))),
            ("min_ns", lambda ns: MonitorDataUtils.format_latency_ms(MonitorDataUtils.calc_min_latency_us(ns))),
            ("max_ns", lambda ns: MonitorDataUtils.format_latency_ms(MonitorDataUtils.calc_max_latency_us(ns))),
            (("count", "min_ns", "max_ns"), lambda c, mn, mx: "{:.1f}%".format(calc_contention_rate(c, mn, mx))),
        ],
        ["SHMID", "COMM", "COUNT", "ERRS", "ERR%", "AVG_LAT", "MIN_LAT", "MAX_LAT", "CONTENT"],
    )

    def should_collect(self, key, value):
        # type: (Any, Any) -> bool
        """判断是否应该收集数据"""
        # 目标shmid过滤
        if self.target_shmids:
            if key.shmid not in self.target_shmids:
                return False

        # 目标进程过滤
        if self.target_processes:
            comm_str = key.comm.decode('utf-8', errors='replace').rstrip('\x00')
            if comm_str not in self.target_processes:
                return False

        # 竞争监控过滤：仅在启用竞争监控时显示有竞争的段
        if self.monitor_contention:
            # 显示所有有操作的段（竞争率在输出时计算）
            pass

        return True
