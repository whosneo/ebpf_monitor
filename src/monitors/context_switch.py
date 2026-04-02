#!/usr/bin/env python
# encoding: utf-8
"""
上下文切换监控器

监控进程级别的上下文切换统计，包括：
- 切换进来/切换出去的次数
- 自愿切换（IO等待、sleep）
- 非自愿切换（时间片用尽、被抢占）

输出模式：统计聚合模式（定期输出）
统计维度：(comm, cpu) -> (switch_in, switch_out, voluntary, involuntary)

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


# ==================== 上下文切换结构体定义 ====================

class ContextSwitchKey:
    """上下文切换键"""
    _fields_ = [
        ("comm", ct.c_char * 16),  # 进程名
        ("cpu", ct.c_uint32),  # CPU编号
    ]


class ContextSwitchValue:
    """上下文切换值"""
    _fields_ = [
        ("switch_in_count", ct.c_uint64),  # 切换进来的次数
        ("switch_out_count", ct.c_uint64),  # 切换出去的次数
        ("voluntary_count", ct.c_uint64),  # 自愿切换次数
        ("involuntary_count", ct.c_uint64),  # 非自愿切换次数
    ]


# ==================== 上下文切换工具函数 ====================

def calc_total_switches(data):
    # type: (Dict[str, Any]) -> int
    """计算总切换次数"""
    return data["switch_in_count"] + data["switch_out_count"]


def calc_voluntary_rate(data):
    # type: (Dict[str, Any]) -> float
    """计算自愿切换比例（百分比）"""
    total = data["voluntary_count"] + data["involuntary_count"]
    if total == 0:
        return 0.0
    return (data["voluntary_count"] * 100.0) / total


# ==================== 上下文切换监控器 ====================


@register_monitor("context_switch")
class ContextSwitchMonitor(BaseMonitor):
    """上下文切换监控器 - 统计聚合模式
    
    监控进程上下文切换，统计切换频率和自愿/非自愿切换比例。
    """
    REQUIRED_TRACEPOINTS = ['sched:sched_switch']  # type: List[str]

    CSV_COLUMNS = [
        ("comm", "comm"),
        ("cpu", "cpu"),
        ("switch_in", "switch_in_count"),
        ("switch_out", "switch_out_count"),
        ("total_switches", ("switch_in_count", "switch_out_count"), lambda a, b: a + b),
        ("voluntary", "voluntary_count"),
        ("involuntary", "involuntary_count"),
        ("voluntary_rate", ("voluntary_count", "involuntary_count"),
         lambda v, inv: "{:.1f}".format((v * 100.0 / (v + inv)) if (v + inv) > 0 else 0.0)),
    ]

    CONSOLE_FORMAT = (
        "{:<16} {:>4} {:>8} {:>8} {:>8} {:>10} {:>10} {:>7.1f}%",
        [
            "comm", "cpu",
            "switch_in_count", "switch_out_count",
            (("switch_in_count", "switch_out_count"), lambda a, b: a + b),
            "voluntary_count", "involuntary_count",
            (("voluntary_count", "involuntary_count"),
             lambda v, inv: (v * 100.0 / (v + inv)) if (v + inv) > 0 else 0.0),
        ],
        ["COMM", "CPU", "IN", "OUT", "TOTAL", "VOL", "INVOL", "VOL_RATE"],
    )

    @classmethod
    def get_default_monitor_config(cls):
        # type: () -> Dict[str, Any]
        """获取默认配置"""
        return {
            "min_switches": 10  # 最小切换次数过滤
        }

    @classmethod
    def validate_monitor_config(cls, config):
        # type: (Dict[str, Any]) -> None
        """验证监控器配置"""
        if config.get("min_switches") is None:
            raise ValueError("min_switches 必须为整数，当前类型: {}".format(type(config.get("min_switches")).__name__))
        if not isinstance(config.get("min_switches"), int):
            raise ValueError("min_switches 必须为整数，当前类型: {}".format(type(config.get("min_switches")).__name__))
        if config.get("min_switches") < 0:
            raise ValueError("min_switches 必须大于等于 0，当前值: {}".format(config.get("min_switches")))

    def _initialize(self, config):
        # type: (Dict[str, Any]) -> None
        """初始化监控器特定的属性"""
        self.min_switches = config.get("min_switches")

    def should_collect(self, key, value):
        # type: (ContextSwitchKey, ContextSwitchValue) -> bool
        """判断是否应该收集数据"""
        total_switches = value.switch_in_count + value.switch_out_count
        if total_switches < self.min_switches:
            return False
        return True
