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

应用场景：
- 识别高频切换的进程（可能过度多线程）
- 发现CPU调度瓶颈
- 优化系统响应性能
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
from ..utils.data_processor import DataProcessor
from ..utils.decorators import register_monitor


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


@register_monitor("context_switch")
class ContextSwitchMonitor(BaseMonitor):
    """上下文切换监控器"""
    REQUIRED_TRACEPOINTS = ['sched:sched_switch']  # type: List[str]

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
        # 过滤：最小切换次数
        total_switches = value.switch_in_count + value.switch_out_count
        if total_switches < self.min_switches:
            return False
        return True

    @staticmethod
    def calc_total_switches(data):
        # type: (Dict[str, Any]) -> int
        """计算总切换次数"""
        return data["switch_in_count"] + data["switch_out_count"]

    @staticmethod
    def calc_voluntary_rate(data):
        # type: (Dict[str, Any]) -> float
        """计算自愿切换比例（百分比）"""
        total = data["voluntary_count"] + data["involuntary_count"]
        if total == 0:
            return 0.0
        return (data["voluntary_count"] * 100.0) / total

    # ==================== 格式化方法实现 ====================

    def monitor_csv_header(self):
        # type: () -> List[str]
        """获取CSV头部字段"""
        return [
            'comm', 'cpu',
            'switch_in', 'switch_out', 'total_switches',
            'voluntary', 'involuntary', 'voluntary_rate'
        ]

    def monitor_csv_data(self, data):
        # type: (Dict[str, Any]) -> Dict[str, Any]
        """格式化为CSV行"""
        return {
            "comm": data["comm"],
            "cpu": data["cpu"],
            "switch_in": data["switch_in_count"],
            "switch_out": data["switch_out_count"],
            "total_switches": ContextSwitchMonitor.calc_total_switches(data),
            "voluntary": data["voluntary_count"],
            "involuntary": data["involuntary_count"],
            "voluntary_rate": "{:.1f}".format(ContextSwitchMonitor.calc_voluntary_rate(data))
        }

    def monitor_console_header(self):
        # type: () -> str
        """获取控制台输出的表头"""
        return "{:<16} {:<4} {:<8} {:<8} {:<8} {:<10} {:<10} {:<8}".format(
            "COMM", "CPU", "IN", "OUT", "TOTAL", "VOLUNTARY", "INVOLUNTARY", "VOL%"
        )

    def monitor_console_data(self, data):
        # type: (Dict[str, Any]) -> str
        """将事件数据格式化为控制台输出"""
        return "{:<16} {:<4} {:<8} {:<8} {:<8} {:<10} {:<10} {:<7.1f}%".format(
            data["comm"],
            data["cpu"],
            data["switch_in_count"],
            data["switch_out_count"],
            ContextSwitchMonitor.calc_total_switches(data),
            data["voluntary_count"],
            data["involuntary_count"],
            ContextSwitchMonitor.calc_voluntary_rate(data)
        )
