#!/usr/bin/env python
# encoding: utf-8
"""
中断监控器

负责加载和管理中断监控eBPF程序，统计硬件中断和软中断频率。
采用统计模式，在内核态累积中断次数，定期批量输出，避免高频中断导致的事件丢失。

统计维度：
- 单表全维度统计：按 (进程名, 中断类型, CPU) 聚合

支持的分析场景：
- 识别哪些进程在哪些CPU上触发了何种类型的中断
- 分析中断在各CPU上的分布情况
- 统计各进程各类型中断的频率
"""

# 兼容性导入
try:
    from typing import Dict, List, Any
except ImportError:
    from ..utils.py2_compat import Dict, List, Any

# 本地模块导入
from .base import BaseMonitor
from ..utils.data_processor import DataProcessor
from ..utils.decorators import register_monitor


@register_monitor("interrupt")
class InterruptMonitor(BaseMonitor):
    """中断监控器"""
    REQUIRED_TRACEPOINTS = [  # type: List[str]
        "irq:irq_handler_exit",
        "irq:softirq_exit",
    ]

    # 软中断类型映射 - 与内核tracepoint格式保持一致
    SOFTIRQ_NAMES = {
        0: "HI",
        1: "TIMER",
        2: "NET_TX",
        3: "NET_RX",
        4: "BLOCK",
        5: "IRQ_POLL",
        6: "TASKLET",
        7: "SCHED",
        8: "HRTIMER",
        9: "RCU"
    }

    # 中断类型常量
    IRQ_TYPE_HARDWARE = 0x1
    IRQ_TYPE_SOFTWARE = 0x2
    IRQ_TYPE_TIMER = 0x4
    IRQ_TYPE_NETWORK = 0x8
    IRQ_TYPE_BLOCK = 0x10

    @staticmethod
    def irq_type_to_str(irq_type):
        # type: (int) -> str
        """获取中断类型字符串（返回优先级最高的单一类型）"""
        # 优先级：HARDWARE > TIMER > NETWORK > BLOCK > SOFTWARE
        if irq_type & InterruptMonitor.IRQ_TYPE_HARDWARE:
            return "HARD"
        elif irq_type & InterruptMonitor.IRQ_TYPE_SOFTWARE:
            if irq_type & InterruptMonitor.IRQ_TYPE_TIMER:
                return "TIMER"
            elif irq_type & InterruptMonitor.IRQ_TYPE_NETWORK:
                return "NETWORK"
            elif irq_type & InterruptMonitor.IRQ_TYPE_BLOCK:
                return "BLOCK"
            else:
                return "SOFT"
        else:
            return "TYPE_{:X}".format(irq_type)

    # ==================== 格式化方法实现 ====================

    def monitor_csv_header(self):
        # type: () -> List[str]
        """获取CSV头部字段"""
        return ["comm", "irq_type", "irq_type_str", "cpu", "count"]

    def monitor_csv_data(self, data):
        # type: (Dict[str, Any]) -> Dict[str, Any]
        """将事件数据格式化为CSV行数据"""
        return {
            "comm": data["comm"],
            "irq_type": data["irq_type"],
            "irq_type_str": InterruptMonitor.irq_type_to_str(data["irq_type"]),
            "cpu": data["cpu"],
            "count": data["count"]
        }

    def monitor_console_header(self):
        # type: () -> str
        """获取控制台输出的表头"""
        return "{:<16} {:<10} {:<3} {}".format('COMMAND', 'IRQ_TYPE', 'CPU', 'COUNT')

    def monitor_console_data(self, data):
        # type: (Dict[str, Any]) -> str
        """将事件数据格式化为控制台输出"""
        comm = data["comm"] if data["comm"] else "N/A"
        return "{:<16} {:<10} {:<3} {}".format(
            comm,
            InterruptMonitor.irq_type_to_str(data["irq_type"]),
            data["cpu"],
            data["count"]
        )
