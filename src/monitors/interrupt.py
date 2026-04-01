#!/usr/bin/env python
# encoding: utf-8
"""
中断监控器

负责加载和管理中断监控eBPF程序，统计硬件中断和软中断频率。
采用统计模式，在内核态累积中断次数，定期批量输出，避免高频中断导致的事件丢失。

统计维度：
- 单表全维度统计：按 (进程名, 中断类型, CPU) 聚合

模式：STATISTICAL（统计聚合）
"""

# 兼容性导入
try:
    from typing import Dict, List, Any
except ImportError:
    from ..utils.py2_compat import Dict, List, Any

# 本地模块导入
from .base import BaseMonitor
from ..utils.decorators import register_monitor


# ==================== 中断常量定义 ====================

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


def irq_type_to_str(irq_type):
    # type: (int) -> str
    """获取中断类型字符串（返回优先级最高的单一类型）"""
    # 优先级：HARDWARE > TIMER > NETWORK > BLOCK > SOFTWARE
    if irq_type & IRQ_TYPE_HARDWARE:
        return "HARD"
    elif irq_type & IRQ_TYPE_SOFTWARE:
        if irq_type & IRQ_TYPE_TIMER:
            return "TIMER"
        elif irq_type & IRQ_TYPE_NETWORK:
            return "NETWORK"
        elif irq_type & IRQ_TYPE_BLOCK:
            return "BLOCK"
        else:
            return "SOFT"
    else:
        return "TYPE_{:X}".format(irq_type)


# ==================== 中断监控器 ====================


@register_monitor("interrupt")
class InterruptMonitor(BaseMonitor):
    """中断监控器 - 统计聚合模式
    
    监控硬件中断和软中断，统计中断频率和分布。
    """
    REQUIRED_TRACEPOINTS = [  # type: List[str]
        "irq:irq_handler_exit",
        "irq:softirq_exit",
    ]

    CSV_COLUMNS = [
        ("comm", "comm"),
        ("irq_type", "irq_type"),
        ("irq_type_str", "irq_type", irq_type_to_str),
        ("cpu", "cpu"),
        ("count", "count"),
    ]

    CONSOLE_FORMAT = (
        "{:<16} {:<10} {:<3} {}",
        [("comm", lambda v: v if v else "N/A"), ("irq_type", irq_type_to_str), "cpu", "count"],
    )
