#!/usr/bin/env python
# encoding: utf-8
"""
页面错误监控器

负责加载和管理页面错误监控eBPF程序，统计页面错误频率和模式。
采用统计模式，在内核态累积页面错误次数，定期批量输出，避免高频事件导致的数据丢失。

统计维度：
- (进程名, 错误类型, CPU) -> 次数

支持的错误类型（通过error_code检测）：
- MAJOR (0x2): 页面不在内存，需要从磁盘加载
- MINOR (0x1): 页面在内存，权限问题
- WRITE (0x4): 写访问导致的错误
- USER (0x8): 用户空间错误

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


# ==================== 页面错误常量定义 ====================

# 页面错误类型常量（与C代码保持一致）
FAULT_TYPE_MINOR = 0x1  # 次要页面错误（页面在内存，权限问题）
FAULT_TYPE_MAJOR = 0x2  # 主要页面错误（页面不在内存，需要加载）
FAULT_TYPE_WRITE = 0x4  # 写错误（写访问导致的错误）
FAULT_TYPE_USER = 0x8   # 用户空间错误（用户模式访问）


def fault_type_to_str(fault_type):
    # type: (int) -> str
    """获取错误类型字符串（显式显示所有维度）"""
    types = []

    # 维度1：MAJOR vs MINOR
    if fault_type & FAULT_TYPE_MINOR:
        types.append("MINOR")
    elif fault_type & FAULT_TYPE_MAJOR:
        types.append("MAJOR")
    else:
        types.append("UNKNOWN")

    # 维度2：WRITE vs READ（显式）
    if fault_type & FAULT_TYPE_WRITE:
        types.append("WRITE")
    else:
        types.append("READ")

    # 维度3：USER vs KERNEL（显式）
    if fault_type & FAULT_TYPE_USER:
        types.append("USER")
    else:
        types.append("KERNEL")

    return "|".join(types)


def is_major_fault(fault_type):
    # type: (int) -> bool
    """是否为主要页面错误"""
    return bool(fault_type & FAULT_TYPE_MAJOR)


def is_minor_fault(fault_type):
    # type: (int) -> bool
    """是否为次要页面错误"""
    return bool(fault_type & FAULT_TYPE_MINOR)


def is_write_fault(fault_type):
    # type: (int) -> bool
    """是否为写错误"""
    return bool(fault_type & FAULT_TYPE_WRITE)


def is_user_fault(fault_type):
    # type: (int) -> bool
    """是否为用户空间错误"""
    return bool(fault_type & FAULT_TYPE_USER)


# ==================== PageFault监控器 ====================


@register_monitor("page_fault")
class PageFaultMonitor(BaseMonitor):
    """页面错误监控器 - 统计聚合模式
    
    监控页面错误，统计错误类型分布和NUMA节点分布。
    """
    REQUIRED_TRACEPOINTS = [  # type: List[str]
        "exceptions:page_fault_user",
        "exceptions:page_fault_kernel"
    ]

    def _get_numa_node(self, cpu):
        # type: (int) -> int
        """根据CPU编号获取NUMA节点"""
        return self.cpu_to_numa.get(cpu, -1)

    CSV_COLUMNS = [
        ("comm", "comm"),
        ("fault_type", "fault_type"),
        ("fault_type_str", "fault_type", fault_type_to_str),
        ("cpu", "cpu"),
        ("numa_node", "cpu", _get_numa_node),
        ("count", "count"),
    ]

    CONSOLE_FORMAT = (
        "{:<16} {:<22} {:<3} {:<4} {:<10}",
        [
            "comm",
            ("fault_type", fault_type_to_str),
            "cpu",
            ("cpu", _get_numa_node),
            "count",
        ],
    )

    def _initialize(self, config):
        # type: (Dict[str, Any]) -> None
        """初始化页面错误监控器"""
        self.cpu_to_numa = {}  # type: Dict[int, int]
        self._init_numa_mapping()

    def _init_numa_mapping(self):
        """初始化CPU到NUMA节点的映射"""
        import os

        if not os.path.exists('/sys/devices/system/node'):
            self.logger.debug("系统不支持NUMA或未检测到NUMA节点")
            return

        try:
            for node_dir in os.listdir('/sys/devices/system/node'):
                if node_dir.startswith('node'):
                    node_id = int(node_dir[4:])
                    cpulist_file = '/sys/devices/system/node/{}/cpulist'.format(node_dir)
                    if os.path.exists(cpulist_file):
                        with open(cpulist_file) as f:
                            cpulist = f.read().strip()
                            for cpu in self._parse_cpulist(cpulist):
                                self.cpu_to_numa[cpu] = node_id

            if self.cpu_to_numa:
                self.logger.info("检测到NUMA系统，已加载CPU到NUMA节点映射")
        except Exception as e:
            self.logger.warning("加载NUMA映射失败: {}".format(e))

    def _parse_cpulist(self, cpulist):
        """解析CPU列表字符串，如 '0-3,8-11' """
        cpus = []
        for part in cpulist.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                cpus.extend(range(start, end + 1))
            else:
                cpus.append(int(part))
        return cpus
