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

支持的分析场景：
- 识别内存密集型进程和页面错误模式
- 分析MAJOR页面错误（涉及磁盘I/O）的来源
- 分析页面错误在各CPU和NUMA节点上的分布
- 区分用户空间和内核空间的页面错误
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


# ==================== PageFault数据处理工具类 ====================

class PageFaultDataUtils(object):
    """
    PageFault数据处理工具类
    
    提供页面错误类型判断和格式化功能。
    仅供PageFaultMonitor内部使用。
    """

    # 页面错误类型常量（与C代码保持一致）
    FAULT_TYPE_MINOR = 0x1  # 次要页面错误（页面在内存，权限问题）
    FAULT_TYPE_MAJOR = 0x2  # 主要页面错误（页面不在内存，需要加载）
    FAULT_TYPE_WRITE = 0x4  # 写错误（写访问导致的错误）
    FAULT_TYPE_USER = 0x8  # 用户空间错误（用户模式访问）

    @staticmethod
    def fault_type_to_str(fault_type):
        # type: (int) -> str
        """获取错误类型字符串（显式显示所有维度）"""
        types = []

        # 维度1：MAJOR vs MINOR
        if fault_type & PageFaultDataUtils.FAULT_TYPE_MINOR:
            types.append("MINOR")
        elif fault_type & PageFaultDataUtils.FAULT_TYPE_MAJOR:
            types.append("MAJOR")
        else:
            types.append("UNKNOWN")

        # 维度2：WRITE vs READ（显式）
        if fault_type & PageFaultDataUtils.FAULT_TYPE_WRITE:
            types.append("WRITE")
        else:
            types.append("READ")

        # 维度3：USER vs KERNEL（显式）
        if fault_type & PageFaultDataUtils.FAULT_TYPE_USER:
            types.append("USER")
        else:
            types.append("KERNEL")

        return "|".join(types)

    @staticmethod
    def is_major_fault(fault_type):
        # type: (int) -> bool
        """是否为主要页面错误"""
        return bool(fault_type & PageFaultDataUtils.FAULT_TYPE_MAJOR)

    @staticmethod
    def is_minor_fault(fault_type):
        # type: (int) -> bool
        """是否为次要页面错误"""
        return bool(fault_type & PageFaultDataUtils.FAULT_TYPE_MINOR)

    @staticmethod
    def is_write_fault(fault_type):
        # type: (int) -> bool
        """是否为写错误"""
        return bool(fault_type & PageFaultDataUtils.FAULT_TYPE_WRITE)

    @staticmethod
    def is_read_fault(fault_type):
        # type: (int) -> bool
        """是否为读错误（即非写错误）"""
        return not PageFaultDataUtils.is_write_fault(fault_type)

    @staticmethod
    def is_user_fault(fault_type):
        # type: (int) -> bool
        """是否为用户空间错误"""
        return bool(fault_type & PageFaultDataUtils.FAULT_TYPE_USER)

    @staticmethod
    def is_kernel_fault(fault_type):
        # type: (int) -> bool
        """是否为内核空间错误（即非用户空间）"""
        return not PageFaultDataUtils.is_user_fault(fault_type)


# ==================== PageFault监控器 ====================


@register_monitor("page_fault")
class PageFaultMonitor(BaseMonitor):
    """页面错误监控器 - 专注于监控流程管理"""
    REQUIRED_TRACEPOINTS = [  # type: List[str]
        "exceptions:page_fault_user",
        "exceptions:page_fault_kernel"
    ]

    def _initialize(self, config):
        # type: (Dict[str, Any]) -> None
        """初始化页面错误监控器"""
        # NUMA节点映射
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

    # ==================== 格式化方法实现 ====================

    def monitor_csv_header(self):
        # type: () -> List[str]
        """获取CSV头部字段"""
        return [
            "comm", "fault_type", "fault_type_str",
            "cpu", "numa_node", "count"
        ]

    def monitor_csv_data(self, data):
        # type: (Dict[str, Any]) -> Dict[str, Any]
        """将事件数据格式化为CSV行数据"""
        return {
            "comm": data["comm"],
            "fault_type": data["fault_type"],
            "fault_type_str": PageFaultDataUtils.fault_type_to_str(data["fault_type"]),
            "cpu": data["cpu"],
            "numa_node": self.cpu_to_numa.get(data["cpu"], -1),
            "count": data["count"]
        }

    def monitor_console_header(self):
        # type: () -> str
        """获取控制台输出的表头"""
        return "{:<16} {:<22} {:<3} {:<4} {:<10}".format(
            "COMM", "FAULT_TYPE", "CPU", "NUMA", "COUNT")

    def monitor_console_data(self, data):
        # type: (Dict[str, Any]) -> str
        """将事件数据格式化为控制台输出"""
        return "{:<16} {:<22} {:<3} {:<4} {:<10}".format(
            data["comm"],
            PageFaultDataUtils.fault_type_to_str(data["fault_type"]),
            data["cpu"],
            self.cpu_to_numa.get(data["cpu"], -1),
            data["count"]
        )
