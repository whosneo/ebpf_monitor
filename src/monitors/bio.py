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

支持的分析场景：
- 识别IO密集型进程
- 分析读写比例和模式
- 评估IO延迟和吞吐量
- 检测慢IO问题
"""

# 兼容性导入
try:
    from typing import Dict, List, Any
except ImportError:
    from ..utils.py2_compat import Dict, List, Any

# 本地模块导入
from .base import BaseMonitor
from ..utils.decorators import register_monitor


# ==================== BIO数据处理工具类 ====================

class BioDataUtils(object):
    """
    BIO数据处理工具类
    
    提供IO类型判断、数据计算和格式化功能。
    仅供BioMonitor内部使用。
    """

    # IO类型常量（与C代码保持一致）
    IO_TYPE_READ = 0x1  # R: Read
    IO_TYPE_WRITE = 0x2  # W: Write
    IO_TYPE_SYNC = 0x4  # S: Synchronous
    IO_TYPE_FLUSH = 0x8  # F: Flush
    IO_TYPE_DISCARD = 0x10  # D: Discard/TRIM
    IO_TYPE_METADATA = 0x20  # M: Metadata
    IO_TYPE_READAHEAD = 0x40  # A: Read-ahead
    IO_TYPE_NONE = 0x80  # N: None (barrier/flush without data)

    # 单位转换常量
    NS_TO_US = 1000.0
    US_TO_MS = 1000.0
    US_TO_SECONDS = 1000000.0
    BYTES_TO_KB = 1024.0
    BYTES_TO_MB = 1024.0 * 1024.0
    BYTES_TO_GB = 1024.0 * 1024.0 * 1024.0

    @staticmethod
    def io_type_to_str(io_type):
        # type: (int) -> str
        """将IO类型转换为字符串"""
        types = []
        if io_type & BioDataUtils.IO_TYPE_READ:
            types.append("READ")
        if io_type & BioDataUtils.IO_TYPE_WRITE:
            types.append("WRITE")
        if io_type & BioDataUtils.IO_TYPE_FLUSH:
            types.append("FLUSH")
        if io_type & BioDataUtils.IO_TYPE_DISCARD:
            types.append("DISCARD")
        if io_type & BioDataUtils.IO_TYPE_METADATA:
            types.append("META")
        if io_type & BioDataUtils.IO_TYPE_READAHEAD:
            types.append("READAHEAD")
        if io_type & BioDataUtils.IO_TYPE_NONE:
            types.append("NONE")
        if io_type & BioDataUtils.IO_TYPE_SYNC:
            types.append("SYNC")
        return "|".join(types) if types else "UNKNOWN"

    @staticmethod
    def is_read(io_type):
        # type: (int) -> bool
        """判断是否为读操作"""
        return bool(io_type & BioDataUtils.IO_TYPE_READ)

    @staticmethod
    def is_write(io_type):
        # type: (int) -> bool
        """判断是否为写操作"""
        return bool(io_type & BioDataUtils.IO_TYPE_WRITE)

    @staticmethod
    def is_sync(io_type):
        # type: (int) -> bool
        """判断是否为同步操作"""
        return bool(io_type & BioDataUtils.IO_TYPE_SYNC)

    @staticmethod
    def calc_avg_latency_us(data):
        # type: (Dict[str, Any]) -> float
        """计算平均延迟（微秒）"""
        if data["count"] > 0:
            return (data["total_ns"] / data["count"]) / BioDataUtils.NS_TO_US
        return 0.0

    @staticmethod
    def calc_min_latency_us(data):
        # type: (Dict[str, Any]) -> float
        """获取最小延迟（微秒）"""
        return data["min_ns"] / BioDataUtils.NS_TO_US

    @staticmethod
    def calc_max_latency_us(data):
        # type: (Dict[str, Any]) -> float
        """获取最大延迟（微秒）"""
        return data["max_ns"] / BioDataUtils.NS_TO_US

    @staticmethod
    def calc_size_mb(data):
        # type: (Dict[str, Any]) -> float
        """计算数据量（MB）"""
        return data["total_bytes"] / BioDataUtils.BYTES_TO_MB

    @staticmethod
    def calc_throughput_mbps(data):
        # type: (Dict[str, Any]) -> float
        """计算吞吐量（MB/s）"""
        if data["count"] > 0:
            avg_latency_us = BioDataUtils.calc_avg_latency_us(data)
            if avg_latency_us > 0:
                total_seconds = (data["count"] * avg_latency_us) / BioDataUtils.US_TO_SECONDS
                if total_seconds > 0:
                    return (data["total_bytes"] / BioDataUtils.BYTES_TO_MB) / total_seconds
        return 0.0

    @staticmethod
    def format_bytes(bytes_val):
        # type: (int) -> str
        """格式化字节数为人类可读格式"""
        if bytes_val >= BioDataUtils.BYTES_TO_GB:
            return "{:.1f} GB".format(bytes_val / BioDataUtils.BYTES_TO_GB)
        elif bytes_val >= BioDataUtils.BYTES_TO_MB:
            return "{:.1f} MB".format(bytes_val / BioDataUtils.BYTES_TO_MB)
        elif bytes_val >= BioDataUtils.BYTES_TO_KB:
            return "{:.1f} KB".format(bytes_val / BioDataUtils.BYTES_TO_KB)
        else:
            return "{} B".format(bytes_val)

    @staticmethod
    def format_latency_ms(latency_us):
        # type: (float) -> str
        """格式化延迟为毫秒字符串"""
        return "{:.1f} ms".format(latency_us / BioDataUtils.US_TO_MS)

    @staticmethod
    def format_throughput(throughput_mbps):
        # type: (float) -> str
        """格式化吞吐量"""
        return "{:.1f} MB/s".format(throughput_mbps)


# ==================== BIO监控器 ====================


@register_monitor("bio")
class BioMonitor(BaseMonitor):
    """BIO监控器 - 专注于监控流程管理"""
    REQUIRED_TRACEPOINTS = [  # type: List[str]
        'block:block_rq_issue',
        'block:block_rq_complete'
    ]

    @classmethod
    def get_default_monitor_config(cls):
        # type: () -> Dict[str, Any]
        """获取BIO监控器默认配置"""
        return {
            "min_latency_us": 0  # 最小延迟过滤（微秒，0表示不过滤）
        }

    @classmethod
    def validate_monitor_config(cls, config):
        # type: (Dict[str, Any]) -> None
        """
        验证BIO监控器配置
        
        Args:
            config: 监控器配置字典
            
        Raises:
            ValueError: 配置验证失败时抛出
        """
        if config.get("min_latency_us") is None:
            raise ValueError("BIO监控配置中缺少必需字段: min_latency_us")
        if not isinstance(config.get("min_latency_us"), (int, float)):
            raise ValueError(
                "min_latency_us 必须为数字，当前类型: {}".format(type(config.get("min_latency_us")).__name__))
        if config.get("min_latency_us") < 0:
            raise ValueError("min_latency_us 必须大于等于 0，当前值: {}".format(config.get("min_latency_us")))

    def _initialize(self, config):
        # type: (Dict[str, Any]) -> None
        """初始化BIO监控器"""
        self.min_latency_us = config.get("min_latency_us")  # type: float

    def should_collect(self, key, value):
        # type: (Any, Any) -> bool
        """判断是否应该收集数据"""
        # 计算平均延迟
        avg_ns = value.total_ns / value.count if value.count > 0 else 0

        # 应用延迟过滤
        if self.min_latency_us > 0:
            if avg_ns < self.min_latency_us * BioDataUtils.NS_TO_US:
                return False
        return True

    # ==================== 格式化方法实现 ====================

    def monitor_csv_header(self):
        # type: () -> List[str]
        """获取CSV头部字段"""
        return [
            'comm', 'io_type', 'io_type_str',
            'count', 'total_bytes', 'size_mb',
            'avg_latency_us', 'min_latency_us', 'max_latency_us',
            'throughput_mbps'
        ]

    def monitor_csv_data(self, data):
        # type: (Dict[str, Any]) -> Dict[str, Any]
        """将事件数据格式化为CSV行数据"""
        return {
            "comm": data["comm"],
            "io_type": data["bio_type"],
            "io_type_str": BioDataUtils.io_type_to_str(data["bio_type"]),
            "count": data["count"],
            "total_bytes": data["total_bytes"],
            "size_mb": BioDataUtils.calc_size_mb(data),
            "avg_latency_us": BioDataUtils.calc_avg_latency_us(data),
            "min_latency_us": BioDataUtils.calc_min_latency_us(data),
            "max_latency_us": BioDataUtils.calc_max_latency_us(data),
            "throughput_mbps": BioDataUtils.calc_throughput_mbps(data)
        }

    def monitor_console_header(self):
        # type: () -> str
        """获取控制台输出的表头"""
        return "{:<16} {:<18} {:<8} {:<10} {:<10} {:<10} {:<10} {:<12}".format(
            'COMM', 'IO_TYPE', 'COUNT', 'SIZE',
            'AVG_LAT', 'MIN_LAT', 'MAX_LAT', 'THROUGHPUT')

    def monitor_console_data(self, data):
        # type: (Dict[str, Any]) -> str
        """将事件数据格式化为控制台输出"""
        return "{:<16} {:<18} {:<8} {:<10} {:<10} {:<10} {:<10} {:<12}".format(
            data["comm"],
            BioDataUtils.io_type_to_str(data["bio_type"]),
            data["count"],
            BioDataUtils.format_bytes(data["total_bytes"]),
            BioDataUtils.format_latency_ms(BioDataUtils.calc_avg_latency_us(data)),
            BioDataUtils.format_latency_ms(BioDataUtils.calc_min_latency_us(data)),
            BioDataUtils.format_latency_ms(BioDataUtils.calc_max_latency_us(data)),
            BioDataUtils.format_throughput(BioDataUtils.calc_throughput_mbps(data))
        )
