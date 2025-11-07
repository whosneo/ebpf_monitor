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

支持的分析场景：
- 识别热点文件（哪些文件被频繁打开）
- 识别IO密集型进程
- 分析文件打开模式和成功率
- 评估文件打开延迟

过滤机制：
- 默认监控所有进程和用户
- 自动过滤内核线程（PID=0）
"""

# 兼容性导入
try:
    from typing import Dict, List, Any
except ImportError:
    from ..utils.py2_compat import Dict, List, Any

# 本地模块导入
from .base import BaseMonitor
from ..utils.decorators import register_monitor


# ==================== Open数据处理工具类 ====================

class OpenDataUtils(object):
    """
    Open数据处理工具类
    
    提供操作类型判断、数据计算和格式化功能。
    仅供OpenMonitor内部使用。
    """

    # 操作类型常量（与C代码保持一致）
    OP_OPEN = 0
    OP_OPENAT = 1

    # 单位转换常量
    NS_TO_US = 1000.0
    US_TO_MS = 1000.0

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

    @staticmethod
    def operation_to_str(operation):
        # type: (int) -> str
        """将操作类型转换为字符串"""
        if operation == OpenDataUtils.OP_OPEN:
            return "OPEN"
        elif operation == OpenDataUtils.OP_OPENAT:
            return "OPENAT"
        else:
            return "UNKNOWN"

    @staticmethod
    def calc_avg_latency_us(data):
        # type: (Dict[str, Any]) -> float
        """计算平均延迟（微秒）"""
        if data["count"] > 0:
            return (data["total_latency_ns"] / data["count"]) / OpenDataUtils.NS_TO_US
        return 0.0

    @staticmethod
    def calc_min_latency_us(data):
        # type: (Dict[str, Any]) -> float
        """获取最小延迟（微秒）"""
        return data["min_latency_ns"] / OpenDataUtils.NS_TO_US

    @staticmethod
    def calc_max_latency_us(data):
        # type: (Dict[str, Any]) -> float
        """获取最大延迟（微秒）"""
        return data["max_latency_ns"] / OpenDataUtils.NS_TO_US

    @staticmethod
    def calc_error_rate(data):
        # type: (Dict[str, Any]) -> float
        """计算错误率（百分比）"""
        if data["count"] == 0:
            return 0.0
        return (data["error_count"] * 100.0) / data["count"]

    @staticmethod
    def parse_flags(flags):
        # type: (int) -> str
        """解析并显示文件打开标志位（显示主要标志）"""
        parts = []

        # 访问模式（互斥）
        access_mode = flags & 0x3
        if access_mode == OpenDataUtils.O_RDONLY:
            parts.append("RD")
        elif access_mode == OpenDataUtils.O_WRONLY:
            parts.append("WR")
        elif access_mode == OpenDataUtils.O_RDWR:
            parts.append("RW")

        # 创建和修改标志
        if flags & OpenDataUtils.O_CREAT:
            parts.append("CR")
        if flags & OpenDataUtils.O_EXCL:
            parts.append("EX")
        if flags & OpenDataUtils.O_TRUNC:
            parts.append("TR")
        if flags & OpenDataUtils.O_APPEND:
            parts.append("AP")

        # 特殊行为标志
        if flags & OpenDataUtils.O_DIRECTORY:
            parts.append("DIR")
        if flags & OpenDataUtils.O_CLOEXEC:
            parts.append("CLO")

        return "|".join(parts) if parts else "0x{:X}".format(flags)

    @staticmethod
    def format_latency(latency_us):
        # type: (float) -> str
        """格式化延迟为人类可读格式"""
        if latency_us >= 1000:
            return "{:.1f} ms".format(latency_us / OpenDataUtils.US_TO_MS)
        else:
            return "{:.1f} us".format(latency_us)

    @staticmethod
    def format_error_count(error_count, error_rate):
        # type: (int, float) -> str
        """格式化错误计数"""
        if error_count > 0:
            return "{} ({:.0f}%)".format(error_count, error_rate)
        else:
            return "0"


# ==================== Open监控器 ====================


@register_monitor("open")
class OpenMonitor(BaseMonitor):
    """文件打开监控器 - 专注于监控流程管理"""
    REQUIRED_TRACEPOINTS = [  # type: List[str]
        "syscalls:sys_enter_open",
        "syscalls:sys_exit_open",
        "syscalls:sys_enter_openat",
        "syscalls:sys_exit_openat",
    ]

    @classmethod
    def get_default_monitor_config(cls):
        # type: () -> Dict[str, Any]
        """获取open监控器默认配置"""
        return {
            "min_count": 1,  # 最小访问次数过滤
            "show_errors_only": False  # 只显示有错误的操作
        }

    @classmethod
    def validate_monitor_config(cls, config):
        # type: (Dict[str, Any]) -> None
        """
        验证open监控器配置
        
        Args:
            config: 监控器配置字典
            
        Raises:
            ValueError: 配置验证失败时抛出
        """
        if config.get("min_count") is None:
            raise ValueError("open监控配置中缺少必需字段: min_count")
        if not isinstance(config.get("min_count"), int):
            raise ValueError("min_count 必须为整数，当前类型: {}".format(type(config.get("min_count")).__name__))
        if config.get("min_count") < 0:
            raise ValueError("min_count 必须大于等于 0，当前值: {}".format(config.get("min_count")))

        if config.get("show_errors_only") is None:
            raise ValueError("open监控配置中缺少必需字段: show_errors_only")
        if not isinstance(config.get("show_errors_only"), bool):
            raise ValueError(
                "show_errors_only 必须为布尔值，当前类型: {}".format(type(config.get("show_errors_only")).__name__))

    def _initialize(self, config):
        # type: (Dict[str, Any]) -> None
        """初始化open监控器"""
        self.min_count = config.get("min_count")  # type: int
        self.show_errors_only = config.get("show_errors_only")  # type: bool

    def should_collect(self, key, value):
        # type: (Dict[str, Any], Dict[str, Any]) -> bool
        """是否收集数据"""
        # 应用过滤：最小计数
        if value.count < self.min_count:
            return False
        # 应用过滤：只显示错误
        if self.show_errors_only and value.error_count == 0:
            return False
        return True

    # ==================== 格式化方法实现 ====================

    def monitor_csv_header(self):
        # type: () -> List[str]
        """获取CSV头部字段"""
        return [
            "comm", "operation", "filename",
            "count", "errors", "error_rate", "avg_lat_us", "min_lat_us",
            "max_lat_us", "flags"
        ]

    def monitor_csv_data(self, data):
        # type: (Dict[str, Any]) -> Dict[str, Any]
        """将事件数据格式化为CSV行数据"""
        return {
            "comm": data["comm"],
            "operation": OpenDataUtils.operation_to_str(data["operation"]),
            "filename": data["filename"],
            "count": data["count"],
            "errors": data["error_count"],
            "error_rate": OpenDataUtils.calc_error_rate(data),
            "avg_lat_us": OpenDataUtils.calc_avg_latency_us(data),
            "min_lat_us": OpenDataUtils.calc_min_latency_us(data),
            "max_lat_us": OpenDataUtils.calc_max_latency_us(data),
            "flags": OpenDataUtils.parse_flags(data["flags_summary"])
        }

    def monitor_console_header(self):
        # type: () -> str
        """获取控制台输出的表头"""
        return "{:<16} {:<8} {:<40} {:<8} {:<8} {:<10} {:<10}".format(
            "COMM", "OP", "FILENAME", "COUNT", "ERRORS", "AVG_LAT", "FLAGS")

    def monitor_console_data(self, data):
        # type: (Dict[str, Any]) -> str
        """将事件数据格式化为控制台输出"""
        # 截断文件名显示
        filename = data["filename"]
        if len(filename) > 40:
            filename = filename[:37] + "..."

        # 格式化输出
        return "{:<16} {:<8} {:<40} {:<8} {:<8} {:<10} {:<10}".format(
            data["comm"],
            OpenDataUtils.operation_to_str(data["operation"]),
            filename,
            data["count"],
            OpenDataUtils.format_error_count(data["error_count"], OpenDataUtils.calc_error_rate(data)),
            OpenDataUtils.format_latency(OpenDataUtils.calc_avg_latency_us(data)),
            OpenDataUtils.parse_flags(data["flags_summary"])
        )
