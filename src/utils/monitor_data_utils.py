#!/usr/bin/env python
# encoding: utf-8
"""
通用监控数据处理工具

提供所有监控器共享的数据处理方法、常量和格式化功能。
消除各监控器工具类中的重复代码，统一数据处理逻辑。

使用方式：
    from utils.monitor_data_utils import MonitorDataUtils
    
    avg_latency = MonitorDataUtils.calc_avg_latency_us(total_ns, count)
    size_str = MonitorDataUtils.format_bytes(bytes_val)
"""

# 兼容性导入
try:
    from typing import Dict, Any, List, Optional
except ImportError:
    from .py2_compat import Dict, Any, List, Optional


class MonitorDataUtils(object):
    """
    通用监控数据处理工具类
    
    提供所有监控器共享的数据处理方法。
    包括：单位转换、延迟计算、数据格式化等。
    """

    # ==================== 单位转换常量 ====================
    
    # 时间单位转换
    NS_TO_US = 1000.0           # 纳秒 -> 微秒
    NS_TO_MS = 1000000.0        # 纳秒 -> 毫秒
    NS_TO_S = 1000000000.0      # 纳秒 -> 秒
    US_TO_MS = 1000.0           # 微秒 -> 毫秒
    US_TO_S = 1000000.0         # 微秒 -> 秒
    MS_TO_S = 1000.0            # 毫秒 -> 秒

    # 数据大小单位转换
    BYTES_TO_KB = 1024.0
    BYTES_TO_MB = 1024.0 * 1024.0
    BYTES_TO_GB = 1024.0 * 1024.0 * 1024.0
    BYTES_TO_TB = 1024.0 * 1024.0 * 1024.0 * 1024.0

    # ==================== 延迟计算方法 ====================

    @staticmethod
    def calc_avg_latency_us(total_ns, count):
        # type: (int, int) -> float
        """计算平均延迟（微秒）"""
        if count > 0:
            return (total_ns / count) / MonitorDataUtils.NS_TO_US
        return 0.0

    @staticmethod
    def calc_avg_latency_ms(total_ns, count):
        # type: (int, int) -> float
        """计算平均延迟（毫秒）"""
        if count > 0:
            return (total_ns / count) / MonitorDataUtils.NS_TO_MS
        return 0.0

    @staticmethod
    def calc_min_latency_us(min_ns):
        # type: (int) -> float
        """获取最小延迟（微秒）"""
        return min_ns / MonitorDataUtils.NS_TO_US

    @staticmethod
    def calc_max_latency_us(max_ns):
        # type: (int) -> float
        """获取最大延迟（微秒）"""
        return max_ns / MonitorDataUtils.NS_TO_US

    @staticmethod
    def calc_total_latency_us(total_ns):
        # type: (int) -> float
        """获取总延迟（微秒）"""
        return total_ns / MonitorDataUtils.NS_TO_US

    # ==================== 数据大小计算方法 ====================

    @staticmethod
    def calc_size_kb(bytes_val):
        # type: (int) -> float
        """计算数据大小（KB）"""
        return bytes_val / MonitorDataUtils.BYTES_TO_KB

    @staticmethod
    def calc_size_mb(bytes_val):
        # type: (int) -> float
        """计算数据大小（MB）"""
        return bytes_val / MonitorDataUtils.BYTES_TO_MB

    @staticmethod
    def calc_size_gb(bytes_val):
        # type: (int) -> float
        """计算数据大小（GB）"""
        return bytes_val / MonitorDataUtils.BYTES_TO_GB

    # ==================== 错误率计算方法 ====================

    @staticmethod
    def calc_error_rate(count, error_count):
        # type: (int, int) -> float
        """计算错误率（百分比）"""
        if count == 0:
            return 0.0
        return (error_count * 100.0) / count

    @staticmethod
    def calc_rate(part, total):
        # type: (int, int) -> float
        """计算占比（百分比）"""
        if total == 0:
            return 0.0
        return (part * 100.0) / total

    # ==================== 吞吐量计算方法 ====================

    @staticmethod
    def calc_throughput_mbps(total_bytes, total_ns):
        # type: (int, int) -> float
        """计算吞吐量（MB/s）"""
        if total_ns > 0:
            total_seconds = total_ns / MonitorDataUtils.NS_TO_S
            if total_seconds > 0:
                return (total_bytes / MonitorDataUtils.BYTES_TO_MB) / total_seconds
        return 0.0

    @staticmethod
    def calc_throughput_ops(count, total_ns):
        # type: (int, int) -> float
        """计算操作吞吐量（ops/s）"""
        if total_ns > 0:
            total_seconds = total_ns / MonitorDataUtils.NS_TO_S
            if total_seconds > 0:
                return count / total_seconds
        return 0.0

    # ==================== 格式化方法 ====================

    @staticmethod
    def format_bytes(bytes_val):
        # type: (int) -> str
        """格式化字节数为人类可读格式"""
        if bytes_val >= MonitorDataUtils.BYTES_TO_TB:
            return "{:.1f} TB".format(bytes_val / MonitorDataUtils.BYTES_TO_TB)
        elif bytes_val >= MonitorDataUtils.BYTES_TO_GB:
            return "{:.1f} GB".format(bytes_val / MonitorDataUtils.BYTES_TO_GB)
        elif bytes_val >= MonitorDataUtils.BYTES_TO_MB:
            return "{:.1f} MB".format(bytes_val / MonitorDataUtils.BYTES_TO_MB)
        elif bytes_val >= MonitorDataUtils.BYTES_TO_KB:
            return "{:.1f} KB".format(bytes_val / MonitorDataUtils.BYTES_TO_KB)
        else:
            return "{} B".format(bytes_val)

    @staticmethod
    def format_latency_us(latency_us):
        # type: (float) -> str
        """格式化延迟为人类可读格式（自动选择单位）"""
        if latency_us >= MonitorDataUtils.US_TO_MS:
            return "{:.1f} ms".format(latency_us / MonitorDataUtils.US_TO_MS)
        else:
            return "{:.1f} us".format(latency_us)

    @staticmethod
    def format_latency_ms(latency_us):
        # type: (float) -> str
        """格式化延迟为毫秒字符串"""
        return "{:.1f} ms".format(latency_us / MonitorDataUtils.US_TO_MS)

    @staticmethod
    def format_throughput(throughput_mbps):
        # type: (float) -> str
        """格式化吞吐量"""
        return "{:.1f} MB/s".format(throughput_mbps)

    @staticmethod
    def format_percentage(value):
        # type: (float) -> str
        """格式化百分比"""
        return "{:.1f}%".format(value)

    @staticmethod
    def format_count(count):
        # type: (int) -> str
        """格式化计数（大数字添加千位分隔符）"""
        if count >= 1000000:
            return "{:.1f}M".format(count / 1000000.0)
        elif count >= 1000:
            return "{:.1f}K".format(count / 1000.0)
        else:
            return str(count)

    @staticmethod
    def format_error_count(error_count, error_rate):
        # type: (int, float) -> str
        """格式化错误计数（包含错误率）"""
        if error_count > 0:
            return "{} ({:.0f}%)".format(error_count, error_rate)
        else:
            return "0"

    # ==================== 通用计算方法 ====================

    @staticmethod
    def calc_total(data, key1, key2):
        # type: (Dict[str, Any], str, str) -> int
        """计算两个字段的总和"""
        return data.get(key1, 0) + data.get(key2, 0)

    @staticmethod
    def safe_divide(numerator, denominator):
        # type: (float, float) -> float
        """安全除法，避免除零错误"""
        if denominator == 0:
            return 0.0
        return numerator / denominator
