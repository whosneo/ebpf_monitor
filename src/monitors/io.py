#!/usr/bin/env python
# encoding: utf-8
"""
IO监控器

负责加载和管理IO监控eBPF程序，收集文件和网络IO性能数据。
支持延迟测量、吞吐量统计、IO模式分析和特定优化。
"""

import ctypes as ct
import time
# 兼容性导入
try:
    from typing import Dict, List, Any
except ImportError:
    from ..utils.py2_compat import Dict, List, Any

from .base import BaseEvent, BaseMonitor
from ..utils.data_processor import DataProcessor
from ..utils.decorators import register_monitor


class IOEvent(BaseEvent):
    """IO事件"""

    _fields_ = [
        ("pid", ct.c_uint32),      # 进程ID
        ("tid", ct.c_uint32),      # 线程ID
        ("fd", ct.c_uint32),       # 文件描述符
        ("io_type", ct.c_uint32),  # IO类型
        ("size", ct.c_uint64),     # IO大小
        ("duration_ns", ct.c_uint64),  # 持续时间(纳秒)
        ("ret_val", ct.c_int64),   # 返回值
        ("cpu", ct.c_uint32),      # CPU编号
        ("comm", ct.c_char * 16),  # 进程名
    ]

    @property
    def duration_us(self):
        # type: () -> float
        """获取IO持续时间（微秒）"""
        return self.duration_ns / 1000.0

    @property
    def duration_ms(self):
        # type: () -> float
        """获取IO持续时间（毫秒）"""
        return self.duration_ns / 1000000.0

    @property
    def type_str(self):
        # type: () -> str
        """获取IO类型字符串"""
        if self.io_type == IOMonitor.IO_TYPE_READ:
            return "READ"
        elif self.io_type == IOMonitor.IO_TYPE_WRITE:
            return "WRITE"
        else:
            return "UNKNOWN"

    @property
    def throughput_mbps(self):
        # type: () -> float
        """获取IO吞吐量（MB/s）"""
        if self.duration_ns == 0:
            return 0.0
        return (self.size / (1024 * 1024)) / (self.duration_ns / 1e9)

    @property
    def is_error(self):
        # type: () -> bool
        """检查是否为错误IO"""
        return self.ret_val < 0


@register_monitor("io")
class IOMonitor(BaseMonitor):
    """IO监控器"""

    EVENT_TYPE = IOEvent

    REQUIRED_TRACEPOINTS = [
        'syscalls:sys_enter_read',
        'syscalls:sys_enter_write'
    ]

    # IO类型常量
    IO_TYPE_READ = 1
    IO_TYPE_WRITE = 2

    @classmethod
    def get_default_config(cls):
        # type: () -> Dict[str, Any]
        """获取默认配置"""
        return {
            "enabled": True,
            "slow_io_threshold_us": 10000,
            "large_io_threshold_kb": 64
        }

    @classmethod
    def validate_monitor_config(cls, config):
        # type: (Dict[str, Any]) -> None
        """验证IO监控器配置"""
        assert config.get("slow_io_threshold_us") is not None, "slow_io_threshold_us不能为空"
        assert isinstance(config.get("slow_io_threshold_us"), int), "slow_io_threshold_us必须为整数"
        assert config.get("slow_io_threshold_us") >= 0, "slow_io_threshold_us必须大于等于0"
        assert config.get("slow_io_threshold_us") <= 20000, "slow_io_threshold_us必须小于等于20000"

        assert config.get("large_io_threshold_kb") is not None, "large_io_threshold_kb不能为空"
        assert isinstance(config.get("large_io_threshold_kb"), int), "large_io_threshold_kb必须为整数"
        assert config.get("large_io_threshold_kb") >= 0, "large_io_threshold_kb必须大于等于0"
        assert config.get("large_io_threshold_kb") <= 1024, "large_io_threshold_kb必须小于等于1024"

    def _initialize(self, config):
        # type: (Dict[str, Any]) -> None
        """初始化IO监控器"""
        # IO性能阈值
        self.slow_io_threshold_us = config.get("slow_io_threshold_us")  # 慢IO阈值（微秒）
        self.large_io_threshold_kb = config.get("large_io_threshold_kb")  # 大IO阈值（KB）

    def _should_handle_event(self, event):
        # type: (IOEvent) -> bool
        """检查是否应该处理事件"""
        if event.duration_us > self.slow_io_threshold_us:
            return True
        if event.size > self.large_io_threshold_kb * 1024:
            return True
        return False

    # ==================== 格式化方法实现 ====================

    def get_csv_header(self):
        # type: () -> List[str]
        """获取CSV头部字段"""
        return ['timestamp', 'time_str', 'io_type', 'type_str', 'fd', 'size', 'duration_ns', 'duration_us', 'throughput_mbps', 'pid', 'tid', 'cpu', 'comm', 'ret_val', 'is_error']

    def format_for_csv(self, event_data):
        # type: (IOEvent) -> Dict[str, Any]
        """将事件数据格式化为CSV行数据"""
        timestamp = self._convert_timestamp(event_data)
        time_str = DataProcessor.format_timestamp(timestamp)
        
        # 处理字节字符串
        comm = DataProcessor.decode_bytes(event_data.comm)
        
        values = [timestamp, time_str, event_data.io_type, event_data.type_str, event_data.fd, event_data.size, event_data.duration_ns, event_data.duration_us, event_data.throughput_mbps, event_data.pid, event_data.tid, event_data.cpu, comm, event_data.ret_val, event_data.is_error]
        
        return dict(zip(self.get_csv_header(), values))

    def get_console_header(self):
        # type: () -> str
        """获取控制台输出的表头"""
        return "{:<22} {:<8} {:<4} {:<8} {:<10} {:<12} {:<8} {:<8} {:<3} {:<16} {:<6}".format(
            'TIME', 'IO_TYPE', 'FD', 'SIZE', 'DURATION', 'THROUGHPUT', 'PID', 'TID', 'CPU', 'COMM', 'RET')

    def format_for_console(self, event_data):
        # type: (IOEvent) -> str
        """将事件数据格式化为控制台输出"""
        timestamp = self._convert_timestamp(event_data)
        time_str = "[{}]".format(DataProcessor.format_timestamp(timestamp))

        # 处理字节字符串
        comm = DataProcessor.decode_bytes(event_data.comm)

        # 格式化大小显示
        if event_data.size >= 1024 * 1024:
            size_str = "{:.1f}MB".format(event_data.size / (1024 * 1024))
        elif event_data.size >= 1024:
            size_str = "{:.1f}KB".format(event_data.size / 1024)
        else:
            size_str = "{}B".format(event_data.size)

        duration_str = "{:.2f}μs".format(event_data.duration_us)

        # 格式化吞吐量显示
        throughput = event_data.throughput_mbps
        if throughput >= 1000:
            throughput_str = "{:.1f}GB/s".format(throughput/1000)
        elif throughput >= 1:
            throughput_str = "{:.1f}MB/s".format(throughput)
        elif throughput >= 0.001:
            throughput_str = "{:.1f}KB/s".format(throughput*1000)
        else:
            throughput_str = "{:.0f}B/s".format(throughput*1000000)

        # 错误标记
        error_mark = "❌" if event_data.is_error else ""

        return "{:<22} {:<8} {:<4} {:<8} {:<10} {:<12} {:<8} {:<8} {:<3} {:<16} {:<6}{}".format(
            time_str, event_data.type_str, event_data.fd, size_str, duration_str, 
            throughput_str, event_data.pid, event_data.tid, event_data.cpu, comm, 
            event_data.ret_val, error_mark)


if __name__ == '__main__':
    """测试模式"""
    import sys
    import time
    from ..utils.application_context import ApplicationContext

    context = ApplicationContext()

    logger = context.get_logger("IOMonitor")
    logger.info("IO监控测试模式")

    monitor = IOMonitor(context, IOMonitor.get_default_config())

    output_controller = context.output_controller
    output_controller.register_monitor("io", monitor)

    if not monitor.load_ebpf_program():
        logger.error("eBPF程序加载失败")
        sys.exit(1)

    output_controller.start()

    if not monitor.run():
        logger.error("IO监控启动失败")
        sys.exit(1)

    logger.info("IO监控已启动")
    logger.info("按 Ctrl+C 停止监控")

    try:
        while monitor.is_running():
            time.sleep(1)
    except KeyboardInterrupt:
        print("")
        logger.info("用户中断，正在停止监控...")
    finally:
        monitor.stop()
        output_controller.stop()
        output_controller.unregister_monitor("io")
        monitor.cleanup()
        output_controller.cleanup()
