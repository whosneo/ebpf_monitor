#!/usr/bin/env python3
# encoding: utf-8
"""
系统调用监控器

监控系统调用执行情况，分析调用模式、性能特征和错误状态。
支持智能分类、性能阈值监控和灵活的过滤策略。
"""

import ctypes as ct
import errno
from enum import Enum
from typing import Dict, List, Any

from bpfcc import syscall  # pyright: ignore[reportMissingImports]

from .base import BaseEvent, BaseMonitor
from ..utils.data_processor import DataProcessor
from ..utils.decorators import register_monitor


class SyscallCategory(Enum):
    """系统调用分类枚举"""
    FILE_IO = "file_io"
    NETWORK = "network"
    MEMORY = "memory"
    PROCESS = "process"
    SIGNAL = "signal"
    TIME = "time"
    UNKNOWN = "unknown"


class SyscallEvent(BaseEvent):
    """系统调用事件"""
    _fields_ = [
        ("pid", ct.c_uint32),          # 进程ID
        ("tid", ct.c_uint32),          # 线程ID
        ("syscall_nr", ct.c_uint32),   # 系统调用号
        ("cpu", ct.c_uint32),          # CPU编号
        ("ret_val", ct.c_int64),       # 返回值
        ("duration_ns", ct.c_uint64),  # 持续时间(纳秒)
        ("comm", ct.c_char * 16),      # 进程名
    ]

    @property
    def duration_us(self) -> float:
        """获取系统调用持续时间（微秒）"""
        return self.duration_ns / 1000.0

    @property
    def duration_ms(self) -> float:
        """获取系统调用持续时间（毫秒）"""
        return self.duration_ns / 1000000.0

    @property
    def category(self) -> SyscallCategory:
        """获取系统调用分类"""
        return SyscallMonitor.classify_syscall(self.syscall_nr)

    @property
    def is_error(self) -> bool:
        """检查是否为错误返回"""
        return self.ret_val < 0

    @property
    def error_name(self) -> str:
        """获取错误名称"""
        if not self.is_error:
            return "SUCCESS"
        error_code = -self.ret_val
        return errno.errorcode.get(error_code, f"ERRNO_{error_code}")

    @property
    def is_slow_call(self) -> bool:
        """是否为慢调用（基于分类的动态阈值）"""
        # 这个方法需要访问Monitor的配置，在format方法中会处理
        return False

    @property
    def is_io_call(self) -> bool:
        """是否为IO调用"""
        return self.category == SyscallCategory.FILE_IO

    @property
    def is_network_call(self) -> bool:
        """是否为网络调用"""
        return self.category == SyscallCategory.NETWORK

    @property
    def is_memory_call(self) -> bool:
        """是否为内存调用"""
        return self.category == SyscallCategory.MEMORY

    @property
    def is_process_call(self) -> bool:
        """是否为进程调用"""
        return self.category == SyscallCategory.PROCESS

    @property
    def is_signal_call(self) -> bool:
        """是否为信号调用"""
        return self.category == SyscallCategory.SIGNAL

    @property
    def is_time_call(self) -> bool:
        """是否为时间调用"""
        return self.category == SyscallCategory.TIME


@register_monitor("syscall")
class SyscallMonitor(BaseMonitor):
    """系统调用监控器"""
    EVENT_TYPE: type = SyscallEvent

    REQUIRED_TRACEPOINTS: List[str] = [
        'raw_syscalls:sys_enter',
        'raw_syscalls:sys_exit'
    ]

    # 系统调用分类映射
    SYSCALL_CATEGORIES = {
        SyscallCategory.FILE_IO: {
            0, 1, 2, 3, 4, 5, 6, 8, 16, 17, 18, 19, 20, 21, 22, 32, 33, 72, 73, 74, 75,
            76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94,
            257, 258, 259, 260, 261, 262, 263, 264, 265, 266, 267, 268, 269, 275, 276,
            277, 278, 280, 285, 292, 293, 294
        },
        SyscallCategory.NETWORK: {
            41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 288
        },
        SyscallCategory.MEMORY: {
            9, 10, 11, 12, 25, 26, 27, 28, 29, 30, 31, 67, 279
        },
        SyscallCategory.PROCESS: {
            56, 57, 58, 59, 60, 61, 62, 101, 105, 106, 109, 110, 111, 112, 113, 114,
            115, 116, 117, 118, 119, 120, 272, 273, 274
        },
        SyscallCategory.SIGNAL: {
            13, 14, 15, 282, 289
        },
        SyscallCategory.TIME: {
            35, 36, 37, 38, 96, 283, 286, 287
        }
    }

    @classmethod
    def classify_syscall(cls, syscall_nr: int) -> SyscallCategory:
        """对系统调用进行分类"""
        for category, syscalls in cls.SYSCALL_CATEGORIES.items():
            if syscall_nr in syscalls:
                return category
        return SyscallCategory.UNKNOWN

    @classmethod
    def get_default_config(cls) -> Dict[str, Any]:
        """获取系统调用监控器默认配置"""
        return {
            "enabled": True,
            "sampling_strategy": "intelligent",  # intelligent/uniform/disabled
            "high_priority_syscalls": [0, 1, 2, 3, 9, 57, 59],  # 高优先级调用
            "monitor_categories": {
                "file_io": True,
                "network": True,
                "memory": True,
                "process": True,
                "signal": False,
                "time": False
            },
            "performance_thresholds": {
                "file_io_ms": 1.0,
                "network_ms": 5.0,
                "memory_ms": 0.5,
                "process_ms": 10.0,
                "default_us": 100
            },
            "max_events_per_second": 1000,
            "show_errors_only": False
        }

    @classmethod
    def validate_monitor_config(cls, config: Dict[str, Any]):
        """验证系统调用监控器配置"""
        assert config.get("sampling_strategy") is not None, "sampling_strategy不能为空"
        assert config.get("sampling_strategy") in ["intelligent", "uniform", "disabled"], "sampling_strategy必须为intelligent/uniform/disabled"
        
        assert config.get("high_priority_syscalls") is not None, "high_priority_syscalls不能为空"
        assert isinstance(config.get("high_priority_syscalls"), list), "high_priority_syscalls必须为列表"
        
        assert config.get("monitor_categories") is not None, "monitor_categories不能为空"
        assert isinstance(config.get("monitor_categories"), dict), "monitor_categories必须为字典"
        
        monitor_categories = config.get("monitor_categories")
        for category in ["file_io", "network", "memory", "process", "signal", "time"]:
            assert category in monitor_categories, f"monitor_categories必须包含{category}"
            assert isinstance(monitor_categories[category], bool), f"monitor_categories.{category}必须为布尔值"
        
        assert config.get("performance_thresholds") is not None, "performance_thresholds不能为空"
        assert isinstance(config.get("performance_thresholds"), dict), "performance_thresholds必须为字典"
        
        thresholds = config.get("performance_thresholds")
        for threshold in ["file_io_ms", "network_ms", "memory_ms", "process_ms", "default_us"]:
            assert threshold in thresholds, f"performance_thresholds必须包含{threshold}"
            assert isinstance(thresholds[threshold], (int, float)), f"performance_thresholds.{threshold}必须为数字"
            assert thresholds[threshold] >= 0, f"performance_thresholds.{threshold}必须大于等于0"
        
        assert config.get("max_events_per_second") is not None, "max_events_per_second不能为空"
        assert isinstance(config.get("max_events_per_second"), int), "max_events_per_second必须为整数"
        assert config.get("max_events_per_second") > 0, "max_events_per_second必须大于0"
        
        assert config.get("show_errors_only") is not None, "show_errors_only不能为空"
        assert isinstance(config.get("show_errors_only"), bool), "show_errors_only必须为布尔值"

    def _initialize(self, config: Dict[str, Any]):
        """初始化系统调用监控器"""
        self.enabled = config.get("enabled")
        
        # 采样策略配置
        self.sampling_strategy = config.get("sampling_strategy")
        self.high_priority_syscalls = set(config.get("high_priority_syscalls"))
        
        # 分类监控配置
        self.monitor_categories = config.get("monitor_categories")
        
        # 性能阈值配置
        self.performance_thresholds = config.get("performance_thresholds")
        
        # 限流配置
        self.max_events_per_second = config.get("max_events_per_second")
        
        # 过滤配置
        self.show_errors_only = config.get("show_errors_only")

    def _should_handle_event(self, event: SyscallEvent) -> bool:
        """检查是否应该处理事件"""
        # 错误过滤
        if self.show_errors_only and not event.is_error:
            return False
        
        # 分类过滤
        category = event.category
        if category == SyscallCategory.FILE_IO and not self.monitor_categories["file_io"]:
            return False
        if category == SyscallCategory.NETWORK and not self.monitor_categories["network"]:
            return False
        if category == SyscallCategory.MEMORY and not self.monitor_categories["memory"]:
            return False
        if category == SyscallCategory.PROCESS and not self.monitor_categories["process"]:
            return False
        if category == SyscallCategory.SIGNAL and not self.monitor_categories["signal"]:
            return False
        if category == SyscallCategory.TIME and not self.monitor_categories["time"]:
            return False
        
        return True

    def _is_slow_call(self, event: SyscallEvent) -> bool:
        """判断是否为慢调用"""
        category = event.category
        if category == SyscallCategory.FILE_IO:
            return event.duration_ms >= self.performance_thresholds["file_io_ms"]
        elif category == SyscallCategory.NETWORK:
            return event.duration_ms >= self.performance_thresholds["network_ms"]
        elif category == SyscallCategory.MEMORY:
            return event.duration_ms >= self.performance_thresholds["memory_ms"]
        elif category == SyscallCategory.PROCESS:
            return event.duration_ms >= self.performance_thresholds["process_ms"]
        else:
            return event.duration_us >= self.performance_thresholds["default_us"]

    # ==================== 格式化方法实现 ====================

    def get_csv_header(self) -> List[str]:
        """获取CSV头部字段"""
        return [
            'timestamp', 'time_str', 'monitor_type', 'pid', 'tid', 'cpu', 'comm',
            'syscall_nr', 'syscall_name', 'category', 'ret_val', 'error_name',
            'duration_ns', 'duration_us', 'duration_ms', 'is_error', 'is_slow_call'
        ]

    def format_for_csv(self, event_data: SyscallEvent) -> Dict[str, Any]:
        """将事件数据格式化为CSV行数据"""
        timestamp = self._convert_timestamp(event_data)
        time_str = DataProcessor.format_timestamp(timestamp)
        
        # 处理字节字符串
        comm = DataProcessor.decode_bytes(event_data.comm)
        syscall_name = DataProcessor.decode_bytes(syscall.syscall_name(event_data.syscall_nr))
        
        # 判断是否为慢调用
        is_slow_call = self._is_slow_call(event_data)
        
        values = [
            timestamp, time_str, self.type, event_data.pid, event_data.tid, event_data.cpu, comm,
            event_data.syscall_nr, syscall_name, event_data.category.value,
            event_data.ret_val, event_data.error_name, event_data.duration_ns,
            event_data.duration_us, event_data.duration_ms, event_data.is_error, is_slow_call
        ]
        
        return dict(zip(self.get_csv_header(), values))

    def get_console_header(self) -> str:
        """获取控制台输出的表头"""
        return f"{'TIME':<22} {'PID':<8} {'TID':<8} {'CPU':<3} {'COMM':<16} {'SYSCALL':<12} {'CATEGORY':<8} {'DURATION':<10} {'RET':<6} {'STATUS'}"

    def format_for_console(self, event_data: SyscallEvent) -> str:
        """将事件数据格式化为控制台输出"""
        timestamp = self._convert_timestamp(event_data)
        time_str = f"[{DataProcessor.format_timestamp(timestamp)}]"

        # 处理字节字符串
        comm = DataProcessor.decode_bytes(event_data.comm)
        syscall_name = DataProcessor.decode_bytes(syscall.syscall_name(event_data.syscall_nr))

        # 格式化持续时间
        if event_data.duration_ms >= 1.0:
            duration_str = f"{event_data.duration_ms:.2f}ms"
        else:
            duration_str = f"{event_data.duration_us:.2f}μs"

        # 状态标记
        status_marks = []
        if event_data.is_error:
            status_marks.append("ERROR")
        if self._is_slow_call(event_data):
            status_marks.append("SLOW")
        
        status_str = "".join(status_marks) if status_marks else "OK"

        return f"{time_str:<22} {event_data.pid:<8} {event_data.tid:<8} {event_data.cpu:<3} {comm:<16} {syscall_name:<12} {event_data.category.value:<8} {duration_str:<10} {event_data.ret_val:<6} {status_str}"


if __name__ == '__main__':
    """测试模式"""
    import sys
    import time
    from ..utils.application_context import ApplicationContext

    context = ApplicationContext()

    logger = context.get_logger("SyscallMonitor")
    logger.info("系统调用监控测试模式")

    monitor = SyscallMonitor(context, SyscallMonitor.get_default_config())

    output_controller = context.output_controller
    output_controller.register_monitor("syscall", monitor)

    if not monitor.load_ebpf_program():
        logger.error("eBPF程序加载失败")
        sys.exit(1)

    output_controller.start()

    if not monitor.run():
        logger.error("系统调用监控启动失败")
        sys.exit(1)

    logger.info("系统调用监控已启动")
    logger.info("按 Ctrl+C 停止监控")

    try:
        while monitor.is_running():
            time.sleep(1)
    except KeyboardInterrupt:
        print()
        logger.info("用户中断，正在停止监控...")
    finally:
        monitor.stop()
        output_controller.stop()
        output_controller.unregister_monitor("syscall")
        monitor.cleanup()
        output_controller.cleanup()