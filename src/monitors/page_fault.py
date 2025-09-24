#!/usr/bin/env python3
# encoding: utf-8
"""
页面错误监控器

监控系统页面错误事件，分析内存访问模式和性能瓶颈。
支持主要/次要页面错误监控、延迟分析和内存压力评估。
"""

import ctypes as ct
from typing import Dict, List, Any

from .base import BaseEvent, BaseMonitor
from ..utils.data_processor import DataProcessor
from ..utils.decorators import register_monitor


class PageFaultEvent(BaseEvent):
    """页面错误事件"""
    _fields_ = [
        ("pid", ct.c_uint32),          # 进程ID
        ("tid", ct.c_uint32),          # 线程ID
        ("comm", ct.c_char * 16),      # 进程名
        ("address", ct.c_uint64),      # 内存地址
        ("fault_type", ct.c_uint32),   # 错误类型
        ("cpu", ct.c_uint32),          # CPU编号
    ]

    @property
    def fault_type_str(self) -> str:
        """获取错误类型字符串"""
        types = []
        if self.fault_type & PageFaultMonitor.FAULT_TYPE_MINOR:
            types.append("MINOR")
        if self.fault_type & PageFaultMonitor.FAULT_TYPE_MAJOR:
            types.append("MAJOR")
        if self.fault_type & PageFaultMonitor.FAULT_TYPE_WRITE:
            types.append("WRITE")
        if self.fault_type & PageFaultMonitor.FAULT_TYPE_USER:
            types.append("USER")
        if self.fault_type & PageFaultMonitor.FAULT_TYPE_SHARED:
            types.append("SHARED")
        if self.fault_type & PageFaultMonitor.FAULT_TYPE_SWAP:
            types.append("SWAP")
        return "|".join(types) if types else "UNKNOWN"

    @property
    def is_major_fault(self) -> bool:
        """是否为主要页面错误"""
        return bool(self.fault_type & PageFaultMonitor.FAULT_TYPE_MAJOR)

    @property
    def is_minor_fault(self) -> bool:
        """是否为次要页面错误"""
        return bool(self.fault_type & PageFaultMonitor.FAULT_TYPE_MINOR)

    @property
    def is_write_fault(self) -> bool:
        """是否为写错误"""
        return bool(self.fault_type & PageFaultMonitor.FAULT_TYPE_WRITE)

    @property
    def is_user_fault(self) -> bool:
        """是否为用户空间错误"""
        return bool(self.fault_type & PageFaultMonitor.FAULT_TYPE_USER)

    @property
    def is_shared_fault(self) -> bool:
        """是否为共享内存错误"""
        return bool(self.fault_type & PageFaultMonitor.FAULT_TYPE_SHARED)

    @property
    def address_hex(self) -> str:
        """获取格式化的内存地址"""
        return f"0x{self.address:x}"


@register_monitor("page_fault")
class PageFaultMonitor(BaseMonitor):
    """页面错误监控器"""
    EVENT_TYPE: type = PageFaultEvent

    REQUIRED_TRACEPOINTS: List[str] = [
        'exceptions:page_fault_user',
        'exceptions:page_fault_kernel'
    ]

    # 页面错误类型常量（与C代码保持一致）
    FAULT_TYPE_MINOR = 0x1
    FAULT_TYPE_MAJOR = 0x2
    FAULT_TYPE_WRITE = 0x4
    FAULT_TYPE_USER = 0x8
    FAULT_TYPE_SHARED = 0x10
    FAULT_TYPE_SWAP = 0x8000

    # 内存压力级别常量
    PRESSURE_NONE = 0
    PRESSURE_LOW = 1
    PRESSURE_MEDIUM = 2
    PRESSURE_HIGH = 3

    @classmethod
    def get_default_config(cls) -> Dict[str, Any]:
        """获取页面错误监控器默认配置"""
        return {
            "enabled": True,
            "monitor_major_faults": True,          # 是否监控主要页面错误
            "monitor_minor_faults": True,          # 是否监控次要页面错误
            "monitor_write_faults": True,          # 是否监控写错误
            "monitor_user_faults": True,           # 是否监控用户空间错误
            "monitor_kernel_faults": False         # 是否监控内核空间错误
        }

    @classmethod
    def validate_monitor_config(cls, config: Dict[str, Any]):
        """验证页面错误监控器配置"""
        # 验证监控开关配置
        assert config.get("monitor_major_faults") is not None, "monitor_major_faults不能为空"
        assert isinstance(config.get("monitor_major_faults"), bool), "monitor_major_faults必须为布尔值"

        assert config.get("monitor_minor_faults") is not None, "monitor_minor_faults不能为空"
        assert isinstance(config.get("monitor_minor_faults"), bool), "monitor_minor_faults必须为布尔值"

        assert config.get("monitor_write_faults") is not None, "monitor_write_faults不能为空"
        assert isinstance(config.get("monitor_write_faults"), bool), "monitor_write_faults必须为布尔值"

        assert config.get("monitor_user_faults") is not None, "monitor_user_faults不能为空"
        assert isinstance(config.get("monitor_user_faults"), bool), "monitor_user_faults必须为布尔值"

        assert config.get("monitor_kernel_faults") is not None, "monitor_kernel_faults不能为空"
        assert isinstance(config.get("monitor_kernel_faults"), bool), "monitor_kernel_faults必须为布尔值"

    def _initialize(self, config: Dict[str, Any]):
        """初始化页面错误监控器"""
        self.enabled = config.get("enabled")
        
        # 监控开关配置
        self.monitor_major_faults = config.get("monitor_major_faults")
        self.monitor_minor_faults = config.get("monitor_minor_faults")
        self.monitor_write_faults = config.get("monitor_write_faults")
        self.monitor_user_faults = config.get("monitor_user_faults")
        self.monitor_kernel_faults = config.get("monitor_kernel_faults")

    def _should_handle_event(self, event: PageFaultEvent) -> bool:
        """检查是否应该处理事件"""
        # 根据错误类型过滤
        if event.is_major_fault and not self.monitor_major_faults:
            return False
        if event.is_minor_fault and not self.monitor_minor_faults:
            return False
        if event.is_write_fault and not self.monitor_write_faults:
            return False
        if event.is_user_fault and not self.monitor_user_faults:
            return False
        # 内核错误过滤（基于是否为用户错误来判断）
        if not event.is_user_fault and not self.monitor_kernel_faults:
            return False

        return True

    def _is_high_latency_event(self, event: PageFaultEvent) -> bool:
        """判断是否为高延迟事件"""
        return event.duration_us >= self.high_latency_threshold_us

    # ==================== 格式化方法实现 ====================

    def get_csv_header(self) -> List[str]:
        """获取CSV头部字段"""
        return [
            'timestamp', 'time_str', 'pid', 'tid', 'comm', 
            'address', 'address_hex', 'fault_type', 'fault_type_str', 
            'cpu', 'is_major_fault', 'is_minor_fault', 'is_write_fault', 'is_user_fault'
        ]

    def format_for_csv(self, event_data: PageFaultEvent) -> Dict[str, Any]:
        """将事件数据格式化为CSV行数据"""
        timestamp = self._convert_timestamp(event_data)
        time_str = DataProcessor.format_timestamp(timestamp)
        
        # 处理字节字符串
        comm = DataProcessor.decode_bytes(event_data.comm)
        
        values = [
            timestamp, time_str, event_data.pid, event_data.tid, comm,
            event_data.address, event_data.address_hex, event_data.fault_type, event_data.fault_type_str,
            event_data.cpu, event_data.is_major_fault, event_data.is_minor_fault, 
            event_data.is_write_fault, event_data.is_user_fault
        ]
        
        return dict(zip(self.get_csv_header(), values))

    def get_console_header(self) -> str:
        """获取控制台输出的表头"""
        return f"{'TIME':<22} {'PID':<8} {'TID':<8} {'COMM':<16} {'CPU':<3} {'ADDRESS':<18} {'FAULT_TYPE':<12}"

    def format_for_console(self, event_data: PageFaultEvent) -> str:
        """将事件数据格式化为控制台输出"""
        timestamp = self._convert_timestamp(event_data)
        time_str = f"[{DataProcessor.format_timestamp(timestamp)}]"

        # 处理字节字符串
        comm = DataProcessor.decode_bytes(event_data.comm)
        
        # 简化的错误类型显示
        if event_data.is_major_fault:
            fault_type_display = "MAJOR"
        elif event_data.is_minor_fault:
            fault_type_display = "MINOR"
        else:
            fault_type_display = "UNKNOWN"
            
        if event_data.is_write_fault:
            fault_type_display += "|WRITE"
        if event_data.is_user_fault:
            fault_type_display += "|USER"

        return f"{time_str:<22} {event_data.pid:<8} {event_data.tid:<8} {comm:<16} {event_data.cpu:<3} {event_data.address_hex:<18} {fault_type_display:<12}"


if __name__ == '__main__':
    """测试模式"""
    import sys
    import time
    from ..utils.application_context import ApplicationContext

    context = ApplicationContext()

    logger = context.get_logger("PageFaultMonitor")
    logger.info("页面错误监控测试模式")

    monitor = PageFaultMonitor(context, PageFaultMonitor.get_default_config())

    output_controller = context.output_controller
    output_controller.register_monitor("page_fault", monitor)

    if not monitor.load_ebpf_program():
        logger.error("eBPF程序加载失败")
        sys.exit(1)

    output_controller.start()

    if not monitor.run():
        logger.error("页面错误监控启动失败")
        sys.exit(1)

    logger.info("页面错误监控已启动")
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
        output_controller.unregister_monitor("page_fault")
        monitor.cleanup()
        output_controller.cleanup()