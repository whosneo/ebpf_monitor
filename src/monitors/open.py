#!/usr/bin/env python3
# encoding: utf-8
"""
文件操作监控器

监控文件打开和访问操作。
"""

import ctypes as ct
from typing import Dict, List, Any

from .base import BaseMonitor, BaseEvent
from ..utils.data_processor import DataProcessor
from ..utils.decorators import register_monitor


class OpenEvent(BaseEvent):
    """文件打开事件"""
    _fields_ = [
        ("pid", ct.c_uint32),      # 进程ID
        ("tid", ct.c_uint32),      # 线程ID
        ("uid", ct.c_uint32),      # 用户ID
        ("flags", ct.c_int),       # 打开标志
        ("mode", ct.c_int),        # 文件权限
        ("ret", ct.c_int32),       # 返回值（文件描述符或错误码）
        ("cpu", ct.c_uint32),      # CPU编号
        ("type", ct.c_int),        # 事件类型
        ("comm", ct.c_char * 16),  # 进程名
        ("filename", ct.c_char * 256),  # 文件路径
    ]

    @property
    def type_str(self) -> str:
        """获取IO类型字符串"""
        if self.type == OpenMonitor.EVENT_OPEN:
            return "OPEN"
        elif self.type == OpenMonitor.EVENT_OPENAT:
            return "OPENAT"
        else:
            return "UNKNOWN"


@register_monitor("open")
class OpenMonitor(BaseMonitor):
    """文件操作监控器"""
    EVENT_TYPE = OpenEvent

    # 事件类型常量
    EVENT_OPEN = 0
    EVENT_OPENAT = 1

    REQUIRED_TRACEPOINTS = [
        "syscalls:sys_enter_open",
        "syscalls:sys_exit_open",
        "syscalls:sys_enter_openat",
        "syscalls:sys_exit_openat",
    ]

    @classmethod
    def get_default_config(cls) -> Dict[str, Any]:
        """获取默认配置"""
        return {
            "enabled": True,
            "show_failed": True
        }

    @classmethod
    def validate_monitor_config(cls, config: Dict[str, Any]):
        """验证文件操作监控器配置"""
        assert config.get("show_failed") is not None, "show_failed不能为空"
        assert isinstance(config.get("show_failed"), bool), "show_failed必须为布尔值"

    def _initialize(self, config: Dict[str, Any]):
        """初始化文件操作监控器"""
        self.enabled = config.get("enabled")
        self.show_failed = config.get("show_failed")  # 是否显示失败的操作

    def _should_handle_event(self, event: OpenEvent) -> bool:
        """
        判断是否应该处理事件
        """
        if not self.show_failed and event.ret < 0:
            return False
        return True

    # ==================== 格式化方法实现 ====================

    def get_csv_header(self) -> List[str]:
        """获取CSV头部字段"""
        return ['timestamp', 'time_str', 'type', 'type_str', 'pid', 'tid', 'uid', 'cpu', 'comm', 'flags', 'mode', 'ret', 'filename']

    def format_for_csv(self, event_data: OpenEvent) -> Dict[str, Any]:
        """将事件数据格式化为CSV行数据"""
        timestamp = self._convert_timestamp(event_data)
        time_str = DataProcessor.format_timestamp(timestamp)
        
        # 处理字节字符串
        comm = DataProcessor.decode_bytes(event_data.comm)
        filename = DataProcessor.decode_bytes(event_data.filename)

        values = [timestamp, time_str, event_data.type, event_data.type_str, event_data.pid, event_data.tid, event_data.uid, event_data.cpu, comm, event_data.flags, event_data.mode, event_data.ret, filename]

        return dict(zip(self.get_csv_header(), values))

    def get_console_header(self) -> str:
        """获取控制台输出的表头"""
        return f"{'TIME':<22} {'TYPE':<6} {'PID':<8} {'TID':<8} {'UID':<6} {'CPU':<3} {'COMM':<16} {'FLAGS':<12} {'MODE':<6} {'RET':<4} {'FILENAME'}"

    def format_for_console(self, event_data: OpenEvent) -> str:
        """将事件数据格式化为控制台输出"""
        timestamp = self._convert_timestamp(event_data)
        time_str = f"[{DataProcessor.format_timestamp(timestamp)}]"

        # 处理字节字符串
        comm = DataProcessor.decode_bytes(event_data.comm)
        filename = DataProcessor.decode_bytes(event_data.filename)

        # 获取标志位名称（简化显示）
        flag_names = self._get_flag_names(event_data.flags)

        # 错误标记
        error_mark = "❌" if event_data.ret < 0 else ""

        # 格式化输出
        return f"{time_str:<22} {event_data.type_str:<6} {event_data.pid:<8} {event_data.tid:<8} {event_data.uid:<6} {event_data.cpu:<3} {comm:<16} {flag_names:<12} {event_data.mode:<6} {event_data.ret:<4} {filename}{error_mark}"

    def _get_flag_names(self, flags: int) -> str:
        """简化的标志位显示"""
        # 只显示主要的访问模式
        access_mode = flags & 0x3
        if access_mode == 0:
            return "RDONLY"
        elif access_mode == 1:
            return "WRONLY"
        elif access_mode == 2:
            return "RDWR"
        else:
            return f"0x{flags:X}"


if __name__ == '__main__':
    """测试模式"""
    import sys
    import time
    from ..utils.application_context import ApplicationContext

    context = ApplicationContext()

    logger = context.get_logger("OpenMonitor")
    logger.info("文件操作监控测试模式")

    monitor = OpenMonitor(context, OpenMonitor.get_default_config())

    output_controller = context.output_controller
    output_controller.register_monitor("open", monitor)

    if not monitor.load_ebpf_program():
        logger.error("eBPF程序加载失败")
        sys.exit(1)

    output_controller.start()

    if not monitor.run():
        logger.error("文件操作监控启动失败")
        sys.exit(1)

    logger.info("文件操作监控已启动")
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
        output_controller.unregister_monitor("open")
        monitor.cleanup()
        output_controller.cleanup()
