#!/usr/bin/env python3
# encoding: utf-8
"""
进程执行监控器

监控进程试图执行哪些程序。
"""

import ctypes as ct
from typing import Dict, List, Any

from .base import BaseEvent, BaseMonitor
from ..utils.data_processor import DataProcessor
from ..utils.decorators import register_monitor


class ExecEvent(BaseEvent):
    """进程执行事件"""
    _fields_ = [
        ("comm", ct.c_char * 16),  # 命令
        ("uid", ct.c_uint32),  # 用户ID
        ("pid", ct.c_uint32),  # 进程ID
        ("ppid", ct.c_uint32),  # 父进程ID
        ("ret", ct.c_int32),  # 返回值
        ("argv", ct.c_char * 256),  # 参数字符串 (ARGSIZE = 256)
    ]


@register_monitor("exec")
class ExecMonitor(BaseMonitor):
    """进程执行监控器"""
    EVENT_TYPE: type = ExecEvent

    REQUIRED_TRACEPOINTS: List[str] = [
        "syscalls:sys_enter_execve",
        "syscalls:sys_exit_execve"
    ]

    # ==================== 格式化方法实现 ====================

    def get_csv_header(self) -> List[str]:
        """获取CSV头部字段"""
        return ['timestamp', 'time_str', 'comm', 'uid', 'pid', 'ppid', 'ret', 'argv']

    def format_for_csv(self, event_data: ExecEvent) -> Dict[str, Any]:
        """将事件数据格式化为CSV行数据"""
        timestamp = self._convert_timestamp(event_data)
        time_str = DataProcessor.format_timestamp(timestamp)

        # 处理 comm 和 argv 字段的字节解码
        comm = DataProcessor.decode_bytes(event_data.comm)
        argv = DataProcessor.decode_bytes(event_data.argv)

        values = [timestamp, time_str, comm, event_data.uid, event_data.pid, event_data.ppid, event_data.ret, argv]

        return dict(zip(self.get_csv_header(), values))

    def get_console_header(self) -> str:
        """获取控制台输出的表头"""
        return f"{'TIME':<22} {'COMM':<16} {'UID':<6} {'PID':<8} {'PPID':<8} {'RET':<4} {'ARGS'}"

    def format_for_console(self, event_data: ExecEvent) -> str:
        """将事件数据格式化为控制台输出"""
        timestamp = self._convert_timestamp(event_data)
        time_str = f"[{DataProcessor.format_timestamp(timestamp)}]"

        # 处理字节字符串
        comm = DataProcessor.decode_bytes(event_data.comm)
        argv = DataProcessor.decode_bytes(event_data.argv)

        # 格式化输出
        return f"{time_str:<22} {comm:<16} {event_data.uid:<6} {event_data.pid:<8} {event_data.ppid:<8} {event_data.ret:<4} {argv}"


if __name__ == "__main__":
    """测试模式"""
    import sys
    import time
    from ..utils.application_context import ApplicationContext

    # 使用ApplicationContext创建组件
    context = ApplicationContext()

    logger = context.get_logger("ExecMonitor")
    logger.info("进程执行监控测试模式")

    monitor = ExecMonitor(context, ExecMonitor.get_default_config())

    output_controller = context.output_controller
    output_controller.register_monitor("exec", monitor)

    if not monitor.load_ebpf_program():
        logger.error("eBPF程序加载失败")
        sys.exit(1)

    output_controller.start()

    if not monitor.run():
        logger.error("进程执行监控启动失败")
        sys.exit(1)

    logger.info("进程执行监控已启动")
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
        output_controller.unregister_monitor("exec")
        monitor.cleanup()
        output_controller.cleanup()
