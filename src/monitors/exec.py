#!/usr/bin/env python
# encoding: utf-8
"""
进程执行监控器

监控进程试图执行哪些程序。
"""

# 标准库导入
import time

# 兼容性导入
try:
    from typing import Dict, List, Any
except ImportError:
    from ..utils.py2_compat import Dict, List, Any

# 本地模块导入
from .base import BaseMonitor
from ..utils.data_processor import DataProcessor
from ..utils.decorators import register_monitor


@register_monitor("exec")
class ExecMonitor(BaseMonitor):
    """进程执行监控器"""
    BPF_POLL_TIMEOUT = 1000

    # 事件字段定义（对应exec_event结构体）
    # struct exec_event {
    #     u32 uid;             // 4 bytes
    #     u32 pid;             // 4 bytes
    #     char comm[16];       // 16 bytes
    #     char filename[256];  // 256 bytes
    # }
    EVENT_FIELDS = [
        ('uid', 'I', 4),  # u32
        ('pid', 'I', 4),  # u32
        ('comm', 's', 16),  # char[16]
        ('filename', 's', 256),  # char[256]
    ]

    def _initialize(self, config):
        # type: (Dict[str, Any]) -> None
        """初始化监控器"""
        self.events_name = "{}_events".format(self.type)

    def _configure_ebpf_program(self):
        # type: () -> None
        """为旧内核附加kprobe，支持多个内核版本的符号名称"""
        # 不同内核版本的execve符号名称：
        # - 3.10 (RHEL 7): sys_execve
        # - 4.17+ (x86_64): __x64_sys_execve
        # - 某些发行版: do_execve, do_execveat
        execve_symbols = [
            "__x64_sys_execve",  # 4.17+ x86_64 (最常见)
            "__ia32_sys_execve",  # 4.17+ x86 32位
            "sys_execve",  # 3.10 等老内核
        ]

        attached = False
        last_error = None

        for symbol in execve_symbols:
            try:
                self.bpf.attach_kprobe(event=symbol, fn_name="trace_execve_entry")
                self.logger.info("成功附加kprobe到 {}".format(symbol))
                attached = True
                break
            except Exception as e:
                last_error = e
                self.logger.debug("尝试附加到 {} 失败: {}".format(symbol, e))
                continue

        if not attached:
            self.logger.error("无法附加kprobe到任何execve符号，最后的错误: {}".format(last_error))
            raise RuntimeError("Failed to attach kprobe to any execve symbol: {}".format(last_error))

        # 绑定事件处理函数
        self.bpf[self.events_name].open_perf_buffer(self._handle_event)

    # noinspection PyUnusedLocal
    def _handle_event(self, cpu, data, size):
        """
        处理具体的事件数据

        Args:
            cpu: 产生事件的CPU编号
            data: 事件数据指针(原始C结构体)
            size: 事件数据大小(字节)
        """
        try:
            # 解析BPF事件数据
            event_data = DataProcessor.parse_event_data(data, size, self.EVENT_FIELDS)
            self.output_controller.handle_data(self.type, dict(
                {"timestamp": time.time()},
                **event_data))
        except Exception as e:
            self.logger.error("处理事件失败: {}".format(e))

    def _collect_and_output(self):
        self.bpf.perf_buffer_poll(timeout=self.BPF_POLL_TIMEOUT)  # 轮询事件

    # ==================== 格式化方法实现 ====================

    def monitor_csv_header(self):
        # type: () -> List[str]
        """获取CSV头部字段"""
        return ['uid', 'pid', 'comm', 'filename']

    def monitor_csv_data(self, data):
        # type: (Dict[str, Any]) -> Dict[str, Any]
        """将事件数据格式化为CSV行数据"""
        return {
            "uid": data["uid"],
            "pid": data["pid"],
            "comm": data["comm"],
            "filename": data["filename"]
        }

    def monitor_console_header(self):
        # type: () -> str
        """获取控制台输出的表头"""
        return "{:<6} {:<8} {:<16} {}".format('UID', 'PID', 'COMM', 'FILENAME')

    def monitor_console_data(self, data):
        # type: (Dict[str, Any]) -> str
        """将事件数据格式化为控制台输出"""
        return "{:<6} {:<8} {:<16} {}".format(
            data["uid"], data["pid"], data["comm"], data["filename"])
