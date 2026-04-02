#!/usr/bin/env python
# encoding: utf-8
"""
控制台写入器

负责控制台输出的格式化和写入，包括表头和数据行。
从OutputController中提取，遵循单一职责原则。
"""

import sys
import threading

# 兼容性导入
try:
    from typing import Dict, Any, List, TYPE_CHECKING
except ImportError:
    from .py2_compat import Dict, Any, List, TYPE_CHECKING

if TYPE_CHECKING:
    from ..monitors.base import BaseMonitor


class ConsoleWriter(object):
    """控制台写入器 - 管理控制台输出的格式化和线程安全"""

    def __init__(self, logger):
        # type: (object) -> None
        """
        初始化控制台写入器
        
        Args:
            logger: 日志记录器
        """
        self.logger = logger
        self.console_lock = threading.Lock()
        self.header_printed = {}  # type: Dict[str, bool]

    def write_batch(self, monitor_type, data, monitors):
        # type: (str, List[Dict[str, Any]], Dict[str, 'BaseMonitor']) -> None
        """
        批量输出到控制台
        
        Args:
            monitor_type: 监控器类型名称
            data: 数据列表
            monitors: 监控器实例字典（用于格式化数据）
        """
        with self.console_lock:
            # 首次输出表头
            if not self.header_printed.get(monitor_type, False):
                try:
                    header = monitors[monitor_type].get_console_header()
                    print(header)
                    print("-" * (len(header) + 16))
                    self.header_printed[monitor_type] = True
                except Exception as e:
                    self.logger.error("控制台表头输出失败 {}: {}".format(monitor_type, e))

            # 批量输出事件
            for data_item in data:  # type: Dict[str, Any]
                try:
                    console_output = monitors[monitor_type].format_for_console(data_item)
                    print(console_output)
                    sys.stdout.flush()
                except Exception as e:
                    self.logger.error("控制台输出失败 {}: {}".format(monitor_type, e))

    def reset_header(self, monitor_type):
        # type: (str) -> None
        """重置指定监控器的表头打印状态"""
        self.header_printed[monitor_type] = False

    def remove_header(self, monitor_type):
        # type: (str) -> None
        """移除指定监控器的表头状态"""
        self.header_printed.pop(monitor_type, None)

    def cleanup(self):
        # type: () -> None
        """清理控制台写入器资源"""
        self.header_printed.clear()
