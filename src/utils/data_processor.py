#!/usr/bin/env python
# encoding: utf-8
"""
数据处理工具类，提供通用的数据处理方法
"""

import time
# 兼容性导入
try:
    from typing import Union
except ImportError:
    from .py2_compat import Union


class DataProcessor:
    """数据处理工具类，提供通用的数据处理方法"""

    @staticmethod
    def decode_bytes(value):
        # type: (Union[bytes, str]) -> str
        """统一字节字符串解码处理"""
        if isinstance(value, bytes):
            return value.decode('utf-8', errors='ignore').rstrip('\x00')
        else:
            return value.rstrip('\x00')

    @staticmethod
    def format_timestamp(timestamp, fmt='%Y-%m-%d %H:%M:%S'):
        # type: (float, str) -> str
        # type: (float, str) -> str
        """统一时间格式化"""
        return time.strftime(fmt, time.localtime(timestamp))

    @staticmethod
    def format_time_prefix(timestamp):
        # type: (float) -> str
        """格式化控制台时间前缀"""
        return time.strftime('%H:%M:%S', time.localtime(timestamp))

    @staticmethod
    def format_size(size):
        # type: (int) -> str
        """格式化数据大小"""
        if size < 1024:
            return "{}B".format(size)
        elif size < 1024 * 1024:
            return "{:.1f}KB".format(size / 1024)
        else:
            return "{:.1f}MB".format(size / (1024 * 1024))

    @staticmethod
    def get_display_name(raw_name, fallback='unknown'):
        # type: (str, str) -> str
        """获取显示名称，处理空值和特殊值"""
        if not raw_name or raw_name in ('(null)', 'unknown'):
            return '<{}>'.format(fallback)
        return raw_name
