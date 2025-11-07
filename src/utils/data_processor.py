#!/usr/bin/env python
# encoding: utf-8
"""
数据处理工具类，提供通用的数据处理方法
"""

# 标准库导入
import time
import struct
import ctypes as ct

# 兼容性导入
try:
    from typing import Union, Dict, Any, List, Tuple
except ImportError:
    from .py2_compat import Union, Dict, Any, List, Tuple


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

    @staticmethod
    def struct_to_dict(struct):
        # type: (Any) -> Dict[str, Any]
        """
        将ctypes结构体转换为字典
        
        将BPF返回的ctypes结构体优雅地转换为Python字典，
        自动处理字节数组字段的解码。
        
        Args:
            struct: ctypes结构体实例
            
        Returns:
            Dict[str, Any]: 包含结构体所有字段的字典
        """
        result = {}  # type: Dict[str, Any]

        # 检查是否有_fields_属性（ctypes结构体特征）
        if not hasattr(struct, '_fields_'):
            return result

        # 遍历所有字段
        for field_name, field_type in struct._fields_:
            value = getattr(struct, field_name)

            # 处理字节数组（如char comm[16]）
            if isinstance(value, bytes):
                result[field_name] = DataProcessor.decode_bytes(value)
            else:
                result[field_name] = value

        return result

    @staticmethod
    def parse_event_data(data, size, fields):
        # type: (int, int, List[Tuple[str, str, int]]) -> Dict[str, Any]
        """
        从BPF事件指针解析数据
        
        无需定义ctypes结构体类，直接从原始指针解析事件数据。
        
        Args:
            data: 事件数据指针地址（整数）
            size: 数据大小（字节）
            fields: 字段定义列表，格式为 [(name, format, size), ...]
                   format: 'Q'=u64, 'I'=u32, 'H'=u16, 'B'=u8, 's'=string
                   
        Returns:
            Dict[str, Any]: 解析后的字段字典
            
        Example:
            fields = [
                ('timestamp', 'Q', 8),
                ('uid', 'I', 4),
                ('comm', 's', 16),
            ]
            result = parse_event_data(data_ptr, size, fields)
        """
        result = {}  # type: Dict[str, Any]

        try:
            # 从指针读取原始字节数据
            raw_data = ct.string_at(data, size)

            # 逐个解析字段
            offset = 0
            for field_name, field_format, field_size in fields:
                if field_format == 's':
                    # 字符串类型：提取字节并解码
                    field_bytes = raw_data[offset:offset + field_size]
                    result[field_name] = DataProcessor.decode_bytes(field_bytes)
                else:
                    # 数值类型：使用struct.unpack解析
                    field_bytes = raw_data[offset:offset + field_size]
                    value = struct.unpack(field_format, field_bytes)[0]
                    result[field_name] = value

                offset += field_size

        except Exception as e:
            # 解析失败时返回空字典，由调用方处理错误
            pass

        return result
