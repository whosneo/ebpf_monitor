#!/usr/bin/env python
# encoding: utf-8
"""
Python2.7兼容性工具模块

提供Python2.7和Python3之间的兼容性支持，
通过条件导入和备用实现确保代码在两个版本下都能正常运行。
"""

import sys

# Python版本检测
PY2 = sys.version_info[0] == 2
PY3 = sys.version_info[0] == 3

# typing模块兼容性处理
try:
    from typing import TYPE_CHECKING, Dict, List, Any, Optional, Union, Type, Callable
except ImportError:
    # Python 2.7 fallback
    TYPE_CHECKING = False
    Dict = dict
    List = list  
    Any = object
    Optional = object
    Union = object
    Type = object
    Callable = object

# pathlib兼容性处理
try:
    from pathlib import Path
    HAS_PATHLIB = True
except ImportError:
    import os

    HAS_PATHLIB = False


    class Path(object):
        """pathlib.Path的最小兼容实现"""

        def __init__(self, path):
            self._path = os.path.abspath(str(path))

        def __str__(self):
            return self._path

        def __repr__(self):
            return "Path({!r})".format(self._path)

        def __truediv__(self, other):
            return Path(os.path.join(self._path, str(other)))

        # Python 2.7兼容性
        __div__ = __truediv__

        @classmethod
        def cwd(cls):
            return cls(os.getcwd())

        @property
        def name(self):
            return os.path.basename(self._path)

        @property
        def stem(self):
            """File name without extension"""
            name = os.path.basename(self._path)
            if '.' in name:
                return name.rsplit('.', 1)[0]
            return name

        @property
        def parent(self):
            return Path(os.path.dirname(self._path))

        def resolve(self):
            return Path(os.path.realpath(self._path))

        def exists(self):
            return os.path.exists(self._path)

        def is_absolute(self):
            return os.path.isabs(self._path)

        def mkdir(self, parents=False, exist_ok=False):
            if exist_ok and self.exists():
                return
            if parents:
                # Python 2.7兼容的makedirs
                try:
                    os.makedirs(self._path)
                except OSError:
                    if not (exist_ok and self.exists()):
                        raise
            else:
                os.mkdir(self._path)

        def glob(self, pattern):
            """Glob pattern matching - Python 2.7 compatible implementation"""
            import glob as glob_module
            # 如果是相对模式，在当前路径下搜索
            if os.path.isabs(pattern):
                search_pattern = pattern
            else:
                search_pattern = os.path.join(self._path, pattern)

            # 使用glob模块搜索并返回Path对象列表
            matches = glob_module.glob(search_pattern)
            return [Path(match) for match in matches]

        def iterdir(self):
            """遍历目录内容"""
            if not os.path.isdir(self._path):
                raise OSError("Not a directory: {}".format(self._path))

            for item in os.listdir(self._path):
                yield Path(os.path.join(self._path, item))

        def is_file(self):
            """检查路径是否为文件"""
            return os.path.isfile(self._path)

        def is_dir(self):
            """检查路径是否为目录"""
            return os.path.isdir(self._path)

# 字符串格式化兼容性
def format_string(template, *args, **kwargs):
    """统一的字符串格式化函数"""
    if PY2:
        # Python 2.7使用%格式化或.format()
        if args and not kwargs:
            return template % args
        elif kwargs and not args:
            return template.format(**kwargs)
        else:
            return template.format(*args, **kwargs)
    else:
        # Python 3可以使用所有格式化方式
        return template.format(*args, **kwargs)

# 字节字符串处理兼容性
def ensure_str(value):
    """确保返回字符串类型"""
    if PY2:
        if isinstance(value, unicode):
            return value.encode('utf-8')
        return str(value)
    else:
        if isinstance(value, bytes):
            return value.decode('utf-8', errors='ignore')
        return str(value)

def ensure_bytes(value):
    """确保返回字节类型"""
    if PY2:
        return str(value)
    else:
        if isinstance(value, str):
            return value.encode('utf-8')
        return bytes(value)

# super()兼容性处理
def compat_super(cls, instance):
    """兼容的super()调用"""
    if PY2:
        return super(cls, instance)
    else:
        return super()

# 异常兼容性
def reraise(exc_type, exc_value, exc_traceback=None):
    """重新抛出异常的兼容方式"""
    if PY2:
        exec("raise exc_type, exc_value, exc_traceback")
    else:
        if exc_value is None:
            exc_value = exc_type()
        if exc_value.__traceback__ is not exc_traceback:
            raise exc_value.with_traceback(exc_traceback)
        raise exc_value

# enum兼容性处理
try:
    from enum import Enum
except ImportError:
    # Python 2.7 fallback - create a complete Enum-like implementation
    class EnumMeta(type):
        def __new__(cls, name, bases, attrs):
            enum_attrs = {}
            enum_members = []
            for key, value in attrs.items():
                if not key.startswith('_') and not callable(value) and key not in ('__module__', '__qualname__'):
                    enum_member = EnumValue(key, value)
                    enum_attrs[key] = enum_member
                    enum_members.append(enum_member)
                else:
                    enum_attrs[key] = value
            enum_attrs['_members'] = enum_members
            return super(EnumMeta, cls).__new__(cls, name, bases, enum_attrs)


    class EnumValue(object):
        def __init__(self, name, value):
            self.name = name
            self.value = value

        def __str__(self):
            return self.name

        def __repr__(self):
            return "<{}: {}>".format(self.name, self.value)

        def __eq__(self, other):
            if isinstance(other, EnumValue):
                return self.value == other.value
            return self.value == other

        def __ne__(self, other):
            return not self.__eq__(other)

        def __hash__(self):
            return hash(self.value)


    class Enum(object):
        __metaclass__ = EnumMeta

# 导入兼容性助手
def safe_import(module_name, fallback=None):
    """安全导入模块"""
    try:
        return __import__(module_name)
    except ImportError:
        return fallback

# 导出所有兼容性工具
__all__ = [
    'PY2', 'PY3', 'TYPE_CHECKING',
    'Dict', 'List', 'Any', 'Optional', 'Union', 'Type', 'Callable',
    'Path', 'HAS_PATHLIB',
    'Enum',
    'format_string', 'ensure_str', 'ensure_bytes',
    'compat_super', 'reraise', 'safe_import'
]
