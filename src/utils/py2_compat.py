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
    from typing import TYPE_CHECKING, Dict, List, Any, Optional, Union, Type, Callable, Tuple, TextIO
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
    Tuple = tuple
    TextIO = object  # 文件对象类型

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

        def stat(self):
            """获取文件状态信息，返回 os.stat_result 对象"""
            return os.stat(self._path)

        def unlink(self):
            """删除文件（不能删除目录）"""
            os.unlink(self._path)


# ProcessLookupError兼容性处理
try:
    ProcessLookupError = ProcessLookupError
except NameError:
    # Python 2.7 中不存在 ProcessLookupError
    # 它是 Python 3.3+ 引入的 OSError 子类，用于表示进程查找失败
    # 在 Python 2 中，相同的错误会抛出 OSError
    ProcessLookupError = OSError

# ABC (Abstract Base Class) 兼容性处理
try:
    from abc import ABC
except ImportError:
    # Python 2.7 fallback
    from abc import ABCMeta

    ABC = ABCMeta('ABC', (object,), {})

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
                # 排除：私有属性、可调用对象、容器类型、装饰器对象、特殊属性
                if (not key.startswith('_') and
                        not callable(value) and
                        not isinstance(value, (dict, set, list, tuple, staticmethod, classmethod, property)) and
                        key not in ('__module__', '__qualname__')):
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


# 集合清理兼容性助手
def safe_clear_collection(collection):
    """
    Python 2/3 兼容的集合清空函数
    
    Args:
        collection: 字典、列表或其他支持clear()的集合
    
    Returns:
        清空后的集合(如果不支持clear则返回新的空集合)
    """
    if hasattr(collection, 'clear'):
        collection.clear()
        return collection
    else:
        # Python 2.7 dict没有clear()方法的fallback
        if isinstance(collection, dict):
            return {}
        elif isinstance(collection, list):
            return []
        elif isinstance(collection, set):
            return set()
        else:
            # 尝试通过构造函数创建空集合
            return type(collection)()


# 导出所有兼容性工具
__all__ = [
    'PY2', 'PY3', 'TYPE_CHECKING',
    'Dict', 'List', 'Any', 'Optional', 'Union', 'Type', 'Callable', 'Tuple', 'TextIO',
    'Path', 'HAS_PATHLIB', 'Enum', 'ABC',
    'safe_clear_collection', 'ProcessLookupError'
]
