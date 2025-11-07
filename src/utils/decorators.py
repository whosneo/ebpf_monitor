#!/usr/bin/env python
# encoding: utf-8
"""
监控工具装饰器

提供通用的装饰器来简化重复的状态检查和错误处理逻辑。
"""

import functools
import sys

# 兼容性导入
try:
    from typing import Callable, Any, Dict, Type, TYPE_CHECKING
except ImportError:
    from .py2_compat import Callable, Any, Dict, Type, TYPE_CHECKING

if TYPE_CHECKING:
    # noinspection PyUnusedImports
    from ..monitors.base import BaseMonitor

# 全局监控器注册表
MONITOR_REGISTRY = {}  # type: Dict[str, Type['BaseMonitor']]


def register_monitor(name):
    # type: (str) -> Callable
    """
    监控器注册装饰器

    用于自动注册监控器类到全局注册表中，使得ConfigManager可以动态获取所有可用的监控器。

    Args:
        name (str): 监控器名称，应与配置文件中的名称一致

    Returns:
        装饰器函数

    Usage:
        @register_monitor("exec")
        class ExecMonitor(BaseMonitor):
            pass
    """

    def decorator(cls):
        # type: (Type['BaseMonitor']) -> Type['BaseMonitor']
        MONITOR_REGISTRY[name] = cls
        return cls

    return decorator


def require_running(func):
    # type: (Callable) -> Callable
    """
    装饰器：要求监控工具处于运行状态

    用于自动检查 self.running 状态，如果未运行则记录错误并返回 False。
    适用于所有需要监控工具启动后才能执行的方法。

    Args:
        func: 被装饰的方法

    Returns:
        装饰后的方法

    Usage:
        @require_running
        def some_method(self):
            # 方法体，只有在 self.running=True 时才会执行
            pass
    """

    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        # type: (*Any, **Any) -> Any
        # 检查运行状态
        if not hasattr(self, "running") or not self.running:
            # 获取日志记录器
            logger = getattr(self, "logger", None)
            if logger:
                logger.error("{}未启动".format(self.__class__.__name__))
            else:
                # 注意：当logger不可用时使用sys.stderr作为备用输出
                sys.stderr.write("错误: {}未启动\n".format(self.__class__.__name__))

            # 返回 False 表示操作失败
            return False

        # 状态正常，执行原方法
        return func(self, *args, **kwargs)

    return wrapper


def require_bpf_loaded(func):
    # type: (Callable) -> Callable
    """
    装饰器：要求eBPF程序已加载

    用于自动检查 self.bpf 状态，如果未加载则记录错误并返回 False。
    适用于所有需要eBPF程序加载后才能执行的方法。
    """

    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        # type: (*Any, **Any) -> Any
        if not hasattr(self, "bpf") or self.bpf is None:  # 不可以使用not self.bpf，部分系统BPF对象属性不同。
            logger = getattr(self, "base_logger", getattr(self, "logger", None))
            if logger:
                logger.error("eBPF程序未加载")
            else:
                # 注意：当logger不可用时使用sys.stderr作为备用输出
                sys.stderr.write("错误: eBPF程序未加载\n")
            return False
        else:
            return func(self, *args, **kwargs)

    return wrapper
