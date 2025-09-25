#!/usr/bin/env python
# encoding: utf-8
"""
eBPF监控器基类

提供所有monitor的共同接口和实现，定义标准的监控流程。
子类只需实现特定的抽象方法即可快速创建新的监控器。
"""

import ctypes as ct
import time
try:
    from abc import ABC, abstractmethod
except ImportError:
    # Python 2.7 fallback
    from abc import ABCMeta, abstractmethod
    ABC = ABCMeta('ABC', (object,), {})
try:
    from pathlib import Path
except ImportError:
    # Python 2.7 fallback
    from ..utils.py2_compat import Path
from threading import Thread, Event
# 兼容性导入
try:
    from typing import Dict, List, Any, TYPE_CHECKING
except ImportError:
    from ..utils.py2_compat import Dict, List, Any, TYPE_CHECKING

import psutil
try:
    # noinspection PyUnresolvedReferences
    from bpfcc import BPF  # pyright: ignore[reportMissingImports]
except ImportError:
    # Python 2.7 fallback
    from bcc import BPF  # pyright: ignore[reportMissingImports]

from ..utils.data_processor import DataProcessor
from ..utils.decorators import MONITOR_REGISTRY, require_bpf_loaded

if TYPE_CHECKING:
    # noinspection PyUnusedImports
    from ..utils.application_context import ApplicationContext


class BaseEvent(ct.Structure):
    """
    事件基类

    用于定义eBPF事件的数据结构，子类需要定义_fields_
    """
    _fields_ = [
        ("timestamp", ct.c_uint64)  # 时间戳
    ]


class BaseMonitor(ABC):
    """eBPF监控器基类

    定义了所有eBPF监控器的通用接口和实现。
    子类需要实现抽象方法来提供特定的监控功能。
    @register_monitor("base")
    基本使用方法（按顺序）：
    BaseMonitor.validate_config(config)  # 解析、验证配置
    monitor = BaseMonitor(config)        # 初始化监控器
    monitor.load_ebpf_program()          # 加载eBPF程序
    monitor.add_target_process(1234)     # 添加目标进程
    monitor.add_target_user(1000)        # 添加目标用户
    monitor.run()                        # 开始监控
    monitor.stop()                       # 停止监控
    monitor.cleanup()                    # 清理资源
    """
    # 事件类型，子类必须实现
    EVENT_TYPE = BaseEvent  # type: type

    # 需要验证的tracepoint，子类可以重写
    REQUIRED_TRACEPOINTS = []  # type: List[str]

    @classmethod
    def get_default_config(cls):
        # type: () -> Dict[str, Any]
        """
        获取监控器默认配置
        
        子类必须实现此方法来提供默认配置
        
        Returns:
            Dict[str, Any]: 默认配置字典
        """
        return {"enabled": True}

    @classmethod
    def validate_config(cls, config):
        # type: (Dict[str, Any]) -> None
        """
        验证监控器配置
        """
        assert config is not None, "监控器配置不能为空"
        assert isinstance(config, dict), "监控器配置必须为字典"
        assert len(config) > 0, "监控器配置不能为空"
        assert config.get("enabled") is not None, "enabled不能为空"
        assert isinstance(config.get("enabled"), bool), "enabled必须为布尔值"
        cls.validate_monitor_config(config)

    @classmethod
    def validate_monitor_config(cls, config):
        # type: (Dict[str, Any]) -> None
        """
        验证监控器配置

        子类需要重写此方法来提供特定的配置验证

        Args:
            config: 配置字典
        """
        pass

    @classmethod
    def get_monitor_type(cls):
        # type: () -> str
        """
        获取监控器名称
        
        从注册表中查找当前类对应的名称
        
        Returns:
            str: 监控器名称
        """
        for _type, _class in MONITOR_REGISTRY.items():
            if _class == cls:
                return _type
        raise ValueError("监控器类 {} 未在注册表中找到".format(cls.__name__))

    def __init__(self, context, config):
        # type: ('ApplicationContext', Dict[str, Any]) -> None
        """
        初始化监控器基类
        
        Args:
            context: 应用上下文（可选，用于依赖注入）
            config: 监控器配置
        """
        self.context = context
        self.base_logger = context.get_logger(BaseMonitor.__name__)  # 基类logger
        self.logger = context.get_logger(self)  # 子类的logger

        self.config_manager = context.config_manager  # 配置管理器
        self.output_controller = context.output_controller  # 输出控制器
        self.capability_checker = context.get_capability_checker()  # 内核兼容性检查器

        self.debug = self.config_manager.app_config.debug  # 调试模式
        self.type = self.get_monitor_type()  # 监控器名称
        self.events_name = "{}_events".format(self.type)  # 事件缓冲区名称
        self.ebpf_file = self.__get_ebpf_file()  # eBPF程序文件路径
        self.bpf = None  # eBPF程序实例
        self.boot_time = psutil.boot_time()  # 系统启动时间

        self.target_pids = {}  # type: Dict[int, str]  # 目标进程管理
        self.target_uids = {}  # type: Dict[int, str]  # 目标用户管理

        self.running = False  # 监控运行状态
        self.stop_event = Event()  # 监控停止事件flag
        self.monitor_thread = None  # 监控线程

        # 统计数据（基础字段）
        self.stats = self.__get_default_stats()

        # 验证内核要求和依赖
        self._validate_requirements()

        # 应用配置
        self.enabled = config.get("enabled")
        self._initialize(config)

    def __get_ebpf_file(self):  # 子类不可重写
        # type: () -> Path
        """
        获取eBPF程序文件路径

        根据 @register_monitor 装饰器的参数自动构建路径：
        ebpf_dir / {monitor_type}.c

        Returns:
            Path: eBPF程序文件路径

        Raises:
            IOError: 当eBPF文件不存在时
            ValueError: 当监控器未注册时
        """
        # 构建eBPF文件路径
        ebpf_file = self.config_manager.get_ebpf_dir() / "{}.c".format(self.type)
        self.base_logger.debug("自动确定eBPF文件路径: {} (基于监控器名称: {})".format(ebpf_file, self.type))

        if not ebpf_file.exists():
            raise IOError("eBPF程序文件不存在: {}".format(ebpf_file))

        return ebpf_file

    @staticmethod
    def __get_default_stats():  # 子类不可重写
        # type: () -> Dict[str, Any]
        """
        获取默认统计数据结构

        Returns:
            Dict[str, Any]: 默认统计数据字典
        """
        return {
            "events_processed": 0,
            "events_dropped": 0,
            "last_reset": time.time()
        }

    def get_statistics(self):
        # type: () -> Dict[str, Any]
        """
        获取统计信息

        子类可以重写此方法来扩展统计信息

        Returns:
            Dict[str, Any]: 统计信息
        """
        stats = self.stats.copy()

        # 添加通用信息
        stats["monitoring"] = self.running
        stats["target_processes"] = self.target_pids.copy()
        stats["target_users"] = self.target_uids.copy()

        return stats

    def reset_statistics(self):
        # type: () -> None
        """重置统计信息"""
        # 重置基础统计
        self.stats.update(self.__get_default_stats())
        self.base_logger.info("{}统计信息已重置".format(self.__class__.__name__))

    def _validate_requirements(self):
        # type: () -> None
        """
        验证内核要求和依赖

        子类可以重写此方法来验证特定的内核功能
        """
        for tp in self.REQUIRED_TRACEPOINTS:
            tp_path = "/sys/kernel/debug/tracing/events/{}/enable".format(tp.replace(':', '/'))
            if not Path(tp_path).exists():
                tp_path = "/sys/kernel/tracing/events/{}/enable".format(tp.replace(':', '/'))
                if not Path(tp_path).exists():
                    self.logger.warning("Tracepoint {} 可能不可用".format(tp))

    def _initialize(self, config):
        # type: (Dict[str, Any]) -> None
        """
        初始化监控器

        子类可以重写此方法来初始化监控器
        """
        pass

    def load_ebpf_program(self):
        # type: () -> bool
        """
        加载eBPF程序

        标准化的eBPF程序加载流程

        Returns:
            bool: 加载是否成功
        """
        if not self.enabled:
            self.base_logger.warning("{}监控未启用".format(self.__class__.__name__))
            return False

        try:
            # 获取编译标志
            flags = self.capability_checker.get_compile_flags()
            self.base_logger.debug("加载eBPF程序: {}, 编译标志: {}".format(self.ebpf_file, flags))

            # 编译和加载eBPF程序
            self.bpf = BPF(text=self._get_ebpf_code(), cflags=flags)
            # 配置程序
            self._configure_ebpf_program()

            self.base_logger.info("{} eBPF程序加载成功".format(self.__class__.__name__))
            return True
        except Exception as e:
            self.base_logger.error("{} eBPF程序加载失败: {}".format(self.__class__.__name__, e))
            return False

    def _get_ebpf_code(self):
        # type: () -> str
        """
        获取eBPF程序代码

        子类可以重写此方法来修改代码
        """
        with open(str(self.ebpf_file), "r") as f:
            ebpf_code = f.read()
        return ebpf_code

    def _configure_ebpf_program(self):
        """
        配置eBPF程序特定参数

        子类可以重写此方法来进行特定的eBPF程序配置
        """
        pass

    @require_bpf_loaded
    def add_target_process(self, pid, comm="unknown"):
        # type: (int, str) -> bool
        """
        添加目标进程

        Args:
            pid: 进程ID
            comm: 进程名称（可选）

        Returns:
            bool: 添加是否成功
        """
        try:
            # 在eBPF程序中添加目标PID
            self.bpf["target_pids"][ct.c_uint32(pid)] = ct.c_uint8(1)

            # 记录到本地映射
            self.target_pids[pid] = comm
            self.base_logger.info("添加目标进程（{}）: PID={}, COMM={}".format(self.__class__.__name__, pid, comm))
            return True

        except Exception as e:
            self.base_logger.error("添加目标进程失败: PID={}, 错误={}".format(pid, e))
            return False

    @require_bpf_loaded
    def remove_target_process(self, pid):
        # type: (int) -> bool
        """
        移除目标进程

        Args:
            pid: 进程ID

        Returns:
            bool: 移除是否成功
        """
        try:
            # 从eBPF程序中移除目标PID
            self.bpf["target_pids"].pop(ct.c_uint32(pid), None)

            # 从本地映射中移除
            if pid in self.target_pids:
                comm = self.target_pids.pop(pid)
                self.base_logger.info("移除目标进程（{}）: PID={}, COMM={}".format(self.__class__.__name__, pid, comm))

            return True

        except Exception as e:
            self.base_logger.error("移除目标进程失败: PID={}, 错误={}".format(pid, e))
            return False

    @require_bpf_loaded
    def add_target_user(self, uid, name="unknown"):
        # type: (int, str) -> bool
        """
        添加目标用户

        Args:
            uid: 用户ID
            name: 用户名称（可选）

        Returns:
            bool: 添加是否成功
        """
        try:
            # 在eBPF程序中添加目标UID
            self.bpf["target_uids"][ct.c_uint32(uid)] = ct.c_uint8(1)

            # 记录到本地映射
            self.target_uids[uid] = name
            self.base_logger.info("添加目标用户（{}）: UID={}, NAME={}".format(self.__class__.__name__, uid, name))
            return True

        except Exception as e:
            self.base_logger.error("添加目标用户失败: UID={}, 错误={}".format(uid, e))
            return False

    @require_bpf_loaded
    def remove_target_user(self, uid):
        # type: (int) -> bool
        """
        移除目标用户

        Args:
            uid: 用户ID

        Returns:
            bool: 移除是否成功
        """
        try:
            # 从eBPF程序中移除目标UID
            self.bpf["target_uids"].pop(ct.c_uint32(uid), None)

            # 从本地映射中移除
            if uid in self.target_uids:
                name = self.target_uids.pop(uid)
                self.base_logger.info("移除目标用户（{}）: UID={}, NAME={}".format(self.__class__.__name__, uid, name))

            return True

        except Exception as e:
            self.base_logger.error("移除目标用户失败: UID={}, 错误={}".format(uid, e))
            return False

    @require_bpf_loaded
    def run(self):
        # type: () -> bool
        """
        开始监控

        Returns:
            bool: 启动是否成功
        """
        if self.running:
            self.base_logger.warning("{}监控已经在运行".format(self.__class__.__name__))
            return True

        try:
            # 绑定事件处理函数
            self.bpf[self.events_name].open_perf_buffer(self.__handle_event_callback)

            # 启动监控线程
            self.stop_event.clear()
            self.monitor_thread = Thread(target=self.__monitor_loop)
            # Python 2.7兼容性：设置daemon属性而不是在__init__中传递
            self.monitor_thread.daemon = True
            self.monitor_thread.start()

            self.running = True
            self.base_logger.info("{}监控开始".format(self.__class__.__name__))
            return True
        except Exception as e:
            self.base_logger.error("启动{}监控失败: {}".format(self.__class__.__name__, e))
            return False

    def __monitor_loop(self):
        """监控循环"""
        while not self.stop_event.is_set():
            try:
                # 轮询事件，超时1秒
                self.bpf.perf_buffer_poll(timeout=1000)
            except Exception as e:
                if not self.stop_event.is_set():
                    self.base_logger.error("事件轮询失败: {}".format(e))
                    time.sleep(1)

    @require_bpf_loaded
    def stop(self):
        """停止监控"""
        if not self.running:
            self.base_logger.warning("{}监控未运行".format(self.__class__.__name__))
            return

        self.base_logger.info("正在停止{}监控...".format(self.__class__.__name__))
        self.stop_event.set()

        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5.0)

        self.running = False
        self.base_logger.info("{}监控已停止".format(self.__class__.__name__))

    # noinspection PyUnusedLocal
    def __handle_event_callback(self, cpu, data, size):
        """
        处理具体的事件数据

        处理从eBPF程序接收到的事件数据

        Args:
            cpu: 产生事件的CPU编号
            data: 事件数据指针
            size: 事件数据大小
        """
        try:
            event = ct.cast(data, ct.POINTER(self.EVENT_TYPE)).contents
            if not self._should_handle_event(event):
                return
            self.output_controller.handle_event(self.type, event)
            self._handle_event_extended_callback(event)
            self.stats["events_processed"] += 1
        except Exception as e:
            self.base_logger.error("处理事件失败: {}".format(e))
            self.stats["events_dropped"] += 1

    def _should_handle_event(self, event):
        # type: (BaseEvent) -> bool
        """
        判断是否应该处理事件

        Args:
            event: 事件数据对象

        Returns:
            bool: 是否应该处理事件

        子类可以重写此方法来判断是否应该处理事件
        """
        return True

    def _handle_event_extended_callback(self, event):
        # type: (BaseEvent) -> None
        """
        处理扩展事件

        子类可以重写此方法来处理特定的扩展事件
        """
        pass

    def _convert_timestamp(self, event):
        # type: (BaseEvent) -> Any
        """
        将内核时间戳转换为Unix时间戳
        """
        return self._convert_timestamp_ns(event.timestamp)

    def _convert_timestamp_ns(self, timestamp):
        # type: (int) -> Any
        """
        将纳秒时间戳转换为Unix时间戳
        """
        return self.boot_time + timestamp / 1e9

    def cleanup(self):
        """清理资源"""
        # cleanup职责：仅清理资源，不负责停止监控
        # 调用者应该先调用stop()再调用cleanup()
        if self.bpf is not None:
            try:
                # 清理目标进程
                self.bpf["target_pids"].clear()
                self.bpf["target_uids"].clear()
                self.bpf.cleanup()
                self.base_logger.info("{} eBPF资源清理完成".format(self.__class__.__name__))
            except Exception as e:
                self.base_logger.error("{} eBPF资源清理失败: {}".format(self.__class__.__name__, e))

        self.target_pids.clear()
        self.target_uids.clear()

    def is_running(self):
        # type: () -> bool
        """
        检查是否正在监控

        Returns:
            bool: 监控状态
        """
        return self.running

    # ==================== 格式化方法接口 ====================
    # 这些方法可以被子类重写以提供自定义的输出格式

    @abstractmethod
    def get_csv_header(self):
        # type: () -> List[str]
        """
        获取CSV头部字段

        子类需要重写此方法以提供特定的CSV头部字段

        Returns:
            List[str]: CSV头部字段列表
        """
        return ['timestamp', 'time_str', 'data']

    @abstractmethod
    def format_for_csv(self, event_data):
        # type: (BaseEvent) -> Dict[str, Any]
        """
        将事件数据格式化为CSV行数据

        子类需要重写此方法以提供特定的CSV格式化逻辑

        Args:
            event_data: 事件数据对象

        Returns:
            Dict[str, Any]: CSV行数据字典
        """
        timestamp = self._convert_timestamp(event_data)
        time_str = DataProcessor.format_timestamp(timestamp)

        return {
            'timestamp': timestamp,
            'time_str': time_str,
            'data': str(event_data)
        }

    @abstractmethod
    def get_console_header(self):
        # type: () -> str
        """
        获取控制台输出的表头

        子类需要重写此方法以提供特定的控制台表头格式

        Returns:
            str: 格式化后的控制台表头字符串
        """
        return "{:<22} {}".format('TIME', 'DATA')

    @abstractmethod
    def format_for_console(self, event_data):
        # type: (BaseEvent) -> str
        """
        将事件数据格式化为控制台输出

        子类需要重写此方法以提供特定的控制台格式化逻辑

        Args:
            event_data: 事件数据对象

        Returns:
            str: 格式化后的控制台输出字符串
        """
        timestamp = self._convert_timestamp(event_data)
        time_str = "[{}]".format(DataProcessor.format_timestamp(timestamp))

        return "{:<22} {}".format(time_str, str(event_data))
