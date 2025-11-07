#!/usr/bin/env python
# encoding: utf-8
"""
eBPF监控器基类

提供所有监控器的共同接口和实现，定义标准的监控流程。
子类只需实现特定的抽象方法即可快速创建新的监控器。
"""

# 标准库导入
import time
from threading import Thread, Event

# 兼容性导入
try:
    from abc import ABC
except ImportError:
    from ..utils.py2_compat import ABC
try:
    from pathlib import Path
except ImportError:
    from ..utils.py2_compat import Path
try:
    from typing import Dict, List, Any
except ImportError:
    from ..utils.py2_compat import Dict, List, Any

# 第三方库导入
try:
    # noinspection PyUnresolvedReferences
    from bpfcc import BPF  # pyright: ignore[reportMissingImports]
except ImportError:
    from bcc import BPF  # pyright: ignore[reportMissingImports]

# 本地模块导入
from ..utils.data_processor import DataProcessor
from ..utils.decorators import MONITOR_REGISTRY, require_bpf_loaded
from ..utils.monitor_context import MonitorContext


class BaseMonitor(ABC):
    """eBPF监控器基类

    定义了所有eBPF监控器的通用接口和实现。
    子类需要实现抽象方法来提供特定的监控功能。
    @register_monitor("base")
    基本使用方法（按顺序）：
    BaseMonitor.validate_config(config)  # 解析、验证配置
    monitor = BaseMonitor(config)        # 初始化监控器
    monitor.load_ebpf_program()          # 加载eBPF程序
    monitor.run()                        # 开始监控
    monitor.stop()                       # 停止监控
    monitor.cleanup()                    # 清理资源
    """
    # 需要验证的tracepoint，子类可以重写
    REQUIRED_TRACEPOINTS = []  # type: List[str]

    MONITOR_THREAD_TIMEOUT = 5.0

    @classmethod
    def get_default_config(cls):
        # type: () -> Dict[str, Any]
        """
        获取监控器默认配置

        Returns:
            Dict[str, Any]: 默认配置字典
        """
        base_config = {
            "enabled": True,
            "interval": 2,
        }
        base_config.update(cls.get_default_monitor_config())
        return base_config

    @classmethod
    def get_default_monitor_config(cls):
        # type: () -> Dict[str, Any]
        """
        获取监控器默认配置

        子类可以重写此方法来提供特定的默认配置

        Returns:
            Dict[str, Any]: 默认配置字典
        """
        return {}

    @classmethod
    def validate_config(cls, config):
        # type: (Dict[str, Any]) -> None
        """
        验证监控器配置
        
        Args:
            config: 监控器配置字典
            
        Raises:
            ValueError: 配置验证失败时抛出
        """
        if config is None:
            raise ValueError("监控器配置不能为空")
        if not isinstance(config, dict):
            raise ValueError("监控器配置必须为字典，当前类型: {}".format(type(config).__name__))
        if len(config) == 0:
            raise ValueError("监控器配置不能为空字典")
        if config.get("enabled") is None:
            raise ValueError("配置中缺少必需字段: enabled")
        if not isinstance(config.get("enabled"), bool):
            raise ValueError("enabled 必须为布尔值，当前类型: {}".format(type(config.get("enabled")).__name__))

        if not config.get("enabled"):
            return  # 如果监控器未启用，则跳过验证

        if config.get("interval") is None:
            raise ValueError("监控器配置中缺少必需字段: interval")
        if not isinstance(config.get("interval"), (int, float)):
            raise ValueError("interval 必须为数字，当前类型: {}".format(type(config.get("interval")).__name__))
        if config.get("interval") <= 0:
            raise ValueError("interval 必须大于 0，当前值: {}".format(config.get("interval")))

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

    def __init__(self, monitor_context, config):
        # type: (MonitorContext, Dict[str, Any]) -> None
        """
        初始化监控器基类
        
        Args:
            monitor_context: 监控器上下文,包含所有必要的依赖
            config: 监控器配置字典
        """
        # 从monitor_context提取依赖
        self.logger = monitor_context.logger
        self.output_controller = monitor_context.output_controller
        self.ebpf_file = monitor_context.ebpf_file_path
        self.compile_flags = monitor_context.compile_flags

        # 基本属性
        self.type = self.get_monitor_type()
        self.stats_name = "{}_stats".format(self.type)
        self.bpf = None

        # 运行状态
        self.running = False
        self.stop_event = Event()  # type: Event
        # noinspection PyTypeChecker
        self.monitor_thread = None  # type: Thread

        # 验证内核要求和依赖
        self._validate_requirements()

        # 从config提取配置
        self.enabled = config.get("enabled")  # type: bool

        if not self.enabled:
            self.logger.debug("[BaseMonitor] {}监控器未启用".format(self.__class__.__name__))
            return

        self.interval = config.get("interval")  # type: float

        # 应用配置
        self._initialize(config)

        self.logger.debug("[BaseMonitor] {}监控器初始化完成".format(self.__class__.__name__))

    def _validate_requirements(self):
        # type: () -> None
        """
        验证内核要求和依赖

        子类可以重写此方法来验证特定的内核功能
        """
        for tp in self.REQUIRED_TRACEPOINTS:
            tp_path = "/sys/kernel/debug/tracing/events/{}/enable".format(tp.replace(":", "/"))
            if not Path(tp_path).exists():
                tp_path = "/sys/kernel/tracing/events/{}/enable".format(tp.replace(":", "/"))
                if not Path(tp_path).exists():
                    self.logger.warning("[BaseMonitor] Tracepoint {} 可能不可用".format(tp))

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
            self.logger.warning("[BaseMonitor] {}监控未启用".format(self.__class__.__name__))
            return False

        try:
            # 使用传入的编译标志
            self.logger.debug("[BaseMonitor] 加载eBPF程序: {}, 编译标志: {}".format(self.ebpf_file, self.compile_flags))

            # 编译和加载eBPF程序
            self.bpf = BPF(text=self._get_ebpf_code(), cflags=self.compile_flags)
            # 配置程序
            self._configure_ebpf_program()

            self.logger.info("[BaseMonitor] {} eBPF程序加载成功".format(self.__class__.__name__))
            return True
        except Exception as e:
            self.logger.error("[BaseMonitor] {} eBPF程序加载失败: {}".format(self.__class__.__name__, e))
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
    def run(self):
        # type: () -> bool
        """
        开始监控

        Returns:
            bool: 启动是否成功
        """
        if self.running:
            self.logger.warning("[BaseMonitor] {}监控器已经在运行".format(self.__class__.__name__))
            return True

        try:
            # 启动统计定时器线程
            self.stop_event.clear()
            self.monitor_thread = Thread(target=self._monitor_loop)
            self.monitor_thread.daemon = True
            self.monitor_thread.start()

            self.running = True
            self.logger.info("[BaseMonitor] {}监控器启动成功".format(self.__class__.__name__))
            return True
        except Exception as e:
            self.logger.error("[BaseMonitor] 启动{}监控器失败: {}".format(self.__class__.__name__, e))
            return False

    def _monitor_loop(self):
        """监控循环"""
        while not self.stop_event.is_set():
            # 等待指定的统计周期
            if self.stop_event.wait(self.interval):
                break  # 收到停止信号

            try:
                self._collect_and_output()
            except Exception as e:
                self.logger.error("[BaseMonitor] 收集统计数据失败: {}".format(e))

    @require_bpf_loaded
    def stop(self):
        """停止监控"""
        if not self.running:
            self.logger.warning("[BaseMonitor] {}监控器未运行".format(self.__class__.__name__))
            return

        self.logger.info("[BaseMonitor] 正在停止{}监控...".format(self.__class__.__name__))
        self.stop_event.set()

        if self.monitor_thread:
            self.monitor_thread.join(timeout=self.MONITOR_THREAD_TIMEOUT)

        self.running = False
        self.logger.info("[BaseMonitor] {}监控器已停止".format(self.__class__.__name__))

    def _collect_and_output(self):
        """收集并输出统计数据（原子读取并删除）"""
        try:
            monitor_stats = self.bpf.get_table(self.stats_name)
        except Exception as e:
            self.logger.error("[BaseMonitor] 获取统计信息失败: {}".format(e))
            return

        # 收集所有统计数据（使用原子的 pop 操作避免竞态条件）
        stats_list = []

        # 先获取所有 key（快照）
        keys_to_process = list(monitor_stats.keys())

        # 逐个原子地读取并删除
        for key in keys_to_process:
            try:
                # pop() 是原子操作：读取并删除
                value = monitor_stats.pop(key)
                if self.should_collect(key, value):
                    # Python 2兼容：dict无法使用多个**解包，使用update()代替
                    stat_data = {"timestamp": time.time()}
                    stat_data.update(DataProcessor.struct_to_dict(key))
                    stat_data.update(DataProcessor.struct_to_dict(value))
                    stats_list.append(stat_data)
            except KeyError:
                # key 在获取快照后被删除或不存在，跳过
                continue
            except Exception as e:
                self.logger.warning("[BaseMonitor] 处理统计条目失败: {}".format(e))
                continue

        if not stats_list:
            return  # 没有数据，不输出

        for stat in stats_list:
            # 通过输出控制器输出
            self.output_controller.handle_data(self.type, stat)

    # noinspection PyUnusedLocal
    def should_collect(self, key, value):
        """
        判断是否应该收集数据

        子类可以重写此方法来提供特定的数据过滤逻辑

        Args:
            key: 键
            value: 值

        Returns:
            bool: 是否应该收集数据
        """
        return True

    def cleanup(self):
        """清理资源（幂等操作）"""
        # cleanup职责：仅清理资源，不负责停止监控
        # 调用者应该先调用stop()再调用cleanup()
        # 此方法可以安全地多次调用

        # 检查是否已清理
        if getattr(self, "_cleaned_up", False):
            self.logger.debug("[BaseMonitor] {} 资源已清理，跳过重复清理".format(self.__class__.__name__))
            return

        if self.bpf is not None:
            try:
                # 清理BPF对象
                self.bpf.cleanup()
                self.logger.debug("[BaseMonitor] {}监控器eBPF资源清理完成".format(self.type))
            except Exception as e:
                self.logger.error("[BaseMonitor] {}监控器eBPF资源清理失败: {}".format(self.type, e))

        # 标记已清理
        self._cleaned_up = True

    def is_running(self):
        # type: () -> bool
        """
        检查是否正在监控

        Returns:
            bool: 监控状态
        """
        return self.running

    # ==================== 格式化方法接口 ====================
    # 允许子类重写以提供自定义的输出格式

    def get_csv_header(self):
        # type: () -> List[str]
        """
        获取CSV头部字段

        子类需要重写此方法以提供特定的CSV头部字段

        Returns:
            List[str]: CSV头部字段列表
        """
        return ["timestamp", "time_str"] + self.monitor_csv_header()

    def monitor_csv_header(self):
        # type: () -> List[str]
        """
        获取监控器CSV头部字段

        Returns:
            List[str]: CSV头部字段列表
        """
        return []

    def format_for_csv(self, data):
        # type: (Dict[str, Any]) -> Dict[str, Any]
        """
        将事件数据格式化为CSV行数据

        Args:
            data: 数据

        Returns:
            Dict[str, Any]: CSV行数据字典
        """
        timestamp = data["timestamp"]
        return dict({
            "timestamp": timestamp,
            "time_str": DataProcessor.format_timestamp(timestamp)
        }, **self.monitor_csv_data(data))

    def monitor_csv_data(self, data):
        # type: (Dict[str, Any]) -> Dict[str, Any]
        """
        将事件数据格式化为CSV行数据

        子类需要重写此方法以提供特定的CSV数据格式化逻辑

        Args:
            data: 数据

        Returns:
            Dict[str, Any]: CSV行数据字典
        """
        return {k: v for k, v in data.items() if k not in ["timestamp", "time_str"]}

    def get_console_header(self):
        # type: () -> str
        """
        获取控制台输出的表头

        Returns:
            str: 格式化后的控制台表头字符串
        """
        return "{:<22} {}".format("TIME", self.monitor_console_header())

    def monitor_console_header(self):
        # type: () -> str
        """
        获取控制台输出的表头

        子类需要重写此方法以提供特定的控制台表头格式

        Returns:
            str: 控制台表头字符串
        """
        return ""

    def format_for_console(self, data):
        # type: (Dict[str, Any]) -> str
        """
        将事件数据格式化为控制台输出

        Args:
            data: 数据

        Returns:
            str: 格式化后的控制台输出字符串
        """
        timestamp = data["timestamp"]
        time_str = "[{}]".format(DataProcessor.format_timestamp(timestamp))

        return "{:<22} {}".format(time_str, self.monitor_console_data(data))

    # noinspection PyUnusedLocal
    def monitor_console_data(self, data):
        # type: (Dict[str, Any]) -> str
        """
        将事件数据格式化为控制台输出

        子类需要重写此方法以提供特定的控制台数据格式化逻辑

        Args:
            data: 数据

        Returns:
            str: 格式化后的控制台输出字符串
        """
        return ""
