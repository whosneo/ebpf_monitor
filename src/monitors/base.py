#!/usr/bin/env python
# encoding: utf-8
"""
eBPF监控器基类

提供所有监控器的共同接口和实现，定义标准的监控流程。
子类只需实现特定的抽象方法即可快速创建新的监控器。

监控器模式：
- STATISTICAL: 统计聚合模式，定期从BPF表读取统计数据
- EVENT: 事件驱动模式，实时处理perf_buffer事件
"""

# 标准库导入
import re
import time
from threading import Thread, Event

# 兼容性导入
try:
    from abc import ABC, abstractmethod
except ImportError:
    from ..utils.py2_compat import ABC
    abstractmethod = lambda f: f
try:
    from enum import Enum
except ImportError:
    from ..utils.py2_compat import Enum
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
from ..utils.config_validator import ConfigValidator
from ..utils.data_processor import DataProcessor
from ..utils.decorators import MONITOR_REGISTRY, require_bpf_loaded
from ..utils.monitor_context import MonitorContext


class MonitorMode(Enum):
    """监控器模式枚举
    
    定义监控器的数据收集方式：
    - STATISTICAL: 统计聚合模式，定期从内核BPF表读取聚合数据
    - EVENT: 事件驱动模式，实时处理perf_buffer事件
    """
    STATISTICAL = "statistical"  # 统计聚合模式（bio, syscall, func, interrupt, page_fault, context_switch, open）
    EVENT = "event"  # 事件驱动模式（exec）


class BaseMonitor(ABC):
    """eBPF监控器基类

    定义了所有eBPF监控器的通用接口和实现。
    子类需要实现抽象方法来提供特定的监控功能。
    
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
        获取监控器特定的默认配置

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

        ConfigValidator.validate_required(config, ["enabled"])
        ConfigValidator.validate_bool(config.get("enabled"), "enabled")

        if not config.get("enabled"):
            return  # 如果监控器未启用，则跳过验证

        ConfigValidator.validate_required(config, ["interval"])
        ConfigValidator.validate_float(config.get("interval"), "interval", min_val=0.001)

        cls.validate_monitor_config(config)

    @classmethod
    def validate_monitor_config(cls, config):
        # type: (Dict[str, Any]) -> None
        """
        验证监控器特定配置

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

    @property
    def mode(self):
        # type: () -> MonitorMode
        """
        监控器模式
        
        子类必须重写此属性以指定监控器模式。
        - MonitorMode.STATISTICAL: 统计聚合模式，定期从BPF表读取数据
        - MonitorMode.EVENT: 事件驱动模式，实时处理perf_buffer事件
        
        Returns:
            MonitorMode: 监控器模式
        """
        return MonitorMode.STATISTICAL

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

        子类可以重写此方法来初始化监控器特定的属性
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
            self.bpf = BPF(text=self.get_ebpf_code(), cflags=self.compile_flags)
            # 配置程序
            self._configure_ebpf_program()

            self.logger.info("[BaseMonitor] {} eBPF程序加载成功".format(self.__class__.__name__))
            return True
        except Exception as e:
            self.logger.error("[BaseMonitor] {} eBPF程序加载失败: {}".format(self.__class__.__name__, e))
            return False

    def get_ebpf_code(self):
        # type: () -> str
        """
        获取eBPF程序代码

        子类可以重写此方法来修改代码（如动态生成探针）
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

        根据监控器模式启动相应的监控流程：
        - STATISTICAL: 启动统计定时器线程
        - EVENT: 启动事件轮询线程

        Returns:
            bool: 启动是否成功
        """
        if self.running:
            self.logger.warning("[BaseMonitor] {}监控器已经在运行".format(self.__class__.__name__))
            return True

        try:
            self.stop_event.clear()
            self.monitor_thread = Thread(target=self._monitor_loop)
            self.monitor_thread.daemon = True
            self.monitor_thread.start()

            self.running = True
            self.logger.info("[BaseMonitor] {}监控器启动成功 (模式: {})".format(
                self.__class__.__name__, self.mode.value))
            return True
        except Exception as e:
            self.logger.error("[BaseMonitor] 启动{}监控器失败: {}".format(self.__class__.__name__, e))
            return False

    def _monitor_loop(self):
        """监控循环
        
        根据监控器模式调用不同的数据收集方法：
        - STATISTICAL: 定时调用 _collect_statistical_data()
        - EVENT: 轮询调用 _poll_events()
        """
        if self.mode == MonitorMode.EVENT:
            # 事件驱动模式：轮询perf_buffer
            self._event_monitor_loop()
        else:
            # 统计聚合模式：定时收集
            self._statistical_monitor_loop()

    def _statistical_monitor_loop(self):
        """统计聚合模式监控循环"""
        while not self.stop_event.is_set():
            # 等待指定的统计周期
            if self.stop_event.wait(self.interval):
                break  # 收到停止信号

            try:
                self._collect_and_output()
            except Exception as e:
                self.logger.error("[BaseMonitor] 收集统计数据失败: {}".format(e))

    def _event_monitor_loop(self):
        """事件驱动模式监控循环
        
        子类可以重写此方法以自定义事件轮询逻辑。
        默认实现调用 _poll_events() 方法。
        """
        while not self.stop_event.is_set():
            try:
                self._poll_events()
            except Exception as e:
                self.logger.error("[BaseMonitor] 处理事件失败: {}".format(e))
                # 短暂休眠后重试，避免错误循环消耗CPU
                if not self.stop_event.is_set():
                    self.stop_event.wait(0.1)

    def _poll_events(self):
        """轮询事件
        
        事件驱动模式的监控器需要重写此方法。
        默认实现从BPF表读取统计数据（与统计模式相同）。
        """
        self._collect_and_output()

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
    # 子类有三种方式提供格式化逻辑（优先级从高到低）：
    #
    # 方式1（最简洁）：声明 CSV_COLUMNS 和 CONSOLE_FORMAT
    #   CSV_COLUMNS 支持3种格式:
    #     ("列名", "数据键")                        — 简单映射
    #     ("列名", "数据键", transform_fn)           — 单键转换
    #     ("列名", ("键1","键2"), transform_fn)      — 多键转换
    #   CONSOLE_FORMAT 支持2种元组格式:
    #     二元组（向后兼容）:
    #       ("格式串", ["键1", "键2"])                  — 简单格式化
    #       ("格式串", [("键1", fn), "键2"])            — 混合模式
    #     三元组（推荐，自动表头）:
    #       ("格式串", ["键1", "键2"], ["标题1", "标题2"]) — 自动表头+格式化
    #       ("格式串", [("键1", fn), "键2"], ["标题1", "标题2"]) — 混合模式+表头
    #   基类自动完成所有格式化，子类无需重写任何方法
    #
    # 方式2（灵活）：重写 monitor_csv_header/monitor_csv_data 和
    #              monitor_console_header/monitor_console_data 四个方法
    #
    # 方式3（完全控制）：直接重写 format_for_csv / format_for_console

    # 声明式CSV列定义
    # 支持3种格式:
    #   ("col", "key")                        — 简单映射 data[key]
    #   ("col", "key", fn)                    — 转换 fn(data[key])
    #   ("col", ("k1","k2"), fn)              — 多键 fn(data[k1], data[k2])
    # 转换函数可以是：
    #   - 无状态纯函数（模块级定义）
    #   - 实例方法（self.xxx），通过子类中定义方法后在CSV_COLUMNS中引用
    #     例: class MyMonitor:
    #           def _fmt_xxx(self, v): return self.lookup[v]
    #           CSV_COLUMNS = [("xxx", "key", _fmt_xxx)]
    CSV_COLUMNS = []  # type: List[tuple]

    # 声明式控制台格式
    # 支持2种元组格式:
    #   二元组（向后兼容）:
    #     ("fmt", ["k1", "k2"])                        — 简单映射
    #     ("fmt", [("k1", fn), "k2"])                  — 混合模式
    #     ("fmt", [("k1", fn), (("k1","k2"), fn)])     — 全转换
    #   三元组（推荐，自动表头）:
    #     ("fmt", ["k1", "k2"], ["COL1", "COL2"])      — 简单映射+表头
    #     ("fmt", [("k1", fn), "k2"], ["COL1", "COL2"]) — 混合模式+表头
    # 第3个元素是列标题列表，与第2个元素一一对应。
    # 转换函数同CSV_COLUMNS，支持实例方法
    CONSOLE_FORMAT = None  # type: tuple

    @staticmethod
    def _is_class_defined_method(fn, cls):
        # type: (Any, type) -> bool
        """
        检查 fn 是否是类 cls 中直接定义的方法（未绑定方法引用）。
        
        用于区分：
        - 模块级纯函数（如 io_type_to_str）→ 不需要 self
        - 类中定义的方法引用（如 self._fmt_xxx）→ 需要 self
        """
        if cls is None:
            return False
        # 检查函数是否直接定义在该类（而非基类）的 __dict__ 中
        for name, member in cls.__dict__.items():
            if member is fn:
                return True
        return False

    def _apply_transform(self, fn, args, col_cls):
        # type: (Any, list, type) -> Any
        """
        调用转换函数，自动判断是否需要传入 self。
        
        如果 fn 是在 col_cls 类中直接定义的方法引用，则传入 self。
        否则作为普通函数调用。
        """
        if self._is_class_defined_method(fn, col_cls):
            return fn(self, *args)
        return fn(*args)

    # ==================== 数据提取与格式化 ====================

    def _extract_column_value(self, col_def, data):
        # type: (Any, Dict[str, Any]) -> Any
        """
        根据列定义从data中提取值。

        统一处理CSV_COLUMNS和CONSOLE_FORMAT的列定义，支持以下格式:
          "key"                         -> data.get("key", "")
          ("key", fn)                   -> fn(data.get("key", ""))
          (("k1", "k2"), fn)           -> fn(data.get("k1"), data.get("k2"))

        fn 可以是：
        - 模块级纯函数（如 io_type_to_str）→ 直接调用 fn(*args)
        - 类中定义的方法引用（如 MyMonitor._fmt_xxx）→ 调用 fn(self, *args)
        """
        if isinstance(col_def, tuple) and len(col_def) >= 2 and callable(col_def[1]):
            keys = col_def[0]
            fn = col_def[1]
            if isinstance(keys, (tuple, list)):
                args = [data.get(k, "") for k in keys]
            else:
                args = [data.get(keys, "")]
            return self._apply_transform(fn, args, type(self))
        # 简单 key 映射: "key" 或 ("col", "key") 的第二项
        if isinstance(col_def, (list, tuple)) and len(col_def) >= 2:
            return data.get(col_def[1], "")
        return data.get(col_def, "")

    @staticmethod
    def _strip_numeric_format(fmt_str):
        # type: (str) -> str
        """
        将格式字符串中的数字类型符降级为字符串格式。

        用于表头生成，避免字符串类型的表头文字触发数字格式化错误。
        如 {:<7.1f}% → {:<7}% 、 {:>8.1f} → {:>8}
        """
        return re.sub(
            r'\{([^}]*?)(?:\.[0-9]+)?[dfFeEgGn]([^}]*?)\}',
            r'{\1\2}',
            fmt_str
        )

    # ==================== CSV 格式化 ====================

    def get_csv_header(self):
        # type: () -> List[str]
        """
        获取CSV头部字段列表。

        Returns:
            List[str]: CSV头部字段列表（含 timestamp 和 time_str）
        """
        return ["timestamp", "time_str"] + self.monitor_csv_header()

    def monitor_csv_header(self):
        # type: () -> List[str]
        """
        获取监控器CSV头部字段。

        如果子类声明了 CSV_COLUMNS，自动从中提取列名。
        否则子类需重写此方法。

        Returns:
            List[str]: 监控器CSV头部字段列表
        """
        if self.CSV_COLUMNS:
            return [col[0] for col in self.CSV_COLUMNS]
        return []

    def format_for_csv(self, data):
        # type: (Dict[str, Any]) -> Dict[str, Any]
        """
        将事件数据格式化为CSV行数据。

        Args:
            data: 原始事件数据

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
        将事件数据格式化为CSV行数据。

        如果子类声明了 CSV_COLUMNS，自动从中提取数据。
        否则子类需重写此方法。

        Args:
            data: 原始事件数据

        Returns:
            Dict[str, Any]: CSV行数据字典
        """
        if self.CSV_COLUMNS:
            return {col[0]: self._extract_column_value(col, data) for col in self.CSV_COLUMNS}
        return {k: v for k, v in data.items() if k not in ["timestamp", "time_str"]}

    # ==================== 控制台格式化 ====================

    def get_console_header(self):
        # type: () -> str
        """
        获取控制台输出的表头。

        基类自动拼接 TIME 前缀与监控器表头。

        Returns:
            str: 格式化后的控制台表头字符串
        """
        return "{:<22} {}".format("TIME", self.monitor_console_header())

    def monitor_console_header(self):
        # type: () -> str
        """
        获取监控器控制台表头。

        如果 CONSOLE_FORMAT 为三元组 (fmt, keys, headers)，自动使用 headers 列表
        格式化为表头文字，数字格式自动降级为字符串格式。
        如果为二元组 (fmt, keys)，返回格式字符串（向后兼容）。
        否则子类需重写此方法。

        Returns:
            str: 监控器控制台表头字符串
        """
        if self.CONSOLE_FORMAT:
            fmt_str = self.CONSOLE_FORMAT[0]
            # 三元组: (format_str, keys, headers)
            if len(self.CONSOLE_FORMAT) >= 3:
                headers = self.CONSOLE_FORMAT[2]
                header_fmt = self._strip_numeric_format(fmt_str)
                try:
                    return header_fmt.format(*headers)
                except (IndexError, KeyError):
                    return " | ".join(str(h) for h in headers)
            # 二元组（向后兼容）: 返回格式字符串
            return fmt_str
        return ""

    def format_for_console(self, data):
        # type: (Dict[str, Any]) -> str
        """
        将事件数据格式化为控制台输出行。

        自动拼接时间戳与监控器数据行。

        Args:
            data: 原始事件数据

        Returns:
            str: 格式化后的控制台输出字符串
        """
        timestamp = data["timestamp"]
        time_str = "[{}]".format(DataProcessor.format_timestamp(timestamp))
        return "{:<22} {}".format(time_str, self.monitor_console_data(data))

    def monitor_console_data(self, data):
        # type: (Dict[str, Any]) -> str
        """
        将事件数据格式化为控制台数据行。

        如果子类声明了 CONSOLE_FORMAT，自动从中提取数据并格式化。
        否则子类需重写此方法。

        Args:
            data: 原始事件数据

        Returns:
            str: 格式化后的控制台数据字符串
        """
        if self.CONSOLE_FORMAT:
            fmt_str = self.CONSOLE_FORMAT[0]
            keys = self.CONSOLE_FORMAT[1]
            values = [self._extract_column_value(k, data) for k in keys]
            try:
                return fmt_str.format(*values)
            except (IndexError, KeyError):
                return " | ".join(str(v) for v in values)
        return ""
