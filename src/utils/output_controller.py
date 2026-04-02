#!/usr/bin/env python
# encoding: utf-8
"""
输出控制器

负责管理监控器的输出格式和目标，支持CSV文件输出和控制台输出。
根据运行的监控器数量自动选择输出模式：
- 单个监控器：CSV文件 + 控制台输出
- 多个监控器：仅CSV文件输出

CSV文件管理和控制台输出委托给CsvWriter和ConsoleWriter。
"""

# 标准库导入
import sys
import threading
import time
from collections import defaultdict, deque

# 兼容性导入
try:
    from enum import Enum
except ImportError:
    from .py2_compat import Enum
try:
    from pathlib import Path
except ImportError:
    from .py2_compat import Path
try:
    from typing import Dict, Any, List
except ImportError:
    from .py2_compat import Dict, Any, List

# 本地模块导入
from .config_manager import ConfigManager
from .configs import OutputConfig
from .csv_writer import CsvWriter
from .console_writer import ConsoleWriter
from .log_manager import LogManager
from ..monitors.base import BaseMonitor


class OutputMode(Enum):
    """输出模式"""
    FILE_ONLY = "file_only"  # 仅文件输出
    FILE_AND_CONSOLE = "file_and_console"  # 文件和控制台输出


class OutputController:
    """
    输出控制器

    负责管理监控器的输出格式和目标，支持CSV文件输出和控制台输出。
    根据运行的监控器数量自动选择输出模式：
    - 单个监控器：CSV文件 + 控制台输出
    - 多个监控器：仅CSV文件输出
    """

    def __init__(self, config_manager, log_manager, output_dir="output"):
        # type: (ConfigManager, LogManager, str) -> None
        """初始化输出控制器"""
        self._setup_output_controller(config_manager, log_manager, output_dir)

    def _setup_output_controller(self, config_manager, log_manager, output_dir):
        # type: (ConfigManager, LogManager, str) -> None
        """设置输出控制器"""
        self.config_manager = config_manager
        self.logger = log_manager.get_logger(self)

        if Path(output_dir).is_absolute():
            self.output_dir = Path(output_dir)
        else:
            self.output_dir = self.config_manager.get_base_dir() / output_dir

        # 输出模式
        self.output_mode = OutputMode.FILE_ONLY

        self.monitors = {}  # type: Dict[str, BaseMonitor]

        # 控制标志
        self.running = False
        self.stop_event = threading.Event()
        self.output_thread = None

        # 简化锁机制
        self.registry_lock = threading.Lock()  # 监控器注册/注销锁
        self.buffer_lock = threading.Lock()  # 缓冲区访问锁(保护data_buffer的创建和访问)

        # 应用配置
        self._apply_config(self.config_manager.get_output_config())

        # 缓冲区和批处理相关
        self.data_buffer = defaultdict(lambda: deque(maxlen=self.buffer_size))  # type: Dict[str, deque]

        # 初始化子组件
        self.csv_writer = CsvWriter(
            self.output_dir, self.csv_delimiter, self.include_header, self.logger
        )
        self.console_writer = ConsoleWriter(self.logger)

        self.logger.debug("输出控制器初始化完成")

    def _apply_config(self, config):
        # type: (OutputConfig) -> None
        """应用输出配置"""
        self.buffer_size = config.buffer_size
        self.batch_size = config.batch_size
        self.large_batch_threshold = config.large_batch_threshold
        self.flush_interval = config.flush_interval
        self.output_thread_sleep = config.output_thread_sleep
        self.csv_delimiter = config.csv_delimiter
        self.include_header = config.include_header

    def register_monitor(self, monitor_type, monitor_instance):
        # type: (str, BaseMonitor) -> None
        """注册监控器"""
        with self.registry_lock:
            self.monitors[monitor_type] = monitor_instance
            # 重置表头标志
            self.console_writer.reset_header(monitor_type)

            self._update_output_mode()
            self.csv_writer.setup_file(monitor_type, monitor_instance)

            self.logger.debug("注册监控器: {}".format(monitor_type))

    def unregister_monitor(self, monitor_type):
        # type: (str) -> None
        """注销监控器"""
        with self.registry_lock:
            if monitor_type in self.monitors:
                self.monitors.pop(monitor_type, None)
                # 清理表头标志
                self.console_writer.remove_header(monitor_type)

                self._update_output_mode()
                self.csv_writer.close_file(monitor_type)

                self.logger.debug("注销监控器: {}".format(monitor_type))

    def _update_output_mode(self):
        # type: () -> None
        """更新输出模式"""
        monitor_count = len(self.monitors)
        old_mode = self.output_mode

        if monitor_count <= 1:
            self.output_mode = OutputMode.FILE_AND_CONSOLE
        else:
            self.output_mode = OutputMode.FILE_ONLY

        if old_mode != self.output_mode:
            self.logger.info("输出模式切换: {} -> {}".format(old_mode.name, self.output_mode.name))

    def start(self):
        # type: () -> bool
        """启动输出控制器"""
        if self.running:
            self.logger.warning("输出控制器已在运行")
            return True

        try:
            self.logger.info("开始启动输出控制器...")

            self.stop_event.clear()
            self.output_thread = threading.Thread(target=self._output_loop)
            # Python 2.7兼容性：设置daemon属性而不是在__init__中传递
            self.output_thread.daemon = True
            self.output_thread.start()

            self.running = True
            self.logger.info("输出控制器启动成功")
            return True
        except Exception as e:
            self.logger.error("输出控制器启动失败: {}".format(e))
            return False

    def handle_data(self, monitor_type, data):
        # type: (str, Dict[str, Any]) -> None
        """
        处理eBPF事件
        
        将事件添加到对应监控器的缓冲区，使用锁保护defaultdict的线程安全

        Args:
            monitor_type: 监控器类型
            data: eBPF数据
        """
        if not self.running:
            return

        if monitor_type not in self.monitors:
            return

        try:
            # 使用buffer_lock保护对defaultdict的访问
            # 虽然deque.append()本身是线程安全的，但defaultdict的key创建不是
            with self.buffer_lock:
                self.data_buffer[monitor_type].append(data)

        except Exception as e:
            self.logger.error("处理eBPF数据失败 {}: {}".format(monitor_type, e))

    def stop(self):
        # type: () -> None
        """停止输出控制器"""
        if not self.running:
            self.logger.warning("输出控制器未启动")
            return

        self.logger.info("正在停止输出控制器...")

        try:
            # 设置停止标志
            self.stop_event.set()

            # 等待线程结束
            if self.output_thread and self.output_thread.is_alive():
                self.output_thread.join(timeout=5)
                if self.output_thread.is_alive():
                    self.logger.warning("输出线程未能在超时时间内结束")

            # 处理剩余缓冲区数据
            for monitor_type in list(self.monitors.keys()):
                try:
                    self._process_buffer(monitor_type)
                except Exception as e:
                    self.logger.error("处理缓冲区数据失败 {}: {}".format(monitor_type, e))

            # 刷新并关闭所有文件
            try:
                self.csv_writer.flush_all()
            except Exception as e:
                self.logger.error("刷新文件失败: {}".format(e))

        finally:
            # 确保所有文件都被关闭，即使前面步骤出错
            self.csv_writer.cleanup()

            self.running = False
            self.logger.info("输出控制器停止成功")

    def _output_loop(self):
        # type: () -> None
        """处理输出线程"""
        last_flush_time = time.time()

        while not self.stop_event.is_set():
            try:
                current_time = time.time()

                # 处理所有监控器的缓冲区
                for monitor_type in list(self.monitors.keys()):
                    self._process_buffer(monitor_type)

                # 定期刷新
                if current_time - last_flush_time >= self.flush_interval:
                    self.csv_writer.flush_all()
                    last_flush_time = current_time

                time.sleep(self.output_thread_sleep)  # 短暂休眠
            except Exception as e:
                self.logger.error("输出处理错误: {}".format(e))
                time.sleep(1)

    def _process_buffer(self, monitor_type):
        # type: (str) -> None
        """
        处理监控器缓冲区 - 消费者端批处理
        
        从缓冲区中批量取出事件进行处理，减少I/O操作次数以提升性能。
        
        批处理逻辑:
        1. 一次性从deque中取出最多batch_size个事件
        2. deque.popleft()是原子操作，线程安全
        3. IndexError表示缓冲区已空，这是正常情况
        4. 批量处理可以显著减少系统调用和磁盘I/O次数
        
        Args:
            monitor_type: 监控器类型
        """
        buffer = self.data_buffer[monitor_type]
        if not buffer:
            return

        # 批量从缓冲区取出事件(最多batch_size个)
        batch = []  # type: List[Dict[str, Any]]
        while len(batch) < self.batch_size:
            try:
                # deque.popleft() 是原子操作，线程安全
                batch.append(buffer.popleft())
            except IndexError:
                # 缓冲区已空，这是正常情况
                break

        if batch:
            # 批量处理事件，减少I/O次数
            self._process_data_batch(monitor_type, batch)

    def _process_data_batch(self, monitor_type, data):
        # type: (str, List[Dict[str, Any]]) -> None
        """批量处理事件 - 减少I/O系统调用次数"""
        try:
            # 批量CSV写入（委托给CsvWriter）
            if self.csv_writer.has_writer(monitor_type):
                self.csv_writer.write_batch(
                    monitor_type, data, self.monitors, self.large_batch_threshold
                )

            # 批量控制台输出（委托给ConsoleWriter）
            if self.output_mode == OutputMode.FILE_AND_CONSOLE:
                self.console_writer.write_batch(monitor_type, data, self.monitors)

        except Exception as e:
            self.logger.error("批处理事件失败 {}: {}".format(monitor_type, e))

    def cleanup(self):
        # type: () -> None
        """清理资源（幂等操作）"""
        # 检查是否已清理
        if getattr(self, '_cleaned_up', False):
            self.logger.debug("OutputController资源已清理，跳过重复清理")
            return

        # 清理子组件
        self.csv_writer.cleanup()
        self.console_writer.cleanup()

        # 清理数据结构
        self.data_buffer.clear()
        self.monitors.clear()

        # 标记已清理
        self._cleaned_up = True
        self.logger.info("输出控制器资源已清理")
