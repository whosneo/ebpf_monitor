#!/usr/bin/env python
# encoding: utf-8
"""
输出控制器

负责管理监控器的输出格式和目标，支持CSV文件输出和控制台输出。
根据运行的监控器数量自动选择输出模式：
- 单个监控器：CSV文件 + 控制台输出
- 多个监控器：仅CSV文件输出
"""

import csv
import sys
import threading
import time
from collections import defaultdict, deque
try:
    from enum import Enum
except ImportError:
    # Python 2.7 fallback
    from .py2_compat import Enum
try:
    from pathlib import Path
except ImportError:
    # Python 2.7 fallback
    from .py2_compat import Path
try:
    from typing import Dict, Any, TextIO
except ImportError:
    # Python 2.7 fallback
    Dict = dict
    Any = object
    TextIO = object

from .config_manager import ConfigManager
from .configs import OutputConfig
from .log_manager import LogManager
from ..monitors.base import BaseEvent, BaseMonitor


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

    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        """实现单例模式，确保全局唯一的 LogManager 实例"""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super(OutputController, cls).__new__(cls)
        return cls._instance

    def __init__(self, output_dir="output"):
        # type: (str) -> None
        """初始化 LogManager"""
        if not hasattr(self, "_initialized"):  # 防止重复初始化
            self._initialized = False
            self._setup_output_controller(output_dir)
            self._initialized = True

    def _setup_output_controller(self, output_dir):
        # type: (str) -> None
        """设置输出控制器"""
        self.log_manager = LogManager()
        self.logger = self.log_manager.get_logger(self)

        self.config_manager = ConfigManager()

        if Path(output_dir).is_absolute():
            self.output_dir = Path(output_dir)
        else:
            self.output_dir = self.config_manager.get_base_dir() / output_dir

        # 输出模式
        self.output_mode = OutputMode.FILE_ONLY

        self.monitors = {}  # type: Dict[str, BaseMonitor]

        # CSV文件管理
        self.csv_files = {}  # type: Dict[str, TextIO]
        self.csv_writers = {}  # type: Dict[str, csv.DictWriter]

        # 控制标志
        self.running = False
        self.stop_event = threading.Event()
        self.output_thread = None

        # 分层锁架构：替换单一全局锁为细粒度锁
        self.monitor_locks = {}  # type: Dict[str, threading.Lock]  # 每个监控器的缓冲区锁
        self.csv_locks = {}  # type: Dict[str, threading.Lock]  # 每个CSV文件的写入锁
        self.console_lock = threading.Lock()  # 控制台输出锁
        self.buffer_mgmt_lock = threading.Lock()  # 缓冲区管理锁

        # 应用配置
        self._apply_config(self.config_manager.get_output_config())

        # 缓冲区和批处理相关
        self.events_buffer = defaultdict(lambda: deque(maxlen=self.buffer_size))  # type: Dict[str, deque]
        self.batch_size = 100  # 批处理大小（消费者端使用）

        # 表头输出控制
        self.header_printed = {}  # type: Dict[str, bool]

        self.logger.info("输出控制器初始化完成")

    def _apply_config(self, config):
        # type: (OutputConfig) -> None
        """应用配置"""
        # 创建新的配置实例，更新输出目录为绝对路径
        self.buffer_size = config.buffer_size
        self.flush_interval = config.flush_interval
        self.csv_delimiter = config.csv_delimiter
        self.include_header = config.include_header

    def register_monitor(self, monitor_type, monitor_instance):
        # type: (str, BaseMonitor) -> None
        """注册监控器"""
        with self.buffer_mgmt_lock:
            self.monitors[monitor_type] = monitor_instance
            # 重置表头标志
            self.header_printed[monitor_type] = False

            # 为新监控器创建专用锁
            self.monitor_locks[monitor_type] = threading.Lock()
            self.csv_locks[monitor_type] = threading.Lock()

            self._update_output_mode()
            self._setup_csv_file(monitor_type)

            self.logger.info("注册监控器: {}".format(monitor_type))

    def unregister_monitor(self, monitor_type):
        # type: (str) -> None
        """注销监控器"""
        with self.buffer_mgmt_lock:
            if monitor_type in self.monitors:
                self.monitors.pop(monitor_type, None)
                # 清理表头标志
                self.header_printed.pop(monitor_type, None)

                # 清理专用锁
                self.monitor_locks.pop(monitor_type, None)
                self.csv_locks.pop(monitor_type, None)

                self._update_output_mode()
                self._close_csv_file(monitor_type)

                self.logger.info("注销监控器: {}".format(monitor_type))

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

    def _setup_csv_file(self, monitor_type):
        # type: (str) -> None
        """设置CSV文件"""
        try:
            # 生成文件名
            timestamp = time.strftime('%Y%m%d_%H%M%S')
            filename = "{}_{}.csv".format(monitor_type, timestamp)
            filepath = self.output_dir / filename

            # 打开文件
            csv_file = open(str(filepath), 'w')

            # 获取头部
            header = self.monitors[monitor_type].get_csv_header()

            # 创建writer
            writer = csv.DictWriter(
                csv_file,
                fieldnames=header,
                delimiter=self.csv_delimiter
            )
            if self.include_header:
                writer.writeheader()

            # 存储引用
            self.csv_files[monitor_type] = csv_file
            self.csv_writers[monitor_type] = writer

            self.logger.info("创建CSV文件: {}".format(filepath))

        except Exception as e:
            self.logger.error("创建CSV文件失败 {}: {}".format(monitor_type, e))

    def _close_csv_file(self, monitor_type):
        # type: (str) -> None
        """关闭CSV文件"""
        if monitor_type in self.csv_files:
            try:
                self.csv_files[monitor_type].close()
                self.logger.info("关闭CSV文件: {}".format(monitor_type))
            except Exception as e:
                self.logger.error("关闭CSV文件失败 {}: {}".format(monitor_type, e))
            finally:
                # 清理引用，使用pop方法更简洁
                self.csv_files.pop(monitor_type, None)
                self.csv_writers.pop(monitor_type, None)

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

    def handle_event(self, monitor_type, event):
        # type: (str, BaseEvent) -> None
        """
        处理eBPF事件 - 使用细粒度锁和智能批处理

        Args:
            monitor_type: 监控器类型
            event: eBPF事件对象
        """
        if not self.running:
            return

        if monitor_type not in self.monitors:
            return

        try:
            # 性能监控：记录锁等待时间
            lock_start_time = time.time()

            # 使用监控器专用锁，避免全局竞争
            monitor_lock = self.monitor_locks.get(monitor_type)
            if not monitor_lock:
                # 动态创建锁（防止竞态条件）
                with self.buffer_mgmt_lock:
                    if monitor_type not in self.monitor_locks:
                        self.monitor_locks[monitor_type] = threading.Lock()
                    monitor_lock = self.monitor_locks[monitor_type]

            with monitor_lock:
                # 生产者：快速入队，保持生产消费分离
                self.events_buffer[monitor_type].append(event)

        except Exception as e:
            self.logger.error("处理eBPF事件失败 {}: {}".format(monitor_type, e))

    def stop(self):
        # type: () -> None
        """停止输出控制器"""
        if not self.running:
            self.logger.warning("输出控制器未启动")
            return

        self.logger.info("正在停止输出控制器...")

        # 设置停止标志
        self.stop_event.set()

        # 等待线程结束
        if self.output_thread and self.output_thread.is_alive():
            self.output_thread.join(timeout=5)

        # 处理剩余缓冲区数据 - 使用细粒度锁
        for monitor_type in list(self.monitors.keys()):
            monitor_lock = self.monitor_locks.get(monitor_type)
            if monitor_lock:
                with monitor_lock:
                    self._process_buffer(monitor_type)

        # 刷新并关闭所有文件
        self._flush_all()
        for monitor_type in list(self.csv_files.keys()):
            self._close_csv_file(monitor_type)

        self.running = False
        self.logger.info("输出控制器停止成功")

    def _output_loop(self):
        # type: () -> None
        """处理输出线程"""
        last_flush_time = time.time()

        while not self.stop_event.is_set():
            try:
                current_time = time.time()

                # 处理所有监控器的缓冲区 - 使用细粒度锁
                for monitor_type in list(self.monitors.keys()):
                    monitor_lock = self.monitor_locks.get(monitor_type)
                    if monitor_lock:
                        with monitor_lock:
                            self._process_buffer(monitor_type)

                # 定期刷新
                if current_time - last_flush_time >= self.flush_interval:
                    self._flush_all()
                    last_flush_time = current_time

                time.sleep(0.1)  # 短暂休眠
            except Exception as e:
                self.logger.error("输出处理错误: {}".format(e))
                time.sleep(1)

    def _process_buffer(self, monitor_type):
        # type: (str) -> None
        """处理监控器缓冲区 - 消费者端批处理"""
        buffer = self.events_buffer[monitor_type]
        if not buffer:
            return

        # 批量处理缓冲区数据
        batch = []
        while len(batch) < self.batch_size:  # 使用配置的批处理大小
            try:
                batch.append(buffer.popleft())
            except IndexError:
                break

        if batch:
            # 批处理：使用新的批量写入方法
            self._process_event_batch(monitor_type, batch)

    def _process_event_batch(self, monitor_type, events):
        # type: (str, list) -> None
        """批量处理事件 - 减少I/O系统调用次数"""
        try:
            # 批量CSV写入
            if monitor_type in self.csv_writers:
                self._write_csv_batch(monitor_type, events)

            # 批量控制台输出
            if self.output_mode == OutputMode.FILE_AND_CONSOLE:
                self._write_console_batch(monitor_type, events)

        except Exception as e:
            self.logger.error("批处理事件失败 {}: {}".format(monitor_type, e))

    def _write_csv_batch(self, monitor_type, events):
        # type: (str, list) -> None
        """批量CSV写入 - 使用文件级锁"""
        csv_lock = self.csv_locks.get(monitor_type)
        if not csv_lock or monitor_type not in self.csv_writers:
            return

        with csv_lock:
            writer = self.csv_writers[monitor_type]
            for event in events:
                try:
                    row_data = self.monitors[monitor_type].format_for_csv(event)
                    writer.writerow(row_data)
                except Exception as e:
                    self.logger.error("CSV写入失败 {}: {}".format(monitor_type, e))

            # 大批次立即刷盘
            if len(events) >= 20:
                try:
                    self.csv_files[monitor_type].flush()
                except Exception as e:
                    self.logger.error("CSV刷盘失败 {}: {}".format(monitor_type, e))

    def _write_console_batch(self, monitor_type, events):
        # type: (str, list) -> None
        """批量控制台输出 - 使用控制台级锁"""
        with self.console_lock:
            # 首次输出表头
            if not self.header_printed.get(monitor_type, False):
                try:
                    header = self.monitors[monitor_type].get_console_header()
                    print(header)
                    print("-" * (len(header) + 16))
                    self.header_printed[monitor_type] = True
                except Exception as e:
                    self.logger.error("控制台表头输出失败: {}".format(e))

            # 批量输出事件
            for event in events:
                try:
                    console_output = self.monitors[monitor_type].format_for_console(event)
                    print(console_output)
                    sys.stdout.flush()
                except Exception as e:
                    self.logger.error("控制台输出失败: {}".format(e))

    def _flush_all(self):
        # type: () -> None
        """刷新所有文件 - 使用文件级锁"""
        for monitor_type, csv_file in self.csv_files.items():
            csv_lock = self.csv_locks.get(monitor_type)
            if csv_lock:
                with csv_lock:
                    try:
                        csv_file.flush()
                    except Exception as e:
                        self.logger.error("刷新文件失败 {}: {}".format(monitor_type, e))
            else:
                # 兜底处理
                try:
                    csv_file.flush()
                except Exception as e:
                    self.logger.error("刷新文件失败 {}: {}".format(monitor_type, e))

    def get_status(self):
        # type: () -> Dict[str, Any]
        """获取状态信息"""
        with self.buffer_mgmt_lock:
            return {
                'running': self.running,
                'output_mode': self.output_mode.value,
                'output_dir': self.output_dir,
                'monitors': list(self.monitors.keys()),
                'buffer_size': self.buffer_size,
                'flush_interval': self.flush_interval,
                'csv_delimiter': self.csv_delimiter,
                'include_header': self.include_header,
                'batch_size': self.batch_size
            }

    def cleanup(self):
        # type: () -> None
        """清理资源"""
        self.csv_files.clear()
        self.csv_writers.clear()
        self.events_buffer.clear()
        self.monitors.clear()
        self.events_buffer.clear()
        self.logger.info("输出控制器资源已清理")
