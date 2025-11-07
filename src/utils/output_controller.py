#!/usr/bin/env python
# encoding: utf-8
"""
输出控制器

负责管理监控器的输出格式和目标，支持CSV文件输出和控制台输出。
根据运行的监控器数量自动选择输出模式：
- 单个监控器：CSV文件 + 控制台输出
- 多个监控器：仅CSV文件输出
"""

# 标准库导入
import csv
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
    from typing import Dict, Any, TextIO, List
except ImportError:
    from .py2_compat import Dict, Any, TextIO, List

# 本地模块导入
from .config_manager import ConfigManager
from .configs import OutputConfig
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

        # CSV文件管理
        self.csv_files = {}  # type: Dict[str, TextIO]
        self.csv_writers = {}  # type: Dict[str, csv.DictWriter]

        # 控制标志
        self.running = False
        self.stop_event = threading.Event()
        self.output_thread = None

        # 简化锁机制
        self.registry_lock = threading.Lock()  # 监控器注册/注销锁
        self.console_lock = threading.Lock()  # 控制台输出锁
        self.buffer_lock = threading.Lock()  # 缓冲区访问锁(保护data_buffer的创建和访问)

        # 应用配置
        self._apply_config(self.config_manager.get_output_config())

        # 缓冲区和批处理相关
        self.data_buffer = defaultdict(lambda: deque(maxlen=self.buffer_size))  # type: Dict[str, deque]

        # 表头输出控制
        self.header_printed = {}  # type: Dict[str, bool]

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
            self.header_printed[monitor_type] = False

            self._update_output_mode()
            self._setup_csv_file(monitor_type)

            self.logger.debug("注册监控器: {}".format(monitor_type))

    def unregister_monitor(self, monitor_type):
        # type: (str) -> None
        """注销监控器"""
        with self.registry_lock:
            if monitor_type in self.monitors:
                self.monitors.pop(monitor_type, None)
                # 清理表头标志
                self.header_printed.pop(monitor_type, None)

                self._update_output_mode()
                self._close_csv_file(monitor_type)

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

    def _setup_csv_file(self, monitor_type):
        # type: (str) -> None
        """
        设置CSV文件
        
        创建并打开CSV文件用于监控数据输出，包含异常处理确保资源正确释放
        """
        csv_file = None
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

            # 存储引用(只有在成功创建writer后才存储)
            self.csv_files[monitor_type] = csv_file
            self.csv_writers[monitor_type] = writer

            self.logger.debug("创建CSV文件: {}".format(filepath))

        except IOError as e:
            self.logger.error("创建CSV文件失败 {} (I/O错误): {}".format(monitor_type, e))
            # 关闭已打开的文件句柄
            if csv_file is not None:
                try:
                    csv_file.close()
                except Exception:
                    pass
        except Exception as e:
            self.logger.error("创建CSV文件失败 {} (未知错误): {}".format(monitor_type, e))
            # 关闭已打开的文件句柄
            if csv_file is not None:
                try:
                    csv_file.close()
                except Exception:
                    pass

    def _close_csv_file(self, monitor_type):
        # type: (str) -> None
        """关闭CSV文件"""
        if monitor_type in self.csv_files:
            try:
                self.csv_files[monitor_type].close()
                self.logger.debug("关闭CSV文件: {}".format(monitor_type))
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
                self._flush_all()
            except Exception as e:
                self.logger.error("刷新文件失败: {}".format(e))

        finally:
            # 确保所有文件都被关闭，即使前面步骤出错
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

                # 处理所有监控器的缓冲区
                for monitor_type in list(self.monitors.keys()):
                    self._process_buffer(monitor_type)

                # 定期刷新
                if current_time - last_flush_time >= self.flush_interval:
                    self._flush_all()
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
            # 批量CSV写入
            if monitor_type in self.csv_writers:
                self._write_csv_batch(monitor_type, data)

            # 批量控制台输出
            if self.output_mode == OutputMode.FILE_AND_CONSOLE:
                self._write_console_batch(monitor_type, data)

        except Exception as e:
            self.logger.error("批处理事件失败 {}: {}".format(monitor_type, e))

    def _write_csv_batch(self, monitor_type, data):
        # type: (str, List[Dict[str, Any]]) -> None
        """批量CSV写入 - 单一消费者,无需锁"""
        writer = self.csv_writers[monitor_type]
        for data_item in data:  # type: Dict[str, Any]
            try:
                row_data = self.monitors[monitor_type].format_for_csv(data_item)
                writer.writerow(row_data)
            except Exception as e:
                self.logger.error("CSV写入失败 {}: {}".format(monitor_type, e))

        # 大批次立即刷盘
        if len(data) >= self.large_batch_threshold:
            try:
                self.csv_files[monitor_type].flush()
            except Exception as e:
                self.logger.error("CSV刷盘失败 {}: {}".format(monitor_type, e))

    def _write_console_batch(self, monitor_type, data):
        # type: (str, List[Dict[str, Any]]) -> None
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
                    self.logger.error("控制台表头输出失败 {}: {}".format(monitor_type, e))

            # 批量输出事件
            for data_item in data:  # type: Dict[str, Any]
                try:
                    console_output = self.monitors[monitor_type].format_for_console(data_item)
                    print(console_output)
                    sys.stdout.flush()
                except Exception as e:
                    self.logger.error("控制台输出失败 {}: {}".format(monitor_type, e))

    def _flush_all(self):
        # type: () -> None
        """刷新所有文件 - 单一消费者,无需锁"""
        for monitor_type, csv_file in self.csv_files.items():
            try:
                csv_file.flush()
            except Exception as e:
                self.logger.error("刷新文件失败 {}: {}".format(monitor_type, e))

    def cleanup(self):
        # type: () -> None
        """清理资源（幂等操作）"""
        # 检查是否已清理
        if getattr(self, '_cleaned_up', False):
            self.logger.debug("OutputController资源已清理，跳过重复清理")
            return

        # 清理数据结构
        self.csv_files.clear()
        self.csv_writers.clear()
        self.data_buffer.clear()
        self.monitors.clear()

        # 标记已清理
        self._cleaned_up = True
        self.logger.info("输出控制器资源已清理")
