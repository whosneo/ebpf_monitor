#!/usr/bin/env python
# encoding: utf-8
"""
CSV写入器

负责CSV文件的创建、写入、刷新和关闭。
从OutputController中提取，遵循单一职责原则。
"""

import csv
import time

# 兼容性导入
try:
    from pathlib import Path
except ImportError:
    from .py2_compat import Path
try:
    from typing import Dict, Any, TextIO, List, TYPE_CHECKING
except ImportError:
    from .py2_compat import Dict, Any, TextIO, List, TYPE_CHECKING

if TYPE_CHECKING:
    from ..monitors.base import BaseMonitor


class CsvWriter(object):
    """CSV写入器 - 管理CSV文件的生命周期和数据写入"""

    def __init__(self, output_dir, csv_delimiter, include_header, logger):
        # type: (Path, str, bool, object) -> None
        """
        初始化CSV写入器
        
        Args:
            output_dir: 输出目录
            csv_delimiter: CSV分隔符
            include_header: 是否包含表头
            logger: 日志记录器
        """
        self.output_dir = output_dir
        self.csv_delimiter = csv_delimiter
        self.include_header = include_header
        self.logger = logger

        self.csv_files = {}  # type: Dict[str, TextIO]
        self.csv_writers = {}  # type: Dict[str, csv.DictWriter]

    def setup_file(self, monitor_type, monitor):
        # type: (str, 'BaseMonitor') -> None
        """
        为监控器创建CSV文件
        
        Args:
            monitor_type: 监控器类型名称
            monitor: 监控器实例（用于获取CSV表头）
        """
        csv_file = None
        try:
            timestamp = time.strftime('%Y%m%d_%H%M%S')
            filename = "{}_{}.csv".format(monitor_type, timestamp)
            filepath = self.output_dir / filename

            csv_file = open(str(filepath), 'w')

            header = monitor.get_csv_header()

            writer = csv.DictWriter(
                csv_file,
                fieldnames=header,
                delimiter=self.csv_delimiter
            )
            if self.include_header:
                writer.writeheader()

            self.csv_files[monitor_type] = csv_file
            self.csv_writers[monitor_type] = writer

            self.logger.debug("创建CSV文件: {}".format(filepath))

        except IOError as e:
            self.logger.error("创建CSV文件失败 {} (I/O错误): {}".format(monitor_type, e))
            if csv_file is not None:
                try:
                    csv_file.close()
                except Exception:
                    pass
        except Exception as e:
            self.logger.error("创建CSV文件失败 {} (未知错误): {}".format(monitor_type, e))
            if csv_file is not None:
                try:
                    csv_file.close()
                except Exception:
                    pass

    def close_file(self, monitor_type):
        # type: (str) -> None
        """
        关闭指定监控器的CSV文件
        
        Args:
            monitor_type: 监控器类型名称
        """
        if monitor_type in self.csv_files:
            try:
                self.csv_files[monitor_type].close()
                self.logger.debug("关闭CSV文件: {}".format(monitor_type))
            except Exception as e:
                self.logger.error("关闭CSV文件失败 {}: {}".format(monitor_type, e))
            finally:
                self.csv_files.pop(monitor_type, None)
                self.csv_writers.pop(monitor_type, None)

    def write_batch(self, monitor_type, data, monitors, large_batch_threshold):
        # type: (str, List[Dict[str, Any]], Dict[str, 'BaseMonitor'], int) -> None
        """
        批量写入CSV数据
        
        Args:
            monitor_type: 监控器类型名称
            data: 数据列表
            monitors: 监控器实例字典（用于格式化数据）
            large_batch_threshold: 大批次阈值，超过时立即刷盘
        """
        if monitor_type not in self.csv_writers:
            return

        writer = self.csv_writers[monitor_type]
        for data_item in data:  # type: Dict[str, Any]
            try:
                row_data = monitors[monitor_type].format_for_csv(data_item)
                writer.writerow(row_data)
            except Exception as e:
                self.logger.error("CSV写入失败 {}: {}".format(monitor_type, e))

        # 大批次立即刷盘
        if len(data) >= large_batch_threshold:
            try:
                self.csv_files[monitor_type].flush()
            except Exception as e:
                self.logger.error("CSV刷盘失败 {}: {}".format(monitor_type, e))

    def flush_all(self):
        # type: () -> None
        """刷新所有CSV文件"""
        for monitor_type, csv_file in self.csv_files.items():
            try:
                csv_file.flush()
            except Exception as e:
                self.logger.error("刷新文件失败 {}: {}".format(monitor_type, e))

    def has_writer(self, monitor_type):
        # type: (str) -> bool
        """检查是否有指定监控器的writer"""
        return monitor_type in self.csv_writers

    def cleanup(self):
        # type: () -> None
        """清理所有CSV资源"""
        for monitor_type in list(self.csv_files.keys()):
            self.close_file(monitor_type)
