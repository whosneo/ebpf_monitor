#!/usr/bin/env python
# encoding: utf-8
"""
CSV写入器

负责CSV文件的创建、写入、刷新和关闭。
从OutputController中提取，遵循单一职责原则。
"""

import csv
import os
import time

# 兼容性导入
try:
    from pathlib import Path
except ImportError:
    from .py2_compat import Path
try:
    from typing import Dict, Any, TextIO, List, TYPE_CHECKING, Optional
except ImportError:
    from .py2_compat import Dict, Any, TextIO, List, TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from ..monitors.base import BaseMonitor


def select_files_for_retention(files_with_mtime_size, max_age_days, max_total_bytes, max_files):
    # type: (List[tuple], float, int, int) -> List[str]
    """
    纯函数：给定 [(path, mtime, size), ...] 返回应删除的 path 列表。

    规则：
    1) 超过 max_age_days 的删除（max_age_days<=0 表示不按年龄）
    2) 按 mtime 新→旧排序后，超过 max_files 的旧文件删除
    3) 总量超过 max_total_bytes 时继续删最旧
    """
    now = time.time()
    to_delete = set()
    remaining = list(files_with_mtime_size)

    if max_age_days and max_age_days > 0:
        age_s = max_age_days * 86400.0
        kept = []
        for path, mtime, size in remaining:
            if now - mtime > age_s:
                to_delete.add(path)
            else:
                kept.append((path, mtime, size))
        remaining = kept

    # newest first
    remaining.sort(key=lambda x: x[1], reverse=True)

    if max_files and max_files > 0 and len(remaining) > max_files:
        for path, mtime, size in remaining[max_files:]:
            to_delete.add(path)
        remaining = remaining[:max_files]

    if max_total_bytes and max_total_bytes > 0:
        total = sum(s for _, _, s in remaining)
        # delete oldest first among remaining
        remaining_oldest_first = sorted(remaining, key=lambda x: x[1])
        idx = 0
        while total > max_total_bytes and idx < len(remaining_oldest_first):
            path, mtime, size = remaining_oldest_first[idx]
            to_delete.add(path)
            total -= size
            idx += 1

    return list(to_delete)


class CsvWriter(object):
    """CSV写入器 - 管理CSV文件的生命周期和数据写入"""

    def __init__(self, output_dir, csv_delimiter, include_header, logger, retention=None):
        # type: (Path, str, bool, object, Optional[Dict[str, Any]]) -> None
        """
        初始化CSV写入器
        
        Args:
            output_dir: 输出目录
            csv_delimiter: CSV分隔符
            include_header: 是否包含表头
            logger: 日志记录器
            retention: 可选保留策略 dict
        """
        self.output_dir = output_dir
        self.csv_delimiter = csv_delimiter
        self.include_header = include_header
        self.logger = logger
        self.retention = retention or {}

        self.csv_files = {}  # type: Dict[str, TextIO]
        self.csv_writers = {}  # type: Dict[str, csv.DictWriter]
        self._last_retention_ts = 0.0

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

    def apply_retention(self, force=False):
        # type: (bool) -> List[str]
        """
        按配置清理 output_dir 下过期/超量 CSV。
        默认最多每小时执行一次（force=True 跳过节流）。
        返回已删除路径列表。
        """
        cfg = self.retention or {}
        if not cfg.get("enabled"):
            return []
        now = time.time()
        if not force and (now - self._last_retention_ts) < 3600:
            return []
        self._last_retention_ts = now

        max_age_days = float(cfg.get("max_age_days") or 7)
        max_total_mb = float(cfg.get("max_total_bytes_mb") or 4096)
        max_total_bytes = int(max_total_mb * 1024 * 1024)
        max_files = int(cfg.get("max_files_per_monitor") or 64)

        # group by monitor prefix (name before last _YYYYMMDD)
        by_monitor = {}  # type: Dict[str, List[tuple]]
        try:
            entries = list(self.output_dir.iterdir()) if hasattr(self.output_dir, "iterdir") else []
            if not entries:
                # pathlib or str
                root = str(self.output_dir)
                if os.path.isdir(root):
                    entries = [Path(root) / n for n in os.listdir(root)]
        except Exception as e:
            self.logger.error("retention list dir failed: {}".format(e))
            return []

        for entry in entries:
            try:
                name = entry.name if hasattr(entry, "name") else os.path.basename(str(entry))
                if not name.endswith(".csv"):
                    continue
                path = str(entry)
                st = os.stat(path)
                # monitor type: strip _YYYYMMDD_HHMMSS.csv
                base = name[:-4]
                parts = base.rsplit("_", 2)
                mon = parts[0] if len(parts) >= 3 else base
                by_monitor.setdefault(mon, []).append((path, st.st_mtime, st.st_size))
            except (OSError, IOError):
                continue

        deleted = []
        for mon, files in by_monitor.items():
            to_del = select_files_for_retention(
                files, max_age_days, max_total_bytes, max_files
            )
            for path in to_del:
                try:
                    os.remove(path)
                    deleted.append(path)
                    self.logger.info("CSV retention deleted: {}".format(path))
                except OSError as e:
                    # ENOSPC etc: log only, never sys.exit
                    self.logger.error("CSV retention delete failed {}: {}".format(path, e))
        return deleted

    def cleanup(self):
        # type: () -> None
        """清理所有CSV资源"""
        for monitor_type in list(self.csv_files.keys()):
            self.close_file(monitor_type)
