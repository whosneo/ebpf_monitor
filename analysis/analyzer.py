#!/usr/bin/env python3
# encoding: utf-8
"""
eBPF数据分析工具主程序
提供数据加载、分析和对比功能
适配新的聚合统计数据格式
"""

import argparse
import logging
import os
import socket
import sys
from io import StringIO
from typing import Optional

import pandas as pd

from data_utils import (
    safe_read_csv
)

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def capture_output_to_file(monitor_type_func):
    """装饰器：捕获print输出并保存到文件"""

    def wrapper(self, date_str: str):
        # 提取监控器类型名
        monitor_type = monitor_type_func.__name__.replace('analyze_', '')

        # 捕获输出
        old_stdout = sys.stdout
        sys.stdout = output_buffer = StringIO()

        try:
            # 执行分析函数
            monitor_type_func(self, date_str)

            # 获取输出内容
            content = output_buffer.getvalue()

            # 恢复stdout
            sys.stdout = old_stdout

            # 保存到文件
            if content.strip():
                self._save_report(monitor_type, date_str, content)
                # 跳过打印到控制台
                # print(content)
        except Exception as e:
            # 恢复stdout
            sys.stdout = old_stdout
            logger.error(f"分析{monitor_type}时出错: {e}")
            raise

    return wrapper


class EBPFAnalyzer:
    """eBPF数据分析器 - 适配新的聚合统计数据格式"""

    def __init__(self, daily_data_dir="./daily_data", reports_dir="./reports", hostname=None):
        self.hostname = hostname or socket.gethostname()
        self.daily_data_dir = os.path.join(daily_data_dir, self.hostname)
        self.reports_dir = os.path.join(reports_dir, self.hostname)
        self.base_reports_dir = reports_dir  # 保存基础reports目录，用于对比功能
        # 更新监控器类型列表
        self.monitor_types = ['exec', 'syscall', 'bio', 'interrupt', 'func', 'open', 'page_fault']

        # 确保目录存在
        if not os.path.exists(self.daily_data_dir):
            os.makedirs(self.daily_data_dir)
        if not os.path.exists(self.reports_dir):
            os.makedirs(self.reports_dir)

    def load_daily_data(self, date_str: str, monitor_type: str) -> Optional[pd.DataFrame]:
        """
        加载指定日期的数据
        
        Args:
            date_str: 日期字符串，格式为YYYYMMDD
            monitor_type: 监控器类型
            
        Returns:
            DataFrame或None
        """
        # 从daily_data目录加载
        daily_file = os.path.join(self.daily_data_dir, f"{monitor_type}_{date_str}.csv")
        if os.path.exists(daily_file):
            logger.info(f"加载数据: {daily_file}")
            df = safe_read_csv(daily_file)
            if not df.empty:
                return self.clean_loaded_data(df, monitor_type)

        logger.warning(f"未找到{monitor_type}在{date_str}的数据，请先运行preprocess_data.sh预处理数据")
        return None

    def clean_loaded_data(self, df: pd.DataFrame, monitor_type: str) -> pd.DataFrame:
        """
        清理加载的数据，处理格式问题
        
        Args:
            df: 原始DataFrame
            monitor_type: 监控器类型
            
        Returns:
            清理后的DataFrame
        """
        if df.empty:
            return df

        original_count = len(df)

        # 1. 移除完全空的行
        df = df.dropna(how='all')

        # 2. 处理timestamp列
        if 'timestamp' in df.columns:
            df = df.dropna(subset=['timestamp'])
            df['timestamp'] = pd.to_numeric(df['timestamp'], errors='coerce')
            df = df.dropna(subset=['timestamp'])

        # 3. 处理time_str列（新格式都有这个字段）
        if 'time_str' in df.columns:
            df['time_str'] = df['time_str'].astype(str).str.strip()

        # 4. 处理comm列（所有监控器都有）
        if 'comm' in df.columns:
            df['comm'] = df['comm'].astype(str).str.strip()

        # 5. 根据监控器类型处理特定字段
        df = self._clean_monitor_specific_fields(df, monitor_type)

        cleaned_count = len(df)
        if original_count != cleaned_count:
            logger.info(f"{monitor_type} 数据清理: {original_count} -> {cleaned_count} 行")

        return df

    def _clean_monitor_specific_fields(self, df: pd.DataFrame, monitor_type: str) -> pd.DataFrame:
        """处理特定监控器的字段"""

        # 通用数值字段
        common_numeric = ['count', 'errors', 'error_count']
        for col in common_numeric:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0).astype(int)

        # 通用浮点字段
        common_float = ['error_rate', 'avg_lat_us', 'min_lat_us', 'max_lat_us', 'avg_latency_us', 'min_latency_us',
                        'max_latency_us']
        for col in common_float:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0.0)

        # 特定监控器的字段处理
        if monitor_type == 'exec':
            if 'uid' in df.columns:
                df['uid'] = pd.to_numeric(df['uid'], errors='coerce').fillna(0).astype(int)
            if 'pid' in df.columns:
                df['pid'] = pd.to_numeric(df['pid'], errors='coerce').fillna(0).astype(int)
            # 确保filename是字符串类型
            if 'filename' in df.columns:
                df['filename'] = df['filename'].astype(str).str.strip()

        elif monitor_type == 'bio':
            numeric_cols = ['io_type', 'total_bytes', 'size_mb', 'throughput_mbps']
            for col in numeric_cols:
                if col in df.columns:
                    df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0.0)

        elif monitor_type == 'syscall':
            if 'syscall_nr' in df.columns:
                df['syscall_nr'] = pd.to_numeric(df['syscall_nr'], errors='coerce').fillna(0).astype(int)
            # 确保syscall_name是字符串类型
            if 'syscall_name' in df.columns:
                df['syscall_name'] = df['syscall_name'].astype(str).str.strip()
            if 'category' in df.columns:
                df['category'] = df['category'].astype(str).str.strip()

        elif monitor_type == 'open':
            # 确保filename和operation是字符串类型
            if 'filename' in df.columns:
                df['filename'] = df['filename'].astype(str).str.strip()
            if 'operation' in df.columns:
                df['operation'] = df['operation'].astype(str).str.strip()

        elif monitor_type == 'func':
            # 确保func_name是字符串类型
            if 'func_name' in df.columns:
                df['func_name'] = df['func_name'].astype(str).str.strip()

        elif monitor_type in ['interrupt', 'page_fault']:
            if 'cpu' in df.columns:
                df['cpu'] = pd.to_numeric(df['cpu'], errors='coerce').fillna(0).astype(int)
            if 'fault_type' in df.columns:
                df['fault_type'] = pd.to_numeric(df['fault_type'], errors='coerce').fillna(0).astype(int)
            if 'irq_type' in df.columns:
                df['irq_type'] = pd.to_numeric(df['irq_type'], errors='coerce').fillna(0).astype(int)
            # 确保类型字符串字段是字符串类型
            if 'fault_type_str' in df.columns:
                df['fault_type_str'] = df['fault_type_str'].astype(str).str.strip()
            if 'irq_type_str' in df.columns:
                df['irq_type_str'] = df['irq_type_str'].astype(str).str.strip()
            if 'numa_node' in df.columns:
                df['numa_node'] = pd.to_numeric(df['numa_node'], errors='coerce').fillna(0).astype(int)

        elif monitor_type == 'vfs':
            if 'bytes_mb' in df.columns:
                df['bytes_mb'] = pd.to_numeric(df['bytes_mb'], errors='coerce').fillna(0.0)

        elif monitor_type == 'context_switch':
            switch_cols = ['switch_in', 'switch_out', 'total_switches', 'voluntary', 'involuntary', 'voluntary_rate']
            for col in switch_cols:
                if col in df.columns:
                    df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

        # 确保bio的io_type_str是字符串类型
        if monitor_type == 'bio' and 'io_type_str' in df.columns:
            df['io_type_str'] = df['io_type_str'].astype(str).str.strip()

        return df

    def _save_report(self, monitor_type: str, date_str: str, content: str):
        """保存分析报告到文件"""
        report_file = os.path.join(self.reports_dir, f"{monitor_type}_{date_str}.txt")
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(content)
        logger.info(f"分析报告已保存: {report_file}")

    # ==================== EXEC 分析 ====================
    @capture_output_to_file
    def analyze_exec(self, date_str: str):
        """分析EXEC数据"""
        df = self.load_daily_data(date_str, 'exec')
        if df is None or df.empty:
            return

        print(f"\n{'=' * 100}")
        print(f"EXEC 监控数据深度分析 - {date_str}")
        print(f"{'=' * 100}\n")

        # 基本统计
        total_execs = len(df)
        unique_files = df['filename'].nunique() if 'filename' in df.columns else 0
        unique_comms = df['comm'].nunique() if 'comm' in df.columns else 0

        print(f"【概览统计】")
        print(f"  总执行次数: {total_execs:,}")
        print(f"  唯一可执行文件数: {unique_files:,}")
        print(f"  唯一进程名数: {unique_comms:,}")
        print(f"  平均每个文件执行次数: {total_execs / unique_files:.2f}" if unique_files > 0 else "")

        # 完整文件执行排名
        if 'filename' in df.columns:
            print(f"\n{'=' * 100}")
            print(f"【可执行文件完整排名】")
            print(f"{'=' * 100}")
            file_counts = df['filename'].value_counts()
            cumulative_pct = 0
            for i, (filename, count) in enumerate(file_counts.items(), 1):
                pct = (count / total_execs) * 100
                cumulative_pct += pct
                print(f"  {i:3d}. {filename:60s} {count:8d}次 ({pct:6.2f}%) [累计: {cumulative_pct:6.2f}%]")

        # 完整进程排名
        if 'comm' in df.columns:
            print(f"\n{'=' * 100}")
            print(f"【进程完整排名】")
            print(f"{'=' * 100}")
            comm_counts = df['comm'].value_counts()
            cumulative_pct = 0
            for i, (comm, count) in enumerate(comm_counts.items(), 1):
                pct = (count / total_execs) * 100
                cumulative_pct += pct
                print(f"  {i:3d}. {comm:30s} {count:8d}次 ({pct:6.2f}%) [累计: {cumulative_pct:6.2f}%]")

        # 用户维度分析
        if 'uid' in df.columns:
            print(f"\n{'=' * 100}")
            print(f"【用户维度分析】")
            print(f"{'=' * 100}")
            uid_stats = df['uid'].value_counts()
            for uid, count in uid_stats.items():
                pct = (count / total_execs) * 100
                user_type = "root" if uid == 0 else f"uid={uid}"
                print(f"  {user_type:15s} {count:8d}次 ({pct:6.2f}%)")

                # 显示该用户执行的主要程序
                user_df = df[df['uid'] == uid]
                if 'filename' in user_df.columns:
                    top_files = user_df['filename'].value_counts().head(5)
                    for j, (filename, fcount) in enumerate(top_files.items(), 1):
                        fpct = (fcount / count) * 100
                        print(f"      {j}. {filename:50s} {fcount:6d}次 ({fpct:5.2f}%)")

        # 进程-文件关联分析
        if 'comm' in df.columns and 'filename' in df.columns:
            print(f"\n{'=' * 100}")
            print(f"【进程-文件关联分析】")
            print(f"{'=' * 100}")
            # 找出每个进程最常执行的文件
            for comm in df['comm'].unique()[:20]:  # 只分析前20个进程
                comm_df = df[df['comm'] == comm]
                comm_total = len(comm_df)
                print(f"\n进程: {comm} (总执行: {comm_total:,}次)")
                file_dist = comm_df['filename'].value_counts().head(10)
                for i, (filename, count) in enumerate(file_dist.items(), 1):
                    pct = (count / comm_total) * 100
                    print(f"  {i:2d}. {filename:60s} {count:6d}次 ({pct:5.2f}%)")

        # 执行频率分析
        if 'filename' in df.columns:
            print(f"\n{'=' * 100}")
            print(f"【执行频率分布】")
            print(f"{'=' * 100}")
            file_counts = df['filename'].value_counts()

            # 按执行次数分段统计
            ranges = [
                (1, 1, "仅执行1次"),
                (2, 5, "执行2-5次"),
                (6, 10, "执行6-10次"),
                (11, 50, "执行11-50次"),
                (51, 100, "执行51-100次"),
                (101, 500, "执行101-500次"),
                (501, float('inf'), "执行500次以上")
            ]

            for min_count, max_count, label in ranges:
                if max_count == float('inf'):
                    files_in_range = file_counts[file_counts >= min_count]
                else:
                    files_in_range = file_counts[(file_counts >= min_count) & (file_counts <= max_count)]

                file_num = len(files_in_range)
                exec_num = files_in_range.sum()
                file_pct = (file_num / unique_files * 100) if unique_files > 0 else 0
                exec_pct = (exec_num / total_execs * 100) if total_execs > 0 else 0

                print(
                    f"  {label:20s} 文件数: {file_num:5d} ({file_pct:5.2f}%)  执行次数: {exec_num:8d} ({exec_pct:6.2f}%)")

    # ==================== BIO 分析 ====================
    @capture_output_to_file
    def analyze_bio(self, date_str: str):
        """分析BIO数据（块I/O）"""
        df = self.load_daily_data(date_str, 'bio')
        if df is None or df.empty:
            return

        print(f"\n{'=' * 100}")
        print(f"BIO (块I/O) 监控数据深度分析 - {date_str}")
        print(f"{'=' * 100}\n")

        # 基本统计
        total_ops = df['count'].sum() if 'count' in df.columns else len(df)
        total_bytes = df['total_bytes'].sum() if 'total_bytes' in df.columns else 0
        total_mb = total_bytes / (1024 * 1024)
        total_gb = total_mb / 1024
        unique_procs = df['comm'].nunique() if 'comm' in df.columns else 0

        print(f"【概览统计】")
        print(f"  总I/O操作数: {total_ops:,}")
        print(f"  总数据量: {total_gb:,.2f} GB ({total_mb:,.2f} MB)")
        print(f"  平均每次I/O大小: {total_bytes / total_ops / 1024:.2f} KB" if total_ops > 0 else "")
        print(f"  唯一进程数: {unique_procs}")

        # I/O类型完整分析
        if 'io_type_str' in df.columns:
            print(f"\n{'=' * 100}")
            print(f"【I/O类型完整分析】")
            print(f"{'=' * 100}")
            io_type_stats = df.groupby('io_type_str').agg({
                'count': 'sum',
                'total_bytes': 'sum',
                'avg_latency_us': 'mean',
                'min_latency_us': 'min',
                'max_latency_us': 'max'
            }).sort_values('count', ascending=False)

            for io_type, row in io_type_stats.iterrows():
                count = row['count']
                bytes_mb = row['total_bytes'] / (1024 * 1024)
                bytes_gb = bytes_mb / 1024
                avg_lat = row['avg_latency_us']
                min_lat = row['min_latency_us']
                max_lat = row['max_latency_us']
                ops_pct = (count / total_ops) * 100 if total_ops > 0 else 0
                bytes_pct = (row['total_bytes'] / total_bytes * 100) if total_bytes > 0 else 0

                print(f"\n{io_type}:")
                print(f"  操作次数: {count:12,.0f} ({ops_pct:6.2f}%)")
                print(f"  数据量:   {bytes_gb:12,.2f} GB ({bytes_mb:,.2f} MB, {bytes_pct:6.2f}%)")
                print(f"  平均延迟: {avg_lat:12,.2f} μs")
                print(f"  延迟范围: {min_lat:12,.2f} - {max_lat:12,.2f} μs")
                print(f"  平均大小: {row['total_bytes'] / count / 1024:12,.2f} KB/次" if count > 0 else "")

        # 进程完整排名
        if 'comm' in df.columns:
            print(f"\n{'=' * 100}")
            print(f"【进程I/O完整排名】")
            print(f"{'=' * 100}")
            proc_stats = df.groupby('comm').agg({
                'count': 'sum',
                'total_bytes': 'sum',
                'avg_latency_us': 'mean'
            }).sort_values('count', ascending=False)

            cumulative_ops_pct = 0
            cumulative_bytes_pct = 0
            for i, (comm, row) in enumerate(proc_stats.iterrows(), 1):
                count = row['count']
                bytes_mb = row['total_bytes'] / (1024 * 1024)
                avg_lat = row['avg_latency_us']
                ops_pct = (count / total_ops) * 100 if total_ops > 0 else 0
                bytes_pct = (row['total_bytes'] / total_bytes * 100) if total_bytes > 0 else 0
                cumulative_ops_pct += ops_pct
                cumulative_bytes_pct += bytes_pct

                print(
                    f"  {i:3d}. {comm:30s} {count:10,.0f}次 ({ops_pct:5.2f}%) | {bytes_mb:10,.2f} MB ({bytes_pct:5.2f}%) | 延迟: {avg_lat:7,.2f}μs")
                print(f"        [累计操作: {cumulative_ops_pct:6.2f}%  累计数据: {cumulative_bytes_pct:6.2f}%]")

        # 进程-I/O类型关联分析
        if 'comm' in df.columns and 'io_type_str' in df.columns:
            print(f"\n{'=' * 100}")
            print(f"【进程-I/O类型关联分析】(Top 20进程)")
            print(f"{'=' * 100}")

            top_procs = df.groupby('comm')['count'].sum().nlargest(20).index
            for comm in top_procs:
                comm_df = df[df['comm'] == comm]
                comm_total = comm_df['count'].sum()
                comm_bytes = comm_df['total_bytes'].sum()

                print(f"\n进程: {comm} (总操作: {comm_total:,}次, 总数据: {comm_bytes / 1024 / 1024:,.2f} MB)")

                io_dist = comm_df.groupby('io_type_str').agg({
                    'count': 'sum',
                    'total_bytes': 'sum',
                    'avg_latency_us': 'mean'
                }).sort_values('count', ascending=False)

                for io_type, row in io_dist.iterrows():
                    count = row['count']
                    bytes_mb = row['total_bytes'] / (1024 * 1024)
                    avg_lat = row['avg_latency_us']
                    ops_pct = (count / comm_total) * 100
                    bytes_pct = (row['total_bytes'] / comm_bytes * 100) if comm_bytes > 0 else 0
                    print(
                        f"  {io_type:15s} {count:10,}次 ({ops_pct:5.2f}%) | {bytes_mb:8,.2f} MB ({bytes_pct:5.2f}%) | {avg_lat:7,.2f}μs")

        # I/O大小分布
        if 'total_bytes' in df.columns and 'count' in df.columns:
            print(f"\n{'=' * 100}")
            print(f"【I/O大小分布】")
            print(f"{'=' * 100}")

            # 计算每次操作的平均大小
            df_copy = df.copy()
            df_copy['avg_size_kb'] = df_copy['total_bytes'] / df_copy['count'] / 1024

            ranges = [
                (0, 4, "0-4 KB (小I/O)"),
                (4, 64, "4-64 KB (中小I/O)"),
                (64, 256, "64-256 KB (中等I/O)"),
                (256, 1024, "256 KB-1 MB (大I/O)"),
                (1024, float('inf'), "1 MB以上 (超大I/O)")
            ]

            for min_size, max_size, label in ranges:
                if max_size == float('inf'):
                    range_df = df_copy[df_copy['avg_size_kb'] >= min_size]
                else:
                    range_df = df_copy[(df_copy['avg_size_kb'] >= min_size) & (df_copy['avg_size_kb'] < max_size)]

                if not range_df.empty:
                    ops_count = range_df['count'].sum()
                    data_bytes = range_df['total_bytes'].sum()
                    ops_pct = (ops_count / total_ops * 100) if total_ops > 0 else 0
                    data_pct = (data_bytes / total_bytes * 100) if total_bytes > 0 else 0

                    print(
                        f"  {label:25s} 操作: {ops_count:10,.0f} ({ops_pct:5.2f}%)  数据: {data_bytes / 1024 / 1024:10,.2f} MB ({data_pct:5.2f}%)")

        # 延迟分析
        if 'avg_latency_us' in df.columns:
            print(f"\n{'=' * 100}")
            print(f"【延迟详细分析】")
            print(f"{'=' * 100}")

            overall_avg = (df['avg_latency_us'] * df['count']).sum() / df['count'].sum() if 'count' in df.columns else \
                df['avg_latency_us'].mean()
            overall_min = df['min_latency_us'].min() if 'min_latency_us' in df.columns else 0
            overall_max = df['max_latency_us'].max() if 'max_latency_us' in df.columns else 0

            print(f"  整体平均延迟: {overall_avg:,.2f} μs")
            print(f"  最小延迟: {overall_min:,.2f} μs")
            print(f"  最大延迟: {overall_max:,.2f} μs")

            # 高延迟进程完整排名
            if 'comm' in df.columns:
                print(f"\n进程延迟完整排名:")
                lat_procs = df.groupby('comm').agg({
                    'avg_latency_us': 'mean',
                    'count': 'sum'
                }).sort_values('avg_latency_us', ascending=False)

                for i, (comm, row) in enumerate(lat_procs.iterrows(), 1):
                    avg_lat = row['avg_latency_us']
                    count = row['count']
                    flag = " ⚠️ " if avg_lat > overall_avg * 2 else "    "
                    print(f"  {i:3d}. {comm:30s} 平均延迟: {avg_lat:10,.2f} μs (操作数: {count:8,.0f}){flag}")

        # 吞吐量统计
        if 'throughput_mbps' in df.columns:
            print(f"\n{'=' * 100}")
            print(f"【吞吐量统计】")
            print(f"{'=' * 100}")

            avg_throughput = df['throughput_mbps'].mean()
            max_throughput = df['throughput_mbps'].max()
            min_throughput = df['throughput_mbps'].min()

            print(f"  平均吞吐量: {avg_throughput:,.2f} MB/s")
            print(f"  最大吞吐量: {max_throughput:,.2f} MB/s")
            print(f"  最小吞吐量: {min_throughput:,.2f} MB/s")

            # 按进程的吞吐量排名
            if 'comm' in df.columns:
                print(f"\n进程吞吐量排名:")
                throughput_procs = df.groupby('comm')['throughput_mbps'].mean().sort_values(ascending=False)
                for i, (comm, tput) in enumerate(throughput_procs.items(), 1):
                    print(f"  {i:3d}. {comm:30s} {tput:10,.2f} MB/s")

    # ==================== FUNC 分析 ====================
    @capture_output_to_file
    def analyze_func(self, date_str: str):
        """分析FUNC数据（VFS函数调用）"""
        df = self.load_daily_data(date_str, 'func')
        if df is None or df.empty:
            return

        print(f"\n{'=' * 100}")
        print(f"FUNC (VFS函数) 监控数据深度分析 - {date_str}")
        print(f"{'=' * 100}\n")

        # 基本统计
        total_calls = df['count'].sum() if 'count' in df.columns else len(df)
        unique_funcs = df['func_name'].nunique() if 'func_name' in df.columns else 0
        unique_procs = df['comm'].nunique() if 'comm' in df.columns else 0

        print(f"【概览统计】")
        print(f"  总函数调用次数: {total_calls:,}")
        print(f"  唯一函数数: {unique_funcs}")
        print(f"  唯一进程数: {unique_procs}")
        print(f"  平均每个函数调用次数: {total_calls / unique_funcs:,.2f}" if unique_funcs > 0 else "")
        print(f"  平均每个进程调用次数: {total_calls / unique_procs:,.2f}" if unique_procs > 0 else "")

        # VFS函数完整排名
        if 'func_name' in df.columns and 'count' in df.columns:
            print(f"\n{'=' * 100}")
            print(f"【VFS函数完整排名】")
            print(f"{'=' * 100}")
            func_stats = df.groupby('func_name')['count'].sum().sort_values(ascending=False)

            cumulative_pct = 0
            for i, (func, count) in enumerate(func_stats.items(), 1):
                pct = (count / total_calls) * 100 if total_calls > 0 else 0
                cumulative_pct += pct
                print(f"  {i:3d}. {func:35s} {count:12,}次 ({pct:6.2f}%) [累计: {cumulative_pct:6.2f}%]")

        # 进程完整排名
        if 'comm' in df.columns and 'count' in df.columns:
            print(f"\n{'=' * 100}")
            print(f"【进程VFS调用完整排名】")
            print(f"{'=' * 100}")
            proc_stats = df.groupby('comm')['count'].sum().sort_values(ascending=False)

            cumulative_pct = 0
            for i, (comm, count) in enumerate(proc_stats.items(), 1):
                pct = (count / total_calls) * 100 if total_calls > 0 else 0
                cumulative_pct += pct
                print(f"  {i:3d}. {comm:35s} {count:12,}次 ({pct:6.2f}%) [累计: {cumulative_pct:6.2f}%]")

        # 进程-函数关联分析
        if 'comm' in df.columns and 'func_name' in df.columns and 'count' in df.columns:
            print(f"\n{'=' * 100}")
            print(f"【进程-函数关联分析】(Top 20进程)")
            print(f"{'=' * 100}")

            top_procs = df.groupby('comm')['count'].sum().nlargest(20).index
            for comm in top_procs:
                comm_df = df[df['comm'] == comm]
                comm_total = comm_df['count'].sum()

                print(f"\n进程: {comm} (总调用: {comm_total:,}次)")

                func_dist = comm_df.groupby('func_name')['count'].sum().sort_values(ascending=False)
                for i, (func, count) in enumerate(func_dist.items(), 1):
                    pct = (count / comm_total) * 100
                    print(f"  {i:3d}. {func:35s} {count:10,}次 ({pct:5.2f}%)")

        # 函数调用频率分布
        if 'func_name' in df.columns and 'count' in df.columns:
            print(f"\n{'=' * 100}")
            print(f"【函数调用频率分布】")
            print(f"{'=' * 100}")

            func_counts = df.groupby('func_name')['count'].sum()

            ranges = [
                (1, 100, "1-100次"),
                (101, 1000, "101-1,000次"),
                (1001, 10000, "1,001-10,000次"),
                (10001, 100000, "10,001-100,000次"),
                (100001, 1000000, "100,001-1,000,000次"),
                (1000001, float('inf'), "1,000,000次以上")
            ]

            for min_count, max_count, label in ranges:
                if max_count == float('inf'):
                    funcs_in_range = func_counts[func_counts >= min_count]
                else:
                    funcs_in_range = func_counts[(func_counts >= min_count) & (func_counts <= max_count)]

                func_num = len(funcs_in_range)
                call_num = funcs_in_range.sum()
                func_pct = (func_num / unique_funcs * 100) if unique_funcs > 0 else 0
                call_pct = (call_num / total_calls * 100) if total_calls > 0 else 0

                print(
                    f"  {label:25s} 函数数: {func_num:4d} ({func_pct:5.2f}%)  调用次数: {call_num:12,} ({call_pct:6.2f}%)")

        # 函数-进程交叉统计矩阵
        if 'comm' in df.columns and 'func_name' in df.columns and 'count' in df.columns:
            print(f"\n{'=' * 100}")
            print(f"【函数-进程调用矩阵】(Top 10进程 × 所有函数)")
            print(f"{'=' * 100}")
            top_procs = df.groupby('comm')['count'].sum().nlargest(10).index
            pivot = df[df['comm'].isin(top_procs)].pivot_table(
                index='comm', columns='func_name', values='count', aggfunc='sum', fill_value=0
            )
            print(pivot.to_string())

    # ==================== OPEN 分析 ====================
    @capture_output_to_file
    def analyze_open(self, date_str: str):
        """分析OPEN数据"""
        df = self.load_daily_data(date_str, 'open')
        if df is None or df.empty:
            return

        print(f"\n{'=' * 100}")
        print(f"OPEN (文件打开) 监控数据深度分析 - {date_str}")
        print(f"{'=' * 100}\n")

        # 基本统计
        total_opens = df['count'].sum() if 'count' in df.columns else len(df)
        total_errors = df['errors'].sum() if 'errors' in df.columns else 0
        error_rate = (total_errors / total_opens * 100) if total_opens > 0 else 0
        unique_files = df['filename'].nunique() if 'filename' in df.columns else 0
        unique_procs = df['comm'].nunique() if 'comm' in df.columns else 0

        print(f"【概览统计】")
        print(f"  总打开次数: {total_opens:,}")
        print(f"  总错误次数: {total_errors:,}")
        print(f"  整体错误率: {error_rate:.4f}%")
        print(f"  唯一文件数: {unique_files:,}")
        print(f"  唯一进程数: {unique_procs}")
        print(f"  平均每个文件被打开次数: {total_opens / unique_files:.2f}" if unique_files > 0 else "")

        # 操作类型分析
        if 'operation' in df.columns and 'count' in df.columns:
            print(f"\n{'=' * 100}")
            print(f"【操作类型分析】")
            print(f"{'=' * 100}")
            op_stats = df.groupby('operation').agg({
                'count': 'sum',
                'errors': 'sum'
            }).sort_values('count', ascending=False)

            for op, row in op_stats.iterrows():
                count = row['count']
                errors = row['errors']
                err_rate = (errors / count * 100) if count > 0 else 0
                pct = (count / total_opens) * 100 if total_opens > 0 else 0
                err_flag = " ⚠️ " if err_rate > 1.0 else "    "
                print(f"  {op:15s} {count:10,}次 ({pct:6.2f}%) | 错误: {errors:8,}次 ({err_rate:6.2f}%){err_flag}")

        # 文件完整排名
        if 'filename' in df.columns and 'count' in df.columns:
            print(f"\n{'=' * 100}")
            print(f"【文件打开排名】 (Top 30)")
            print(f"{'=' * 100}")
            file_stats = df.groupby('filename').agg({
                'count': 'sum',
                'errors': 'sum'
            }).sort_values('count', ascending=False).head(30)

            cumulative_pct = 0
            for i, (filename, row) in enumerate(file_stats.iterrows(), 1):
                count = row['count']
                errors = row['errors']
                err_rate = (errors / count * 100) if count > 0 else 0
                pct = (count / total_opens) * 100 if total_opens > 0 else 0
                cumulative_pct += pct

                err_flag = " ⚠️ " if err_rate > 5.0 else "    "
                print(
                    f"  {i:4d}. {filename:70s} {count:8,}次 ({pct:5.2f}%) [累计: {cumulative_pct:6.2f}%] | 错误: {errors:6,} ({err_rate:5.2f}%){err_flag}")

        # 进程完整排名
        if 'comm' in df.columns and 'count' in df.columns:
            print(f"\n{'=' * 100}")
            print(f"【进程文件打开排名】 (Top 30)")
            print(f"{'=' * 100}")
            proc_stats = df.groupby('comm').agg({
                'count': 'sum',
                'errors': 'sum'
            }).sort_values('count', ascending=False).head(30)

            cumulative_pct = 0
            for i, (comm, row) in enumerate(proc_stats.iterrows(), 1):
                count = row['count']
                errors = row['errors']
                err_rate = (errors / count * 100) if count > 0 else 0
                pct = (count / total_opens) * 100 if total_opens > 0 else 0
                cumulative_pct += pct

                err_flag = " ⚠️ " if err_rate > 1.0 else "    "
                print(
                    f"  {i:3d}. {comm:30s} {count:10,}次 ({pct:6.2f}%) [累计: {cumulative_pct:6.2f}%] | 错误: {errors:8,}次 ({err_rate:6.2f}%){err_flag}")

        # 进程-文件关联分析
        if 'comm' in df.columns and 'filename' in df.columns:
            print(f"\n{'=' * 100}")
            print(f"【进程-文件关联分析】(Top 20进程)")
            print(f"{'=' * 100}")

            top_procs = df.groupby('comm')['count'].sum().nlargest(20).index
            for comm in top_procs:
                comm_df = df[df['comm'] == comm]
                comm_total = comm_df['count'].sum()
                comm_errors = comm_df['errors'].sum()

                print(f"\n进程: {comm} (总打开: {comm_total:,}次, 错误: {comm_errors:,}次)")

                file_dist = comm_df.groupby('filename').agg({
                    'count': 'sum',
                    'errors': 'sum'
                }).sort_values('count', ascending=False).head(15)

                for i, (filename, row) in enumerate(file_dist.iterrows(), 1):
                    count = row['count']
                    errors = row['errors']
                    pct = (count / comm_total) * 100
                    err_rate = (errors / count * 100) if count > 0 else 0
                    print(f"  {i:3d}. {filename:65s} {count:6,}次 ({pct:5.2f}%) | 错误: {errors:4,} ({err_rate:5.2f}%)")

        # 错误详细分析
        if 'errors' in df.columns:
            print(f"\n{'=' * 100}")
            print(f"【错误详细分析】")
            print(f"{'=' * 100}")

            error_df = df[df['errors'] > 0].copy()
            if not error_df.empty:
                # 按filename聚合错误数据
                if 'filename' in error_df.columns:
                    file_error_stats = error_df.groupby('filename').agg({
                        'count': 'sum',
                        'errors': 'sum'
                    })
                    file_error_stats['err_rate'] = (file_error_stats['errors'] / file_error_stats['count'] * 100)

                    # 错误率最高的文件
                    print(f"\n错误率最高的文件 (Top 30):")
                    top_err_files = file_error_stats.sort_values(
                        by=['err_rate', 'errors'],
                        ascending=[False, False]
                    ).head(30)
                    for i, (filename, row) in enumerate(top_err_files.iterrows(), 1):
                        print(
                            f"  {i:2d}. {filename:65s} 错误率: {row['err_rate']:6.2f}% ({row['errors']:,}/{row['count']:,})")

                    # 错误次数最多的文件
                    print(f"\n错误次数最多的文件 (Top 30):")
                    top_err_counts = file_error_stats.nlargest(30, 'errors')
                    for i, (filename, row) in enumerate(top_err_counts.iterrows(), 1):
                        print(f"  {i:2d}. {filename:65s} 错误: {row['errors']:6,}次 (错误率: {row['err_rate']:6.2f}%)")

                # 错误最多的进程
                if 'comm' in error_df.columns:
                    print(f"\n错误最多的进程 (Top 30):")
                    proc_errors = error_df.groupby('comm').agg({
                        'count': 'sum',
                        'errors': 'sum'
                    }).sort_values('errors', ascending=False).head(30)

                    for i, (comm, row) in enumerate(proc_errors.iterrows(), 1):
                        err_rate = (row['errors'] / row['count'] * 100) if row['count'] > 0 else 0
                        print(f"  {i:2d}. {comm:30s} 错误: {row['errors']:8,}次 (错误率: {err_rate:6.2f}%)")

        # 文件访问频率分布
        if 'filename' in df.columns and 'count' in df.columns:
            print(f"\n{'=' * 100}")
            print(f"【文件访问频率分布】")
            print(f"{'=' * 100}")

            file_counts = df.groupby('filename')['count'].sum()

            ranges = [
                (1, 1, "仅打开1次"),
                (2, 10, "打开2-10次"),
                (11, 100, "打开11-100次"),
                (101, 1000, "打开101-1,000次"),
                (1001, 10000, "打开1,001-10,000次"),
                (10001, float('inf'), "打开10,000次以上")
            ]

            for min_count, max_count, label in ranges:
                if max_count == float('inf'):
                    files_in_range = file_counts[file_counts >= min_count]
                else:
                    files_in_range = file_counts[(file_counts >= min_count) & (file_counts <= max_count)]

                file_num = len(files_in_range)
                open_num = files_in_range.sum()
                file_pct = (file_num / unique_files * 100) if unique_files > 0 else 0
                open_pct = (open_num / total_opens * 100) if total_opens > 0 else 0

                print(
                    f"  {label:25s} 文件数: {file_num:6d} ({file_pct:5.2f}%)  打开次数: {open_num:10,} ({open_pct:6.2f}%)")

    # ==================== SYSCALL 分析 ====================
    @capture_output_to_file
    def analyze_syscall(self, date_str: str):
        """分析SYSCALL数据"""
        df = self.load_daily_data(date_str, 'syscall')
        if df is None or df.empty:
            return

        print(f"\n{'=' * 100}")
        print(f"SYSCALL (系统调用) 监控数据深度分析 - {date_str}")
        print(f"{'=' * 100}\n")

        # 基本统计
        total_calls = df['count'].sum() if 'count' in df.columns else len(df)
        total_errors = df['error_count'].sum() if 'error_count' in df.columns else 0
        error_rate = (total_errors / total_calls * 100) if total_calls > 0 else 0
        unique_syscalls = df['syscall_name'].nunique() if 'syscall_name' in df.columns else 0
        unique_procs = df['comm'].nunique() if 'comm' in df.columns else 0

        print(f"【概览统计】")
        print(f"  总系统调用次数: {total_calls:,}")
        print(f"  总错误次数: {total_errors:,}")
        print(f"  整体错误率: {error_rate:.4f}%")
        print(f"  唯一系统调用数: {unique_syscalls}")
        print(f"  唯一进程数: {unique_procs}")

        # 系统调用完整排名
        if 'syscall_name' in df.columns and 'count' in df.columns:
            print(f"\n{'=' * 100}")
            print(f"【系统调用完整排名】")
            print(f"{'=' * 100}")
            syscall_stats = df.groupby('syscall_name').agg({
                'count': 'sum',
                'error_count': 'sum'
            }).sort_values('count', ascending=False)

            cumulative_pct = 0
            for i, (syscall, row) in enumerate(syscall_stats.iterrows(), 1):
                count = row['count']
                errors = row['error_count']
                err_rate = (errors / count * 100) if count > 0 else 0
                pct = (count / total_calls) * 100 if total_calls > 0 else 0
                cumulative_pct += pct

                # 标记高错误率
                err_flag = " ⚠️ " if err_rate > 1.0 else "    "
                print(
                    f"  {i:3d}. {syscall:25s} {count:12,}次 ({pct:6.2f}%) [累计: {cumulative_pct:6.2f}%] | 错误: {errors:10,}次 ({err_rate:6.2f}%){err_flag}")

        # 按类别统计
        if 'category' in df.columns and 'count' in df.columns:
            print(f"\n{'=' * 100}")
            print(f"【系统调用类别分析】")
            print(f"{'=' * 100}")
            cat_stats = df.groupby('category').agg({
                'count': 'sum',
                'error_count': 'sum'
            }).sort_values('count', ascending=False)

            for cat, row in cat_stats.iterrows():
                count = row['count']
                errors = row['error_count']
                err_rate = (errors / count * 100) if count > 0 else 0
                pct = (count / total_calls) * 100 if total_calls > 0 else 0
                print(f"  {cat:20s} {count:12,}次 ({pct:6.2f}%) | 错误: {errors:10,}次 ({err_rate:6.2f}%)")

                # 显示该类别下的主要系统调用
                cat_df = df[df['category'] == cat]
                cat_syscalls = cat_df.groupby('syscall_name')['count'].sum().sort_values(ascending=False).head(5)
                for j, (syscall, scount) in enumerate(cat_syscalls.items(), 1):
                    spct = (scount / count) * 100
                    print(f"      {j}. {syscall:20s} {scount:10,}次 ({spct:5.2f}%)")

        # 进程完整排名
        if 'comm' in df.columns and 'count' in df.columns:
            print(f"\n{'=' * 100}")
            print(f"【进程系统调用完整排名】")
            print(f"{'=' * 100}")
            proc_stats = df.groupby('comm').agg({
                'count': 'sum',
                'error_count': 'sum'
            }).sort_values('count', ascending=False)

            cumulative_pct = 0
            for i, (comm, row) in enumerate(proc_stats.iterrows(), 1):
                count = row['count']
                errors = row['error_count']
                err_rate = (errors / count * 100) if count > 0 else 0
                pct = (count / total_calls) * 100 if total_calls > 0 else 0
                cumulative_pct += pct

                err_flag = " ⚠️ " if err_rate > 1.0 else "    "
                print(
                    f"  {i:3d}. {comm:30s} {count:12,}次 ({pct:6.2f}%) [累计: {cumulative_pct:6.2f}%] | 错误: {errors:10,}次 ({err_rate:6.2f}%){err_flag}")

        # 进程-系统调用关联分析
        if 'comm' in df.columns and 'syscall_name' in df.columns and 'count' in df.columns:
            print(f"\n{'=' * 100}")
            print(f"【进程-系统调用关联分析】(Top 15进程)")
            print(f"{'=' * 100}")

            top_procs = df.groupby('comm')['count'].sum().nlargest(15).index
            for comm in top_procs:
                comm_df = df[df['comm'] == comm]
                comm_total = comm_df['count'].sum()
                print(f"\n进程: {comm} (总调用: {comm_total:,}次)")

                syscall_dist = comm_df.groupby('syscall_name').agg({
                    'count': 'sum',
                    'error_count': 'sum'
                }).sort_values('count', ascending=False).head(10)

                for i, (syscall, row) in enumerate(syscall_dist.iterrows(), 1):
                    count = row['count']
                    errors = row['error_count']
                    pct = (count / comm_total) * 100
                    err_rate = (errors / count * 100) if count > 0 else 0
                    print(
                        f"  {i:2d}. {syscall:25s} {count:10,}次 ({pct:5.2f}%) | 错误: {errors:8,}次 ({err_rate:5.2f}%)")

        # 错误分析
        if 'error_count' in df.columns:
            print(f"\n{'=' * 100}")
            print(f"【错误详细分析】")
            print(f"{'=' * 100}")

            # 错误率最高的系统调用
            error_df = df[df['error_count'] > 0].copy()
            if not error_df.empty and 'syscall_name' in error_df.columns and 'count' in error_df.columns:
                # 按syscall_name聚合错误数据
                syscall_error_stats = error_df.groupby('syscall_name').agg({
                    'count': 'sum',
                    'error_count': 'sum'
                })
                syscall_error_stats['err_rate'] = (
                            syscall_error_stats['error_count'] / syscall_error_stats['count'] * 100)

                print(f"\n错误率最高的系统调用 (Top 20):")
                top_errors = syscall_error_stats.sort_values(
                    by=['err_rate', 'error_count'],
                    ascending=[False, False]
                ).head(20)
                for i, (syscall_name, row) in enumerate(top_errors.iterrows(), 1):
                    print(
                        f"  {i:2d}. {syscall_name:25s} 错误率: {row['err_rate']:6.2f}% ({row['error_count']:,}/{row['count']:,})")

                # 错误次数最多的系统调用
                print(f"\n错误次数最多的系统调用 (Top 20):")
                top_error_counts = syscall_error_stats.nlargest(20, 'error_count')
                for i, (syscall_name, row) in enumerate(top_error_counts.iterrows(), 1):
                    print(
                        f"  {i:2d}. {syscall_name:25s} 错误: {row['error_count']:10,}次 (错误率: {row['err_rate']:6.2f}%)")

            # 错误最多的进程
            if not error_df.empty and 'comm' in error_df.columns:
                print(f"\n错误最多的进程 (Top 20):")
                proc_errors = error_df.groupby('comm').agg({
                    'count': 'sum',
                    'error_count': 'sum'
                }).sort_values('error_count', ascending=False).head(20)

                for i, (comm, row) in enumerate(proc_errors.iterrows(), 1):
                    err_rate = (row['error_count'] / row['count'] * 100) if row['count'] > 0 else 0
                    print(f"  {i:2d}. {comm:30s} 错误: {row['error_count']:10,}次 (错误率: {err_rate:6.2f}%)")

        # 调用频率分布
        if 'syscall_name' in df.columns and 'count' in df.columns:
            print(f"\n{'=' * 100}")
            print(f"【系统调用频率分布】")
            print(f"{'=' * 100}")

            syscall_counts = df.groupby('syscall_name')['count'].sum()

            ranges = [
                (1, 100, "1-100次"),
                (101, 1000, "101-1,000次"),
                (1001, 10000, "1,001-10,000次"),
                (10001, 100000, "10,001-100,000次"),
                (100001, 1000000, "100,001-1,000,000次"),
                (1000001, float('inf'), "1,000,000次以上")
            ]

            for min_count, max_count, label in ranges:
                if max_count == float('inf'):
                    syscalls_in_range = syscall_counts[syscall_counts >= min_count]
                else:
                    syscalls_in_range = syscall_counts[(syscall_counts >= min_count) & (syscall_counts <= max_count)]

                syscall_num = len(syscalls_in_range)
                call_num = syscalls_in_range.sum()
                syscall_pct = (syscall_num / unique_syscalls * 100) if unique_syscalls > 0 else 0
                call_pct = (call_num / total_calls * 100) if total_calls > 0 else 0

                print(
                    f"  {label:25s} 系统调用数: {syscall_num:4d} ({syscall_pct:5.2f}%)  调用次数: {call_num:12,} ({call_pct:6.2f}%)")

    # ==================== INTERRUPT 分析 ====================
    @capture_output_to_file
    def analyze_interrupt(self, date_str: str):
        """分析INTERRUPT数据"""
        df = self.load_daily_data(date_str, 'interrupt')
        if df is None or df.empty:
            return

        print(f"\n{'=' * 100}")
        print(f"INTERRUPT (中断) 监控数据深度分析 - {date_str}")
        print(f"{'=' * 100}\n")

        # 基本统计
        total_interrupts = df['count'].sum() if 'count' in df.columns else len(df)
        unique_types = df['irq_type_str'].nunique() if 'irq_type_str' in df.columns else 0
        unique_procs = df['comm'].nunique() if 'comm' in df.columns else 0
        unique_cpus = df['cpu'].nunique() if 'cpu' in df.columns else 0

        print(f"【概览统计】")
        print(f"  总中断次数: {total_interrupts:,}")
        print(f"  中断类型数: {unique_types}")
        print(f"  涉及进程数: {unique_procs}")
        print(f"  涉及CPU数: {unique_cpus}")
        print(f"  平均每CPU中断数: {total_interrupts / unique_cpus:,.2f}" if unique_cpus > 0 else "")

        # 中断类型完整分析
        if 'irq_type_str' in df.columns and 'count' in df.columns:
            print(f"\n{'=' * 100}")
            print(f"【中断类型完整分析】")
            print(f"{'=' * 100}")
            type_stats = df.groupby('irq_type_str')['count'].sum().sort_values(ascending=False)

            cumulative_pct = 0
            for i, (irq_type, count) in enumerate(type_stats.items(), 1):
                pct = (count / total_interrupts) * 100 if total_interrupts > 0 else 0
                cumulative_pct += pct
                print(f"  {i:3d}. {irq_type:30s} {count:12,}次 ({pct:6.2f}%) [累计: {cumulative_pct:6.2f}%]")

        # CPU负载分析
        if 'cpu' in df.columns and 'count' in df.columns:
            print(f"\n{'=' * 100}")
            print(f"【CPU中断负载分析】")
            print(f"{'=' * 100}")
            cpu_stats = df.groupby('cpu')['count'].sum().sort_values(ascending=False)
            avg_per_cpu = total_interrupts / len(cpu_stats) if len(cpu_stats) > 0 else 0

            print(f"  平均每CPU中断数: {avg_per_cpu:,.2f}")
            print(f"\nCPU中断分布:")

            for cpu, count in cpu_stats.items():
                pct = (count / total_interrupts) * 100 if total_interrupts > 0 else 0
                ratio = count / avg_per_cpu if avg_per_cpu > 0 else 0
                deviation = ((count - avg_per_cpu) / avg_per_cpu * 100) if avg_per_cpu > 0 else 0

                # 负载标记
                if ratio > 2.0:
                    indicator = "🔥🔥"
                elif ratio > 1.5:
                    indicator = "🔥 "
                elif ratio < 0.5:
                    indicator = "❄️ "
                else:
                    indicator = "   "

                print(
                    f"  {indicator} CPU {cpu:3d}: {count:12,}次 ({pct:5.2f}%) | 负载比: {ratio:5.2f}x | 偏差: {deviation:+6.1f}%")

        # CPU-中断类型关联分析
        if 'cpu' in df.columns and 'irq_type_str' in df.columns and 'count' in df.columns:
            print(f"\n{'=' * 100}")
            print(f"【CPU-中断类型关联分析】(Top 10 CPU)")
            print(f"{'=' * 100}")

            top_cpus = df.groupby('cpu')['count'].sum().nlargest(10).index
            for cpu in top_cpus:
                cpu_df = df[df['cpu'] == cpu]
                cpu_total = cpu_df['count'].sum()

                print(f"\nCPU {cpu} (总中断: {cpu_total:,}次)")

                irq_dist = cpu_df.groupby('irq_type_str')['count'].sum().sort_values(ascending=False)
                for i, (irq_type, count) in enumerate(irq_dist.items(), 1):
                    pct = (count / cpu_total) * 100
                    print(f"  {i:2d}. {irq_type:30s} {count:10,}次 ({pct:5.2f}%)")

        # 进程完整排名
        if 'comm' in df.columns and 'count' in df.columns:
            print(f"\n{'=' * 100}")
            print(f"【进程中断完整排名】")
            print(f"{'=' * 100}")
            proc_stats = df.groupby('comm')['count'].sum().sort_values(ascending=False)

            cumulative_pct = 0
            for i, (comm, count) in enumerate(proc_stats.items(), 1):
                pct = (count / total_interrupts) * 100 if total_interrupts > 0 else 0
                cumulative_pct += pct
                print(f"  {i:3d}. {comm:35s} {count:12,}次 ({pct:6.2f}%) [累计: {cumulative_pct:6.2f}%]")

        # 进程-中断类型关联分析
        if 'comm' in df.columns and 'irq_type_str' in df.columns and 'count' in df.columns:
            print(f"\n{'=' * 100}")
            print(f"【进程-中断类型关联分析】(Top 15进程)")
            print(f"{'=' * 100}")

            top_procs = df.groupby('comm')['count'].sum().nlargest(15).index
            for comm in top_procs:
                comm_df = df[df['comm'] == comm]
                comm_total = comm_df['count'].sum()

                print(f"\n进程: {comm} (总中断: {comm_total:,}次)")

                irq_dist = comm_df.groupby('irq_type_str')['count'].sum().sort_values(ascending=False)
                for i, (irq_type, count) in enumerate(irq_dist.items(), 1):
                    pct = (count / comm_total) * 100
                    print(f"  {i:2d}. {irq_type:30s} {count:10,}次 ({pct:5.2f}%)")

        # 中断频率分布
        if 'irq_type_str' in df.columns and 'count' in df.columns:
            print(f"\n{'=' * 100}")
            print(f"【中断频率分布】")
            print(f"{'=' * 100}")

            irq_counts = df.groupby('irq_type_str')['count'].sum()

            ranges = [
                (1, 1000, "1-1,000次"),
                (1001, 10000, "1,001-10,000次"),
                (10001, 100000, "10,001-100,000次"),
                (100001, 1000000, "100,001-1,000,000次"),
                (1000001, 10000000, "1,000,001-10,000,000次"),
                (10000001, float('inf'), "10,000,000次以上")
            ]

            for min_count, max_count, label in ranges:
                if max_count == float('inf'):
                    irqs_in_range = irq_counts[irq_counts >= min_count]
                else:
                    irqs_in_range = irq_counts[(irq_counts >= min_count) & (irq_counts <= max_count)]

                irq_num = len(irqs_in_range)
                int_num = irqs_in_range.sum()
                irq_pct = (irq_num / unique_types * 100) if unique_types > 0 else 0
                int_pct = (int_num / total_interrupts * 100) if total_interrupts > 0 else 0

                print(
                    f"  {label:30s} 中断类型: {irq_num:3d} ({irq_pct:5.2f}%)  中断次数: {int_num:12,} ({int_pct:6.2f}%)")

        # CPU负载均衡分析
        if 'cpu' in df.columns and 'count' in df.columns:
            print(f"\n{'=' * 100}")
            print(f"【CPU负载均衡分析】")
            print(f"{'=' * 100}")

            cpu_counts = df.groupby('cpu')['count'].sum()
            max_load = cpu_counts.max()
            min_load = cpu_counts.min()
            avg_load = cpu_counts.mean()
            std_load = cpu_counts.std()

            print(f"  最大负载CPU: {cpu_counts.idxmax()} ({max_load:,}次)")
            print(f"  最小负载CPU: {cpu_counts.idxmin()} ({min_load:,}次)")
            print(f"  平均负载: {avg_load:,.2f}次")
            print(f"  标准差: {std_load:,.2f}")
            print(f"  负载差异: {max_load - min_load:,}次 ({(max_load - min_load) / avg_load * 100:.1f}%)")
            print(f"  负载比: {max_load / min_load:.2f}x" if min_load > 0 else "")

            # 负载均衡度评估
            balance_score = 1 - (std_load / avg_load) if avg_load > 0 else 0
            if balance_score > 0.9:
                balance_level = "优秀 ✓"
            elif balance_score > 0.7:
                balance_level = "良好"
            elif balance_score > 0.5:
                balance_level = "一般"
            else:
                balance_level = "较差 ⚠️"

            print(f"\n  负载均衡度: {balance_score * 100:.1f}% ({balance_level})")

    # ==================== PAGE_FAULT 分析 ====================
    @capture_output_to_file
    def analyze_page_fault(self, date_str: str):
        """分析PAGE_FAULT数据"""
        df = self.load_daily_data(date_str, 'page_fault')
        if df is None or df.empty:
            return

        print(f"\n{'=' * 100}")
        print(f"PAGE_FAULT (页面错误) 监控数据深度分析 - {date_str}")
        print(f"{'=' * 100}\n")

        # 基本统计
        total_faults = df['count'].sum() if 'count' in df.columns else len(df)
        unique_types = df['fault_type_str'].nunique() if 'fault_type_str' in df.columns else 0
        unique_procs = df['comm'].nunique() if 'comm' in df.columns else 0
        unique_cpus = df['cpu'].nunique() if 'cpu' in df.columns else 0
        unique_numa = df['numa_node'].nunique() if 'numa_node' in df.columns else 0

        print(f"【概览统计】")
        print(f"  总页面错误次数: {total_faults:,}")
        print(f"  错误类型数: {unique_types}")
        print(f"  涉及进程数: {unique_procs}")
        print(f"  涉及CPU数: {unique_cpus}")
        print(f"  涉及NUMA节点数: {unique_numa}")
        print(f"  平均每进程页面错误: {total_faults / unique_procs:,.2f}" if unique_procs > 0 else "")

        # 页面错误类型完整分析
        if 'fault_type_str' in df.columns and 'count' in df.columns:
            print(f"\n{'=' * 100}")
            print(f"【页面错误类型完整分析】")
            print(f"{'=' * 100}")
            type_stats = df.groupby('fault_type_str')['count'].sum().sort_values(ascending=False)

            cumulative_pct = 0
            for i, (fault_type, count) in enumerate(type_stats.items(), 1):
                pct = (count / total_faults) * 100 if total_faults > 0 else 0
                cumulative_pct += pct
                print(f"  {i:3d}. {fault_type:40s} {count:12,}次 ({pct:6.2f}%) [累计: {cumulative_pct:6.2f}%]")

        # CPU负载分析
        if 'cpu' in df.columns and 'count' in df.columns:
            print(f"\n{'=' * 100}")
            print(f"【CPU页面错误负载分析】")
            print(f"{'=' * 100}")
            cpu_stats = df.groupby('cpu')['count'].sum().sort_values(ascending=False)
            avg_per_cpu = total_faults / len(cpu_stats) if len(cpu_stats) > 0 else 0

            print(f"  平均每CPU页面错误数: {avg_per_cpu:,.2f}")
            print(f"\nCPU页面错误分布:")

            for cpu, count in cpu_stats.items():
                pct = (count / total_faults) * 100 if total_faults > 0 else 0
                ratio = count / avg_per_cpu if avg_per_cpu > 0 else 0
                deviation = ((count - avg_per_cpu) / avg_per_cpu * 100) if avg_per_cpu > 0 else 0

                # 负载标记
                if ratio > 2.0:
                    indicator = "🔥🔥"
                elif ratio > 1.5:
                    indicator = "🔥 "
                elif ratio < 0.5:
                    indicator = "❄️ "
                else:
                    indicator = "   "

                print(
                    f"  {indicator} CPU {cpu:3d}: {count:12,}次 ({pct:5.2f}%) | 负载比: {ratio:5.2f}x | 偏差: {deviation:+6.1f}%")

        # NUMA节点分析
        if 'numa_node' in df.columns and 'count' in df.columns:
            print(f"\n{'=' * 100}")
            print(f"【NUMA节点页面错误分析】")
            print(f"{'=' * 100}")
            numa_stats = df.groupby('numa_node')['count'].sum().sort_values(ascending=False)

            for numa, count in numa_stats.items():
                pct = (count / total_faults) * 100 if total_faults > 0 else 0
                print(f"  NUMA节点 {numa}: {count:12,}次 ({pct:6.2f}%)")

                # 显示该NUMA节点上的主要错误类型
                if 'fault_type_str' in df.columns:
                    numa_df = df[df['numa_node'] == numa]
                    numa_types = numa_df.groupby('fault_type_str')['count'].sum().sort_values(ascending=False).head(5)
                    for i, (fault_type, fcount) in enumerate(numa_types.items(), 1):
                        fpct = (fcount / count) * 100
                        print(f"      {i}. {fault_type:35s} {fcount:10,}次 ({fpct:5.2f}%)")

        # 进程完整排名
        if 'comm' in df.columns and 'count' in df.columns:
            print(f"\n{'=' * 100}")
            print(f"【进程页面错误完整排名】")
            print(f"{'=' * 100}")
            proc_stats = df.groupby('comm')['count'].sum().sort_values(ascending=False)

            cumulative_pct = 0
            for i, (comm, count) in enumerate(proc_stats.items(), 1):
                pct = (count / total_faults) * 100 if total_faults > 0 else 0
                cumulative_pct += pct
                print(f"  {i:3d}. {comm:35s} {count:12,}次 ({pct:6.2f}%) [累计: {cumulative_pct:6.2f}%]")

        # 进程-错误类型关联分析
        if 'comm' in df.columns and 'fault_type_str' in df.columns and 'count' in df.columns:
            print(f"\n{'=' * 100}")
            print(f"【进程-错误类型关联分析】(Top 15进程)")
            print(f"{'=' * 100}")

            top_procs = df.groupby('comm')['count'].sum().nlargest(15).index
            for comm in top_procs:
                comm_df = df[df['comm'] == comm]
                comm_total = comm_df['count'].sum()

                print(f"\n进程: {comm} (总页面错误: {comm_total:,}次)")

                fault_dist = comm_df.groupby('fault_type_str')['count'].sum().sort_values(ascending=False)
                for i, (fault_type, count) in enumerate(fault_dist.items(), 1):
                    pct = (count / comm_total) * 100
                    print(f"  {i:2d}. {fault_type:40s} {count:10,}次 ({pct:5.2f}%)")

        # CPU-错误类型关联分析
        if 'cpu' in df.columns and 'fault_type_str' in df.columns and 'count' in df.columns:
            print(f"\n{'=' * 100}")
            print(f"【CPU-错误类型关联分析】(Top 10 CPU)")
            print(f"{'=' * 100}")

            top_cpus = df.groupby('cpu')['count'].sum().nlargest(10).index
            for cpu in top_cpus:
                cpu_df = df[df['cpu'] == cpu]
                cpu_total = cpu_df['count'].sum()

                print(f"\nCPU {cpu} (总页面错误: {cpu_total:,}次)")

                fault_dist = cpu_df.groupby('fault_type_str')['count'].sum().sort_values(ascending=False)
                for i, (fault_type, count) in enumerate(fault_dist.items(), 1):
                    pct = (count / cpu_total) * 100
                    print(f"  {i:2d}. {fault_type:40s} {count:10,}次 ({pct:5.2f}%)")

        # 页面错误频率分布
        if 'fault_type_str' in df.columns and 'count' in df.columns:
            print(f"\n{'=' * 100}")
            print(f"【页面错误频率分布】")
            print(f"{'=' * 100}")

            fault_counts = df.groupby('fault_type_str')['count'].sum()

            ranges = [
                (1, 1000, "1-1,000次"),
                (1001, 10000, "1,001-10,000次"),
                (10001, 100000, "10,001-100,000次"),
                (100001, 1000000, "100,001-1,000,000次"),
                (1000001, 10000000, "1,000,001-10,000,000次"),
                (10000001, float('inf'), "10,000,000次以上")
            ]

            for min_count, max_count, label in ranges:
                if max_count == float('inf'):
                    faults_in_range = fault_counts[fault_counts >= min_count]
                else:
                    faults_in_range = fault_counts[(fault_counts >= min_count) & (fault_counts <= max_count)]

                fault_num = len(faults_in_range)
                count_num = faults_in_range.sum()
                fault_pct = (fault_num / unique_types * 100) if unique_types > 0 else 0
                count_pct = (count_num / total_faults * 100) if total_faults > 0 else 0

                print(
                    f"  {label:30s} 错误类型: {fault_num:3d} ({fault_pct:5.2f}%)  错误次数: {count_num:12,} ({count_pct:6.2f}%)")

        # CPU负载均衡分析
        if 'cpu' in df.columns and 'count' in df.columns:
            print(f"\n{'=' * 100}")
            print(f"【CPU负载均衡分析】")
            print(f"{'=' * 100}")

            cpu_counts = df.groupby('cpu')['count'].sum()
            max_load = cpu_counts.max()
            min_load = cpu_counts.min()
            avg_load = cpu_counts.mean()
            std_load = cpu_counts.std()

            print(f"  最大负载CPU: {cpu_counts.idxmax()} ({max_load:,}次)")
            print(f"  最小负载CPU: {cpu_counts.idxmin()} ({min_load:,}次)")
            print(f"  平均负载: {avg_load:,.2f}次")
            print(f"  标准差: {std_load:,.2f}")
            print(f"  负载差异: {max_load - min_load:,}次 ({(max_load - min_load) / avg_load * 100:.1f}%)")
            print(f"  负载比: {max_load / min_load:.2f}x" if min_load > 0 else "")

            # 负载均衡度评估
            balance_score = 1 - (std_load / avg_load) if avg_load > 0 else 0
            if balance_score > 0.9:
                balance_level = "优秀 ✓"
            elif balance_score > 0.7:
                balance_level = "良好"
            elif balance_score > 0.5:
                balance_level = "一般"
            else:
                balance_level = "较差 ⚠️"

            print(f"\n  负载均衡度: {balance_score * 100:.1f}% ({balance_level})")


if __name__ == '__main__':
    """主函数"""
    parser = argparse.ArgumentParser(description='eBPF数据分析工具 - 适配新的聚合统计格式')
    parser.add_argument('--daily-dir', default='./daily_data', help='预处理数据目录路径')
    parser.add_argument('--reports-dir', default='./reports', help='分析报告输出目录')
    parser.add_argument('--date', required=True, help='分析日期，格式: YYYYMMDD')
    parser.add_argument('--type', choices=['exec', 'bio', 'func', 'open', 'syscall', 'interrupt', 'page_fault', 'all'],
                        default='all', help='监控器类型')
    parser.add_argument('--hostname', help='指定主机名（默认使用当前主机名）')

    args = parser.parse_args()

    analyzer = EBPFAnalyzer(args.daily_dir, args.reports_dir, hostname=args.hostname)

    # 执行分析
    if args.type == 'all':
        # 分析所有类型
        for monitor_type in analyzer.monitor_types:
            try:
                method = getattr(analyzer, f'analyze_{monitor_type}')
                method(args.date)
            except Exception as e:
                logger.error(f"分析{monitor_type}时出错: {e}")
    else:
        # 分析指定类型
        try:
            method = getattr(analyzer, f'analyze_{args.type}')
            method(args.date)
        except Exception as e:
            logger.error(f"分析{args.type}时出错: {e}")
