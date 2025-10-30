#!/usr/bin/env python3
"""
eBPF数据分析工具主程序
提供数据分割、加载、分析和对比功能
"""

import os
import sys
import argparse
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import logging

from data_utils import (
    scan_output_files, safe_read_csv, extract_date, 
    parse_timestamp, get_date_range_from_files
)

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class EBPFAnalyzer:
    """eBPF数据分析器"""
    
    def __init__(self, output_dir: str = "../output", daily_data_dir: str = "./daily_data"):
        self.output_dir = output_dir
        self.daily_data_dir = daily_data_dir
        self.monitor_types = ['exec', 'syscall', 'io', 'interrupt', 'func', 'open', 'page_fault']
        
        # 确保目录存在
        os.makedirs(self.daily_data_dir, exist_ok=True)
    
    
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
            # 移除无效的timestamp
            df = df.dropna(subset=['timestamp'])
            
            # 尝试转换timestamp为数值类型
            def safe_convert_timestamp(ts):
                try:
                    if pd.isna(ts) or ts == '':
                        return None
                    # 尝试转换为浮点数
                    return float(str(ts).strip())
                except:
                    return None
            
            df['timestamp'] = df['timestamp'].apply(safe_convert_timestamp)
            df = df.dropna(subset=['timestamp'])
        
        # 3. 处理其他数值列
        numeric_columns = {
            'exec': ['uid', 'pid', 'ppid', 'ret'],
            'syscall': ['pid', 'tid', 'cpu', 'syscall_nr', 'ret_val', 'duration_ns', 'duration_us', 'duration_ms'],
            'io': ['io_type', 'fd', 'size', 'duration_ns', 'duration_us', 'throughput_mbps', 'pid', 'tid', 'cpu', 'ret_val'],
            'interrupt': ['irq_num', 'irq_type', 'duration_ns', 'duration_us', 'cpu', 'softirq_vec', 'pid', 'tid'],
            'func': ['pid', 'ppid', 'uid'],
            'open': ['type', 'pid', 'tid', 'uid', 'cpu', 'flags', 'mode', 'ret'],
            'page_fault': ['pid', 'tid', 'address', 'fault_type', 'cpu']
        }
        
        if monitor_type in numeric_columns:
            for col in numeric_columns[monitor_type]:
                if col in df.columns:
                    def safe_convert_numeric(val):
                        try:
                            if pd.isna(val) or val == '':
                                return 0
                            return pd.to_numeric(str(val).strip(), errors='coerce')
                        except:
                            return 0
                    
                    df[col] = df[col].apply(safe_convert_numeric)
        
        # 4. 处理布尔列
        boolean_columns = {
            'syscall': ['is_error', 'is_slow_call'],
            'io': ['is_error'],
            'page_fault': ['is_major_fault', 'is_minor_fault', 'is_write_fault', 'is_user_fault']
        }
        
        if monitor_type in boolean_columns:
            for col in boolean_columns[monitor_type]:
                if col in df.columns:
                    def safe_convert_boolean(val):
                        try:
                            if pd.isna(val) or val == '':
                                return False
                            val_str = str(val).strip().lower()
                            return val_str in ['true', '1', 'yes', 'on']
                        except:
                            return False
                    
                    df[col] = df[col].apply(safe_convert_boolean)
        
        # 5. 清理字符串列，移除引号和特殊字符
        string_columns = df.select_dtypes(include=['object']).columns
        for col in string_columns:
            if col not in ['timestamp']:  # 跳过已处理的列
                def clean_string(val):
                    try:
                        if pd.isna(val):
                            return ''
                        val_str = str(val).strip()
                        # 移除首尾的引号
                        if val_str.startswith('"') and val_str.endswith('"'):
                            val_str = val_str[1:-1]
                        # 处理转义的引号
                        val_str = val_str.replace('""', '"')
                        return val_str
                    except:
                        return ''
                
                df[col] = df[col].apply(clean_string)
        
        cleaned_count = len(df)
        if original_count != cleaned_count:
            logger.info(f"{monitor_type} 数据清理: {original_count} -> {cleaned_count} 行")
        
        return df
    
    def load_daily_data(self, date: str, monitor_types: Optional[List[str]] = None) -> Dict[str, pd.DataFrame]:
        """
        加载指定日期的数据
        
        Args:
            date: 日期字符串 (YYYYMMDD格式)
            monitor_types: 监控器类型列表，None表示加载所有类型
            
        Returns:
            按监控器类型分组的DataFrame字典
        """
        if monitor_types is None:
            monitor_types = self.monitor_types
        
        data = {}
        
        for monitor_type in monitor_types:
            filepath = os.path.join(self.daily_data_dir, f"{monitor_type}_{date}.csv")
            if os.path.exists(filepath):
                try:
                    df = safe_read_csv(filepath)
                    if not df.empty:
                        # 清理数据
                        df = self.clean_loaded_data(df, monitor_type)
                        if not df.empty:
                            data[monitor_type] = df
                            logger.info(f"加载 {monitor_type} 数据: {len(df)} 行")
                        else:
                            logger.warning(f"数据清理后为空: {filepath}")
                    else:
                        logger.warning(f"文件为空: {filepath}")
                except Exception as e:
                    logger.error(f"加载数据失败 {filepath}: {e}")
            else:
                logger.warning(f"文件不存在: {filepath}")
        
        return data
    
    def load_date_range(self, start_date: str, end_date: str, 
                       monitor_types: Optional[List[str]] = None) -> Dict[str, Dict[str, pd.DataFrame]]:
        """
        加载日期范围内的数据
        
        Args:
            start_date: 开始日期 (YYYYMMDD格式)
            end_date: 结束日期 (YYYYMMDD格式)
            monitor_types: 监控器类型列表
            
        Returns:
            按日期和监控器类型分组的嵌套字典
        """
        data_by_date = {}
        
        start_dt = datetime.strptime(start_date, '%Y%m%d')
        end_dt = datetime.strptime(end_date, '%Y%m%d')
        
        current_dt = start_dt
        while current_dt <= end_dt:
            date_str = current_dt.strftime('%Y%m%d')
            daily_data = self.load_daily_data(date_str, monitor_types)
            if daily_data:
                data_by_date[date_str] = daily_data
            current_dt += timedelta(days=1)
        
        return data_by_date
    
    def analyze_performance(self, data: Dict[str, pd.DataFrame]) -> Dict[str, Dict]:
        """
        分析系统性能指标
        
        Args:
            data: 按监控器类型分组的数据
            
        Returns:
            性能分析结果字典
        """
        results = {}
        
        # 分析系统调用性能
        if 'syscall' in data:
            syscall_df = data['syscall']
            if not syscall_df.empty and 'duration_ms' in syscall_df.columns:
                results['syscall'] = {
                    'total_calls': len(syscall_df),
                    'avg_duration_ms': syscall_df['duration_ms'].mean(),
                    'max_duration_ms': syscall_df['duration_ms'].max(),
                    'error_rate': (syscall_df['is_error'] == True).sum() / len(syscall_df) if 'is_error' in syscall_df.columns else 0,
                    'slow_calls': (syscall_df['is_slow_call'] == True).sum() if 'is_slow_call' in syscall_df.columns else 0
                }
        
        # 分析I/O性能
        if 'io' in data:
            io_df = data['io']
            if not io_df.empty:
                results['io'] = {
                    'total_operations': len(io_df),
                    'avg_throughput_mbps': io_df['throughput_mbps'].mean() if 'throughput_mbps' in io_df.columns else 0,
                    'avg_duration_us': io_df['duration_us'].mean() if 'duration_us' in io_df.columns else 0,
                    'read_operations': len(io_df[io_df['type_str'] == 'READ']) if 'type_str' in io_df.columns else 0,
                    'write_operations': len(io_df[io_df['type_str'] == 'WRITE']) if 'type_str' in io_df.columns else 0
                }
        
        # 分析进程执行
        if 'exec' in data:
            exec_df = data['exec']
            if not exec_df.empty:
                results['exec'] = {
                    'total_processes': len(exec_df),
                    'unique_commands': exec_df['comm'].nunique() if 'comm' in exec_df.columns else 0,
                    'failed_executions': (exec_df['ret'] != 0).sum() if 'ret' in exec_df.columns else 0
                }
                
                # 分析filename字段分布
                if 'filename' in exec_df.columns:
                    filename_counts = exec_df['filename'].value_counts()
                    results['exec']['filename_distribution'] = filename_counts.head(10).to_dict()
                
                # 分析argv字段分布（可执行文件路径）
                if 'argv' in exec_df.columns:
                    # 提取可执行文件路径（argv的第一部分）
                    exec_paths = exec_df['argv'].str.split().str[0].value_counts()
                    results['exec']['executable_distribution'] = exec_paths.head(10).to_dict()
        
        # 分析中断
        if 'interrupt' in data:
            interrupt_df = data['interrupt']
            if not interrupt_df.empty:
                results['interrupt'] = {
                    'total_interrupts': len(interrupt_df),
                    'avg_duration_us': interrupt_df['duration_us'].mean() if 'duration_us' in interrupt_df.columns else 0,
                    'hardware_interrupts': len(interrupt_df[interrupt_df['irq_type_str'].str.contains('HARDWARE', na=False)]) if 'irq_type_str' in interrupt_df.columns else 0,
                    'software_interrupts': len(interrupt_df[interrupt_df['irq_type_str'].str.contains('SOFTWARE', na=False)]) if 'irq_type_str' in interrupt_df.columns else 0
                }
        
        # 分析页面错误
        if 'page_fault' in data:
            pf_df = data['page_fault']
            if not pf_df.empty:
                results['page_fault'] = {
                    'total_faults': len(pf_df),
                    'major_faults': (pf_df['is_major_fault'] == True).sum() if 'is_major_fault' in pf_df.columns else 0,
                    'minor_faults': (pf_df['is_minor_fault'] == True).sum() if 'is_minor_fault' in pf_df.columns else 0,
                    'write_faults': (pf_df['is_write_fault'] == True).sum() if 'is_write_fault' in pf_df.columns else 0
                }
        
        return results
    
    def compare_systems(self, dates: List[str], monitor_types: Optional[List[str]] = None) -> Dict[str, Dict]:
        """
        对比不同日期的系统性能
        
        Args:
            dates: 日期列表
            monitor_types: 监控器类型列表
            
        Returns:
            对比结果字典
        """
        comparison_results = {}
        
        for date in dates:
            logger.info(f"分析日期: {date}")
            daily_data = self.load_daily_data(date, monitor_types)
            if daily_data:
                performance = self.analyze_performance(daily_data)
                comparison_results[date] = performance
            else:
                logger.warning(f"日期 {date} 无可用数据")
        
        return comparison_results
    
    def detect_anomalies(self, data: Dict[str, pd.DataFrame], threshold_std: float = 3.0) -> Dict[str, List]:
        """
        检测性能异常
        
        Args:
            data: 数据字典
            threshold_std: 异常检测阈值（标准差倍数）
            
        Returns:
            异常检测结果
        """
        anomalies = {}
        
        # 检测系统调用异常
        if 'syscall' in data:
            syscall_df = data['syscall']
            if not syscall_df.empty and 'duration_ms' in syscall_df.columns:
                mean_duration = syscall_df['duration_ms'].mean()
                std_duration = syscall_df['duration_ms'].std()
                threshold = mean_duration + threshold_std * std_duration
                
                anomaly_calls = syscall_df[syscall_df['duration_ms'] > threshold]
                if not anomaly_calls.empty:
                    anomalies['syscall_duration'] = anomaly_calls.to_dict('records')
        
        # 检测I/O异常
        if 'io' in data:
            io_df = data['io']
            if not io_df.empty and 'duration_us' in io_df.columns:
                mean_duration = io_df['duration_us'].mean()
                std_duration = io_df['duration_us'].std()
                threshold = mean_duration + threshold_std * std_duration
                
                anomaly_io = io_df[io_df['duration_us'] > threshold]
                if not anomaly_io.empty:
                    anomalies['io_duration'] = anomaly_io.to_dict('records')
        
        return anomalies
    
    def get_available_dates(self) -> List[str]:
        """
        获取daily_data目录中可用的日期列表
        
        Returns:
            日期列表，格式为YYYYMMDD
        """
        dates = set()
        
        if os.path.exists(self.daily_data_dir):
            for filename in os.listdir(self.daily_data_dir):
                if filename.endswith('.csv'):
                    # 提取日期部分
                    parts = filename.replace('.csv', '').split('_')
                    if len(parts) >= 2:
                        date_part = parts[-1]
                        if len(date_part) == 8 and date_part.isdigit():
                            dates.add(date_part)
        
        return sorted(list(dates))
    
    def analyze_exec_details(self, data: Dict[str, pd.DataFrame]) -> Dict:
        """
        详细分析exec数据
        
        Args:
            data: 数据字典
            
        Returns:
            详细分析结果
        """
        if 'exec' not in data:
            return {}
        
        exec_df = data['exec']
        if exec_df.empty:
            return {}
        
        analysis = {}
        
        # filename字段分析
        if 'filename' in exec_df.columns:
            filename_series = exec_df['filename'].dropna()
            if not filename_series.empty:
                filename_counts = filename_series.value_counts()
                analysis['filename_analysis'] = {
                    'total_with_filename': len(filename_series),
                    'unique_filenames': len(filename_counts),
                    'top_filenames': filename_counts.head(20).to_dict(),
                    'empty_filenames': (exec_df['filename'].isna() | (exec_df['filename'] == '')).sum()
                }
        
        # argv字段分析（可执行文件路径）
        if 'argv' in exec_df.columns:
            argv_series = exec_df['argv'].dropna()
            if not argv_series.empty:
                # 提取可执行文件路径
                exec_paths = argv_series.str.split().str[0]
                exec_path_counts = exec_paths.value_counts()
                analysis['executable_analysis'] = {
                    'total_executions': len(exec_paths),
                    'unique_executables': len(exec_path_counts),
                    'top_executables': exec_path_counts.head(20).to_dict()
                }
        
        # comm字段分析
        if 'comm' in exec_df.columns:
            comm_counts = exec_df['comm'].value_counts()
            analysis['command_analysis'] = {
                'unique_commands': len(comm_counts),
                'top_commands': comm_counts.head(20).to_dict()
            }
        
        # 用户分析
        if 'uid' in exec_df.columns:
            uid_counts = exec_df['uid'].value_counts()
            analysis['user_analysis'] = {
                'unique_users': len(uid_counts),
                'executions_by_uid': uid_counts.to_dict()
            }
        
        # 失败分析
        if 'ret' in exec_df.columns:
            failed_df = exec_df[exec_df['ret'] != 0]
            if not failed_df.empty:
                analysis['failure_analysis'] = {
                    'total_failures': len(failed_df),
                    'failure_rate': len(failed_df) / len(exec_df),
                    'failed_commands': failed_df['comm'].value_counts().head(10).to_dict() if 'comm' in failed_df.columns else {}
                }
        
        return analysis
    
    def analyze_open_details(self, data: Dict[str, pd.DataFrame]) -> Dict:
        """
        详细分析open数据
        
        Args:
            data: 数据字典
            
        Returns:
            详细分析结果
        """
        if 'open' not in data:
            return {}
        
        open_df = data['open']
        if open_df.empty:
            return {}
        
        analysis = {}
        
        # filename字段分析
        if 'filename' in open_df.columns:
            filename_series = open_df['filename'].dropna()
            if not filename_series.empty:
                filename_counts = filename_series.value_counts()
                analysis['filename_analysis'] = {
                    'total_with_filename': len(filename_series),
                    'unique_filenames': len(filename_counts),
                    'top_filenames': filename_counts.head(20).to_dict(),
                    'empty_filenames': (open_df['filename'].isna() | (open_df['filename'] == '')).sum()
                }
                
                # 按文件扩展名分析
                extensions = filename_series.str.extract(r'\.([^./]+)$')[0].dropna()
                if not extensions.empty:
                    ext_counts = extensions.value_counts()
                    analysis['filename_analysis']['file_extensions'] = ext_counts.head(10).to_dict()
                
                # 按目录分析
                directories = filename_series.str.extract(r'^(/[^/]*(?:/[^/]*)*)/')[0].dropna()
                if not directories.empty:
                    dir_counts = directories.value_counts()
                    analysis['filename_analysis']['top_directories'] = dir_counts.head(10).to_dict()
        
        # comm字段分析
        if 'comm' in open_df.columns:
            comm_counts = open_df['comm'].value_counts()
            analysis['command_analysis'] = {
                'unique_commands': len(comm_counts),
                'top_commands': comm_counts.head(20).to_dict()
            }
        
        # type_str字段分析
        if 'type_str' in open_df.columns:
            type_counts = open_df['type_str'].value_counts()
            analysis['operation_type_analysis'] = {
                'unique_types': len(type_counts),
                'type_distribution': type_counts.to_dict()
            }
        
        # 用户分析
        if 'uid' in open_df.columns:
            uid_counts = open_df['uid'].value_counts()
            analysis['user_analysis'] = {
                'unique_users': len(uid_counts),
                'operations_by_uid': uid_counts.to_dict()
            }
        
        # 失败分析
        if 'ret' in open_df.columns:
            failed_df = open_df[open_df['ret'] < 0]  # 负数表示失败
            if not failed_df.empty:
                analysis['failure_analysis'] = {
                    'total_failures': len(failed_df),
                    'failure_rate': len(failed_df) / len(open_df),
                    'failed_commands': failed_df['comm'].value_counts().head(10).to_dict() if 'comm' in failed_df.columns else {},
                    'failed_files': failed_df['filename'].value_counts().head(10).to_dict() if 'filename' in failed_df.columns else {}
                }
        
        # 权限分析
        if 'flags' in open_df.columns:
            flags_counts = open_df['flags'].value_counts()
            analysis['flags_analysis'] = {
                'unique_flags': len(flags_counts),
                'top_flags': flags_counts.head(10).to_dict()
            }
        
        return analysis
    
    def analyze_func_details(self, data: Dict[str, pd.DataFrame]) -> Dict:
        """详细分析func数据"""
        if 'func' not in data:
            return {}
        
        func_df = data['func']
        if func_df.empty:
            return {}
        
        analysis = {}
        
        # func_name字段分析
        if 'func_name' in func_df.columns:
            func_counts = func_df['func_name'].value_counts()
            analysis['function_analysis'] = {
                'unique_functions': len(func_counts),
                'top_functions': func_counts.head(20).to_dict(),
                'total_calls': len(func_df)
            }
            
            # 按函数类型分类
            vfs_funcs = func_df[func_df['func_name'].str.startswith('vfs_', na=False)]
            sys_funcs = func_df[func_df['func_name'].str.startswith('sys_', na=False)]
            analysis['function_analysis']['vfs_calls'] = len(vfs_funcs)
            analysis['function_analysis']['sys_calls'] = len(sys_funcs)
        
        # comm字段分析
        if 'comm' in func_df.columns:
            comm_counts = func_df['comm'].value_counts()
            analysis['command_analysis'] = {
                'unique_commands': len(comm_counts),
                'top_commands': comm_counts.head(20).to_dict()
            }
        
        # 用户分析
        if 'uid' in func_df.columns:
            uid_counts = func_df['uid'].value_counts()
            analysis['user_analysis'] = {
                'unique_users': len(uid_counts),
                'calls_by_uid': uid_counts.to_dict()
            }
        
        return analysis
    
    def analyze_interrupt_details(self, data: Dict[str, pd.DataFrame]) -> Dict:
        """详细分析interrupt数据"""
        if 'interrupt' not in data:
            return {}
        
        interrupt_df = data['interrupt']
        if interrupt_df.empty:
            return {}
        
        analysis = {}
        
        # irq_type_str字段分析
        if 'irq_type_str' in interrupt_df.columns:
            type_counts = interrupt_df['irq_type_str'].value_counts()
            analysis['interrupt_type_analysis'] = {
                'unique_types': len(type_counts),
                'type_distribution': type_counts.to_dict()
            }
        
        # irq_name字段分析
        if 'irq_name' in interrupt_df.columns:
            name_counts = interrupt_df['irq_name'].value_counts()
            analysis['interrupt_name_analysis'] = {
                'unique_names': len(name_counts),
                'top_interrupts': name_counts.head(20).to_dict()
            }
        
        # 持续时间分析
        if 'duration_us' in interrupt_df.columns:
            duration_stats = interrupt_df['duration_us'].describe()
            analysis['duration_analysis'] = {
                'avg_duration_us': duration_stats['mean'],
                'max_duration_us': duration_stats['max'],
                'min_duration_us': duration_stats['min'],
                'std_duration_us': duration_stats['std']
            }
        
        # CPU分析
        if 'cpu' in interrupt_df.columns:
            cpu_counts = interrupt_df['cpu'].value_counts()
            analysis['cpu_analysis'] = {
                'interrupts_by_cpu': cpu_counts.to_dict()
            }
        
        # comm字段分析
        if 'comm' in interrupt_df.columns:
            comm_counts = interrupt_df['comm'].value_counts()
            analysis['command_analysis'] = {
                'unique_commands': len(comm_counts),
                'top_commands': comm_counts.head(20).to_dict()
            }
        
        return analysis
    
    def analyze_io_details(self, data: Dict[str, pd.DataFrame]) -> Dict:
        """详细分析io数据"""
        if 'io' not in data:
            return {}
        
        io_df = data['io']
        if io_df.empty:
            return {}
        
        analysis = {}
        
        # type_str字段分析
        if 'type_str' in io_df.columns:
            type_counts = io_df['type_str'].value_counts()
            analysis['io_type_analysis'] = {
                'type_distribution': type_counts.to_dict()
            }
        
        # 性能分析
        if 'throughput_mbps' in io_df.columns:
            throughput_stats = io_df['throughput_mbps'].describe()
            analysis['performance_analysis'] = {
                'avg_throughput_mbps': throughput_stats['mean'],
                'max_throughput_mbps': throughput_stats['max'],
                'min_throughput_mbps': throughput_stats['min']
            }
        
        if 'duration_us' in io_df.columns:
            duration_stats = io_df['duration_us'].describe()
            analysis['performance_analysis'].update({
                'avg_duration_us': duration_stats['mean'],
                'max_duration_us': duration_stats['max'],
                'min_duration_us': duration_stats['min']
            })
        
        # 文件描述符分析
        if 'fd' in io_df.columns:
            fd_counts = io_df['fd'].value_counts()
            analysis['fd_analysis'] = {
                'unique_fds': len(fd_counts),
                'top_fds': fd_counts.head(10).to_dict()
            }
        
        # 大小分析
        if 'size' in io_df.columns:
            size_stats = io_df['size'].describe()
            analysis['size_analysis'] = {
                'avg_size_bytes': size_stats['mean'],
                'max_size_bytes': size_stats['max'],
                'total_bytes': io_df['size'].sum()
            }
        
        # comm字段分析
        if 'comm' in io_df.columns:
            comm_counts = io_df['comm'].value_counts()
            analysis['command_analysis'] = {
                'unique_commands': len(comm_counts),
                'top_commands': comm_counts.head(20).to_dict()
            }
        
        # 错误分析
        if 'is_error' in io_df.columns:
            error_count = (io_df['is_error'] == True).sum()
            analysis['error_analysis'] = {
                'total_errors': error_count,
                'error_rate': error_count / len(io_df)
            }
        
        return analysis
    
    def analyze_page_fault_details(self, data: Dict[str, pd.DataFrame]) -> Dict:
        """详细分析page_fault数据"""
        if 'page_fault' not in data:
            return {}
        
        pf_df = data['page_fault']
        if pf_df.empty:
            return {}
        
        analysis = {}
        
        # fault_type_str字段分析
        if 'fault_type_str' in pf_df.columns:
            type_counts = pf_df['fault_type_str'].value_counts()
            analysis['fault_type_analysis'] = {
                'unique_types': len(type_counts),
                'type_distribution': type_counts.to_dict()
            }
        
        # 错误类型分析
        fault_types = ['is_major_fault', 'is_minor_fault', 'is_write_fault', 'is_user_fault']
        for fault_type in fault_types:
            if fault_type in pf_df.columns:
                count = (pf_df[fault_type] == True).sum()
                if 'fault_breakdown' not in analysis:
                    analysis['fault_breakdown'] = {}
                analysis['fault_breakdown'][fault_type] = count
        
        # 地址分析
        if 'address' in pf_df.columns:
            # 分析地址范围
            address_stats = pf_df['address'].describe()
            analysis['address_analysis'] = {
                'min_address': int(address_stats['min']),
                'max_address': int(address_stats['max']),
                'unique_addresses': pf_df['address'].nunique()
            }
        
        # comm字段分析
        if 'comm' in pf_df.columns:
            comm_counts = pf_df['comm'].value_counts()
            analysis['command_analysis'] = {
                'unique_commands': len(comm_counts),
                'top_commands': comm_counts.head(20).to_dict()
            }
        
        # CPU分析
        if 'cpu' in pf_df.columns:
            cpu_counts = pf_df['cpu'].value_counts()
            analysis['cpu_analysis'] = {
                'faults_by_cpu': cpu_counts.to_dict()
            }
        
        return analysis
    
    def analyze_syscall_details(self, data: Dict[str, pd.DataFrame]) -> Dict:
        """详细分析syscall数据"""
        if 'syscall' not in data:
            return {}
        
        syscall_df = data['syscall']
        if syscall_df.empty:
            return {}
        
        analysis = {}
        
        # syscall_name字段分析
        if 'syscall_name' in syscall_df.columns:
            syscall_counts = syscall_df['syscall_name'].value_counts()
            analysis['syscall_analysis'] = {
                'unique_syscalls': len(syscall_counts),
                'top_syscalls': syscall_counts.head(20).to_dict(),
                'total_calls': len(syscall_df)
            }
        
        # category字段分析
        if 'category' in syscall_df.columns:
            category_counts = syscall_df['category'].value_counts()
            analysis['category_analysis'] = {
                'unique_categories': len(category_counts),
                'category_distribution': category_counts.to_dict()
            }
        
        # 性能分析
        if 'duration_ms' in syscall_df.columns:
            duration_stats = syscall_df['duration_ms'].describe()
            analysis['performance_analysis'] = {
                'avg_duration_ms': duration_stats['mean'],
                'max_duration_ms': duration_stats['max'],
                'min_duration_ms': duration_stats['min'],
                'std_duration_ms': duration_stats['std']
            }
        
        # 错误分析
        if 'is_error' in syscall_df.columns:
            error_count = (syscall_df['is_error'] == True).sum()
            analysis['error_analysis'] = {
                'total_errors': error_count,
                'error_rate': error_count / len(syscall_df)
            }
            
            if 'error_name' in syscall_df.columns:
                error_df = syscall_df[syscall_df['is_error'] == True]
                if not error_df.empty:
                    error_names = error_df['error_name'].value_counts()
                    analysis['error_analysis']['error_types'] = error_names.to_dict()
        
        # 慢调用分析
        if 'is_slow_call' in syscall_df.columns:
            slow_count = (syscall_df['is_slow_call'] == True).sum()
            analysis['slow_call_analysis'] = {
                'total_slow_calls': slow_count,
                'slow_call_rate': slow_count / len(syscall_df)
            }
        
        # comm字段分析
        if 'comm' in syscall_df.columns:
            comm_counts = syscall_df['comm'].value_counts()
            analysis['command_analysis'] = {
                'unique_commands': len(comm_counts),
                'top_commands': comm_counts.head(20).to_dict()
            }
        
        return analysis
    
    def print_summary(self, results: Dict) -> None:
        """
        打印分析结果摘要
        
        Args:
            results: 分析结果字典
        """
        print("\n" + "="*60)
        print("eBPF 系统性能分析报告")
        print("="*60)
        
        for date, performance in results.items():
            print(f"\n日期: {date}")
            print("-" * 40)
            
            for monitor_type, metrics in performance.items():
                print(f"\n{monitor_type.upper()} 监控器:")
                for metric, value in metrics.items():
                    if isinstance(value, dict) and metric.endswith('_distribution'):
                        print(f"  {metric}:")
                        for k, v in list(value.items())[:5]:  # 只显示前5个
                            print(f"    {k}: {v}")
                        if len(value) > 5:
                            print(f"    ... 还有 {len(value) - 5} 项")
                    elif isinstance(value, float):
                        print(f"  {metric}: {value:.4f}")
                    else:
                        print(f"  {metric}: {value}")
    
    def print_exec_details(self, exec_analysis: Dict) -> None:
        """
        打印exec详细分析结果
        
        Args:
            exec_analysis: exec分析结果
        """
        print("\n" + "="*60)
        print("EXEC 监控器详细分析报告")
        print("="*60)
        
        if 'filename_analysis' in exec_analysis:
            fa = exec_analysis['filename_analysis']
            print(f"\n📁 FILENAME 字段分析:")
            print(f"  包含filename的记录数: {fa['total_with_filename']}")
            print(f"  空filename记录数: {fa['empty_filenames']}")
            print(f"  唯一filename数量: {fa['unique_filenames']}")
            print(f"  前20个最常见的filename:")
            for i, (filename, count) in enumerate(fa['top_filenames'].items(), 1):
                print(f"    {i:2d}. {filename or '(空)'}: {count} 次")
        
        if 'executable_analysis' in exec_analysis:
            ea = exec_analysis['executable_analysis']
            print(f"\n🚀 可执行文件分析:")
            print(f"  总执行次数: {ea['total_executions']}")
            print(f"  唯一可执行文件数: {ea['unique_executables']}")
            print(f"  前20个最常执行的程序:")
            for i, (exe, count) in enumerate(ea['top_executables'].items(), 1):
                print(f"    {i:2d}. {exe}: {count} 次")
        
        if 'command_analysis' in exec_analysis:
            ca = exec_analysis['command_analysis']
            print(f"\n💻 命令分析:")
            print(f"  唯一命令数: {ca['unique_commands']}")
            print(f"  前20个最常见的命令:")
            for i, (cmd, count) in enumerate(ca['top_commands'].items(), 1):
                print(f"    {i:2d}. {cmd}: {count} 次")
        
        if 'user_analysis' in exec_analysis:
            ua = exec_analysis['user_analysis']
            print(f"\n👤 用户分析:")
            print(f"  涉及用户数: {ua['unique_users']}")
            print(f"  各用户执行次数:")
            for uid, count in ua['executions_by_uid'].items():
                user_name = "root" if uid == 0 else f"uid_{uid}"
                print(f"    {user_name}: {count} 次")
        
        if 'failure_analysis' in exec_analysis:
            fa = exec_analysis['failure_analysis']
            print(f"\n❌ 失败分析:")
            print(f"  失败次数: {fa['total_failures']}")
            print(f"  失败率: {fa['failure_rate']:.2%}")
            if fa['failed_commands']:
                print(f"  失败最多的命令:")
                for cmd, count in fa['failed_commands'].items():
                    print(f"    {cmd}: {count} 次")
    
    def print_open_details(self, open_analysis: Dict) -> None:
        """
        打印open详细分析结果
        
        Args:
            open_analysis: open分析结果
        """
        print("\n" + "="*60)
        print("OPEN 监控器详细分析报告")
        print("="*60)
        
        if 'filename_analysis' in open_analysis:
            fa = open_analysis['filename_analysis']
            print(f"\n📁 FILENAME 字段分析:")
            print(f"  包含filename的记录数: {fa['total_with_filename']}")
            print(f"  空filename记录数: {fa['empty_filenames']}")
            print(f"  唯一filename数量: {fa['unique_filenames']}")
            print(f"  前20个最常访问的文件:")
            for i, (filename, count) in enumerate(fa['top_filenames'].items(), 1):
                print(f"    {i:2d}. {filename or '(空)'}: {count} 次")
            
            if 'file_extensions' in fa:
                print(f"\n  📄 文件扩展名分布:")
                for i, (ext, count) in enumerate(fa['file_extensions'].items(), 1):
                    print(f"    {i:2d}. .{ext}: {count} 次")
            
            if 'top_directories' in fa:
                print(f"\n  📂 最常访问的目录:")
                for i, (directory, count) in enumerate(fa['top_directories'].items(), 1):
                    print(f"    {i:2d}. {directory}: {count} 次")
        
        if 'command_analysis' in open_analysis:
            ca = open_analysis['command_analysis']
            print(f"\n💻 命令分析:")
            print(f"  唯一命令数: {ca['unique_commands']}")
            print(f"  前20个最活跃的命令:")
            for i, (cmd, count) in enumerate(ca['top_commands'].items(), 1):
                print(f"    {i:2d}. {cmd}: {count} 次")
        
        if 'operation_type_analysis' in open_analysis:
            ota = open_analysis['operation_type_analysis']
            print(f"\n🔧 操作类型分析:")
            print(f"  唯一操作类型数: {ota['unique_types']}")
            print(f"  操作类型分布:")
            for op_type, count in ota['type_distribution'].items():
                print(f"    {op_type}: {count} 次")
        
        if 'user_analysis' in open_analysis:
            ua = open_analysis['user_analysis']
            print(f"\n👤 用户分析:")
            print(f"  涉及用户数: {ua['unique_users']}")
            print(f"  各用户操作次数:")
            for uid, count in ua['operations_by_uid'].items():
                user_name = "root" if uid == 0 else f"uid_{uid}"
                print(f"    {user_name}: {count} 次")
        
        if 'failure_analysis' in open_analysis:
            fa = open_analysis['failure_analysis']
            print(f"\n❌ 失败分析:")
            print(f"  失败次数: {fa['total_failures']}")
            print(f"  失败率: {fa['failure_rate']:.2%}")
            if fa['failed_commands']:
                print(f"  失败最多的命令:")
                for cmd, count in fa['failed_commands'].items():
                    print(f"    {cmd}: {count} 次")
            if fa['failed_files']:
                print(f"  失败最多的文件:")
                for filename, count in fa['failed_files'].items():
                    print(f"    {filename}: {count} 次")
        
        if 'flags_analysis' in open_analysis:
            fla = open_analysis['flags_analysis']
            print(f"\n🏁 标志位分析:")
            print(f"  唯一标志位数: {fla['unique_flags']}")
            print(f"  前10个最常见的标志位:")
            for i, (flag, count) in enumerate(fla['top_flags'].items(), 1):
                print(f"    {i:2d}. {flag}: {count} 次")
    
    def print_func_details(self, func_analysis: Dict) -> None:
        """打印func详细分析结果"""
        print("\n" + "="*60)
        print("FUNC 监控器详细分析报告")
        print("="*60)
        
        if 'function_analysis' in func_analysis:
            fa = func_analysis['function_analysis']
            print(f"\n🔧 函数调用分析:")
            print(f"  总调用次数: {fa['total_calls']}")
            print(f"  唯一函数数: {fa['unique_functions']}")
            print(f"  VFS函数调用: {fa.get('vfs_calls', 0)} 次")
            print(f"  SYS函数调用: {fa.get('sys_calls', 0)} 次")
            print(f"  前20个最常调用的函数:")
            for i, (func, count) in enumerate(fa['top_functions'].items(), 1):
                print(f"    {i:2d}. {func}: {count} 次")
        
        if 'command_analysis' in func_analysis:
            ca = func_analysis['command_analysis']
            print(f"\n💻 命令分析:")
            print(f"  唯一命令数: {ca['unique_commands']}")
            print(f"  前20个最活跃的命令:")
            for i, (cmd, count) in enumerate(ca['top_commands'].items(), 1):
                print(f"    {i:2d}. {cmd}: {count} 次")
        
        if 'user_analysis' in func_analysis:
            ua = func_analysis['user_analysis']
            print(f"\n👤 用户分析:")
            print(f"  涉及用户数: {ua['unique_users']}")
            print(f"  各用户调用次数:")
            for uid, count in ua['calls_by_uid'].items():
                user_name = "root" if uid == 0 else f"uid_{uid}"
                print(f"    {user_name}: {count} 次")
    
    def print_interrupt_details(self, interrupt_analysis: Dict) -> None:
        """打印interrupt详细分析结果"""
        print("\n" + "="*60)
        print("INTERRUPT 监控器详细分析报告")
        print("="*60)
        
        if 'interrupt_type_analysis' in interrupt_analysis:
            ita = interrupt_analysis['interrupt_type_analysis']
            print(f"\n⚡ 中断类型分析:")
            print(f"  唯一中断类型数: {ita['unique_types']}")
            print(f"  中断类型分布:")
            for irq_type, count in ita['type_distribution'].items():
                print(f"    {irq_type}: {count} 次")
        
        if 'interrupt_name_analysis' in interrupt_analysis:
            ina = interrupt_analysis['interrupt_name_analysis']
            print(f"\n📛 中断名称分析:")
            print(f"  唯一中断名称数: {ina['unique_names']}")
            print(f"  前20个最频繁的中断:")
            for i, (name, count) in enumerate(ina['top_interrupts'].items(), 1):
                print(f"    {i:2d}. {name}: {count} 次")
        
        if 'duration_analysis' in interrupt_analysis:
            da = interrupt_analysis['duration_analysis']
            print(f"\n⏱️ 持续时间分析:")
            print(f"  平均持续时间: {da['avg_duration_us']:.2f} μs")
            print(f"  最大持续时间: {da['max_duration_us']:.2f} μs")
            print(f"  最小持续时间: {da['min_duration_us']:.2f} μs")
            print(f"  标准差: {da['std_duration_us']:.2f} μs")
        
        if 'cpu_analysis' in interrupt_analysis:
            ca = interrupt_analysis['cpu_analysis']
            print(f"\n🖥️ CPU分布分析:")
            for cpu, count in sorted(ca['interrupts_by_cpu'].items()):
                print(f"    CPU {cpu}: {count} 次中断")
        
        if 'command_analysis' in interrupt_analysis:
            ca = interrupt_analysis['command_analysis']
            print(f"\n💻 命令分析:")
            print(f"  唯一命令数: {ca['unique_commands']}")
            print(f"  前20个最活跃的命令:")
            for i, (cmd, count) in enumerate(ca['top_commands'].items(), 1):
                print(f"    {i:2d}. {cmd}: {count} 次")
    
    def print_io_details(self, io_analysis: Dict) -> None:
        """打印io详细分析结果"""
        print("\n" + "="*60)
        print("IO 监控器详细分析报告")
        print("="*60)
        
        if 'io_type_analysis' in io_analysis:
            ita = io_analysis['io_type_analysis']
            print(f"\n📊 I/O类型分析:")
            for io_type, count in ita['type_distribution'].items():
                print(f"    {io_type}: {count} 次")
        
        if 'performance_analysis' in io_analysis:
            pa = io_analysis['performance_analysis']
            print(f"\n🚀 性能分析:")
            if 'avg_throughput_mbps' in pa:
                print(f"  平均吞吐量: {pa['avg_throughput_mbps']:.2f} MB/s")
                print(f"  最大吞吐量: {pa['max_throughput_mbps']:.2f} MB/s")
                print(f"  最小吞吐量: {pa['min_throughput_mbps']:.2f} MB/s")
            if 'avg_duration_us' in pa:
                print(f"  平均持续时间: {pa['avg_duration_us']:.2f} μs")
                print(f"  最大持续时间: {pa['max_duration_us']:.2f} μs")
                print(f"  最小持续时间: {pa['min_duration_us']:.2f} μs")
        
        if 'fd_analysis' in io_analysis:
            fa = io_analysis['fd_analysis']
            print(f"\n📁 文件描述符分析:")
            print(f"  唯一文件描述符数: {fa['unique_fds']}")
            print(f"  前10个最活跃的文件描述符:")
            for i, (fd, count) in enumerate(fa['top_fds'].items(), 1):
                print(f"    {i:2d}. FD {fd}: {count} 次")
        
        if 'size_analysis' in io_analysis:
            sa = io_analysis['size_analysis']
            print(f"\n📏 数据大小分析:")
            print(f"  平均大小: {sa['avg_size_bytes']:.0f} 字节")
            print(f"  最大大小: {sa['max_size_bytes']:.0f} 字节")
            print(f"  总数据量: {sa['total_bytes']:.0f} 字节 ({sa['total_bytes']/1024/1024:.2f} MB)")
        
        if 'command_analysis' in io_analysis:
            ca = io_analysis['command_analysis']
            print(f"\n💻 命令分析:")
            print(f"  唯一命令数: {ca['unique_commands']}")
            print(f"  前20个最活跃的命令:")
            for i, (cmd, count) in enumerate(ca['top_commands'].items(), 1):
                print(f"    {i:2d}. {cmd}: {count} 次")
        
        if 'error_analysis' in io_analysis:
            ea = io_analysis['error_analysis']
            print(f"\n❌ 错误分析:")
            print(f"  错误次数: {ea['total_errors']}")
            print(f"  错误率: {ea['error_rate']:.2%}")
    
    def print_page_fault_details(self, pf_analysis: Dict) -> None:
        """打印page_fault详细分析结果"""
        print("\n" + "="*60)
        print("PAGE_FAULT 监控器详细分析报告")
        print("="*60)
        
        if 'fault_type_analysis' in pf_analysis:
            fta = pf_analysis['fault_type_analysis']
            print(f"\n🔍 页面错误类型分析:")
            print(f"  唯一错误类型数: {fta['unique_types']}")
            print(f"  错误类型分布:")
            for fault_type, count in fta['type_distribution'].items():
                print(f"    {fault_type}: {count} 次")
        
        if 'fault_breakdown' in pf_analysis:
            fb = pf_analysis['fault_breakdown']
            print(f"\n📊 错误分类统计:")
            for fault_type, count in fb.items():
                fault_name = fault_type.replace('is_', '').replace('_fault', '').replace('_', ' ').title()
                print(f"    {fault_name}: {count} 次")
        
        if 'address_analysis' in pf_analysis:
            aa = pf_analysis['address_analysis']
            print(f"\n🎯 地址分析:")
            print(f"  最小地址: 0x{aa['min_address']:x}")
            print(f"  最大地址: 0x{aa['max_address']:x}")
            print(f"  唯一地址数: {aa['unique_addresses']}")
        
        if 'command_analysis' in pf_analysis:
            ca = pf_analysis['command_analysis']
            print(f"\n💻 命令分析:")
            print(f"  唯一命令数: {ca['unique_commands']}")
            print(f"  前20个最活跃的命令:")
            for i, (cmd, count) in enumerate(ca['top_commands'].items(), 1):
                print(f"    {i:2d}. {cmd}: {count} 次")
        
        if 'cpu_analysis' in pf_analysis:
            ca = pf_analysis['cpu_analysis']
            print(f"\n🖥️ CPU分布分析:")
            for cpu, count in sorted(ca['faults_by_cpu'].items()):
                print(f"    CPU {cpu}: {count} 次页面错误")
    
    def print_syscall_details(self, syscall_analysis: Dict) -> None:
        """打印syscall详细分析结果"""
        print("\n" + "="*60)
        print("SYSCALL 监控器详细分析报告")
        print("="*60)
        
        if 'syscall_analysis' in syscall_analysis:
            sa = syscall_analysis['syscall_analysis']
            print(f"\n🔧 系统调用分析:")
            print(f"  总调用次数: {sa['total_calls']}")
            print(f"  唯一系统调用数: {sa['unique_syscalls']}")
            print(f"  前20个最常用的系统调用:")
            for i, (syscall, count) in enumerate(sa['top_syscalls'].items(), 1):
                print(f"    {i:2d}. {syscall}: {count} 次")
        
        if 'category_analysis' in syscall_analysis:
            ca = syscall_analysis['category_analysis']
            print(f"\n📂 类别分析:")
            print(f"  唯一类别数: {ca['unique_categories']}")
            print(f"  类别分布:")
            for category, count in ca['category_distribution'].items():
                print(f"    {category}: {count} 次")
        
        if 'performance_analysis' in syscall_analysis:
            pa = syscall_analysis['performance_analysis']
            print(f"\n⏱️ 性能分析:")
            print(f"  平均持续时间: {pa['avg_duration_ms']:.4f} ms")
            print(f"  最大持续时间: {pa['max_duration_ms']:.4f} ms")
            print(f"  最小持续时间: {pa['min_duration_ms']:.4f} ms")
            print(f"  标准差: {pa['std_duration_ms']:.4f} ms")
        
        if 'error_analysis' in syscall_analysis:
            ea = syscall_analysis['error_analysis']
            print(f"\n❌ 错误分析:")
            print(f"  错误次数: {ea['total_errors']}")
            print(f"  错误率: {ea['error_rate']:.2%}")
            if 'error_types' in ea:
                print(f"  错误类型分布:")
                for error_type, count in ea['error_types'].items():
                    print(f"    {error_type}: {count} 次")
        
        if 'slow_call_analysis' in syscall_analysis:
            sca = syscall_analysis['slow_call_analysis']
            print(f"\n🐌 慢调用分析:")
            print(f"  慢调用次数: {sca['total_slow_calls']}")
            print(f"  慢调用率: {sca['slow_call_rate']:.2%}")
        
        if 'command_analysis' in syscall_analysis:
            ca = syscall_analysis['command_analysis']
            print(f"\n💻 命令分析:")
            print(f"  唯一命令数: {ca['unique_commands']}")
            print(f"  前20个最活跃的命令:")
            for i, (cmd, count) in enumerate(ca['top_commands'].items(), 1):
                print(f"    {i:2d}. {cmd}: {count} 次")


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='eBPF数据分析工具')
    parser.add_argument('--analyze', type=str, help='分析指定日期的数据 (YYYYMMDD格式)')
    parser.add_argument('--analyze-exec', type=str, help='详细分析指定日期的exec数据 (YYYYMMDD格式)')
    parser.add_argument('--analyze-open', type=str, help='详细分析指定日期的open数据 (YYYYMMDD格式)')
    parser.add_argument('--analyze-func', type=str, help='详细分析指定日期的func数据 (YYYYMMDD格式)')
    parser.add_argument('--analyze-interrupt', type=str, help='详细分析指定日期的interrupt数据 (YYYYMMDD格式)')
    parser.add_argument('--analyze-io', type=str, help='详细分析指定日期的io数据 (YYYYMMDD格式)')
    parser.add_argument('--analyze-page-fault', type=str, help='详细分析指定日期的page_fault数据 (YYYYMMDD格式)')
    parser.add_argument('--analyze-syscall', type=str, help='详细分析指定日期的syscall数据 (YYYYMMDD格式)')
    parser.add_argument('--compare', nargs='+', help='对比多个日期的数据')
    parser.add_argument('--date-range', nargs=2, metavar=('START', 'END'), 
                       help='分析日期范围内的数据')
    parser.add_argument('--monitors', nargs='+', 
                       choices=['exec', 'syscall', 'io', 'interrupt', 'func', 'open', 'page_fault'],
                       help='指定监控器类型')
    parser.add_argument('--list-dates', action='store_true', help='列出可用的日期')
    parser.add_argument('--output-dir', default='../output', help='输出目录路径')
    parser.add_argument('--daily-dir', default='./daily_data', help='日数据目录路径')
    parser.add_argument('--verbose', action='store_true', help='详细输出')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    analyzer = EBPFAnalyzer(args.output_dir, args.daily_dir)
    
    if args.list_dates:
        dates = analyzer.get_available_dates()
        print("可用日期:")
        for date in dates:
            print(f"  {date}")
    
    elif args.analyze:
        data = analyzer.load_daily_data(args.analyze, args.monitors)
        if data:
            performance = analyzer.analyze_performance(data)
            results = {args.analyze: performance}
            analyzer.print_summary(results)
            
            # 异常检测
            anomalies = analyzer.detect_anomalies(data)
            if anomalies:
                print(f"\n检测到异常:")
                for anomaly_type, anomaly_list in anomalies.items():
                    print(f"  {anomaly_type}: {len(anomaly_list)} 个异常")
        else:
            print(f"未找到日期 {args.analyze} 的数据")
    
    elif args.analyze_exec:
        data = analyzer.load_daily_data(args.analyze_exec, ['exec'])
        if data:
            exec_analysis = analyzer.analyze_exec_details(data)
            analyzer.print_exec_details(exec_analysis)
        else:
            print(f"未找到日期 {args.analyze_exec} 的exec数据")
    
    elif args.analyze_open:
        data = analyzer.load_daily_data(args.analyze_open, ['open'])
        if data:
            open_analysis = analyzer.analyze_open_details(data)
            analyzer.print_open_details(open_analysis)
        else:
            print(f"未找到日期 {args.analyze_open} 的open数据")
    
    elif args.analyze_func:
        data = analyzer.load_daily_data(args.analyze_func, ['func'])
        if data:
            func_analysis = analyzer.analyze_func_details(data)
            analyzer.print_func_details(func_analysis)
        else:
            print(f"未找到日期 {args.analyze_func} 的func数据")
    
    elif args.analyze_interrupt:
        data = analyzer.load_daily_data(args.analyze_interrupt, ['interrupt'])
        if data:
            interrupt_analysis = analyzer.analyze_interrupt_details(data)
            analyzer.print_interrupt_details(interrupt_analysis)
        else:
            print(f"未找到日期 {args.analyze_interrupt} 的interrupt数据")
    
    elif args.analyze_io:
        data = analyzer.load_daily_data(args.analyze_io, ['io'])
        if data:
            io_analysis = analyzer.analyze_io_details(data)
            analyzer.print_io_details(io_analysis)
        else:
            print(f"未找到日期 {args.analyze_io} 的io数据")
    
    elif args.analyze_page_fault:
        data = analyzer.load_daily_data(args.analyze_page_fault, ['page_fault'])
        if data:
            pf_analysis = analyzer.analyze_page_fault_details(data)
            analyzer.print_page_fault_details(pf_analysis)
        else:
            print(f"未找到日期 {args.analyze_page_fault} 的page_fault数据")
    
    elif args.analyze_syscall:
        data = analyzer.load_daily_data(args.analyze_syscall, ['syscall'])
        if data:
            syscall_analysis = analyzer.analyze_syscall_details(data)
            analyzer.print_syscall_details(syscall_analysis)
        else:
            print(f"未找到日期 {args.analyze_syscall} 的syscall数据")
    
    elif args.compare:
        results = analyzer.compare_systems(args.compare, args.monitors)
        analyzer.print_summary(results)
    
    elif args.date_range:
        start_date, end_date = args.date_range
        data_by_date = analyzer.load_date_range(start_date, end_date, args.monitors)
        
        # 分析每一天的数据
        results = {}
        for date, daily_data in data_by_date.items():
            performance = analyzer.analyze_performance(daily_data)
            results[date] = performance
        
        analyzer.print_summary(results)
    
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
