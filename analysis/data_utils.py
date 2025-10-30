#!/usr/bin/env python3
"""
数据处理工具函数
提供时间戳处理、数据清洗、文件操作等基础功能
"""

import os
import re
import pandas as pd
from datetime import datetime
from typing import List, Dict, Tuple, Optional
import logging

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def parse_timestamp(timestamp_str: str) -> Optional[datetime]:
    """
    解析时间戳字符串，支持多种格式
    
    Args:
        timestamp_str: 时间戳字符串
        
    Returns:
        datetime对象，解析失败返回None
    """
    try:
        # 尝试解析浮点数时间戳
        if '.' in timestamp_str:
            timestamp_float = float(timestamp_str)
            return datetime.fromtimestamp(timestamp_float)
        else:
            # 尝试解析整数时间戳
            timestamp_int = int(timestamp_str)
            return datetime.fromtimestamp(timestamp_int)
    except (ValueError, OSError):
        try:
            # 尝试解析标准时间格式
            return datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            logger.warning(f"无法解析时间戳: {timestamp_str}")
            return None

def extract_date(timestamp_str: str) -> Optional[str]:
    """
    从时间戳中提取日期字符串 (YYYYMMDD格式)
    
    Args:
        timestamp_str: 时间戳字符串
        
    Returns:
        日期字符串，格式为YYYYMMDD，解析失败返回None
    """
    dt = parse_timestamp(timestamp_str)
    if dt:
        return dt.strftime('%Y%m%d')
    return None

def get_monitor_type(filename: str) -> Optional[str]:
    """
    从文件名中提取监控器类型
    
    Args:
        filename: 文件名
        
    Returns:
        监控器类型，如exec、syscall等
    """
    # 匹配模式: {monitor_type}_{timestamp}.csv
    pattern = r'^([a-z_]+)_\d+.*\.csv$'
    match = re.match(pattern, filename)
    if match:
        return match.group(1)
    return None

def scan_output_files(output_dir: str) -> Dict[str, List[str]]:
    """
    扫描output目录，按监控器类型分组文件
    
    Args:
        output_dir: output目录路径
        
    Returns:
        按监控器类型分组的文件字典
    """
    files_by_monitor = {}
    
    if not os.path.exists(output_dir):
        logger.error(f"输出目录不存在: {output_dir}")
        return files_by_monitor
    
    for filename in os.listdir(output_dir):
        if filename.endswith('.csv'):
            monitor_type = get_monitor_type(filename)
            if monitor_type:
                if monitor_type not in files_by_monitor:
                    files_by_monitor[monitor_type] = []
                files_by_monitor[monitor_type].append(os.path.join(output_dir, filename))
    
    logger.info(f"发现监控器类型: {list(files_by_monitor.keys())}")
    for monitor_type, files in files_by_monitor.items():
        logger.info(f"{monitor_type}: {len(files)} 个文件")
    
    return files_by_monitor


def safe_read_csv(filepath: str, chunk_size: int = 10000) -> pd.DataFrame:
    """
    安全读取CSV文件，处理各种格式问题
    
    Args:
        filepath: 文件路径
        chunk_size: 分块读取大小（用于大文件）
        
    Returns:
        DataFrame对象
    """
    # 定义多种读取策略
    read_strategies = [
        # 策略1: 标准读取
        {
            'params': {
                'on_bad_lines': 'skip',
                'low_memory': False,
                'engine': 'python'
            },
            'name': '标准读取'
        },
        # 策略2: 处理引号问题
        {
            'params': {
                'on_bad_lines': 'skip',
                'low_memory': False,
                'engine': 'python',
                'quoting': 3,  # QUOTE_NONE
                'escapechar': '\\'
            },
            'name': '无引号模式'
        },
        # 策略3: 处理分隔符问题
        {
            'params': {
                'on_bad_lines': 'skip',
                'low_memory': False,
                'engine': 'python',
                'sep': ',',
                'quotechar': '"',
                'doublequote': True,
                'skipinitialspace': True
            },
            'name': '严格CSV模式'
        },
        # 策略4: 最宽松模式
        {
            'params': {
                'on_bad_lines': 'skip',
                'low_memory': False,
                'engine': 'python',
                'quoting': 3,  # QUOTE_NONE
                'sep': ',',
                'error_bad_lines': False,
                'warn_bad_lines': False
            },
            'name': '宽松模式'
        }
    ]
    
    for strategy in read_strategies:
        try:
            logger.debug(f"尝试使用{strategy['name']}读取文件: {filepath}")
            
            # 首先尝试直接读取
            try:
                df = pd.read_csv(filepath, **strategy['params'])
                if not df.empty:
                    logger.info(f"成功读取文件 {filepath} (使用{strategy['name']}, 行数: {len(df)})")
                    return df
            except Exception as e:
                logger.debug(f"{strategy['name']}直接读取失败: {e}")
                
                # 尝试分块读取
                try:
                    chunks = []
                    for chunk in pd.read_csv(filepath, chunksize=chunk_size, **strategy['params']):
                        if not chunk.empty:
                            chunks.append(chunk)
                    
                    if chunks:
                        df = pd.concat(chunks, ignore_index=True)
                        logger.info(f"成功分块读取文件 {filepath} (使用{strategy['name']}, 行数: {len(df)})")
                        return df
                except Exception as e2:
                    logger.debug(f"{strategy['name']}分块读取失败: {e2}")
                    continue
        
        except Exception as e:
            logger.debug(f"{strategy['name']}完全失败: {e}")
            continue
    
    # 所有策略都失败，尝试手动解析
    logger.warning(f"所有标准方法都失败，尝试手动解析: {filepath}")
    return manual_parse_csv(filepath)

def manual_parse_csv(filepath: str) -> pd.DataFrame:
    """
    手动解析CSV文件，处理严重格式问题
    
    Args:
        filepath: 文件路径
        
    Returns:
        DataFrame对象
    """
    try:
        rows = []
        header = None
        
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                
                try:
                    # 简单的CSV解析，处理基本的逗号分隔
                    # 这里不处理复杂的引号嵌套，只做基本分割
                    fields = []
                    current_field = ""
                    in_quotes = False
                    
                    i = 0
                    while i < len(line):
                        char = line[i]
                        
                        if char == '"' and not in_quotes:
                            in_quotes = True
                        elif char == '"' and in_quotes:
                            # 检查是否是转义的引号
                            if i + 1 < len(line) and line[i + 1] == '"':
                                current_field += '"'
                                i += 1  # 跳过下一个引号
                            else:
                                in_quotes = False
                        elif char == ',' and not in_quotes:
                            fields.append(current_field.strip())
                            current_field = ""
                        else:
                            current_field += char
                        
                        i += 1
                    
                    # 添加最后一个字段
                    fields.append(current_field.strip())
                    
                    if line_num == 1:
                        header = fields
                    else:
                        # 确保字段数量匹配
                        while len(fields) < len(header):
                            fields.append("")
                        if len(fields) > len(header):
                            fields = fields[:len(header)]
                        
                        rows.append(fields)
                
                except Exception as e:
                    logger.debug(f"跳过问题行 {line_num}: {e}")
                    continue
        
        if header and rows:
            df = pd.DataFrame(rows, columns=header)
            logger.info(f"手动解析成功 {filepath} (行数: {len(df)})")
            return df
        else:
            logger.warning(f"手动解析失败，文件可能为空: {filepath}")
            return pd.DataFrame()
    
    except Exception as e:
        logger.error(f"手动解析文件失败 {filepath}: {e}")
        return pd.DataFrame()

def get_date_range_from_files(files: List[str]) -> Tuple[Optional[str], Optional[str]]:
    """
    从文件列表中获取日期范围
    
    Args:
        files: 文件路径列表
        
    Returns:
        (开始日期, 结束日期) 元组，格式为YYYYMMDD
    """
    dates = []
    
    for filepath in files:
        filename = os.path.basename(filepath)
        # 提取文件名中的时间戳
        timestamp_match = re.search(r'_(\d{8})(?:_\d+)?\.csv$', filename)
        if timestamp_match:
            dates.append(timestamp_match.group(1))
        else:
            # 尝试从文件内容中获取日期
            try:
                df = safe_read_csv(filepath)
                if not df.empty and 'timestamp' in df.columns:
                    first_timestamp = str(df['timestamp'].iloc[0])
                    date_str = extract_date(first_timestamp)
                    if date_str:
                        dates.append(date_str)
            except Exception as e:
                logger.debug(f"无法从文件内容获取日期 {filepath}: {e}")
    
    if dates:
        dates.sort()
        return dates[0], dates[-1]
    
    return None, None
