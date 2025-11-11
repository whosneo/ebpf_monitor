#!/usr/bin/env python
# encoding: utf-8
"""
数据处理工具函数
提供时间戳处理、数据清洗、文件操作等基础功能
"""

import logging
import os
import re
from datetime import datetime

import pandas as pd

# 配置日志
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def parse_timestamp(timestamp_str):
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
            logger.warning("无法解析时间戳: {}".format(timestamp_str))
            return None


def extract_date(timestamp_str):
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


def get_monitor_type(filename):
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


def scan_output_files(output_dir, monitor_type=None):
    """
    扫描output目录，按监控器类型分组文件
    
    Args:
        output_dir: output目录路径
        monitor_type: 可选，指定监控器类型，只返回该类型的文件列表
        
    Returns:
        如果指定monitor_type，返回文件列表；否则返回按监控器类型分组的文件字典
    """
    files_by_monitor = {}

    if not os.path.exists(output_dir):
        logger.error("输出目录不存在: {}".format(output_dir))
        return [] if monitor_type else files_by_monitor

    for filename in os.listdir(output_dir):
        if filename.endswith('.csv'):
            mtype = get_monitor_type(filename)
            if mtype:
                if mtype not in files_by_monitor:
                    files_by_monitor[mtype] = []
                files_by_monitor[mtype].append(os.path.join(output_dir, filename))

    logger.info("发现监控器类型: {}".format(list(files_by_monitor.keys())))
    for mtype, files in files_by_monitor.items():
        logger.info("{}: {} 个文件".format(mtype, len(files)))

    # 如果指定了monitor_type，只返回该类型的文件列表
    if monitor_type:
        return sorted(files_by_monitor.get(monitor_type, []))

    return files_by_monitor


def safe_read_csv(filepath, chunk_size=10000):
    """
    安全读取CSV文件，处理各种格式问题
    
    Args:
        filepath: 文件路径
        chunk_size: 分块读取大小（用于大文件）
        
    Returns:
        DataFrame对象
    """
    # 定义多种读取策略 (Python3/pandas 2.x+)
    read_strategies = [
        # 策略1: 标准读取
        {
            'params': {
                'on_bad_lines': 'skip',
                'engine': 'python'
            },
            'name': '标准读取'
        },
        # 策略2: 处理引号问题
        {
            'params': {
                'on_bad_lines': 'skip',
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
                'engine': 'python',
                'quoting': 3,  # QUOTE_NONE
                'sep': ','
            },
            'name': '宽松模式'
        }
    ]

    for strategy in read_strategies:
        try:
            logger.debug("尝试使用{}读取文件: {}".format(strategy['name'], filepath))

            # 首先尝试直接读取
            try:
                df = pd.read_csv(filepath, **strategy['params'])
                if not df.empty:
                    logger.info("成功读取文件 {} (使用{}, 行数: {})".format(filepath, strategy['name'], len(df)))
                    return df
            except Exception as e:
                logger.debug("{}直接读取失败: {}".format(strategy['name'], e))

                # 尝试分块读取
                try:
                    chunks = []
                    for chunk in pd.read_csv(filepath, chunksize=chunk_size, **strategy['params']):
                        if not chunk.empty:
                            chunks.append(chunk)

                    if chunks:
                        df = pd.concat(chunks, ignore_index=True)
                        logger.info(
                            "成功分块读取文件 {} (使用{}, 行数: {})".format(filepath, strategy['name'], len(df)))
                        return df
                except Exception as e2:
                    logger.debug("{}分块读取失败: {}".format(strategy['name'], e2))
                    continue

        except Exception as e:
            logger.debug("{}完全失败: {}".format(strategy['name'], e))
            continue

    # 所有策略都失败，尝试手动解析
    logger.warning("所有标准方法都失败，尝试手动解析: {}".format(filepath))
    return manual_parse_csv(filepath)


def manual_parse_csv(filepath):
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
                    logger.debug("跳过问题行 {}: {}".format(line_num, e))
                    continue

        if header and rows:
            df = pd.DataFrame(rows, columns=header)
            logger.info("手动解析成功 {} (行数: {})".format(filepath, len(df)))
            return df
        else:
            logger.warning("手动解析失败，文件可能为空: {}".format(filepath))
            return pd.DataFrame()

    except Exception as e:
        logger.error("手动解析文件失败 {}: {}".format(filepath, e))
        return pd.DataFrame()


def get_date_range_from_files(files):
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
                logger.debug("无法从文件内容获取日期 {}: {}".format(filepath, e))

    if dates:
        dates.sort()
        return dates[0], dates[-1]

    return None, None
