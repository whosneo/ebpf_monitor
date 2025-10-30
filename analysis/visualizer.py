#!/usr/bin/env python3
"""
可视化工具
提供图表生成和报告导出功能
"""

import os
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import seaborn as sns
import pandas as pd
import numpy as np
from datetime import datetime
from typing import Dict, List, Optional, Any
import logging

# 配置matplotlib中文显示
plt.rcParams['font.sans-serif'] = ['SimHei', 'DejaVu Sans', 'Arial Unicode MS']
plt.rcParams['axes.unicode_minus'] = False

# 配置seaborn样式
sns.set_style("whitegrid")
sns.set_palette("husl")

logger = logging.getLogger(__name__)

class EBPFVisualizer:
    """eBPF数据可视化器"""
    
    def __init__(self, output_dir: str = "./reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        
        # 设置图表样式
        plt.style.use('default')
        self.colors = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd', 
                      '#8c564b', '#e377c2', '#7f7f7f', '#bcbd22', '#17becf']
    
    def plot_performance_comparison(self, comparison_data: Dict[str, Dict], 
                                  metric: str, monitor_type: str, 
                                  title: Optional[str] = None) -> str:
        """
        绘制性能对比图
        
        Args:
            comparison_data: 对比数据字典
            metric: 指标名称
            monitor_type: 监控器类型
            title: 图表标题
            
        Returns:
            生成的图片文件路径
        """
        dates = []
        values = []
        
        for date, performance in comparison_data.items():
            if monitor_type in performance and metric in performance[monitor_type]:
                dates.append(datetime.strptime(date, '%Y%m%d'))
                values.append(performance[monitor_type][metric])
        
        if not dates:
            logger.warning(f"没有找到 {monitor_type}.{metric} 的数据")
            return ""
        
        plt.figure(figsize=(12, 6))
        plt.plot(dates, values, marker='o', linewidth=2, markersize=8)
        
        plt.title(title or f'{monitor_type.upper()} - {metric}', fontsize=16, fontweight='bold')
        plt.xlabel('日期', fontsize=12)
        plt.ylabel(metric, fontsize=12)
        
        # 格式化x轴日期
        plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d'))
        plt.gca().xaxis.set_major_locator(mdates.DayLocator(interval=1))
        plt.xticks(rotation=45)
        
        plt.grid(True, alpha=0.3)
        plt.tight_layout()
        
        filename = f"{monitor_type}_{metric}_comparison.png"
        filepath = os.path.join(self.output_dir, filename)
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        plt.close()
        
        logger.info(f"生成对比图: {filepath}")
        return filepath
    
    def plot_multi_metric_comparison(self, comparison_data: Dict[str, Dict], 
                                   monitor_type: str, metrics: List[str],
                                   title: Optional[str] = None) -> str:
        """
        绘制多指标对比图
        
        Args:
            comparison_data: 对比数据字典
            monitor_type: 监控器类型
            metrics: 指标列表
            title: 图表标题
            
        Returns:
            生成的图片文件路径
        """
        dates = list(comparison_data.keys())
        date_objects = [datetime.strptime(date, '%Y%m%d') for date in dates]
        
        fig, axes = plt.subplots(len(metrics), 1, figsize=(12, 4 * len(metrics)))
        if len(metrics) == 1:
            axes = [axes]
        
        for i, metric in enumerate(metrics):
            values = []
            for date in dates:
                if (monitor_type in comparison_data[date] and 
                    metric in comparison_data[date][monitor_type]):
                    values.append(comparison_data[date][monitor_type][metric])
                else:
                    values.append(0)
            
            axes[i].plot(date_objects, values, marker='o', linewidth=2, 
                        markersize=6, color=self.colors[i % len(self.colors)])
            axes[i].set_title(f'{metric}', fontsize=12, fontweight='bold')
            axes[i].set_ylabel(metric, fontsize=10)
            axes[i].grid(True, alpha=0.3)
            
            # 格式化x轴
            axes[i].xaxis.set_major_formatter(mdates.DateFormatter('%m-%d'))
            if i == len(metrics) - 1:  # 只在最后一个子图显示x轴标签
                axes[i].set_xlabel('日期', fontsize=10)
                plt.setp(axes[i].xaxis.get_majorticklabels(), rotation=45)
            else:
                axes[i].set_xticklabels([])
        
        plt.suptitle(title or f'{monitor_type.upper()} 多指标对比', fontsize=16, fontweight='bold')
        plt.tight_layout()
        
        filename = f"{monitor_type}_multi_metrics.png"
        filepath = os.path.join(self.output_dir, filename)
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        plt.close()
        
        logger.info(f"生成多指标对比图: {filepath}")
        return filepath
    
    def plot_distribution(self, data: pd.DataFrame, column: str, 
                         title: Optional[str] = None, bins: int = 50) -> str:
        """
        绘制数据分布图
        
        Args:
            data: 数据DataFrame
            column: 列名
            title: 图表标题
            bins: 直方图分箱数
            
        Returns:
            生成的图片文件路径
        """
        if column not in data.columns:
            logger.warning(f"列 {column} 不存在")
            return ""
        
        plt.figure(figsize=(10, 6))
        
        # 创建子图
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
        
        # 直方图
        ax1.hist(data[column].dropna(), bins=bins, alpha=0.7, color='skyblue', edgecolor='black')
        ax1.set_title(f'{column} 分布直方图', fontsize=12, fontweight='bold')
        ax1.set_xlabel(column, fontsize=10)
        ax1.set_ylabel('频次', fontsize=10)
        ax1.grid(True, alpha=0.3)
        
        # 箱线图
        ax2.boxplot(data[column].dropna(), vert=True)
        ax2.set_title(f'{column} 箱线图', fontsize=12, fontweight='bold')
        ax2.set_ylabel(column, fontsize=10)
        ax2.grid(True, alpha=0.3)
        
        plt.suptitle(title or f'{column} 数据分布分析', fontsize=16, fontweight='bold')
        plt.tight_layout()
        
        filename = f"{column}_distribution.png"
        filepath = os.path.join(self.output_dir, filename)
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        plt.close()
        
        logger.info(f"生成分布图: {filepath}")
        return filepath
    
    def plot_heatmap(self, data: Dict[str, Dict], title: Optional[str] = None) -> str:
        """
        绘制性能指标热力图
        
        Args:
            data: 数据字典
            title: 图表标题
            
        Returns:
            生成的图片文件路径
        """
        # 构建热力图数据
        dates = list(data.keys())
        all_metrics = set()
        
        # 收集所有指标
        for date_data in data.values():
            for monitor_type, metrics in date_data.items():
                for metric in metrics.keys():
                    all_metrics.add(f"{monitor_type}_{metric}")
        
        all_metrics = sorted(list(all_metrics))
        
        # 构建数据矩阵
        matrix_data = []
        for date in dates:
            row = []
            for metric in all_metrics:
                monitor_type, metric_name = metric.split('_', 1)
                if (monitor_type in data[date] and 
                    metric_name in data[date][monitor_type]):
                    value = data[date][monitor_type][metric_name]
                    row.append(value)
                else:
                    row.append(np.nan)
            matrix_data.append(row)
        
        # 创建DataFrame
        df = pd.DataFrame(matrix_data, index=dates, columns=all_metrics)
        
        # 标准化数据（按列）
        df_normalized = df.apply(lambda x: (x - x.min()) / (x.max() - x.min()) if x.max() != x.min() else x)
        
        plt.figure(figsize=(max(12, len(all_metrics) * 0.8), max(8, len(dates) * 0.5)))
        
        sns.heatmap(df_normalized, annot=False, cmap='YlOrRd', 
                   cbar_kws={'label': '标准化值'}, 
                   xticklabels=True, yticklabels=True)
        
        plt.title(title or '系统性能指标热力图', fontsize=16, fontweight='bold')
        plt.xlabel('性能指标', fontsize=12)
        plt.ylabel('日期', fontsize=12)
        plt.xticks(rotation=45, ha='right')
        plt.yticks(rotation=0)
        plt.tight_layout()
        
        filename = "performance_heatmap.png"
        filepath = os.path.join(self.output_dir, filename)
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        plt.close()
        
        logger.info(f"生成热力图: {filepath}")
        return filepath
    
    def plot_time_series(self, data: pd.DataFrame, time_column: str, 
                        value_column: str, title: Optional[str] = None,
                        sample_rate: Optional[int] = None) -> str:
        """
        绘制时间序列图
        
        Args:
            data: 数据DataFrame
            time_column: 时间列名
            value_column: 数值列名
            title: 图表标题
            sample_rate: 采样率（每N个点取一个）
            
        Returns:
            生成的图片文件路径
        """
        if time_column not in data.columns or value_column not in data.columns:
            logger.warning(f"列 {time_column} 或 {value_column} 不存在")
            return ""
        
        # 数据预处理
        df = data[[time_column, value_column]].copy()
        df = df.dropna()
        
        # 转换时间戳
        df[time_column] = pd.to_datetime(df[time_column], unit='s', errors='coerce')
        df = df.dropna()
        df = df.sort_values(time_column)
        
        # 采样
        if sample_rate and len(df) > sample_rate:
            df = df.iloc[::len(df)//sample_rate]
        
        plt.figure(figsize=(15, 8))
        plt.plot(df[time_column], df[value_column], linewidth=1, alpha=0.7)
        
        plt.title(title or f'{value_column} 时间序列', fontsize=16, fontweight='bold')
        plt.xlabel('时间', fontsize=12)
        plt.ylabel(value_column, fontsize=12)
        
        # 格式化x轴
        plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
        plt.xticks(rotation=45)
        
        plt.grid(True, alpha=0.3)
        plt.tight_layout()
        
        filename = f"{value_column}_timeseries.png"
        filepath = os.path.join(self.output_dir, filename)
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        plt.close()
        
        logger.info(f"生成时间序列图: {filepath}")
        return filepath
    
    def generate_html_report(self, comparison_data: Dict[str, Dict], 
                           image_paths: List[str], 
                           title: str = "eBPF系统性能分析报告") -> str:
        """
        生成HTML报告
        
        Args:
            comparison_data: 对比数据
            image_paths: 图片路径列表
            title: 报告标题
            
        Returns:
            HTML文件路径
        """
        html_content = f"""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        body {{
            font-family: 'Microsoft YaHei', Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #2c3e50;
            text-align: center;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #34495e;
            border-left: 4px solid #3498db;
            padding-left: 15px;
            margin-top: 30px;
        }}
        .summary-table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        .summary-table th, .summary-table td {{
            border: 1px solid #ddd;
            padding: 12px;
            text-align: left;
        }}
        .summary-table th {{
            background-color: #3498db;
            color: white;
        }}
        .summary-table tr:nth-child(even) {{
            background-color: #f9f9f9;
        }}
        .chart-container {{
            text-align: center;
            margin: 30px 0;
        }}
        .chart-container img {{
            max-width: 100%;
            height: auto;
            border: 1px solid #ddd;
            border-radius: 5px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .metric-card {{
            background-color: #ecf0f1;
            padding: 15px;
            margin: 10px 0;
            border-radius: 5px;
            border-left: 4px solid #e74c3c;
        }}
        .timestamp {{
            color: #7f8c8d;
            font-size: 0.9em;
            text-align: center;
            margin-top: 30px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>{title}</h1>
        
        <h2>📊 性能指标摘要</h2>
        <table class="summary-table">
            <thead>
                <tr>
                    <th>日期</th>
                    <th>监控器</th>
                    <th>关键指标</th>
                    <th>数值</th>
                </tr>
            </thead>
            <tbody>
"""
        
        # 添加摘要数据
        for date, performance in comparison_data.items():
            for monitor_type, metrics in performance.items():
                for metric, value in metrics.items():
                    if isinstance(value, float):
                        value_str = f"{value:.4f}"
                    else:
                        value_str = str(value)
                    html_content += f"""
                <tr>
                    <td>{date}</td>
                    <td>{monitor_type.upper()}</td>
                    <td>{metric}</td>
                    <td>{value_str}</td>
                </tr>
"""
        
        html_content += """
            </tbody>
        </table>
        
        <h2>📈 性能趋势图表</h2>
"""
        
        # 添加图表
        for image_path in image_paths:
            if os.path.exists(image_path):
                image_name = os.path.basename(image_path)
                html_content += f"""
        <div class="chart-container">
            <h3>{image_name.replace('_', ' ').replace('.png', '').title()}</h3>
            <img src="{image_name}" alt="{image_name}">
        </div>
"""
        
        html_content += f"""
        <div class="timestamp">
            <p>报告生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
    </div>
</body>
</html>
"""
        
        filename = f"ebpf_analysis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"生成HTML报告: {filepath}")
        return filepath
    
    def create_dashboard(self, comparison_data: Dict[str, Dict]) -> List[str]:
        """
        创建完整的可视化仪表板
        
        Args:
            comparison_data: 对比数据
            
        Returns:
            生成的图片文件路径列表
        """
        image_paths = []
        
        # 生成热力图
        heatmap_path = self.plot_heatmap(comparison_data, "系统性能指标热力图")
        if heatmap_path:
            image_paths.append(heatmap_path)
        
        # 为每个监控器生成多指标对比图
        monitor_metrics = {
            'syscall': ['total_calls', 'avg_duration_ms', 'error_rate'],
            'io': ['total_operations', 'avg_throughput_mbps', 'avg_duration_us'],
            'exec': ['total_processes', 'unique_commands', 'failed_executions'],
            'interrupt': ['total_interrupts', 'avg_duration_us'],
            'page_fault': ['total_faults', 'major_faults', 'minor_faults']
        }
        
        for monitor_type, metrics in monitor_metrics.items():
            # 检查是否有该监控器的数据
            has_data = any(monitor_type in data for data in comparison_data.values())
            if has_data:
                chart_path = self.plot_multi_metric_comparison(
                    comparison_data, monitor_type, metrics,
                    f"{monitor_type.upper()} 监控器性能趋势"
                )
                if chart_path:
                    image_paths.append(chart_path)
        
        return image_paths
