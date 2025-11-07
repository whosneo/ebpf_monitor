#!/usr/bin/env python
# encoding: utf-8
"""
监控器上下文 - 封装监控器运行所需的所有依赖和配置
"""

import logging
from .py2_compat import Path, List


class MonitorContext(object):
    """
    监控器上下文 - 纯数据容器,无业务逻辑
    
    封装BaseMonitor运行所需的所有依赖:
    - logger: 日志记录器
    - output_controller: 输出控制器
    - ebpf_file_path: eBPF程序文件路径
    - compile_flags: eBPF编译标志
    
    优势:
    - 减少BaseMonitor构造函数参数
    - 集中管理依赖,易于扩展
    - 易于测试(可整体mock)
    """

    def __init__(self, logger, output_controller, ebpf_file_path, compile_flags):
        # type: (logging.Logger, object, Path, List[str], object) -> None
        """
        初始化监控器上下文
        
        Args:
            logger: 日志记录器
            output_controller: 输出控制器
            ebpf_file_path: eBPF程序文件路径
            compile_flags: eBPF编译标志列表
        """
        self.logger = logger
        self.output_controller = output_controller
        self.ebpf_file_path = ebpf_file_path
        self.compile_flags = compile_flags

    def __repr__(self):
        # type: () -> str
        """字符串表示"""
        return "MonitorContext(ebpf_file={}, compile_flags_count={})".format(
            self.ebpf_file_path.name if self.ebpf_file_path else None,
            len(self.compile_flags)
        )
