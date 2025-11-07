#!/usr/bin/env python
# encoding: utf-8
"""
监控器工厂 - 负责创建和配置监控器实例
"""

# 兼容性导入
try:
    from pathlib import Path
except ImportError:
    from .py2_compat import Path
try:
    from typing import TYPE_CHECKING, Type, Dict, Any
except ImportError:
    from .py2_compat import TYPE_CHECKING, Type, Dict, Any

from .monitor_context import MonitorContext

if TYPE_CHECKING:
    from .application_context import ApplicationContext
    from ..monitors.base import BaseMonitor


class MonitorFactory(object):
    """
    监控器工厂类
    
    职责:
    1. 一次性准备所有监控器共享的资源(compile_flags, boot_time等)
    2. 为每个监控器创建专属的MonitorContext
    3. 使用MonitorContext创建监控器实例
    
    优势:
    - 集中管理监控器创建逻辑
    - 避免重复准备共享资源
    - 封装创建复杂度
    - 易于扩展和测试
    """

    def __init__(self, context):
        # type: (ApplicationContext) -> None
        """
        初始化监控器工厂
        
        Args:
            context: 应用上下文
        """
        self.context = context
        self.logger = context.log_manager.get_logger(self)

        # 一次性准备所有共享资源
        self._prepare_shared_resources()

        self.logger.debug("监控器工厂初始化完成")

    def _prepare_shared_resources(self):
        # type: () -> None
        """准备所有监控器共享的资源"""
        # eBPF程序目录
        self.ebpf_dir = self.context.config_manager.get_ebpf_dir()
        self.logger.debug("eBPF程序目录: {}".format(self.ebpf_dir))

        # eBPF编译标志
        capability_checker = self.context.get_capability_checker()
        self.compile_flags = capability_checker.get_compile_flags()
        self.logger.debug("eBPF编译标志: {}".format(self.compile_flags))

    def create_monitor(self, monitor_class, monitor_type, config):
        # type: (Type[BaseMonitor], str, Dict[str, Any]) -> BaseMonitor
        """
        创建监控器实例
        
        Args:
            monitor_class: 监控器类
            monitor_type: 监控器类型名称(如'exec', 'syscall')
            config: 监控器配置字典
        
        Returns:
            配置好的监控器实例
        
        Raises:
            IOError: eBPF文件不存在
            ValueError: 监控器配置无效
        """
        self.logger.debug("创建监控器: {} (类型: {})".format(
            monitor_class.__name__, monitor_type
        ))

        # 1. 准备监控器专属依赖
        monitor_logger = self.context.log_manager.get_logger(monitor_class)
        output_controller = self.context.output_controller
        ebpf_file_path = self.ebpf_dir / "{}.c".format(monitor_type)

        # 2. 验证eBPF文件存在
        if not ebpf_file_path.exists():
            error_msg = "eBPF程序文件不存在: {}".format(ebpf_file_path)
            self.logger.error(error_msg)
            raise IOError(error_msg)

        # 3. 创建MonitorContext
        monitor_context = MonitorContext(
            logger=monitor_logger,
            output_controller=output_controller,
            ebpf_file_path=ebpf_file_path,
            compile_flags=self.compile_flags,
        )

        self.logger.debug("MonitorContext创建完成: {}".format(monitor_context))

        # 4. 使用MonitorContext创建监控器
        monitor = monitor_class(monitor_context, config)

        return monitor

    def get_shared_resources_info(self):
        # type: () -> Dict[str, Any]
        """
        获取共享资源信息(用于调试)
        
        Returns:
            包含共享资源信息的字典
        """
        return {
            'ebpf_dir': str(self.ebpf_dir),
            'compile_flags': self.compile_flags
        }
