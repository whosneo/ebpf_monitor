#!/usr/bin/env python
# encoding: utf-8
"""
应用上下文管理器

负责管理应用程序的核心组件依赖关系，替代单例模式。
提供依赖注入和组件生命周期管理功能。
"""

import logging

# 兼容性导入
try:
    from typing import Dict, Any, Optional, List, TYPE_CHECKING
except ImportError:
    from .py2_compat import Dict, Any, Optional, List, TYPE_CHECKING

from .config_manager import ConfigManager
from .daemon_manager import DaemonManager
from .log_manager import LogManager
from .output_controller import OutputController

if TYPE_CHECKING:
    from .capability_checker import CapabilityChecker
    from .monitor_registry import MonitorRegistry
    from .monitor_factory import MonitorFactory
    from ..ebpf_monitor import eBPFMonitor


class ApplicationContext:
    """
    应用上下文管理器
    
    管理应用程序的核心组件，提供依赖注入功能。
    替代直接使用单例模式，提高可测试性和灵活性。
    """

    def __init__(self, config_file="config/monitor_config.yaml"):
        # type: (str) -> None
        """
        初始化应用上下文
        
        Args:
            config_file: 配置文件路径
        """
        # 组件缓存字典
        self.components = {}  # type: Dict[str, Any]

        # 按依赖顺序创建核心组件
        # 1. ConfigManager (无依赖)
        self.config_manager = ConfigManager(config_file)

        # 2. LogManager (依赖ConfigManager, 保持单例)
        self.log_manager = LogManager(self.config_manager)

        # 3. 获取基础配置（在创建其他组件前）
        self.base_dir = self.config_manager.get_base_dir()

        # 4. OutputController (依赖ConfigManager和LogManager)
        self.output_controller = OutputController(
            self.config_manager,
            self.log_manager
        )

        # 5. DaemonManager (依赖LogManager和base_dir)
        self.daemon_manager = DaemonManager(self.log_manager, self.base_dir)

        # 获取logger
        self.logger = self.log_manager.get_logger(self)

        self.logger.debug("应用上下文初始化完成")

    def get_logger(self, obj=None):
        # type: (Any) -> logging.Logger
        """
        获取logger实例
        
        Args:
            obj: 对象，默认使用调用者类名
        
        Returns:
            logging.Logger: logger实例
        """
        return self.log_manager.get_logger(obj)

    def get_component(self, name):
        # type: (str) -> Optional[Any]
        """
        获取注册的组件
        
        Args:
            name: 组件名称
            
        Returns:
            Optional[Any]: 组件实例，如果不存在返回None
        """
        return self.components.get(name)

    def get_capability_checker(self):
        # type: () -> 'CapabilityChecker'
        """
        创建内核兼容性检查器实例（缓存机制，避免重复创建）
        
        Returns:
            CapabilityChecker: 内核兼容性检查器实例
        """
        if 'capability_checker' not in self.components:
            from .capability_checker import CapabilityChecker
            checker = CapabilityChecker(context=self)
            self._register_component('capability_checker', checker)
            return checker
        return self.components['capability_checker']

    def get_monitor_registry(self):
        # type: () -> 'MonitorRegistry'
        """
        获取监控器注册表实例（缓存机制，避免重复创建）
        
        Returns:
            MonitorRegistry: 监控器注册表实例
        """
        # 使用缓存机制，避免重复创建MonitorRegistry（因为它需要扫描文件系统）
        if 'monitor_registry' not in self.components:
            from .monitor_registry import MonitorRegistry
            registry = MonitorRegistry(context=self)
            self._register_component('monitor_registry', registry)
            return registry
        return self.components['monitor_registry']

    def get_monitor_factory(self):
        # type: () -> 'MonitorFactory'
        """
        获取监控器工厂实例（缓存机制，避免重复创建）
        
        Returns:
            MonitorFactory: 监控器工厂实例
        """
        if 'monitor_factory' not in self.components:
            from .monitor_factory import MonitorFactory
            factory = MonitorFactory(context=self)
            self._register_component('monitor_factory', factory)
            return factory
        return self.components['monitor_factory']

    def get_ebpf_monitor(self, selected_monitors=None):
        # type: (Optional[List[str]]) -> 'eBPFMonitor'
        """
        创建新的eBPF监控器实例（不缓存，因为参数可能变化）
        
        Args:
            selected_monitors: 选定的监控器列表，None表示使用所有已注册的监控器
            
        Returns:
            eBPFMonitor: 新创建的eBPF监控器实例
        """
        from ..ebpf_monitor import eBPFMonitor
        monitor = eBPFMonitor(context=self, selected_monitors=selected_monitors)
        # 注册到组件以便cleanup时可以清理
        self._register_component('ebpf_monitor', monitor)
        return monitor

    def _register_component(self, name, component):
        # type: (str, Any) -> None
        """
        注册组件到上下文
        
        Args:
            name: 组件名称
            component: 组件实例
        """
        self.components[name] = component
        self.logger.debug("注册组件: {}".format(name))

    def _unregister_component(self, name):
        # type: (str) -> bool
        """
        注销组件
        
        Args:
            name: 组件名称
            
        Returns:
            bool: 是否成功注销
        """
        if name in self.components:
            del self.components[name]
            self.logger.debug("注销组件: {}".format(name))
            return True
        return False

    def cleanup(self):
        # type: () -> None
        """清理上下文和所有注册的组件"""
        self.logger.info("开始清理应用上下文...")

        # 清理注册的组件
        for name, component in list(self.components.items()):
            if hasattr(component, 'cleanup'):
                try:
                    component.cleanup()
                    self.logger.debug("清理组件: {}".format(name))
                except Exception as e:
                    self.logger.error("清理组件失败 {}: {}".format(name, e))

        self.components.clear()
        self.logger.info("应用上下文清理完成")
