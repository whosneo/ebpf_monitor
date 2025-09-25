#!/usr/bin/env python
# encoding: utf-8
"""
应用上下文管理器

负责管理应用程序的核心组件依赖关系，替代单例模式。
提供依赖注入和组件生命周期管理功能。
"""

import logging
import threading
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
        # 分层锁架构：替换单一全局锁为细粒度锁
        self.component_registry_lock = threading.RLock()  # 组件注册/注销锁
        self.component_access_lock = threading.RLock()  # 组件访问锁
        self.components = {}  # type: Dict[str, Any]

        # 初始化核心组件（保留单例的组件）
        self.config_manager = ConfigManager(config_file)
        self.log_manager = LogManager()
        self.output_controller = OutputController()
        self.daemon_manager = DaemonManager()

        # 获取基础配置
        self.logger = self.log_manager.get_logger(self)
        self.base_dir = self.config_manager.get_base_dir()

        self.logger.info("应用上下文初始化完成")

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
        获取注册的组件 - 使用组件访问锁
        
        Args:
            name: 组件名称
            
        Returns:
            Optional[Any]: 组件实例，如果不存在返回None
        """
        with self.component_access_lock:
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

    def get_ebpf_monitor(self, selected_monitors=None):
        # type: (List[str]) -> 'eBPFMonitor'
        """
        获取eBPF监控器实例（缓存机制，避免重复创建）
        
        Args:
            selected_monitors: 选定的监控器列表
            
        Returns:
            eBPFMonitor: eBPF监控器实例
        """
        if 'ebpf_monitor' not in self.components:
            from ..ebpf_monitor import eBPFMonitor
            monitor = eBPFMonitor(context=self, selected_monitors=selected_monitors)
            self._register_component('ebpf_monitor', monitor)
            return monitor
        return self.components['ebpf_monitor']

    def _register_component(self, name, component):
        # type: (str, Any) -> None
        """
        注册组件到上下文 - 使用组件注册锁
        
        Args:
            name: 组件名称
            component: 组件实例
        """
        with self.component_registry_lock:
            self.components[name] = component
            self.logger.debug("注册组件: {}".format(name))

    def _unregister_component(self, name):
        # type: (str) -> bool
        """
        注销组件 - 使用组件注册锁
        
        Args:
            name: 组件名称
            
        Returns:
            bool: 是否成功注销
        """
        with self.component_registry_lock:
            if name in self.components:
                del self.components[name]
                self.logger.debug("注销组件: {}".format(name))
                return True
            return False

    def cleanup(self):
        # type: () -> None
        """清理上下文和所有注册的组件 - 使用组件注册锁"""
        with self.component_registry_lock:
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

    def get_status(self):
        # type: () -> Dict[str, Any]
        """
        获取上下文状态信息 - 使用组件访问锁
        
        Returns:
            Dict[str, Any]: 状态信息
        """
        with self.component_access_lock:
            return {
                'base_dir': str(self.base_dir),
                'registered_components': list(self.components.keys()),
                'config_file': self.config_manager.config_file,
                'log_level': logging.getLevelName(self.log_manager.level)
            }


if __name__ == "__main__":
    """测试应用上下文"""
    print("=== 应用上下文测试 ===")

    context = ApplicationContext()

    # 测试组件创建
    capability_checker = context.get_capability_checker()
    monitor_registry = context.get_monitor_registry()
    ebpf_monitor = context.get_ebpf_monitor()

    print("兼容性检查器: {}".format(capability_checker))
    print("监控器注册表: {}".format(monitor_registry))
    print("eBPF监控器: {}".format(ebpf_monitor))

    # 测试状态获取
    status = context.get_status()
    print("上下文状态: {}".format(status))

    # 清理
    context.cleanup()
    print("测试完成")
