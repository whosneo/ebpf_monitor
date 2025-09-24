#!/usr/bin/env python3
# encoding: utf-8
"""
应用上下文管理器

负责管理应用程序的核心组件依赖关系，替代单例模式。
提供依赖注入和组件生命周期管理功能。
"""

import logging
import threading
from typing import Dict, Any, Optional, List, TYPE_CHECKING

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

    def __init__(self, config_file: str = "config/monitor_config.yaml"):
        """
        初始化应用上下文
        
        Args:
            config_file: 配置文件路径
        """
        # 分层锁架构：替换单一全局锁为细粒度锁
        self.component_registry_lock = threading.RLock()  # 组件注册/注销锁
        self.component_access_lock = threading.RLock()  # 组件访问锁
        self.components: Dict[str, Any] = {}

        # 初始化核心组件（保留单例的组件）
        self.config_manager = ConfigManager(config_file)
        self.log_manager = LogManager()
        self.output_controller = OutputController()
        self.daemon_manager = DaemonManager()

        # 获取基础配置
        self.logger = self.log_manager.get_logger(self)
        self.base_dir = self.config_manager.get_base_dir()

        self.logger.info("应用上下文初始化完成")

    def get_logger(self, obj: Any = None) -> logging.Logger:
        """
        获取logger实例
        
        Args:
            obj: 对象，默认使用调用者类名
        
        Returns:
            logging.Logger: logger实例
        """
        return self.log_manager.get_logger(obj)

    def get_component(self, name: str) -> Optional[Any]:
        """
        获取注册的组件 - 使用组件访问锁
        
        Args:
            name: 组件名称
            
        Returns:
            Optional[Any]: 组件实例，如果不存在返回None
        """
        with self.component_access_lock:
            return self.components.get(name)

    def get_capability_checker(self) -> 'CapabilityChecker':
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

    def get_monitor_registry(self) -> 'MonitorRegistry':
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

    def get_ebpf_monitor(self, selected_monitors: List[str] = None) -> 'eBPFMonitor':
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

    def _register_component(self, name: str, component: Any) -> None:
        """
        注册组件到上下文 - 使用组件注册锁
        
        Args:
            name: 组件名称
            component: 组件实例
        """
        with self.component_registry_lock:
            self.components[name] = component
            self.logger.debug(f"注册组件: {name}")

    def _unregister_component(self, name: str) -> bool:
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
                self.logger.debug(f"注销组件: {name}")
                return True
            return False

    def cleanup(self) -> None:
        """清理上下文和所有注册的组件 - 使用组件注册锁"""
        with self.component_registry_lock:
            self.logger.info("开始清理应用上下文...")

            # 清理注册的组件
            for name, component in list(self.components.items()):
                if hasattr(component, 'cleanup'):
                    try:
                        component.cleanup()
                        self.logger.debug(f"清理组件: {name}")
                    except Exception as e:
                        self.logger.error(f"清理组件失败 {name}: {e}")

            self.components.clear()
            self.logger.info("应用上下文清理完成")

    def get_status(self) -> Dict[str, Any]:
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

    print(f"兼容性检查器: {capability_checker}")
    print(f"监控器注册表: {monitor_registry}")
    print(f"eBPF监控器: {ebpf_monitor}")

    # 测试状态获取
    status = context.get_status()
    print(f"上下文状态: {status}")

    # 清理
    context.cleanup()
    print("测试完成")
