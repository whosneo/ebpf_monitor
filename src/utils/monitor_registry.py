#!/usr/bin/env python3
# encoding: utf-8
"""
监控器注册管理器

专门负责监控器的发现、注册和管理，实现单一职责原则。
与配置系统解耦，避免循环依赖。
"""

import importlib
from typing import Dict, Type, List

from typing import TYPE_CHECKING

from ..monitors.base import BaseMonitor

if TYPE_CHECKING:
    # noinspection PyUnusedImports
    from .application_context import ApplicationContext


class MonitorRegistry:
    """
    监控器注册管理器
    
    负责监控器的自动发现和注册管理。
    不再使用单例模式，通过依赖注入获取所需组件。
    """

    def __init__(self, context: 'ApplicationContext'):
        """
        初始化注册管理器
        
        Args:
            context: 应用上下文，提供所需的依赖组件
        """
        self.context = context
        self.logger = context.get_logger(self)
        self.monitors_dir = context.config_manager.get_monitors_dir()

        self._auto_discover_monitors()

    def _auto_discover_monitors(self):
        """
        自动发现并导入所有监控器模块
        
        扫描 monitors 目录下所有非 '_' 开头的文件，
        自动导入以触发装饰器注册。
        """
        try:
            # 扫描监控器模块文件
            monitor_files = list(self.monitors_dir.glob("*.py"))
            # 过滤掉 base.py（基类，不是具体监控器）和下划线开头的文件
            monitor_files = [f for f in monitor_files if f.name != "base.py" and not f.name.startswith("_")]

            self.logger.debug(f"发现 {len(monitor_files)} 个监控器模块文件")

            for monitor_file in monitor_files:
                module_name = monitor_file.stem  # 去掉 .py 后缀

                try:
                    # 动态导入模块，触发 @register_monitor 装饰器执行
                    module_path = f"src.monitors.{module_name}"
                    importlib.import_module(module_path)
                    self.logger.debug(f"成功导入监控器模块: {module_name}")
                except ImportError as e:
                    self.logger.warning(f"导入监控器模块失败 {module_name}: {e}")
                except Exception as e:
                    self.logger.error(f"导入监控器模块时发生错误 {module_name}: {e}")

            from .decorators import MONITOR_REGISTRY
            self.logger.info(f"自动发现完成，注册了 {len(MONITOR_REGISTRY)} 个监控器")

        except Exception as e:
            self.logger.error(f"自动发现监控器失败: {e}")

    @staticmethod
    def get_registered_monitors() -> Dict[str, Type[BaseMonitor]]:
        """
        获取已注册的监控器
        
        Returns:
            Dict[str, Type]: 监控器名称到类的映射
        """
        from .decorators import MONITOR_REGISTRY
        return MONITOR_REGISTRY.copy()

    def get_monitor_names(self) -> List[str]:
        """
        获取所有已注册的监控器名称
        
        Returns:
            List[str]: 监控器名称列表
        """
        return list(self.get_registered_monitors().keys())

    def is_monitor_registered(self, monitor_name: str) -> bool:
        """
        检查监控器是否已注册
        
        Args:
            monitor_name: 监控器名称
            
        Returns:
            bool: 是否已注册
        """
        return monitor_name in self.get_registered_monitors()

    def get_monitor_class(self, monitor_name: str) -> Type:
        """
        获取指定监控器的类
        
        Args:
            monitor_name: 监控器名称
            
        Returns:
            Type: 监控器类
            
        Raises:
            KeyError: 监控器未注册时
        """
        registered_monitors = self.get_registered_monitors()
        if monitor_name not in registered_monitors:
            raise KeyError(f"监控器 '{monitor_name}' 未注册")
        return registered_monitors[monitor_name]

    def get_statistics(self) -> Dict[str, any]:
        """
        获取注册统计信息
        
        Returns:
            Dict[str, any]: 统计信息
        """
        monitors = self.get_registered_monitors()
        return {
            "total_registered": len(monitors),
            "monitor_names": list(monitors.keys())
        }


if __name__ == "__main__":
    """测试模式"""
    from .application_context import ApplicationContext
    print("=== 监控器注册管理器测试 ===")

    test_context = ApplicationContext()
    test_registry = test_context.get_monitor_registry()

    # 发现并注册监控器
    test_monitors = test_registry.get_registered_monitors()
    print(f"发现的监控器: {list(test_monitors.keys())}")

    # 获取统计信息
    test_stats = test_registry.get_statistics()
    print(f"统计信息: {test_stats}")
