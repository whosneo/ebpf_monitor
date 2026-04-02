#!/usr/bin/env python
# encoding: utf-8
"""
监控配置类

将 MonitorsConfig 从 configs.py 中独立出来，解除 configs.py 对 monitors.base 的依赖，
避免循环导入风险。
"""

# 兼容性导入
try:
    from typing import Dict, Any, Type
except ImportError:
    from .py2_compat import Dict, Any, Type

from ..monitors.base import BaseMonitor
from .configs import ValidatedConfig


class MonitorsConfig(ValidatedConfig):
    """监控配置 - 完全动态化"""

    def __init__(self, **kwargs):
        """
        动态初始化监控器配置
        
        根据已注册的监控器自动创建配置属性
        """
        # 获取所有已注册的监控器
        discovered_monitors = self._get_registered_monitors()

        # 为每个监控器创建配置属性
        for monitor_type, monitor_class in discovered_monitors.items():
            # 获取监控器的默认配置
            default_config = monitor_class.get_default_config()

            # 如果用户提供了该监控器的配置，合并它
            user_config = kwargs.get(monitor_type, {})
            final_config = dict(default_config, **user_config)

            # 动态设置属性
            setattr(self, monitor_type, final_config)

        # 记录未知的用户配置（用于验证时警告）
        known_monitors = set(discovered_monitors.keys())
        self._unknown_configs = {k: v for k, v in kwargs.items() if k not in known_monitors}

    @classmethod
    def _get_registered_monitors(cls):
        # type: () -> Dict[str, Type[BaseMonitor]]
        """
        获取已注册的监控器
        
        Returns:
            Dict[str, Type]: 监控器名称到类的映射
        """
        from .decorators import MONITOR_REGISTRY
        return MONITOR_REGISTRY.copy()

    @classmethod
    def validate(cls, config):
        # type: (Dict[str, Any]) -> 'MonitorsConfig'
        """
        验证监控配置 - 动态验证所有监控器
        
        Args:
            config: 监控配置字典
            
        Returns:
            MonitorsConfig: 验证后的配置对象
            
        Raises:
            ValueError: 配置验证失败时抛出
        """
        if config is None:
            raise ValueError("监控配置不能为空。请在配置文件中添加'monitors'节")
        if not isinstance(config, dict):
            raise ValueError("监控配置必须为字典类型，当前类型: {}。请检查YAML格式".format(type(config).__name__))
        if len(config) == 0:
            raise ValueError("监控配置不能为空字典。请至少配置一个监控器（如exec、syscall等）")

        # 第1步：创建MonitorsConfig对象（会自动发现和合并配置）
        try:
            monitors_config = cls(**config)
        except Exception as e:
            raise ValueError("创建监控配置失败: {}".format(e))

        # 第2步：验证每个监控器的配置
        discovered_monitors = cls._get_registered_monitors()

        for monitor_type, monitor_class in discovered_monitors.items():
            if hasattr(monitors_config, monitor_type):
                monitor_config = getattr(monitors_config, monitor_type)
                # 调用监控器的验证方法
                monitor_class.validate_config(monitor_config)

        # 第3步：对未知配置发出警告
        for unknown_name in monitors_config._unknown_configs:
            raise ValueError("未知的监控器配置: {}，请检查监控器名称或确认监控器已正确注册".format(unknown_name))

        return monitors_config
