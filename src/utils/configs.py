#!/usr/bin/env python3
# encoding: utf-8
"""
配置类定义

统一定义所有配置类，提供硬编码的默认值作为兜底配置。
包含应用、日志、监控、输出、数据收集等各个模块的配置。
每个配置类都包含自己的验证逻辑。
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Any, Type

from ..monitors.base import BaseMonitor


class ValidatedConfig(ABC):
    """可验证配置的基类"""

    @classmethod
    @abstractmethod
    def validate(cls, config: Dict[str, Any]) -> 'ValidatedConfig':
        """验证配置 - 子类需要实现"""
        # noinspection PyAbstractClass
        return ValidatedConfig()


@dataclass
class AppConfig(ValidatedConfig):
    """应用配置"""
    name: str = "ebpf_monitor"
    version: str = "1.0.0"
    description: str = "eBPF Monitor for Linux"
    author: str = "bwyu"
    email: str = "bwyu@czce.com.cn"
    url: str = "https://github.com/whosneo/ebpf_monitor"
    environment: str = "production"
    debug: bool = False

    @classmethod
    def validate(cls, config: Dict[str, Any]) -> 'AppConfig':
        """验证应用配置"""
        assert config is not None, "应用配置不能为空"
        assert isinstance(config, dict), "应用配置必须为字典"
        assert len(config) > 0, "应用配置不能为空"
        assert config.get("name") is not None, "应用名称不能为空"
        assert config.get("version") is not None, "版本号不能为空"
        assert config.get("environment") is not None, "环境不能为空"
        assert config.get("environment") in ["development", "production"], "环境必须是development或production"

        # 创建配置对象
        try:
            app_config = cls(**config)
        except TypeError as e:
            raise ValueError(f"应用配置中存在无效的配置项: {e}")

        return app_config


@dataclass
class LogConfig(ValidatedConfig):
    """日志配置"""
    version: int = 1
    level: str = "INFO"
    formatters: Dict[str, Dict[str, Any]] = field(default_factory=lambda: {
        "detailed": {"format": "%(asctime)s [%(levelname)s] %(name)s:%(lineno)d %(message)s"},
        "simple": {"format": "%(levelname)s: %(message)s"}
    })
    handlers: Dict[str, Dict[str, Any]] = field(default_factory=lambda: {
        "console": {"class": "logging.StreamHandler", "formatter": "simple", "stream": "ext://sys.stdout"},
        "file": {"class": "logging.handlers.TimedRotatingFileHandler", "formatter": "detailed",
                 "filename": "monitor.log", "when": "D", "interval": 1, "backupCount": 365}
    })
    loggers: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    @classmethod
    def validate(cls, config: Dict[str, Any]) -> 'LogConfig':
        """验证日志配置"""
        assert config is not None, "日志配置不能为空"
        assert isinstance(config, dict), "日志配置必须为字典"
        assert len(config) > 0, "日志配置不能为空"
        assert config.get("version") is not None, "日志版本不能为空"
        assert config.get("version") == 1, "日志版本必须为1"
        assert config.get("level") is not None, "日志级别不能为空"
        assert config.get("level") in ["DEBUG", "INFO", "WARNING", "ERROR",
                                       "CRITICAL"], "日志级别必须是DEBUG, INFO, WARNING, ERROR, CRITICAL之一"
        assert config.get("formatters") is not None, "日志格式器不能为空"
        assert isinstance(config.get("formatters"), dict), "日志格式器必须为字典"
        assert config.get("handlers") is not None, "日志处理器不能为空"
        assert isinstance(config.get("handlers"), dict), "日志处理器必须为字典"

        # 创建配置对象
        try:
            log_config = cls(**config)
        except TypeError as e:
            raise ValueError(f"日志配置中存在无效的配置项: {e}")

        return log_config


@dataclass
class OutputConfig(ValidatedConfig):
    """输出控制器配置"""
    buffer_size: int = 2000
    flush_interval: float = 2.0  # 秒
    csv_delimiter: str = ","
    include_header: bool = True

    @classmethod
    def validate(cls, config: Dict[str, Any]) -> 'OutputConfig':
        """验证输出配置"""
        assert config is not None, "输出配置不能为空"
        assert isinstance(config, dict), "输出配置必须为字典"
        assert len(config) > 0, "输出配置不能为空"
        assert config.get("buffer_size") is not None, "缓冲区大小不能为空"
        assert isinstance(config.get("buffer_size"), int), "缓冲区大小必须为整数"
        assert config.get("buffer_size") > 0, "缓冲区大小必须大于0"
        assert config.get("flush_interval") is not None, "刷新间隔不能为空"
        assert isinstance(config.get("flush_interval"), float), "刷新间隔必须为浮点数"
        assert config.get("flush_interval") > 0, "刷新间隔必须大于0"
        assert config.get("csv_delimiter") is not None, "CSV分隔符不能为空"
        assert len(config.get("csv_delimiter")) == 1, "CSV分隔符必须为单字符"

        # 创建配置对象
        try:
            output_config = cls(**config)
        except TypeError as e:
            raise ValueError(f"输出配置中存在无效的配置项: {e}")

        return output_config


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
            final_config = {**default_config, **user_config}

            # 动态设置属性
            setattr(self, monitor_type, final_config)

        # 记录未知的用户配置（用于验证时警告）
        known_monitors = set(discovered_monitors.keys())
        self._unknown_configs = {k: v for k, v in kwargs.items() if k not in known_monitors}

    @classmethod
    def _get_registered_monitors(cls) -> Dict[str, Type[BaseMonitor]]:
        """
        获取已注册的监控器
        
        Returns:
            Dict[str, Type]: 监控器名称到类的映射
        """
        from .decorators import MONITOR_REGISTRY
        return MONITOR_REGISTRY.copy()

    @classmethod
    def validate(cls, config: Dict[str, Any]) -> 'MonitorsConfig':
        """验证监控配置 - 动态验证所有监控器"""
        assert config is not None, "监控配置不能为空"
        assert isinstance(config, dict), "监控配置必须为字典"
        assert len(config) > 0, "监控配置不能为空"

        # 第1步：创建MonitorsConfig对象（会自动发现和合并配置）
        try:
            monitors_config = cls(**config)
        except Exception as e:
            raise ValueError(f"创建监控配置失败: {e}")

        # 第2步：验证每个监控器的配置
        discovered_monitors = cls._get_registered_monitors()

        for monitor_type, monitor_class in discovered_monitors.items():
            if hasattr(monitors_config, monitor_type):
                monitor_config = getattr(monitors_config, monitor_type)
                # 调用监控器的验证方法
                monitor_class.validate_config(monitor_config)

        # 第3步：对未知配置发出警告
        for unknown_name in monitors_config._unknown_configs:
            raise ValueError(f"未知的监控器配置: {unknown_name}",
                             "请检查监控器名称或确认监控器已正确注册")

        return monitors_config
