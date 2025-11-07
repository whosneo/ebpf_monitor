#!/usr/bin/env python
# encoding: utf-8
"""
配置类定义

统一定义所有配置类，提供硬编码的默认值作为兜底配置。
包含应用、日志、监控、输出、数据收集等各个模块的配置。
每个配置类都包含自己的验证逻辑。
"""

from abc import abstractmethod

try:
    from abc import ABC
except ImportError:
    from ..utils.py2_compat import ABC
# 兼容性导入
try:
    from typing import Dict, Any, Type
except ImportError:
    from ..utils.py2_compat import Dict, Any, Type

from ..monitors.base import BaseMonitor


class ValidatedConfig(ABC):
    """可验证配置的基类"""

    @classmethod
    @abstractmethod
    def validate(cls, config):
        # type: (Dict[str, Any]) -> 'ValidatedConfig'
        """验证配置 - 子类需要实现"""
        # noinspection PyAbstractClass
        return ValidatedConfig()


class AppConfig(ValidatedConfig):
    """应用配置"""

    def __init__(self, name="ebpf_monitor", version="1.0.0",
                 description="eBPF Monitor for Linux", author="bwyu",
                 email="bwyu@czce.com.cn",
                 url="https://github.com/whosneo/ebpf_monitor",
                 environment="production", debug=False, **kwargs):
        self.name = name
        self.version = version
        self.description = description
        self.author = author
        self.email = email
        self.url = url
        self.environment = environment
        self.debug = debug
        # 处理额外的关键字参数
        for key, value in kwargs.items():
            setattr(self, key, value)

    @classmethod
    def validate(cls, config):
        # type: (Dict[str, Any]) -> 'AppConfig'
        """
        验证应用配置
        
        Args:
            config: 应用配置字典
            
        Returns:
            AppConfig: 验证后的配置对象
            
        Raises:
            ValueError: 配置验证失败时抛出
        """
        if config is None:
            raise ValueError("应用配置不能为空。请在配置文件中添加'app'节")
        if not isinstance(config, dict):
            raise ValueError("应用配置必须为字典类型，当前类型: {}。请检查YAML格式".format(type(config).__name__))
        if len(config) == 0:
            raise ValueError("应用配置不能为空字典。请至少提供name、version和environment字段")
        if config.get("name") is None:
            raise ValueError("应用配置中缺少必需字段: name。示例: name: ebpf_monitor")
        if config.get("version") is None:
            raise ValueError("应用配置中缺少必需字段: version。示例: version: 1.0.0")
        if config.get("environment") is None:
            raise ValueError("应用配置中缺少必需字段: environment。示例: environment: production")
        if config.get("environment") not in ["development", "production"]:
            raise ValueError(
                "environment 必须是 'development' 或 'production'，当前值: '{}'".format(config.get("environment")))

        # 创建配置对象
        try:
            app_config = cls(**config)
        except TypeError as e:
            raise ValueError("应用配置中存在无效的配置项: {}".format(e))

        return app_config


class LogConfig(ValidatedConfig):
    """日志配置"""

    def __init__(self, version=1, level="INFO", formatters=None, handlers=None, loggers=None, **kwargs):
        self.version = version
        self.level = level

        # 默认格式化器
        if formatters is None:
            formatters = {
                "detailed": {"format": "%(asctime)s [%(levelname)s] %(name)s:%(lineno)d %(message)s"},
                "simple": {"format": "%(levelname)s: %(message)s"}
            }
        self.formatters = formatters

        # 默认处理器
        if handlers is None:
            handlers = {
                "console": {"class": "logging.StreamHandler", "formatter": "simple", "stream": "ext://sys.stdout"},
                "file": {"class": "logging.handlers.TimedRotatingFileHandler", "formatter": "detailed",
                         "filename": "monitor.log", "when": "D", "interval": 1, "backupCount": 365}
            }
        self.handlers = handlers

        # 默认日志记录器
        if loggers is None:
            loggers = {}
        self.loggers = loggers

        # 处理额外的关键字参数
        for key, value in kwargs.items():
            setattr(self, key, value)

    @classmethod
    def validate(cls, config):
        # type: (Dict[str, Any]) -> 'LogConfig'
        """
        验证日志配置
        
        Args:
            config: 日志配置字典
            
        Returns:
            LogConfig: 验证后的配置对象
            
        Raises:
            ValueError: 配置验证失败时抛出
        """
        if config is None:
            raise ValueError("日志配置不能为空")
        if not isinstance(config, dict):
            raise ValueError("日志配置必须为字典，当前类型: {}".format(type(config).__name__))
        if len(config) == 0:
            raise ValueError("日志配置不能为空字典")
        if config.get("version") is None:
            raise ValueError("日志配置中缺少必需字段: version")
        if config.get("version") != 1:
            raise ValueError("日志版本必须为 1，当前值: {}".format(config.get("version")))
        if config.get("level") is None:
            raise ValueError("日志配置中缺少必需字段: level")

        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if config.get("level") not in valid_levels:
            raise ValueError("日志级别必须是 {} 之一，当前值: {}".format(
                ", ".join(valid_levels), config.get("level")))

        if config.get("formatters") is None:
            raise ValueError("日志配置中缺少必需字段: formatters")
        if not isinstance(config.get("formatters"), dict):
            raise ValueError("formatters 必须为字典，当前类型: {}".format(type(config.get("formatters")).__name__))
        if config.get("handlers") is None:
            raise ValueError("日志配置中缺少必需字段: handlers")
        if not isinstance(config.get("handlers"), dict):
            raise ValueError("handlers 必须为字典，当前类型: {}".format(type(config.get("handlers")).__name__))

        # 创建配置对象
        try:
            log_config = cls(**config)
        except TypeError as e:
            raise ValueError("日志配置中存在无效的配置项: {}".format(e))

        return log_config


class OutputConfig(ValidatedConfig):
    """输出控制器配置"""

    def __init__(self, buffer_size=5000, batch_size=1000, large_batch_threshold=500, flush_interval=2.0, output_thread_sleep=0.1, csv_delimiter=",", include_header=True, **kwargs):
        self.buffer_size = buffer_size
        self.batch_size = batch_size
        self.large_batch_threshold = large_batch_threshold
        self.flush_interval = flush_interval
        self.output_thread_sleep = output_thread_sleep
        self.csv_delimiter = csv_delimiter
        self.include_header = include_header

        # 处理额外的关键字参数
        for key, value in kwargs.items():
            setattr(self, key, value)

    @classmethod
    def validate(cls, config):
        # type: (Dict[str, Any]) -> 'OutputConfig'
        """
        验证输出配置
        
        Args:
            config: 输出配置字典
            
        Returns:
            OutputConfig: 验证后的配置对象
            
        Raises:
            ValueError: 配置验证失败时抛出
        """
        if config is None:
            raise ValueError("输出配置不能为空。请在配置文件中添加'output'节")
        if not isinstance(config, dict):
            raise ValueError("输出配置必须为字典类型，当前类型: {}。请检查YAML格式".format(type(config).__name__))
        if len(config) == 0:
            raise ValueError("输出配置不能为空字典。请至少提供buffer_size、flush_interval和csv_delimiter字段")
        if config.get("buffer_size") is None:
            raise ValueError("输出配置中缺少必需字段: buffer_size。示例: buffer_size: 2000")
        if not isinstance(config.get("buffer_size"), int):
            raise ValueError("buffer_size 必须为整数类型，当前类型: {}。示例: buffer_size: 2000".format(
                type(config.get("buffer_size")).__name__))
        if config.get("buffer_size") <= 0:
            raise ValueError("buffer_size 必须大于 0，当前值: {}。建议值: 1000-5000".format(config.get("buffer_size")))
        if config.get("batch_size") is None:
            raise ValueError("输出配置中缺少必需字段: batch_size。示例: batch_size: 1000")
        if not isinstance(config.get("batch_size"), int):
            raise ValueError("batch_size 必须为整数类型，当前类型: {}。示例: batch_size: 1000".format(
                type(config.get("batch_size")).__name__))
        if config.get("batch_size") <= 0:
            raise ValueError("batch_size 必须大于 0，当前值: {}。建议值: 500-2000".format(
                config.get("batch_size")))
        if config.get("large_batch_threshold") is None:
            raise ValueError("输出配置中缺少必需字段: large_batch_threshold。示例: large_batch_threshold: 500")
        if not isinstance(config.get("large_batch_threshold"), int):
            raise ValueError("large_batch_threshold 必须为整数类型，当前类型: {}。示例: large_batch_threshold: 500".format(
                type(config.get("large_batch_threshold")).__name__))
        if config.get("large_batch_threshold") <= 0:
            raise ValueError("large_batch_threshold 必须大于 0，当前值: {}。建议值: 10-50".format(
                config.get("large_batch_threshold")))
        if config.get("flush_interval") is None:
            raise ValueError("输出配置中缺少必需字段: flush_interval。示例: flush_interval: 2.0")
        if not isinstance(config.get("flush_interval"), (int, float)):
            raise ValueError("flush_interval 必须为数字类型，当前类型: {}。示例: flush_interval: 2.0".format(
                type(config.get("flush_interval")).__name__))
        if config.get("flush_interval") <= 0:
            raise ValueError(
                "flush_interval 必须大于 0，当前值: {}。建议值: 1.0-10.0秒".format(config.get("flush_interval")))
        if config.get("output_thread_sleep") is None:
            raise ValueError("输出配置中缺少必需字段: output_thread_sleep。示例: output_thread_sleep: 0.1")
        if not isinstance(config.get("output_thread_sleep"), (int, float)):
            raise ValueError("output_thread_sleep 必须为数字类型，当前类型: {}。示例: output_thread_sleep: 0.1".format(
                type(config.get("output_thread_sleep")).__name__))
        if config.get("output_thread_sleep") <= 0:
            raise ValueError("output_thread_sleep 必须大于 0，当前值: {}。建议值: 0.1-1.0秒".format(
                config.get("output_thread_sleep")))
        if config.get("csv_delimiter") is None:
            raise ValueError("输出配置中缺少必需字段: csv_delimiter。示例: csv_delimiter: ','")
        if len(config.get("csv_delimiter")) != 1:
            raise ValueError(
                "csv_delimiter 必须为单字符，当前长度: {}。示例: ',' 或 '\\t'".format(len(config.get("csv_delimiter"))))

        # 创建配置对象
        try:
            output_config = cls(**config)
        except TypeError as e:
            raise ValueError("输出配置中存在无效的配置项: {}".format(e))

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
