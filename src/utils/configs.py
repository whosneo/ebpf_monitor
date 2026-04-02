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

from .config_validator import ConfigValidator


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

        ConfigValidator.validate_required(config, ["name", "version", "environment"])
        ConfigValidator.validate_string(config.get("environment"), "environment",
                                        allowed_values=["development", "production"])

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

        ConfigValidator.validate_required(config, ["version", "level", "formatters", "handlers"])

        if config.get("version") != 1:
            raise ValueError("日志版本必须为 1，当前值: {}".format(config.get("version")))

        ConfigValidator.validate_string(config.get("level"), "level",
                                        allowed_values=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
        ConfigValidator.validate_dict(config.get("formatters"), "formatters")
        ConfigValidator.validate_dict(config.get("handlers"), "handlers")

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

        ConfigValidator.validate_required(config, [
            "buffer_size", "batch_size", "large_batch_threshold",
            "flush_interval", "output_thread_sleep", "csv_delimiter"
        ])

        ConfigValidator.validate_int(config.get("buffer_size"), "buffer_size", min_val=1)
        ConfigValidator.validate_int(config.get("batch_size"), "batch_size", min_val=1)
        ConfigValidator.validate_int(config.get("large_batch_threshold"), "large_batch_threshold", min_val=1)
        ConfigValidator.validate_float(config.get("flush_interval"), "flush_interval", min_val=0.001)
        ConfigValidator.validate_float(config.get("output_thread_sleep"), "output_thread_sleep", min_val=0.001)

        csv_delimiter = config.get("csv_delimiter")
        if len(csv_delimiter) != 1:
            raise ValueError(
                "csv_delimiter 必须为单字符，当前长度: {}。示例: ',' 或 '\\t'".format(len(csv_delimiter)))

        # 创建配置对象
        try:
            output_config = cls(**config)
        except TypeError as e:
            raise ValueError("输出配置中存在无效的配置项: {}".format(e))

        return output_config
