#!/usr/bin/env python
# encoding: utf-8
"""
配置管理器

负责加载、验证和管理监控工具的配置信息。
默认先加载验证基础配置，监控器配置延迟加载。
"""

import sys
import threading
# 兼容性导入
try:
    from typing import Dict
except ImportError:
    from .py2_compat import Dict

try:
    from pathlib import Path
except ImportError:
    from .py2_compat import Path

import yaml

# 导入统一的配置类
from .configs import AppConfig, LogConfig, MonitorsConfig, OutputConfig, ValidatedConfig


class ConfigManager:
    """配置管理器"""

    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        """实现单例模式，确保全局唯一的 ConfigManager 实例"""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super(ConfigManager, cls).__new__(cls)
        return cls._instance

    def __init__(self, config_file="config/monitor_config.yaml"):
        # type: (str) -> None
        """
        初始化配置管理器

        Args:
            config_file: 配置文件路径
        """
        # 首先初始化配置管理器，再初始化日志管理器，所以在初始化过程中只能使用print
        if not hasattr(self, "_initialized"):  # 防止重复初始化
            self._initialized = False
            self._setup_config_manager(config_file)
            self._initialized = True

    def _setup_config_manager(self, config_file):
        # type: (str) -> None
        """
        初始化配置管理器，加载配置文件

        Args:
            config_file: 配置文件路径
        """
        # 延迟初始化日志管理器以避免循环导入
        self.logger = None
        self.log_manager = None

        # ebpf工具根目录
        self.base_dir = Path(__file__).parent.parent.parent.resolve()
        self.config_file = config_file

        # 加载配置文件
        self._load_config()

        # 解析、验证
        self._validate_config()

    def _load_config(self):
        """
        加载配置文件

        Returns:
            bool: 加载是否成功
        """
        config_path = self.base_dir / self.config_file
        self.config_data = self._get_default_config_data()
        try:
            if config_path.exists():
                with open(str(config_path), "r") as f:
                    config_data = yaml.safe_load(f)
                    if config_data:
                        self.config_data = config_data
                    else:
                        sys.stdout.write("配置文件为空，使用默认配置\n")
            else:
                sys.stdout.write("配置文件不存在，使用默认配置\n")
        except (OSError, IOError) as e:
            # Python 2.7 compatibility - PermissionError doesn't exist
            if hasattr(e, 'errno') and e.errno == 13:  # Permission denied
                sys.stderr.write("配置文件权限错误: {}\n".format(config_path))
            raise
        except yaml.YAMLError as e:
            sys.stderr.write("配置文件格式错误: {}\n".format(e))
            raise
        except Exception as e:
            sys.stderr.write("加载配置文件失败: {}\n".format(e))
            sys.stdout.write("加载配置文件失败，使用默认配置\n")

    @staticmethod
    def _get_default_config_data():
        # type: () -> Dict[str, Dict]
        """加载默认配置"""
        def _obj_to_dict(obj):
            """将对象转换为字典"""
            result = {}
            for key, value in obj.__dict__.items():
                if not key.startswith('_'):
                    result[key] = value
            return result
            
        return {
            "app": _obj_to_dict(AppConfig()),
            "logging": _obj_to_dict(LogConfig()),
            "output": _obj_to_dict(OutputConfig()),
            "monitors": {}  # 延迟初始化监控配置
        }

    def _validate_config(self):
        """验证配置"""
        app_config = self.config_data.get("app", {})
        log_config = self.config_data.get("logging", {})
        output_config = self.config_data.get("output", {})

        self.app_config = AppConfig.validate(app_config)
        self.log_config = LogConfig.validate(log_config)
        self.output_config = OutputConfig.validate(output_config)
        self.monitors_config = None  # 延迟初始化监控配置

    def _get_logger(self):
        """延迟初始化并获取logger"""
        if self.logger is None:
            from .log_manager import LogManager
            self.log_manager = LogManager()
            self.logger = self.log_manager.get_logger(self)
        return self.logger

    def parse_validate_monitors_config(self):
        """解析并验证监控配置"""
        monitors_config = self.config_data.get("monitors", {})
        self.monitors_config = MonitorsConfig.validate(monitors_config)

    def get_base_dir(self):
        # type: () -> Path
        """获取工具根目录"""
        return self.base_dir

    def get_monitors_dir(self):
        # type: () -> Path
        """获取监控器目录"""
        return self.base_dir / "src" / "monitors"

    def get_ebpf_dir(self):
        # type: () -> Path
        """获取eBPF目录"""
        return self.base_dir / "src" / "ebpf"

    def get_app_name(self):
        # type: () -> str
        """获取应用名称"""
        return self.app_config.name

    def get_config(self):
        # type: () -> Dict[str, ValidatedConfig]
        """
        获取完整配置

        Returns:
            dict: 完整配置数据
        """
        return {
            "app": self.app_config,
            "logging": self.log_config,
            "output": self.output_config,
            "monitors": self.monitors_config
        }

    def get_app_config(self):
        # type: () -> AppConfig
        """获取应用配置"""
        return self.app_config

    def get_log_config(self):
        # type: () -> LogConfig
        """获取日志配置"""
        return self.log_config

    def get_output_config(self):
        # type: () -> OutputConfig
        """获取输出配置"""
        return self.output_config

    def get_monitors_config(self):
        # type: () -> MonitorsConfig
        """获取监控配置"""
        return self.monitors_config


if __name__ == "__main__":
    """测试函数"""
    # 测试配置管理器
    from .log_manager import LogManager

    config_manager = ConfigManager()

    log_manager = LogManager()
    logger = log_manager.get_logger()

    logger.info("=== 配置管理器测试 ===")

    # 显示配置
    logger.info("配置文件: {}".format(config_manager.config_file))
    logger.info("应用配置: {}".format(config_manager.get_app_config()))
    logger.info("日志配置: {}".format(config_manager.get_log_config()))
    logger.info("输出配置: {}".format(config_manager.get_output_config()))
    logger.info("监控配置: {}".format(config_manager.get_monitors_config()))
