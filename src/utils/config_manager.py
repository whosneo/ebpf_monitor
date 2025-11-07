#!/usr/bin/env python
# encoding: utf-8
"""
配置管理器

负责加载、验证和管理监控工具的配置信息。
默认先加载验证基础配置，监控器配置延迟加载。
"""

# 标准库导入
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

# 第三方库导入
import yaml

# 本地模块导入
from .configs import AppConfig, LogConfig, MonitorsConfig, OutputConfig, ValidatedConfig


class ConfigManager:
    """配置管理器"""

    def __init__(self, config_file="config/monitor_config.yaml"):
        # type: (str) -> None
        """
        初始化配置管理器

        Args:
            config_file: 配置文件路径
        """
        self._setup_config_manager(config_file)

    def _setup_config_manager(self, config_file):
        # type: (str) -> None
        """
        初始化配置管理器，加载配置文件

        Args:
            config_file: 配置文件路径
        """
        # 使用标准 logging 模块，避免循环依赖
        import logging
        self._logger = logging.getLogger('ConfigManager')

        # ebpf工具根目录
        self.base_dir = Path(__file__).parent.parent.parent.resolve()
        self.config_file = config_file

        # 加载配置文件
        self._load_config()

        # 解析、验证
        self._validate_config()

    def _load_config(self):
        """
        加载配置文件（带路径验证）

        Returns:
            bool: 加载是否成功
        """
        # 注意：此方法在logger初始化之前调用，因此使用sys.stdout/stderr输出
        config_path = self.base_dir / self.config_file

        # 验证配置文件路径
        if not self._validate_config_path(config_path):
            sys.stdout.write("配置文件路径验证失败，使用默认配置\n")
            self.config_data = self._get_default_config_data()
            return

        self.config_data = self._get_default_config_data()
        try:
            if config_path.exists():
                # 验证文件可读性
                if not config_path.is_file():
                    sys.stderr.write("配置路径不是文件: {}\n".format(config_path))
                    sys.stdout.write("使用默认配置\n")
                    return

                with open(str(config_path), "r") as f:
                    config_data = yaml.safe_load(f)
                    if config_data:
                        self.config_data = config_data
                    else:
                        sys.stdout.write("配置文件为空，使用默认配置\n")
            else:
                sys.stdout.write("配置文件不存在: {}，使用默认配置\n".format(config_path))
        except (OSError, IOError) as e:
            # Python 2.7 compatibility - PermissionError doesn't exist
            if hasattr(e, 'errno') and e.errno == 13:  # Permission denied
                sys.stderr.write("配置文件权限错误: {}。请检查文件权限\n".format(config_path))
            else:
                sys.stderr.write("读取配置文件失败: {}。错误: {}\n".format(config_path, e))
            raise
        except yaml.YAMLError as e:
            sys.stderr.write("配置文件YAML格式错误: {}。请检查语法\n".format(e))
            raise
        except Exception as e:
            sys.stderr.write("加载配置文件失败: {}。错误: {}\n".format(config_path, e))
            sys.stdout.write("使用默认配置\n")

    @staticmethod
    def _validate_config_path(config_path):
        # type: (Path) -> bool
        """
        验证配置文件路径的安全性
        
        Args:
            config_path: 配置文件路径
            
        Returns:
            bool: 路径是否有效
        """
        try:
            # 解析为绝对路径
            abs_path = config_path.resolve()

            # 检查路径是否包含可疑字符（路径遍历攻击）
            path_str = str(abs_path)
            if '..' in path_str or path_str.startswith('/etc') or path_str.startswith('/sys'):
                sys.stderr.write("配置文件路径不安全: {}\n".format(path_str))
                return False

            # 检查父目录是否存在
            if not abs_path.parent.exists():
                sys.stderr.write("配置文件所在目录不存在: {}\n".format(abs_path.parent))
                return False

            return True
        except Exception as e:
            sys.stderr.write("验证配置路径失败: {}\n".format(e))
            return False

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
