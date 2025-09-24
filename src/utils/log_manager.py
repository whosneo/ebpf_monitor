#!/usr/bin/env python3
# encoding: utf-8
"""
日志管理器

负责管理日志记录器和日志输出配置，确保日志记录的正确性和一致性。
"""

import logging
import logging.config
import sys
import threading
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict

from .config_manager import ConfigManager
from .configs import LogConfig

LEVEL_MAP = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARN": logging.WARNING,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "FATAL": logging.CRITICAL,
    "CRITICAL": logging.CRITICAL,
}


class LogManager:
    """日志管理类，负责初始化日志系统、管理上下文和提供 logger"""

    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        """实现单例模式，确保全局唯一的 LogManager 实例"""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super(LogManager, cls).__new__(cls)
        return cls._instance

    def __init__(self, log_dir: str = "logs"):
        """初始化 LogManager"""
        if not hasattr(self, "_initialized"):  # 防止重复初始化
            self._initialized = False
            self._setup_log_manager(log_dir)
            self._initialized = True

    def _setup_log_manager(self, log_dir: str):
        """
        初始化日志系统，从配置中加载日志设置。
        """
        # 初始化日志记录器Map
        self.loggers: Dict[str, logging.Logger] = {}

        self.config_manager = ConfigManager()

        if Path(log_dir).is_absolute():
            self.log_dir = Path(log_dir)
        else:
            self.log_dir = self.config_manager.get_base_dir() / log_dir

        self.namespace = self.config_manager.get_app_name()
        self._apply_config(self.config_manager.get_log_config())

        self.logger = self.get_logger(self)
        self.logger.info("日志管理器初始化完成")

    def _apply_config(self, config: LogConfig):
        """应用配置"""
        log_config = asdict(config)

        self.level = LEVEL_MAP.get(config.level.upper(), logging.INFO)

        # 调整文件处理器中的路径
        for handler in log_config["handlers"].values():
            if handler.get("class") == "logging.handlers.TimedRotatingFileHandler":
                if "filename" in handler:
                    handler["filename"] = self.log_dir / handler["filename"]
            handler["formatter"] = "detailed" if self.level <= logging.DEBUG else "simple"

        # 确保配置中包含loggers部分
        if not log_config.get("loggers"):
            log_config["loggers"] = {}

        # 为应用命名空间配置logger
        log_config["loggers"][self.namespace] = {
            "level": config.level.upper(),
            "handlers": list(log_config["handlers"].keys()),
            "propagate": False
        }

        # 配置根logger使用相同的handlers
        if not log_config.get("root"):
            log_config["root"] = {
                "level": config.level.upper(),
                "handlers": list(log_config["handlers"].keys())
            }

        # 应用日志配置
        logging.config.dictConfig(log_config)

    def get_logger(self, obj: Any = None):
        """获取指定名称的logger或者根据对象获取logger"""
        if isinstance(obj, str):
            name = obj
        elif obj:
            name = obj.__class__.__name__
        else:
            name = self.namespace

        if obj != self:
            self.logger.debug(f"获取logger: {name}")

        if name not in self.loggers:
            new_logger = logging.getLogger(name)
            new_logger.setLevel(self.level)

            # 检查logger是否正确配置，避免在logger上调用warning造成循环
            if not self._initialized and not new_logger.handlers and not new_logger.parent.handlers:
                # 使用标准错误输出而不是logger本身来输出警告
                print(f"警告: Logger \"{name}\" 未配置handlers。"
                      f"日志配置可能存在问题。", file=sys.stderr)

            self.loggers[name] = new_logger

        return self.loggers[name]

    def set_level(self, level):
        """设置日志级别"""
        self.logger.debug(f"设置日志级别为: {level}")
        self.level = level
        logging.getLogger().setLevel(level)
        logging.getLogger(self.namespace).setLevel(level)
        for logger in self.loggers.values():
            logger.setLevel(level)
        self.logger.debug(f"设置日志级别完成")

    def get_log_file_path(self):
        """
        获取当前日志文件的路径
        
        从已配置的logging系统中获取文件处理器的实际文件路径。
        
        Returns:
            Path: 日志文件的完整路径
        """
        try:
            # 从已配置的logging系统中获取文件处理器
            from pathlib import Path

            # 检查根logger的handlers
            root_logger = logging.getLogger()
            for handler in root_logger.handlers:
                if isinstance(handler, logging.handlers.TimedRotatingFileHandler):
                    if hasattr(handler, 'baseFilename'):
                        return Path(handler.baseFilename)

            # 检查应用命名空间logger的handlers
            app_logger = logging.getLogger(self.namespace)
            for handler in app_logger.handlers:
                if isinstance(handler, logging.handlers.TimedRotatingFileHandler):
                    if hasattr(handler, 'baseFilename'):
                        return Path(handler.baseFilename)

        except Exception:
            pass

        # 如果无法从logging系统获取，回退到配置文件方式
        try:
            log_config = self.config_manager.get_log_config()
            filename = log_config.handlers.get("file", {}).get("filename", "monitor.log")
            return self.log_dir / filename
        except Exception:
            # 最终回退到默认路径
            return self.log_dir / "monitor.log"


if __name__ == "__main__":
    """测试函数"""
    config_manager = ConfigManager()
    log_manager = LogManager()

    logger = log_manager.get_logger()
    logger.debug("This is a debug message")
    logger.info("This is an info message")
    logger.warning("This is a warning message")
    logger.error("This is an error message")

    test_logger = log_manager.get_logger("test_logger")
    test_logger.debug("This is a debug message")
    test_logger.info("This is an info message")
    test_logger.warning("This is a warning message")
    test_logger.error("This is an error message")

    log_manager.set_level(logging.WARNING)
    logger.debug("This is a debug message")
    logger.info("This is an info message")
    logger.warning("This is a warning message")
    logger.error("This is an error message")
    test_logger.debug("This is a debug message")
    test_logger.info("This is an info message")
    test_logger.warning("This is a warning message")
    test_logger.error("This is an error message")
