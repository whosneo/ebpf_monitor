#!/usr/bin/env python
# encoding: utf-8
"""
eBPF性能监控工具 - 主程序入口

集成所有监控模块，提供完整的系统性能监控解决方案。
支持内存、中断、系统调用、IO等多维度监控。

使用方法:
    python3 main.py [options]

示例:
    python3 main.py -c config/monitor_config.yaml
    python3 main.py --verbose
"""

# 标准库导入
import argparse
import logging
import os
import sys
import time

# 兼容性导入
try:
    from pathlib import Path
except ImportError:
    from src.utils.py2_compat import Path
try:
    from typing import List
except ImportError:
    from src.utils.py2_compat import List

# 本地模块导入
from src.utils.application_context import ApplicationContext

# 必要目录
REQUIRED_DIRS = ["src", "src/ebpf", "src/monitors", "src/utils", "config", "logs", "temp", "output"]


def get_version_info():
    # type: () -> str
    """获取版本信息，支持多种来源的容错处理

    总是返回一个字符串，避免 argparse 在创建 parser 时拿到 None。
    """
    try:
        # 优先从配置文件获取
        from src.utils.config_manager import ConfigManager
        config_manager = ConfigManager()
        app_config = config_manager.get_app_config()
        if getattr(app_config, 'version', None):
            return "eBPF监控工具 v{}".format(app_config.version)
    except Exception:
        # 忽略并使用回退版本
        pass
    # 明确的回退值，确保返回字符串
    return "eBPF监控工具 v1.0.0"


def parse_arguments():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(
        description="eBPF性能监控工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例用法:
  %(prog)s                          # 使用默认配置启动
  %(prog)s -c custom.yaml           # 使用自定义配置文件
  %(prog)s -m exec                  # 使用指定监控器
  %(prog)s --daemon                 # 后台运行模式
  %(prog)s --verbose                # 详细输出模式
  %(prog)s --version                # 显示版本信息
        """
    )
    parser.add_argument(
        "-c",
        "--config",
        type=str,
        default="config/monitor_config.yaml",
        help="配置文件路径",
    )
    parser.add_argument(
        "-m",
        "--monitors",
        type=str,
        help="监控器列表，用逗号分隔 (例如: exec,func,syscall,open,bio,interrupt,memory)",
    )
    parser.add_argument(
        "-d",
        "--daemon",
        action="store_true",
        help="后台运行模式（非交互式）",
    )
    parser.add_argument(
        "--daemon-status",
        action="store_true",
        help="查询守护进程运行状态",
    )
    parser.add_argument(
        "--daemon-stop",
        action="store_true",
        help="停止运行中的守护进程",
    )
    # 使用 -V 作为短选项，保留 -v 给 verbose
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=get_version_info(),
        help="显示版本信息",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="详细输出模式",
    )
    return parser.parse_args()


if __name__ == "__main__":
    """主函数"""
    # 确保当前工作目录正确，如果不正确则退出程序
    # 注意：这里使用sys.stderr是因为logger尚未初始化，这是程序启动前的检查
    current_dir = Path.cwd().name
    expected_dir = Path(__file__).resolve().parent.name

    if current_dir != expected_dir:
        sys.stderr.write("错误: 必须从\"{}\"目录运行此脚本\n".format(expected_dir))
        sys.stderr.write("当前工作目录: {}\n".format(current_dir))
        sys.stderr.write("预期工作目录: {}\n".format(expected_dir))
        sys.exit(1)

    # 检查必要目录
    for dir_name in REQUIRED_DIRS:
        if not Path(dir_name).exists():
            sys.stderr.write("缺少必要的目录: {}\n".format(dir_name))
            sys.exit(1)

    # 解析命令行参数
    args = parse_arguments()

    # 1.初始化应用上下文
    context = ApplicationContext(args.config)
    logger = context.get_logger()
    logger.info("应用上下文初始化完成")

    # 处理守护进程相关命令
    if args.daemon_status:
        if context.daemon_manager.is_running():
            pid = context.daemon_manager.get_daemon_pid()
            print("守护进程正在运行，PID: {}".format(pid))
            sys.exit(0)
        else:
            print("守护进程未运行")
            sys.exit(0)

    # 停止守护进程
    if args.daemon_stop:
        if context.daemon_manager.stop_daemon():
            print("守护进程停止成功")
            sys.exit(0)
        else:
            # 注意：这里使用sys.stderr是为了与用户交互，与上面的print保持输出一致性
            sys.stderr.write("守护进程停止失败\n")
            sys.exit(1)

    # 设置日志级别（如果 verbose）
    if args.verbose:
        logger.info("设置日志级别为DEBUG")
        context.log_manager.set_level(logging.DEBUG)
        logger.debug("日志级别已设置为DEBUG")

    # 2.检查内核兼容性
    checker = context.get_capability_checker()
    logger.info("系统信息: {}".format(checker.get_system_info()))
    if not checker.validate_environment():
        logger.error("环境验证失败")
        sys.exit(1)

    # 3.初始化监控器注册表（预先创建，避免在eBPFMonitor中重复创建）
    monitor_registry = context.get_monitor_registry()
    logger.info("监控器注册表初始化完成")

    # 处理daemon模式 - 在创建监控器之前进行daemon化
    if args.daemon:
        logger.info("启动守护进程模式...")
        if not context.daemon_manager.daemonize():
            logger.error("守护进程化失败")
            sys.exit(1)
        # daemonize()成功返回意味着当前是子进程，父进程已退出
        logger.info("守护进程化成功，PID: {}".format(os.getpid()))

    selected_monitors = []  # type: List[str]
    if args.monitors:
        selected_monitors = [m.strip() for m in args.monitors.split(",")]
        # 验证监控器名称
        available_monitors = monitor_registry.get_monitor_names()
        for monitor in selected_monitors:
            if monitor not in available_monitors:
                logger.error("错误: 未知监控器 '{}'".format(monitor))
                logger.error("可用监控器: {}".format(', '.join(available_monitors)))
                sys.exit(1)

    # 4.解析并验证监控配置
    context.config_manager.parse_validate_monitors_config()

    # 5.创建监控工具实例
    ebpf_monitor = None
    try:
        ebpf_monitor = context.get_ebpf_monitor(selected_monitors)

        if not ebpf_monitor.load():
            logger.error("加载监控器失败")
            sys.exit(1)

        # 在daemon模式下，设置eBPF监控器实例到daemon管理器
        if args.daemon:
            context.daemon_manager.set_ebpf_monitor(ebpf_monitor)

        # 启动监控
        if not ebpf_monitor.start():
            logger.error("启动失败")
            sys.exit(1)

        try:
            while ebpf_monitor.is_running():
                # 检查守护进程关闭请求
                if args.daemon and context.daemon_manager.shutdown_requested.is_set():
                    logger.info("收到守护进程关闭信号")
                    break
                time.sleep(1)
        except KeyboardInterrupt:
            print("")
            logger.info("收到用户中断信号，正在关闭监控工具...")
        except Exception as e:
            logger.error("监控循环异常: {}".format(e))
        finally:
            # 守护进程模式：由perform_shutdown()统一管理关闭流程
            # 普通模式：直接调用stop()
            if args.daemon:
                context.daemon_manager.perform_shutdown()
            else:
                ebpf_monitor.stop()

    except Exception as e:
        logger.error("eBPF监控工具运行失败: {}".format(e))
        sys.exit(1)
    finally:
        # 清理资源
        if ebpf_monitor is not None:
            ebpf_monitor.cleanup()
