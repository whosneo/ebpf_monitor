#!/usr/bin/env python
# encoding: utf-8
"""
守护进程管理器

实现传统Unix守护进程功能，包括进程守护化、PID文件管理、信号处理等。
"""

import fcntl
import os
import signal
import sys
import threading
# 兼容性导入
try:
    from typing import Optional
except ImportError:
    from .py2_compat import Optional

try:
    from pathlib import Path
except ImportError:
    from .py2_compat import Path

from .log_manager import LogManager


class DaemonManager:
    """
    守护进程管理器
    
    负责将进程守护化，管理PID文件，处理信号等。
    实现传统Unix守护进程标准。
    """

    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        """实现单例模式，确保全局唯一的 DaemonManager 实例"""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super(DaemonManager, cls).__new__(cls)
        return cls._instance

    def __init__(self, pid_file="temp/monitor.pid"):
        # type: (str) -> None
        """
        初始化守护进程管理器
        
        Args:
            pid_file: PID文件路径，相对于项目根目录
        """
        if not hasattr(self, "_initialized"):
            self._initialized = False
            self._setup_daemon_manager(pid_file)
            self._initialized = True

    def _setup_daemon_manager(self, pid_file):
        # type: (str) -> None
        """设置守护进程管理器"""
        self.log_manager = LogManager()
        self.logger = self.log_manager.get_logger(self)

        # PID文件路径
        self.pid_file = Path(pid_file)
        self.pid_file.parent.mkdir(parents=True, exist_ok=True)

        # 守护进程状态
        self.is_daemon = False
        self.ebpf_monitor = None  # 将在daemon化后设置

        self.logger.info("守护进程管理器初始化完成")

    def daemonize(self):
        # type: () -> bool
        """
        将当前进程守护化
        
        使用传统的双重fork方法实现守护进程。
        
        Returns:
            bool: 守护化是否成功
        """
        try:
            # 检查是否已有守护进程在运行
            if self.is_running():
                existing_pid = self.get_daemon_pid()
                self.logger.error("守护进程已在运行，PID: {}".format(existing_pid))
                return False

            self.logger.info("开始守护进程化...")

            # 第一次fork
            pid = os.fork()
            if pid > 0:
                # 父进程退出
                sys.exit(0)

            # 第一个子进程
            # 脱离父进程的进程组和控制终端
            os.setsid()

            # 第二次fork
            pid = os.fork()
            if pid > 0:
                # 第一个子进程退出
                sys.exit(0)

            # 第二个子进程（真正地守护进程）
            # 重定向标准输入输出
            self._redirect_standard_streams()

            # 设置文件创建掩码
            os.umask(0o022)

            # 写入PID文件
            if not self._write_pid_file():
                self.logger.error("写入PID文件失败")
                return False

            # 设置信号处理器
            self._setup_signal_handlers()

            self.is_daemon = True
            self.logger.info("守护进程启动成功，PID: {}".format(os.getpid()))
            return True

        except OSError as e:
            self.logger.error("守护进程化失败: {}".format(e))
            return False

    @staticmethod
    def _redirect_standard_streams():
        """重定向标准输入输出到/dev/null"""
        # 刷新缓冲区
        sys.stdout.flush()
        sys.stderr.flush()

        # 重定向到/dev/null
        with open('/dev/null', 'r') as null_in:
            os.dup2(null_in.fileno(), sys.stdin.fileno())

        with open('/dev/null', 'w') as null_out:
            os.dup2(null_out.fileno(), sys.stdout.fileno())
            os.dup2(null_out.fileno(), sys.stderr.fileno())

    def is_running(self):
        # type: () -> bool
        """
        检查守护进程是否正在运行
        
        Returns:
            bool: 守护进程是否在运行
        """
        pid = self.get_daemon_pid()
        if pid is None:
            return False

        try:
            # 发送 0 信号检查进程是否存在
            os.kill(pid, 0)
            return True
        except (OSError, ProcessLookupError):
            # 进程不存在，清理僵尸PID文件
            self._remove_pid_file()
            return False

    def get_daemon_pid(self):
        # type: () -> Optional[int]
        """
        获取守护进程PID
        
        Returns:
            Optional[int]: 守护进程PID，如果不存在返回None
        """
        try:
            if not self.pid_file.exists():
                return None

            with open(str(self.pid_file), 'r') as f:
                pid_str = f.read().strip()
                return int(pid_str) if pid_str else None
        except (IOError, OSError, ValueError):
            # Python 2.7 compatibility - FileNotFoundError and PermissionError don't exist
            return None

    def stop_daemon(self):
        # type: () -> bool
        """
        停止守护进程
        
        向守护进程发送SIGTERM信号，实现优雅停止。
        同时监控日志文件，显示停止过程。
        
        Returns:
            bool: 停止操作是否成功
        """
        pid = self.get_daemon_pid()
        if pid is None:
            self.logger.info("没有运行中的守护进程")
            return True

        try:
            self.logger.info("正在停止守护进程 PID: {}".format(pid))

            # 启动日志监控线程
            import threading
            import time
            try:
                from pathlib import Path
            except ImportError:
                from .py2_compat import Path

            log_file = self.log_manager.get_log_file_path()
            if log_file.exists():
                # 记录当前日志文件大小，只显示新增的日志
                initial_size = log_file.stat().st_size

                def monitor_log():
                    """监控日志文件，显示新增的日志内容"""
                    try:
                        with open(str(log_file), 'r') as f:
                            f.seek(initial_size)  # 跳到文件末尾
                            no_data_count = 0
                            while True:
                                line = f.readline()
                                if line:
                                    print("守护进程: {}".format(line.strip()))
                                    no_data_count = 0  # 重置计数器
                                else:
                                    time.sleep(0.1)
                                    no_data_count += 1

                                    # 检查进程是否还在运行
                                    if not self.is_running():
                                        # 进程已停止，但继续读取一段时间以获取最后的日志
                                        if no_data_count >= 20:  # 2秒无新数据后退出
                                            break
                    except Exception:
                        pass

                # 启动监控线程
                monitor_thread = threading.Thread(target=monitor_log, daemon=True)
                monitor_thread.start()

            # 发送停止信号
            os.kill(pid, signal.SIGTERM)

            # 等待进程结束
            for _ in range(10):  # 最多等待10秒
                if not self.is_running():
                    self.logger.info("守护进程已成功停止")
                    time.sleep(0.5)  # 给日志监控一点时间
                    return True
                time.sleep(1)

            # 如果还没停止，发送SIGKILL
            self.logger.warning("守护进程未响应SIGTERM，发送SIGKILL")
            os.kill(pid, signal.SIGKILL)
            return True

        except (OSError, ProcessLookupError) as e:
            self.logger.error("停止守护进程失败: {}".format(e))
            return False

    def _setup_signal_handlers(self):
        """设置信号处理器"""
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

        # 忽略SIGHUP和SIGPIPE
        signal.signal(signal.SIGHUP, signal.SIG_IGN)
        signal.signal(signal.SIGPIPE, signal.SIG_IGN)

    # noinspection PyUnusedLocal
    def _signal_handler(self, signum, frame):
        """
        信号处理函数
        
        Args:
            signum: 信号编号
            frame: 当前栈帧
        """
        # 守护进程无法直接输出到终端，通过日志文件记录停止过程

        signal_name = signal.Signals(signum).name
        self.logger.info("收到信号 {} ({})，开始优雅关闭...".format(signal_name, signum))

        try:
            # 停止eBPF监控器
            if self.ebpf_monitor:
                self.ebpf_monitor.stop()
                self.ebpf_monitor.cleanup()

            # 清理PID文件
            self._remove_pid_file()

            self.logger.info("守护进程优雅关闭完成")
            sys.exit(0)

        except Exception as e:
            self.logger.error("优雅关闭过程中发生错误: {}".format(e))
            sys.exit(1)

    def _write_pid_file(self):
        # type: () -> bool
        """
        写入PID文件
        
        Returns:
            bool: 写入是否成功
        """
        try:
            with open(str(self.pid_file), 'w') as f:
                # 获取文件锁
                fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                f.write(str(os.getpid()))
                f.flush()
                os.fsync(f.fileno())
            return True
        except (IOError, OSError) as e:
            self.logger.error("写入PID文件失败: {}".format(e))
            return False

    def _remove_pid_file(self):
        """删除PID文件"""
        try:
            if self.pid_file.exists():
                self.pid_file.unlink()
                self.logger.debug("PID文件已删除")
        except OSError as e:
            self.logger.error("删除PID文件失败: {}".format(e))

    def set_ebpf_monitor(self, ebpf_monitor):
        """
        设置eBPF监控器实例
        
        Args:
            ebpf_monitor: eBPFMonitor实例
        """
        self.ebpf_monitor = ebpf_monitor


if __name__ == "__main__":
    # 测试函数
    daemon_manager = DaemonManager()
    print("守护进程是否运行: {}".format(daemon_manager.is_running()))
    if daemon_manager.is_running():
        print("守护进程PID: {}".format(daemon_manager.get_daemon_pid()))
