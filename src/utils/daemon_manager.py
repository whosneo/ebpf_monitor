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

try:
    ProcessLookupError = ProcessLookupError
except NameError:
    from .py2_compat import ProcessLookupError

from .log_manager import LogManager


class DaemonManager:
    """
    守护进程管理器
    
    负责将进程守护化，管理PID文件，处理信号等。
    实现传统Unix守护进程标准。
    """

    def __init__(self, log_manager, pid_file="temp/monitor.pid"):
        # type: (LogManager, str) -> None
        """
        初始化守护进程管理器
        
        Args:
            log_manager: 日志管理器
            pid_file: PID文件路径，相对于项目根目录
        """
        self._setup_daemon_manager(log_manager, pid_file)

    def _setup_daemon_manager(self, log_manager, pid_file):
        # type: (LogManager, str) -> None
        """设置守护进程管理器"""
        self.log_manager = log_manager
        self.logger = log_manager.get_logger(self)

        # PID文件路径
        self.pid_file = Path(pid_file)
        self.pid_file.parent.mkdir(parents=True, exist_ok=True)

        # 守护进程状态
        self.is_daemon = False
        self.ebpf_monitor = None  # 将在daemon化后设置
        self.pid_file_handle = None  # PID文件句柄（持有锁）
        self.shutdown_requested = threading.Event()  # 关闭请求标志

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

            # 清理可能存在的过期PID文件
            self.cleanup_stale_pid_file()

            self.logger.info("开始守护进程化...")

            # 第一次fork
            pid = os.fork()
            if pid > 0:
                # 父进程退出
                sys.exit(0)

            # 第一个子进程
            # 脱离父进程的进程组和控制终端
            try:
                sid = os.setsid()
                # Python 2/3 兼容：某些系统可能返回None
                if sid is not None and sid < 0:
                    self.logger.error("setsid失败")
                    sys.exit(1)

                # 记录会话ID（如果可用）
                if sid is not None:
                    self.logger.debug("创建新会话成功，SID: {}".format(sid))
                else:
                    self.logger.debug("创建新会话成功")
            except OSError as e:
                self.logger.error("setsid失败: {}".format(e))
                sys.exit(1)

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
        """
        重定向标准输入输出到/dev/null
        
        保持/dev/null文件描述符打开，避免过早关闭导致的问题。
        """
        # 刷新缓冲区
        sys.stdout.flush()
        sys.stderr.flush()

        # 打开/dev/null（不使用with，保持打开直到进程结束）
        null_in = open('/dev/null', 'r')
        null_out = open('/dev/null', 'w')

        # 重定向标准流
        os.dup2(null_in.fileno(), sys.stdin.fileno())
        os.dup2(null_out.fileno(), sys.stdout.fileno())
        os.dup2(null_out.fileno(), sys.stderr.fileno())

        # 注意：不关闭null_in和null_out
        # 它们会在进程结束时自动关闭

    def is_running(self):
        # type: () -> bool
        """
        检查守护进程是否正在运行（纯查询，无副作用）
        
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
            # 进程不存在，但不在这里清理PID文件
            return False

    def cleanup_stale_pid_file(self):
        """
        清理过期的PID文件
        
        如果PID文件存在但进程不存在，则删除PID文件。
        应该在需要时显式调用，而不是作为is_running的副作用。
        
        Returns:
            bool: 是否清理了过期文件
        """
        if not self.is_running() and self.pid_file.exists():
            self.logger.info("检测到过期的PID文件，正在清理...")
            self._remove_pid_file()
            return True
        return False

    def get_daemon_pid(self):
        # type: () -> Optional[int]
        """
        获取守护进程PID（使用非阻塞共享锁防止读取不完整数据）
        
        Returns:
            Optional[int]: 守护进程PID，如果不存在返回None
        """
        try:
            if not self.pid_file.exists():
                return None

            with open(str(self.pid_file), 'r') as f:
                # 尝试获取共享锁（非阻塞），确保读取时不会被其他进程修改
                try:
                    fcntl.flock(f.fileno(), fcntl.LOCK_SH | fcntl.LOCK_NB)
                except IOError:
                    # 无法获取锁（守护进程持有排他锁），这是正常情况
                    # 直接读取即可，不需要日志
                    pass

                # 读取PID（无论是否获取到锁）
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
        
        Returns:
            bool: 停止操作是否成功
        """
        pid = self.get_daemon_pid()
        if pid is None:
            self.logger.info("没有运行中的守护进程")
            return True

        try:
            self.logger.info("正在停止守护进程 PID: {}".format(pid))

            # 启动日志监控线程（如果日志文件存在）
            import time
            monitor_thread = None
            monitor_stop_event = threading.Event()

            log_file = self.log_manager.get_log_file_path()
            if log_file.exists():
                initial_size = log_file.stat().st_size

                def monitor_log():
                    """监控日志文件，显示新增的日志内容"""
                    try:
                        with open(str(log_file), 'r') as f:
                            f.seek(initial_size)
                            no_data_count = 0

                            while not monitor_stop_event.is_set():
                                line = f.readline()
                                if line:
                                    # 输出到控制台（用户交互）
                                    print("守护进程: {}".format(line.strip()))
                                    no_data_count = 0
                                else:
                                    time.sleep(0.1)
                                    no_data_count += 1

                                    # 进程已停止且无新数据
                                    if not self.is_running() and no_data_count >= 20:
                                        break

                    except IOError as e:
                        self.logger.error("读取日志文件失败: {}".format(e))
                    except Exception as e:
                        self.logger.error("日志监控异常: {}".format(e))

                # 启动监控线程
                monitor_thread = threading.Thread(target=monitor_log)
                monitor_thread.daemon = True
                monitor_thread.start()

            # 发送停止信号
            os.kill(pid, signal.SIGTERM)

            # 等待进程结束
            for _ in range(10):
                if not self.is_running():
                    self.logger.info("守护进程已成功停止")

                    # 停止日志监控线程
                    if monitor_thread:
                        monitor_stop_event.set()
                        monitor_thread.join(timeout=2.0)

                    return True
                time.sleep(1)

            # 如果还没停止，发送SIGKILL
            self.logger.warning("守护进程未响应SIGTERM，发送SIGKILL")
            os.kill(pid, signal.SIGKILL)

            # 停止日志监控线程
            if monitor_thread:
                monitor_stop_event.set()
                monitor_thread.join(timeout=2.0)

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
        信号处理函数 - 只设置关闭标志
        
        信号处理器中只能调用异步信号安全的函数，
        因此这里只设置标志位，实际的清理工作由主循环完成。
        
        Args:
            signum: 信号编号
            frame: 当前栈帧
        """
        # 设置关闭标志（线程安全）
        self.shutdown_requested.set()

    def perform_shutdown(self):
        """
        执行实际的关闭操作
        
        由主循环调用，在非信号处理器上下文中安全执行。
        """
        self.logger.info("开始优雅关闭守护进程...")

        try:
            # 停止eBPF监控器
            if self.ebpf_monitor:
                self.logger.info("停止eBPF监控器...")
                self.ebpf_monitor.stop()
                self.ebpf_monitor.cleanup()

            # 清理PID文件
            self._remove_pid_file()

            self.logger.info("守护进程优雅关闭完成")

        except Exception as e:
            self.logger.error("优雅关闭过程中发生错误: {}".format(e))
            raise

    def _write_pid_file(self):
        # type: () -> bool
        """
        写入PID文件并持有锁直到进程结束
        
        使用文件锁确保只有一个守护进程实例运行。
        锁会在进程退出时自动释放。
        
        Returns:
            bool: 写入是否成功
        """
        try:
            # 打开PID文件（如果不存在则创建）
            self.pid_file_handle = open(str(self.pid_file), 'w')

            # 尝试获取排他锁（非阻塞）
            try:
                fcntl.flock(self.pid_file_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except IOError:
                self.logger.error("无法获取PID文件锁，可能已有守护进程在运行")
                self.pid_file_handle.close()
                self.pid_file_handle = None
                return False

            # 写入PID
            self.pid_file_handle.write(str(os.getpid()) + '\n')
            self.pid_file_handle.flush()
            os.fsync(self.pid_file_handle.fileno())

            # 注意：不关闭文件句柄，保持锁直到进程结束
            # 锁会在进程退出或文件句柄关闭时自动释放

            self.logger.debug("PID文件已写入并加锁: {}".format(self.pid_file))
            return True

        except (IOError, OSError) as e:
            self.logger.error("写入PID文件失败: {}".format(e))
            if self.pid_file_handle:
                try:
                    self.pid_file_handle.close()
                except Exception:
                    pass
                self.pid_file_handle = None
            return False

    def _remove_pid_file(self):
        """删除PID文件（先释放锁）"""
        try:
            # 先关闭文件句柄，释放锁
            if self.pid_file_handle:
                try:
                    self.pid_file_handle.close()
                except Exception:
                    pass
                self.pid_file_handle = None

            # 删除PID文件
            if self.pid_file.exists():
                self.pid_file.unlink()
                self.logger.debug("PID文件已删除")
        except OSError as e:
            self.logger.error("删除PID文件失败: {}".format(e))

    def get_status(self):
        # type: () -> dict
        """
        获取守护进程详细状态
        
        Returns:
            dict: 包含守护进程状态信息的字典
        """
        pid = self.get_daemon_pid()

        if pid is None:
            return {
                'running': False,
                'pid': None,
                'pid_file': str(self.pid_file),
                'pid_file_exists': self.pid_file.exists()
            }

        try:
            os.kill(pid, 0)
            # 进程存在，尝试获取更多信息
            try:
                import psutil
                proc = psutil.Process(pid)
                return {
                    'running': True,
                    'pid': pid,
                    'pid_file': str(self.pid_file),
                    'create_time': proc.create_time(),
                    'cpu_percent': proc.cpu_percent(interval=0.1),
                    'memory_info': {
                        'rss': proc.memory_info().rss,
                        'vms': proc.memory_info().vms
                    },
                    'num_threads': proc.num_threads(),
                    'status': proc.status()
                }
            except (ImportError, Exception):
                # psutil不可用或获取信息失败
                return {
                    'running': True,
                    'pid': pid,
                    'pid_file': str(self.pid_file)
                }

        except (OSError, ProcessLookupError):
            # 进程不存在
            return {
                'running': False,
                'pid': pid,
                'pid_file': str(self.pid_file),
                'stale': True  # PID文件存在但进程不存在
            }

    def set_ebpf_monitor(self, ebpf_monitor):
        """
        设置eBPF监控器实例
        
        Args:
            ebpf_monitor: eBPFMonitor实例
        """
        self.ebpf_monitor = ebpf_monitor
