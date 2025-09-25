#!/usr/bin/env python
# encoding: utf-8

"""
eBPF性能监控工具

集成所有监控模块，提供完整的系统性能监控解决方案。
"""

import pwd
import threading
import time
# dataclass已替换为普通类以兼容Python2.7
# 兼容性导入
try:
    from typing import List, Dict, Optional, Any, Type, TYPE_CHECKING
except ImportError:
    from .utils.py2_compat import List, Dict, Optional, Any, Type, TYPE_CHECKING

import psutil

from .monitors.base import BaseMonitor

if TYPE_CHECKING:
    # noinspection PyUnusedImports
    from .utils.application_context import ApplicationContext


class MonitorStatus:
    """监控器状态"""
    
    def __init__(self, type=None, loaded=False, running=False, error=None, last_update=0.0):
        # type: (str, bool, bool, Optional[str], float) -> None
        self.type = type # type: str
        self.loaded = loaded # type: bool
        self.running = running # type: bool
        self.error = error # type: Optional[str]
        self.last_update = last_update # type: float


class eBPFMonitor:
    """
    eBPF性能监控工具

    集成所有监控模块，提供完整的系统性能监控解决方案。
    不再使用单例模式，支持多实例使用。
    """

    def __init__(self, context, selected_monitors=None):
        # type: ('ApplicationContext', List[str]) -> None
        """
        初始化监控工具
        
        Args:
            context: 应用上下文，提供所需的依赖组件
            selected_monitors: 选定的监控器列表
        """
        self.context = context
        self.logger = context.get_logger(self)

        # 创建组件实例
        self.monitor_registry = context.get_monitor_registry()
        self.output_controller = context.output_controller

        self.monitors_config = context.config_manager.get_monitors_config()
        self.all_monitors = self.monitor_registry.get_registered_monitors()  # type: Dict[str, Type[BaseMonitor]]
        self.selected_monitors = selected_monitors if selected_monitors else list(self.monitor_registry.get_monitor_names()) # type: List[str]
        self.monitors = {}  # type: Dict[str, BaseMonitor]  # 监控器实例
        self.monitor_status = {}  # type: Dict[str, MonitorStatus]  # 监控器状态

        self.target_processes = {}  # type: Dict[int, str]  # 目标进程
        self.target_users = {}  # type: Dict[int, str]  # 目标用户

        self.running = False  # 运行状态

        # 分层锁架构：替换单一全局锁为细粒度锁
        self.target_lock = threading.RLock()  # 目标进程/用户管理锁
        self.status_lock = threading.RLock()  # 监控器状态管理锁
        self.stats_lock = threading.Lock()  # 统计信息更新锁

        self.stats = self._get_default_stats()  # 统计信息

        self._create_monitors()  # 创建监控器实例

        self.logger.info("eBPF监控工具初始化完成")

    @staticmethod
    def _get_default_stats():
        # type: () -> Dict[str, Any]
        """获取默认统计信息"""
        return {
            "start_time": time.time(),
            "errors": 0,
            "processes_monitored": 0,
            "users_monitored": 0
        }

    def _create_monitors(self):
        """创建监控器实例"""
        try:
            for monitor_type in self.selected_monitors:
                # 使用注册表创建监控器实例，传递上下文和输出控制器
                monitor = self.all_monitors[monitor_type](
                    self.context,
                    getattr(self.monitors_config, monitor_type)
                )
                if not monitor.enabled:
                    self.logger.warning("{}监控未启用".format(monitor_type))
                    del monitor
                    continue
                self.monitors[monitor_type] = monitor
                self.monitor_status[monitor_type] = MonitorStatus(monitor_type)
                self.logger.info("{}监控器已创建".format(monitor_type))
        except Exception as e:
            self.logger.error("创建监控器失败: {}".format(e))
            raise

    def load(self):
        # type: () -> bool
        """加载所有监控器"""
        success_count = 0
        for monitor_type, monitor in self.monitors.items():
            if self._load_monitor(monitor_type, monitor):
                success_count += 1

        self.logger.info("监控器加载完成: {}/{}".format(success_count, len(self.monitors)))
        return success_count > 0

    def _load_monitor(self, monitor_type, monitor):
        # type: (str, BaseMonitor) -> bool
        """加载指定监控器 - 使用状态锁保护状态更新"""
        # 加载eBPF程序
        if monitor.load_ebpf_program():
            # 更新状态 - 使用状态锁
            with self.status_lock:
                self.monitor_status[monitor_type].loaded = True
                self.monitor_status[monitor_type].error = None
                self.monitor_status[monitor_type].last_update = time.time()
            self.output_controller.register_monitor(monitor_type, monitor)
            self.logger.info("{}监控器加载成功".format(monitor_type))
            return True
        else:
            error_msg = "{}监控器加载失败".format(monitor_type)
            self.logger.error(error_msg)
            with self.status_lock:
                self.monitor_status[monitor_type].error = error_msg
            return False

    def add_target_processes(self, process_names):
        # type: (List[str]) -> int
        """根据进程名添加目标进程"""
        added_count = 0

        for proc in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                proc_info = proc.info
                proc_name = proc_info["name"]

                if proc_name in process_names:
                    if self._add_target_process(proc_info["pid"], proc_name):
                        added_count += 1

            except psutil.NoSuchProcess as e:
                self.logger.debug("进程不存在: {} {}".format(proc_name, e))
                continue
            except psutil.AccessDenied as e:
                self.logger.debug("进程访问失败: {} {}".format(proc_name, e))
                continue

        self.logger.info("根据进程名添加了 {} 个目标进程".format(added_count))
        return added_count

    def _add_target_process(self, pid, comm=None):
        # type: (int, str) -> bool
        """添加目标进程到所有监控器 - 使用细粒度锁"""
        if not comm:
            try:
                process = psutil.Process(pid)
                comm = process.name()
            except psutil.NoSuchProcess or psutil.AccessDenied:
                comm = "unknown"

        success = True
        added_monitors = set()

        with self.target_lock:  # 使用专用的目标管理锁
            for monitor_type, monitor in self.monitors.items():
                # 读取监控器状态时使用状态锁
                with self.status_lock:
                    status = self.monitor_status.get(monitor_type)
                    is_loaded = status and status.loaded

                if is_loaded:
                    if monitor.add_target_process(pid, comm):
                        added_monitors.add(monitor_type)
                    else:
                        success = False

            if success:
                self.target_processes[pid] = comm
                # 统计信息使用专用锁
                with self.stats_lock:
                    self.stats["processes_monitored"] = len(self.target_processes)
                self.logger.info("目标进程已添加到所有监控器: PID={}, COMM={}".format(pid, comm))
            else:
                # 回滚已添加的监控器
                for monitor_type in added_monitors:
                    self.monitors[monitor_type].remove_target_process(pid)
                self.logger.error("添加目标进程失败: PID={}".format(pid))

        return success

    def add_target_users(self, user_names):
        # type: (List[str]) -> int
        """根据用户名添加目标用户"""
        added_count = 0

        for user_name in user_names:
            try:
                user = pwd.getpwnam(user_name)
                if self._add_target_user(user.pw_uid, user.pw_name):
                    added_count += 1
            except KeyError as e:
                self.logger.debug("用户不存在: {} {}".format(user_name, e))
                continue
            except Exception as e:
                self.logger.debug("添加用户失败: {} {}".format(user_name, e))
                continue

        self.logger.info("根据用户名添加了 {} 个目标用户".format(added_count))
        return added_count

    def _add_target_user(self, uid, name=None):
        # type: (int, str) -> bool
        """添加目标用户 - 使用细粒度锁"""
        if not name:
            try:
                user = pwd.getpwuid(uid)
                name = user.pw_name
            except (KeyError, OSError) as e:
                self.logger.debug("无法获取用户名: {}".format(e))
                name = "unknown"

        success = True
        added_monitors = set()

        with self.target_lock:  # 使用专用的目标管理锁
            for monitor_type, monitor in self.monitors.items():
                # 读取监控器状态时使用状态锁
                with self.status_lock:
                    status = self.monitor_status.get(monitor_type)
                    is_loaded = status and status.loaded

                if is_loaded:
                    if monitor.add_target_user(uid, name):
                        added_monitors.add(monitor_type)
                    else:
                        success = False

            if success:
                self.target_users[uid] = name
                # 统计信息使用专用锁
                with self.stats_lock:
                    self.stats["users_monitored"] = len(self.target_users)
                self.logger.info("目标用户已添加到所有监控器: UID={}, NAME={}".format(uid, name))
            else:
                # 回滚已添加的监控器
                for monitor_type in added_monitors:
                    self.monitors[monitor_type].remove_target_user(uid)
                self.logger.error("添加目标用户失败: UID={}".format(uid))

        return success

    def start(self):
        # type: () -> bool
        """
        开始监控

        Returns:
            bool: 启动是否成功
        """
        if self.running:
            self.logger.warning("监控工具已在运行")
            return True

        try:
            self.logger.info("开始启动监控...")
            # 启动输出控制器
            if not self.output_controller.start():
                self.logger.error("输出控制器启动失败")
                return False
            # 启动所有监控器
            if not self._start_monitors():
                self.logger.error("监控器启动失败")
                return False
            self.running = True
            self.logger.info("eBPF监控工具启动成功")
            return True
        except Exception as e:
            self.logger.error("启动监控失败: {}".format(e))
            return False

    def _start_monitors(self):
        # type: () -> bool
        """启动所有加载的监控器 - 使用状态锁保护状态更新"""
        if not self.monitors:
            self.logger.warning("没有可用的监控器")
            return False

        success_count = 0
        for monitor_type, monitor in self.monitors.items():
            # 检查加载状态时使用状态锁
            with self.status_lock:
                is_loaded = self.monitor_status[monitor_type].loaded

            if not is_loaded:
                self.logger.warning("{}监控器未加载，跳过启动".format(monitor_type))
                continue

            try:
                if monitor.run():
                    with self.status_lock:
                        self.monitor_status[monitor_type].running = True
                        self.monitor_status[monitor_type].error = None
                    success_count += 1
                    self.logger.info("{}监控器启动成功".format(monitor_type))
                else:
                    with self.status_lock:
                        self.monitor_status[monitor_type].error = "启动失败"
                    self.logger.error("{}监控器启动失败".format(monitor_type))

            except Exception as e:
                error_msg = "启动{}监控器失败: {}".format(monitor_type, e)
                self.logger.error(error_msg)
                with self.status_lock:
                    self.monitor_status[monitor_type].error = error_msg

        self.logger.info("监控器启动完成: {}/{}".format(success_count, len(self.monitors)))
        return success_count > 0

    def stop(self):
        # type: () -> bool
        """关闭监控工具"""
        if not self.running:
            self.logger.warning("监控工具未启动")
            return True

        self.logger.info("正在关闭监控工具...")

        try:
            self.output_controller.stop()
            # 停止监控器
            self._stop_monitors()
            self.running = False
            self.logger.info("监控工具已关闭")
            return True
        except Exception as e:
            self.logger.error("关闭监控工具时发生错误: {}".format(e))
            return False

    def _stop_monitors(self):
        """停止所有监控器 - 使用状态锁保护状态更新"""
        for monitor_type, monitor in self.monitors.items():
            # 检查运行状态时使用状态锁
            with self.status_lock:
                is_running = self.monitor_status[monitor_type].running

            if is_running:
                try:
                    monitor.stop()
                    with self.status_lock:
                        self.monitor_status[monitor_type].running = False
                        self.monitor_status[monitor_type].last_update = time.time()
                    self.output_controller.unregister_monitor(monitor_type)
                    self.logger.info("{}监控器已停止".format(monitor_type))
                except Exception as e:
                    self.logger.error("停止{}监控器失败: {}".format(monitor_type, e))

    def cleanup(self):
        """清理所有资源"""
        # cleanup职责：仅清理资源，不负责停止监控
        # 调用者应该先调用stop()再调用cleanup()
        for monitor_type, monitor in self.monitors.items():
            try:
                monitor.cleanup()
                self.logger.info("{}监控器资源已清理".format(monitor_type))
            except Exception as e:
                self.logger.error("清理{}监控器资源失败: {}".format(monitor_type, e))

        # Python 2.7兼容性：清理集合和字典
        # target_processes 和 target_users 是字典
        if hasattr(self.target_processes, 'clear'):
            self.target_processes.clear()
        else:
            self.target_processes = {}
        if hasattr(self.target_users, 'clear'):
            self.target_users.clear()
        else:
            self.target_users = {}
        # all_monitors 和 selected_monitors 是列表/字典
        if hasattr(self.all_monitors, 'clear'):
            self.all_monitors.clear()
        else:
            self.all_monitors = {}
        if hasattr(self.selected_monitors, 'clear'):
            self.selected_monitors.clear()
        else:
            self.selected_monitors = {}
        # Python 2.7兼容性：dict没有clear()方法
        if hasattr(self.monitors, 'clear'):
            self.monitors.clear()
        else:
            self.monitors = {}
        if hasattr(self.monitor_status, 'clear'):
            self.monitor_status.clear()
        else:
            self.monitor_status = {}

    def is_running(self):
        # type: () -> bool
        """
        检查是否正在监控

        Returns:
            bool: 监控状态
        """
        return self.running


if __name__ == "__main__":
    # 禁止直接运行
    pass
