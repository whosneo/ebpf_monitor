#!/usr/bin/env python
# encoding: utf-8
"""
eBPF性能监控工具

集成所有监控模块，提供完整的系统性能监控解决方案。
"""

# 标准库导入
import threading
import time

# 兼容性导入
try:
    from typing import List, Dict, Optional, Any, Type, TYPE_CHECKING
except ImportError:
    from .utils.py2_compat import List, Dict, Optional, Any, Type, TYPE_CHECKING

# 本地模块导入
from .monitors.base import BaseMonitor

if TYPE_CHECKING:
    # noinspection PyUnusedImports
    from .utils.application_context import ApplicationContext


class MonitorStatus:
    """监控器状态"""

    def __init__(self, type=None, loaded=False, running=False, error=None, last_update=0.0):
        # type: (str, bool, bool, Optional[str], float) -> None
        self.type = type  # type: str
        self.loaded = loaded  # type: bool
        self.running = running  # type: bool
        self.error = error  # type: Optional[str]
        self.last_update = last_update  # type: float
        self.restart_count = 0  # type: int
        self.degraded = False  # type: bool
        self.last_error_count_snapshot = 0  # type: int
        self.restart_timestamps = []  # type: List[float]


class eBPFMonitor:
    """
    eBPF性能监控工具

    集成所有监控模块，提供完整的系统性能监控解决方案。
    不再使用单例模式，支持多实例使用。
    """

    def __init__(self, context, selected_monitors=None):
        # type: ('ApplicationContext', Optional[List[str]]) -> None
        """
        初始化监控工具
        
        Args:
            context: 应用上下文，提供所需的依赖组件
            selected_monitors: 选定的监控器列表，None表示使用所有已注册的监控器
        """
        self.context = context
        self.logger = context.get_logger(self)

        # 创建组件实例
        self.monitor_registry = context.get_monitor_registry()
        self.output_controller = context.output_controller

        self.monitors_config = context.config_manager.get_monitors_config()
        self.all_monitors = self.monitor_registry.get_registered_monitors()  # type: Dict[str, Type[BaseMonitor]]
        # 类型修正: selected_monitors 在初始化后保证是 List[str]
        self.selected_monitors = selected_monitors if selected_monitors else list(
            self.monitor_registry.get_monitor_names())  # type: List[str]
        self.monitors = {}  # type: Dict[str, BaseMonitor]  # 监控器实例
        self.monitor_status = {}  # type: Dict[str, MonitorStatus]  # 监控器状态

        self.running = False  # 运行状态

        # 统一状态管理锁
        self.state_lock = threading.RLock()

        self.stats = self._get_default_stats()  # 统计信息

        # watchdog 配置（来自 app 配置，缺省安全值）
        app_cfg = context.config_manager.get_app_config()
        self.watchdog_enabled = bool(getattr(app_cfg, "watchdog_enabled", True))
        self.watchdog_interval = float(getattr(app_cfg, "watchdog_interval", 10))
        self.watchdog_stale_intervals = int(getattr(app_cfg, "watchdog_stale_intervals", 5))
        self.watchdog_error_delta = int(getattr(app_cfg, "watchdog_error_delta", 50))
        self.watchdog_max_restarts_per_window = int(
            getattr(app_cfg, "watchdog_max_restarts_per_window", 3)
        )
        self.watchdog_restart_window_s = float(
            getattr(app_cfg, "watchdog_restart_window_s", 60)
        )
        self._watchdog_thread = None  # type: Optional[threading.Thread]
        self._watchdog_stop = threading.Event()
        self._last_health_log_ts = 0.0  # type: float
        self._health_log_interval_s = 60.0  # type: float  # design §9.2

        self._create_monitors()  # 创建监控器实例

        self.logger.debug("eBPF监控工具初始化完成")

    @staticmethod
    def _get_default_stats():
        # type: () -> Dict[str, Any]
        """获取默认统计信息"""
        return {
            "start_time": time.time(),
            "errors": 0
        }

    def _create_monitors(self):
        # type: () -> None
        """创建所有选定的监控器"""
        # 通过依赖注入获取监控器工厂
        factory = self.context.get_monitor_factory()

        for monitor_type in self.selected_monitors:
            try:
                monitor_class = self.all_monitors[monitor_type]
                monitor_config = getattr(self.monitors_config, monitor_type)

                # 使用工厂创建监控器
                monitor = factory.create_monitor(
                    monitor_class,
                    monitor_type,
                    monitor_config
                )

                if not monitor.enabled:
                    self.logger.debug("{}监控器未启用".format(monitor_type))
                    continue

                self.monitors[monitor_type] = monitor
                with self.state_lock:
                    self.monitor_status[monitor_type] = MonitorStatus(monitor_type)

                self.logger.debug("{}监控器已创建".format(monitor_type))

            except KeyError as e:
                self.logger.error("未知的监控器类型 '{}': {}".format(monitor_type, e))
            except AttributeError as e:
                self.logger.error("监控器 '{}' 配置项缺失: {}".format(monitor_type, e))
            except IOError as e:
                self.logger.error("监控器 '{}' eBPF文件不存在或无法读取: {}".format(monitor_type, e))
            except (RuntimeError, ValueError) as e:
                self.logger.error("监控器 '{}' 初始化失败: {}".format(monitor_type, e))
            except Exception as e:
                self.logger.error("创建 '{}' 监控器时发生未知错误: {}".format(monitor_type, e))

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
        """加载指定监控器"""
        # 加载eBPF程序
        if monitor.load_ebpf_program():
            # 更新状态
            with self.state_lock:
                self.monitor_status[monitor_type].loaded = True
                self.monitor_status[monitor_type].error = None
                self.monitor_status[monitor_type].last_update = time.time()
            self.output_controller.register_monitor(monitor_type, monitor)
            self.logger.info("{}监控器加载成功".format(monitor_type))
            return True
        else:
            error_msg = "{}监控器加载失败".format(monitor_type)
            self.logger.error(error_msg)
            with self.state_lock:
                self.monitor_status[monitor_type].error = error_msg
            return False

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
            self._start_watchdog()
            self.logger.info("eBPF监控工具启动成功")
            return True
        except Exception as e:
            self.logger.error("启动监控失败: {}".format(e))
            return False

    def _start_monitors(self):
        # type: () -> bool
        """启动所有加载的监控器"""
        if not self.monitors:
            self.logger.warning("没有可用的监控器")
            return False

        success_count = 0
        for monitor_type, monitor in self.monitors.items():
            # 检查加载状态
            with self.state_lock:
                is_loaded = self.monitor_status[monitor_type].loaded

            if not is_loaded:
                self.logger.warning("{}监控器未加载，跳过启动".format(monitor_type))
                continue

            try:
                if monitor.run():
                    with self.state_lock:
                        self.monitor_status[monitor_type].running = True
                        self.monitor_status[monitor_type].error = None
                    success_count += 1
                    self.logger.info("{}监控器启动成功".format(monitor_type))
                else:
                    with self.state_lock:
                        self.monitor_status[monitor_type].error = "启动失败"
                    self.logger.error("{}监控器启动失败".format(monitor_type))

            except Exception as e:
                error_msg = "启动{}监控器失败: {}".format(monitor_type, e)
                self.logger.error(error_msg)
                with self.state_lock:
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
            self._stop_watchdog()
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
        """停止所有监控器"""
        for monitor_type, monitor in self.monitors.items():
            # 检查运行状态
            with self.state_lock:
                is_running = self.monitor_status[monitor_type].running

            if is_running:
                try:
                    monitor.stop()
                    with self.state_lock:
                        self.monitor_status[monitor_type].running = False
                        self.monitor_status[monitor_type].last_update = time.time()
                    self.output_controller.unregister_monitor(monitor_type)
                    self.logger.info("{}监控器已停止".format(monitor_type))
                except Exception as e:
                    self.logger.error("停止{}监控器失败: {}".format(monitor_type, e))

    def cleanup(self):
        """
        清理所有资源（幂等操作）
        
        注意: cleanup职责仅为清理资源，不负责停止监控
        调用者应该先调用stop()再调用cleanup()
        此方法可以安全地多次调用
        """
        # 检查是否已清理，避免重复操作
        if getattr(self, '_cleaned_up', False):
            self.logger.debug("eBPFMonitor资源已清理，跳过重复清理")
            return

        # 清理各个监控器的资源
        for monitor_type, monitor in list(self.monitors.items()):
            try:
                monitor.cleanup()
                self.logger.debug("{}监控器资源已清理".format(monitor_type))
            except Exception as e:
                self.logger.error("清理{}监控器资源失败: {}".format(monitor_type, e))

        # Python 2/3 兼容: 使用统一的集合清理函数
        from .utils.py2_compat import safe_clear_collection
        self.all_monitors = safe_clear_collection(self.all_monitors)
        self.selected_monitors = safe_clear_collection(self.selected_monitors)
        self.monitors = safe_clear_collection(self.monitors)
        self.monitor_status = safe_clear_collection(self.monitor_status)

        # 标记已清理
        self._cleaned_up = True
        self.logger.info("eBPFMonitor资源清理完成")

    def is_running(self):
        # type: () -> bool
        """
        检查是否正在监控

        Returns:
            bool: 监控状态
        """
        with self.state_lock:
            return self.running

    def restart_monitor(self, name, reason=""):
        # type: (str, str) -> bool
        """
        单监控器重启：永远经 Factory 新建实例（禁止复用 cleanup 后实例）。

        顺序：先 create+load 新实例；成功后再 stop/cleanup 旧实例并替换。
        create/load 失败时保留旧实例在 self.monitors（不丢覆盖）。
        run 失败时已换上新实例并保留 key，status.running=False。
        """
        with self.state_lock:
            if name not in self.all_monitors:
                self.logger.error("restart_monitor unknown type: {}".format(name))
                return False

            status = self.monitor_status.get(name)
            if status is None:
                status = MonitorStatus(name)
                self.monitor_status[name] = status

            # 退避：窗口内超限则 degraded
            now = time.time()
            window = self.watchdog_restart_window_s
            status.restart_timestamps = [
                t for t in status.restart_timestamps if now - t < window
            ]
            if len(status.restart_timestamps) >= self.watchdog_max_restarts_per_window:
                status.degraded = True
                self.logger.error(
                    "monitor_restart degraded name=%s reason=%s (backoff)",
                    name, reason,
                )
                return False

            old = self.monitors.get(name)

            try:
                cfg = getattr(self.monitors_config, name)
            except AttributeError:
                status.error = "config missing"
                # 不改 self.monitors：旧实例仍在
                return False

            factory = self.context.get_monitor_factory()
            try:
                new = factory.create_monitor(self.all_monitors[name], name, cfg)
            except Exception as e:
                status.error = "create failed: {}".format(e)
                self.logger.error("restart create {}: {}".format(name, e))
                # 旧实例仍在 map 中
                return False

            if not new.enabled:
                # 配置变为禁用：停掉旧实例并移除
                if old is not None:
                    self._teardown_monitor_instance(name, old)
                    self.monitors.pop(name, None)
                status.loaded = False
                status.running = False
                status.error = "disabled"
                return False

            if not new.load_ebpf_program():
                status.error = "reload load failed"
                # 不替换：清理失败的新实例，旧实例继续服务
                try:
                    new.cleanup()
                except Exception:
                    pass
                self.logger.error("restart load failed name=%s; keeping previous instance", name)
                return False

            # 新实例已 load 成功（含软等待时 bpf 仍为 None）→ 替换旧实例
            if old is not None:
                self._teardown_monitor_instance(name, old)

            self.monitors[name] = new
            try:
                self.output_controller.register_monitor(name, new)
            except Exception as e:
                self.logger.error("restart register {}: {}".format(name, e))

            if not new.run():
                status.error = "reload run failed"
                status.loaded = True
                status.running = False
                # 新实例保留在 map 中，避免 key 丢失；status 与实例一致
                self.logger.error(
                    "restart run failed name=%s; new instance kept (not running)",
                    name,
                )
                return False

            status.loaded = True
            status.running = True
            status.error = None
            status.last_update = now
            status.restart_count += 1
            status.restart_timestamps.append(now)
            status.degraded = False
            status.last_error_count_snapshot = getattr(new, "collect_error_count", 0)
            self.logger.info(
                "monitor_restart name=%s reason=%s count=%s",
                name, reason, status.restart_count,
            )
            return True

    def _teardown_monitor_instance(self, name, instance):
        # type: (str, BaseMonitor) -> None
        """停止、注销输出并 cleanup 监控器实例（尽力而为）。"""
        try:
            if instance.is_running():
                instance.stop()
        except Exception as e:
            self.logger.error("restart stop {}: {}".format(name, e))
        try:
            self.output_controller.unregister_monitor(name)
        except Exception:
            pass
        try:
            instance.cleanup()
        except Exception as e:
            self.logger.error("restart cleanup {}: {}".format(name, e))

    def get_health(self):
        # type: () -> Dict[str, Any]
        """进程级 + 各监控器健康快照（JSON 可序列化）。"""
        monitors = {}
        with self.state_lock:
            for name, mon in self.monitors.items():
                try:
                    h = mon.get_health()
                except Exception as e:
                    h = {"type": name, "error": str(e)}
                st = self.monitor_status.get(name)
                if st is not None:
                    h["status_error"] = st.error
                    h["restart_count"] = st.restart_count
                    h["degraded"] = st.degraded
                monitors[name] = h
            running = self.running
        return {
            "running": running,
            "watchdog_enabled": self.watchdog_enabled,
            "monitors": monitors,
            "start_time": self.stats.get("start_time"),
        }

    def _start_watchdog(self):
        # type: () -> None
        if not self.watchdog_enabled:
            return
        self._watchdog_stop.clear()
        self._watchdog_thread = threading.Thread(target=self._watchdog_loop)
        self._watchdog_thread.daemon = True
        self._watchdog_thread.start()

    def _stop_watchdog(self):
        # type: () -> None
        self._watchdog_stop.set()
        if self._watchdog_thread and self._watchdog_thread.is_alive():
            self._watchdog_thread.join(timeout=5)
        self._watchdog_thread = None

    def _watchdog_loop(self):
        # type: () -> None
        while not self._watchdog_stop.wait(self.watchdog_interval):
            try:
                self._watchdog_tick()
                self._maybe_log_health()
            except Exception as e:
                self.logger.error("watchdog tick failed: {}".format(e))

    def _maybe_log_health(self):
        # type: () -> None
        """设计 §9.2：每 60s 限速 logger.info 一行 JSON 健康快照。"""
        now = time.time()
        if now - self._last_health_log_ts < self._health_log_interval_s:
            return
        self._last_health_log_ts = now
        try:
            import json
            health = self.get_health()
            self.logger.info("health_snapshot %s", json.dumps(health, default=str))
        except Exception as e:
            try:
                # fallback key=value summary without json
                h = self.get_health()
                parts = ["running={}".format(h.get("running"))]
                for name, mh in (h.get("monitors") or {}).items():
                    parts.append(
                        "{}:running={}:errs={}:alive={}".format(
                            name,
                            mh.get("running"),
                            mh.get("collect_error_count"),
                            mh.get("thread_alive"),
                        )
                    )
                self.logger.info("health_snapshot %s", " ".join(parts))
            except Exception as e2:
                self.logger.warning("health log failed: {} / {}".format(e, e2))

    def _watchdog_tick(self):
        # type: () -> None
        """双条件 watchdog：死线程 / stale success / error delta。"""
        now = time.time()
        with self.state_lock:
            names = list(self.monitors.keys())
        for name in names:
            with self.state_lock:
                mon = self.monitors.get(name)
                status = self.monitor_status.get(name)
            if mon is None or status is None:
                continue
            if not status.running:
                continue
            if status.degraded:
                continue

            reason = None
            # 软等待（ufunc waiting_for_process）：勿因 last_success_ts==0 触发重启
            waiting = bool(getattr(mon, "waiting_for_process", False))

            # 1) 线程已死（软等待期间若线程挂掉仍需重启）
            if not mon.is_thread_alive():
                reason = "dead_thread"
            elif waiting:
                # 故意等待目标进程/二进制：跳过 stale / no_success_yet
                # 采集路径若在疯狂报错，仍用错误增量触发
                err = int(getattr(mon, "collect_error_count", 0) or 0)
                delta = err - int(status.last_error_count_snapshot or 0)
                status.last_error_count_snapshot = err
                if delta >= self.watchdog_error_delta:
                    reason = "error_delta"
            else:
                # 2) 成功采集时间过旧
                interval = float(getattr(mon, "interval", 2) or 2)
                stale_limit = interval * self.watchdog_stale_intervals
                last_ok = float(getattr(mon, "last_success_ts", 0) or 0)
                started = float(self.stats.get("start_time") or now)
                if last_ok > 0 and (now - last_ok) > stale_limit:
                    reason = "stale_success"
                elif last_ok == 0 and (now - started) > stale_limit:
                    reason = "no_success_yet"
                # 3) 采集错误增量
                err = int(getattr(mon, "collect_error_count", 0) or 0)
                delta = err - int(status.last_error_count_snapshot or 0)
                status.last_error_count_snapshot = err
                if reason is None and delta >= self.watchdog_error_delta:
                    reason = "error_delta"

            if reason:
                self.logger.warning(
                    "watchdog trigger name=%s reason=%s", name, reason
                )
                self.restart_monitor(name, reason=reason)
