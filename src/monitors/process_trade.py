#!/usr/bin/env python
# encoding: utf-8
"""
交易进程级监控器

负责加载和管理交易进程级监控eBPF程序，对ZMB/ZME进程的系统调用模式进行专项分析。
采用统计模式，在内核态累积交易进程统计，定期批量输出。

统计维度：
- process_trade_stats: (进程名, 系统调用分类) -> (调用次数, 错误次数, 延迟统计)
- process_trade_ipc_stats: (进程名, IPC类型) -> (调用次数, 延迟统计)

模式：STATISTICAL（统计聚合）
"""

try:
    from typing import Dict, List, Any
except ImportError:
    from ..utils.py2_compat import Dict, List, Any

from .base import BaseMonitor
from ..utils.monitor_data_utils import MonitorDataUtils
from ..utils.decorators import register_monitor
from ..utils.process_target_manager import (
    ProcessTargetManager,
    decode_comm,
    truncate_comm,
)


# ==================== 系统调用分类常量 ====================

SCAT_FILE_IO = 1
SCAT_NETWORK = 2
SCAT_MEMORY = 3
SCAT_PROCESS = 4
SCAT_IPC = 5
SCAT_TIME = 6
SCAT_SIGNAL = 7
SCAT_OTHER = 0

IPC_TYPE_TO_CATEGORY = {
    1: "IPC_PIPE",
    2: "IPC_SHM",
    3: "IPC_FUTEX",
    4: "IPC_MSG",
}


def category_to_str(category):
    # type: (int) -> str
    """将系统调用分类转换为字符串"""
    categories = {
        SCAT_FILE_IO: "FILE_IO",
        SCAT_NETWORK: "NETWORK",
        SCAT_MEMORY: "MEMORY",
        SCAT_PROCESS: "PROCESS",
        SCAT_IPC: "IPC",
        SCAT_TIME: "TIME",
        SCAT_SIGNAL: "SIGNAL",
        SCAT_OTHER: "OTHER",
    }
    return categories.get(int(category) if category is not None else -1, "UNKNOWN")


def ipc_type_to_category(ipc_type):
    # type: (int) -> str
    return IPC_TYPE_TO_CATEGORY.get(int(ipc_type) if ipc_type is not None else -1, "IPC_UNKNOWN")


def calc_error_rate(count, error_count):
    # type: (int, int) -> float
    """计算错误率（百分比）"""
    if count == 0:
        return 0.0
    return (error_count * 100.0) / count


@register_monitor("process_trade")
class ProcessTradeMonitor(BaseMonitor):
    """交易进程级监控器 - 统计聚合模式"""

    CONFIG_SCHEMA = {
        "zmb_processes": {
            "type": list,
            "required": True,
            "item_type": str,
            "default": [],
        },
        "zme_processes": {
            "type": list,
            "required": True,
            "item_type": str,
            "default": [],
        },
        "monitor_syscalls": {
            "type": bool,
            "required": False,
            "default": True,
        },
        "monitor_ipc": {
            "type": bool,
            "required": False,
            "default": True,
        },
    }

    # 声明式 CSV：仅简单二元组（派生列在 _normalize_stat_row 写平）
    CSV_COLUMNS = [
        ("record_type", "record_type"),
        ("comm", "comm"),
        ("category", "category"),
        ("count", "count"),
        ("error_count", "error_count"),
        ("error_rate", "error_rate"),
        ("avg_latency_us", "avg_latency_us"),
        ("min_latency_us", "min_latency_us"),
        ("max_latency_us", "max_latency_us"),
    ]

    CONSOLE_FORMAT = (
        "{:<8} {:<16} {:<12} {:>8} {:>8} {:>7.1f}% {:>10.1f} {:>10.1f} {:>10.1f}",
        [
            "record_type",
            "comm",
            "category",
            "count",
            "error_count",
            "error_rate",
            "avg_latency_us",
            "min_latency_us",
            "max_latency_us",
        ],
        ["TYPE", "COMM", "CATEGORY", "COUNT", "ERRORS", "ERR%", "AVG_LAT", "MIN_LAT", "MAX_LAT"],
    )

    @classmethod
    def validate_config(cls, config):
        # type: (Dict[str, Any]) -> None
        BaseMonitor.validate_config(config)
        if not config.get("enabled"):
            return
        ms = config.get("monitor_syscalls", True)
        mi = config.get("monitor_ipc", True)
        if ms is False and mi is False:
            raise ValueError(
                "process_trade: monitor_syscalls and monitor_ipc cannot both be false"
            )

    def _initialize(self, config):
        # type: (Dict[str, Any]) -> None
        self.zmb_processes = list(config.get("zmb_processes") or [])
        self.zme_processes = list(config.get("zme_processes") or [])
        self.monitor_syscalls = config.get("monitor_syscalls", True)
        self.monitor_ipc = config.get("monitor_ipc", True)

        tables = []
        if self.monitor_syscalls:
            tables.append(("process_trade_stats", "syscall"))
        if self.monitor_ipc:
            tables.append(("process_trade_ipc_stats", "ipc"))
        if not tables:
            raise ValueError(
                "process_trade: monitor_syscalls and monitor_ipc cannot both be false"
            )
        # 实例属性覆盖类属性（D24）
        self.STATS_TABLES = tables

        names = []
        for n in self.zmb_processes + self.zme_processes:
            t = truncate_comm(n)
            if t and t not in names:
                names.append(t)
        self._ptm = ProcessTargetManager(names, self.logger)
        # cflag 与 sync 共用：仅当截断后仍有真实进程名时启用内核白名单
        self._pid_filter_enabled = bool(names)

    def _pid_filter_targets_nonempty(self):
        # type: () -> bool
        """与 _pid_filter_enabled 一致（截断后非空），禁止空串/空白启用空白名单。"""
        return bool(getattr(self, "_pid_filter_enabled", False))

    def get_extra_cflags(self):
        # type: () -> List[str]
        if self._pid_filter_targets_nonempty():
            return ["-DENABLE_PID_FILTER=1"]
        return []

    def _configure_ebpf_program(self):
        # type: () -> None
        self._sync_pid_allow()

    def _sync_pid_allow(self):
        # type: () -> None
        if self._pid_filter_enabled and self.bpf is not None:
            self._ptm.refresh()
            self._ptm.sync_pid_allow_map(self.bpf, "pid_allow")

    def _on_collect_tick(self):
        # type: () -> None
        """运行时刷新 pid_allow，避免 load 后新起目标进程被内核丢弃。"""
        self._sync_pid_allow()

    def _normalize_stat_row(self, stat_data, record_type):
        # type: (Dict[str, Any], str) -> Dict[str, Any]
        """写平 CSV 字段；IPC 的 error/min/max 为 0。"""
        out = dict(stat_data)
        out["record_type"] = record_type
        out["comm"] = decode_comm(out.get("comm", ""))

        count = int(out.get("count") or 0)
        total_ns = int(out.get("total_ns") or 0)

        if record_type == "ipc":
            out["category"] = ipc_type_to_category(out.get("ipc_type", -1))
            out["error_count"] = 0
            out["error_rate"] = 0.0
            out["avg_latency_us"] = MonitorDataUtils.calc_avg_latency_us(total_ns, count)
            out["min_latency_us"] = 0.0
            out["max_latency_us"] = 0.0
        else:
            # syscall
            cat = out.get("syscall_category", out.get("category", SCAT_OTHER))
            out["category"] = category_to_str(cat)
            error_count = int(out.get("error_count") or 0)
            out["error_count"] = error_count
            out["error_rate"] = calc_error_rate(count, error_count)
            out["avg_latency_us"] = MonitorDataUtils.calc_avg_latency_us(total_ns, count)
            out["min_latency_us"] = MonitorDataUtils.calc_min_latency_us(
                int(out.get("min_ns") or 0)
            )
            out["max_latency_us"] = MonitorDataUtils.calc_max_latency_us(
                int(out.get("max_ns") or 0)
            )
        out["count"] = count
        return out

    def should_collect(self, key, value):
        # type: (Any, Any) -> bool
        """进程名过滤；空 zmb+zme = 全部。"""
        comm = decode_comm(getattr(key, "comm", b""))
        return self._ptm.should_include_comm(comm)
