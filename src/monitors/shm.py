#!/usr/bin/env python
# encoding: utf-8
"""
共享内存通信监控器

负责加载和管理共享内存通信监控eBPF程序，统计System V SHM操作统计。
采用统计模式，在内核态累积共享内存操作统计，定期批量输出。

统计维度：
- (shmid, 进程名) -> (操作次数, 操作耗时统计, 错误次数)
- shmid -> (操作次数, 附加次数, 分离次数) 跟踪活跃内存段

支持的监控场景：
- 共享内存段访问热点分析
- 锁竞争检测（通过操作耗时异常判断）
- 共享内存段生命周期跟踪

模式：STATISTICAL（统计聚合）
"""

# 标准库导入
import ctypes as ct

# 兼容性导入
try:
    from typing import Dict, List, Any
except ImportError:
    from ..utils.py2_compat import Dict, List, Any

# 本地模块导入
from .base import BaseMonitor
from ..utils.monitor_data_utils import MonitorDataUtils
from ..utils.decorators import register_monitor
from ..utils.process_target_manager import ProcessTargetManager


# ==================== SHM常量定义 ====================

SHMOP_GET = 1   # shmget
SHMOP_AT = 2    # shmat
SHMOP_DT = 3    # shmdt
SHMOP_CTL = 4   # shmctl


def op_type_to_str(op_type):
    # type: (int) -> str
    """将操作类型转换为字符串"""
    ops = {
        SHMOP_GET: "GET",
        SHMOP_AT: "AT",
        SHMOP_DT: "DT",
        SHMOP_CTL: "CTL",
    }
    return ops.get(op_type, "UNKNOWN")


def calc_contention_rate(count, min_ns, max_ns):
    # type: (int, int, int) -> float
    """计算竞争率（基于延迟方差，百分比）"""
    if count < 2 or min_ns == 0:
        return 0.0
    avg_ns = max_ns  # 简化：用max/avg比值近似竞争程度
    if avg_ns == 0:
        return 0.0
    # 竞争率 = (max - min) / max * 100
    return ((max_ns - min_ns) * 100.0) / max_ns if max_ns > 0 else 0.0


# ==================== SHM监控器 ====================


@register_monitor("shm")
class ShmMonitor(BaseMonitor):
    """共享内存通信监控器 - 统计聚合模式
    
    监控System V SHM操作统计，分析内存访问模式和竞争情况。
    使用 MonitorDataUtils 进行通用的数据处理和格式化。
    """

    # 配置模式定义
    CONFIG_SCHEMA = {
        "target_shmids": {
            "type": list,
            "required": False,
            "default": [],
            "item_type": int,
        },
        "target_processes": {
            "type": list,
            "required": False,
            "default": [],
            "item_type": str,
        },
        "monitor_contention": {
            "type": bool,
            "required": False,
            "default": True,
        },
        "monitor_barriers": {
            "type": bool,
            "required": False,
            "default": False,
        },
    }

    CSV_COLUMNS = [
        ("shmid", "shmid"),
        ("comm", "comm"),
        ("access_count", "count"),
        ("err_count", "err_count"),
        ("err_rate", ("count", "err_count"), MonitorDataUtils.calc_error_rate),
        ("avg_latency_us", ("total_ns", "count"), MonitorDataUtils.calc_avg_latency_us),
        ("min_latency_us", "min_ns", MonitorDataUtils.calc_min_latency_us),
        ("max_latency_us", "max_ns", MonitorDataUtils.calc_max_latency_us),
        ("contention_rate", ("count", "min_ns", "max_ns"), calc_contention_rate),
    ]

    CONSOLE_FORMAT = (
        "{:>8} {:<16} {:>8} {:>6} {:>8.1f}% {:>10} {:>10} {:>10} {:>7.1f}%",
        [
            "shmid",
            "comm",
            "count",
            "err_count",
            (("count", "err_count"), lambda c, e: MonitorDataUtils.calc_error_rate(c, e)),
            (("total_ns", "count"), lambda tn, c: MonitorDataUtils.format_latency_ms(MonitorDataUtils.calc_avg_latency_us(tn, c))),
            ("min_ns", lambda ns: MonitorDataUtils.format_latency_ms(MonitorDataUtils.calc_min_latency_us(ns))),
            ("max_ns", lambda ns: MonitorDataUtils.format_latency_ms(MonitorDataUtils.calc_max_latency_us(ns))),
            (("count", "min_ns", "max_ns"), lambda c, mn, mx: "{:.1f}%".format(calc_contention_rate(c, mn, mx))),
        ],
        ["SHMID", "COMM", "COUNT", "ERRS", "ERR%", "AVG_LAT", "MIN_LAT", "MAX_LAT", "CONTENT"],
    )

    def _initialize(self, config):
        # type: (Dict[str, Any]) -> None
        self.target_shmids = list(config.get("target_shmids") or [])
        self.target_processes = list(config.get("target_processes") or [])
        self.monitor_contention = config.get("monitor_contention", True)
        self.monitor_barriers = config.get("monitor_barriers", False)
        self._ptm = ProcessTargetManager(self.target_processes, self.logger)

    def _configure_ebpf_program(self):
        # type: () -> None
        """多符号回退附加 SHM kprobe/kretprobe（兼容 3.10 与 4.17+ 内核）。

        不依赖 BCC 自动 kprobe__* 名（现代内核无裸名 shmat 等）。
        """
        # (fn_name, is_retprobe, symbol_candidates)
        # shmat 优先 do_shmat：直接参数 ABI，避免 __x64_sys_* 嵌套 pt_regs
        # shmctl 优先 __x64_sys_shmctl：C 侧使用包装器参数读取
        probe_specs = [
            ("trace_shmget_entry", False,
             ["ksys_shmget", "__x64_sys_shmget", "sys_shmget"]),
            ("trace_shmget_return", True,
             ["ksys_shmget", "__x64_sys_shmget", "sys_shmget"]),
            ("trace_shmat_entry", False,
             ["do_shmat", "__x64_sys_shmat", "sys_shmat"]),
            ("trace_shmat_return", True,
             ["do_shmat", "__x64_sys_shmat", "sys_shmat"]),
            ("trace_shmdt_entry", False,
             ["ksys_shmdt", "__x64_sys_shmdt", "sys_shmdt"]),
            ("trace_shmdt_return", True,
             ["ksys_shmdt", "__x64_sys_shmdt", "sys_shmdt"]),
            ("trace_shmctl_entry", False,
             ["__x64_sys_shmctl", "sys_shmctl"]),
            ("trace_shmctl_return", True,
             ["__x64_sys_shmctl", "sys_shmctl"]),
        ]

        attached = 0
        for fn_name, is_ret, symbols in probe_specs:
            last_error = None
            ok = False
            for symbol in symbols:
                try:
                    if is_ret:
                        self.bpf.attach_kretprobe(event=symbol, fn_name=fn_name)
                    else:
                        self.bpf.attach_kprobe(event=symbol, fn_name=fn_name)
                    self.logger.info(
                        "shm: 成功附加 {} 到 {}".format(
                            "kretprobe" if is_ret else "kprobe", symbol
                        )
                    )
                    attached += 1
                    ok = True
                    break
                except Exception as e:
                    last_error = e
                    self.logger.debug(
                        "shm: 无法附加 {} 到 {}，跳过: {}".format(
                            fn_name, symbol, e
                        )
                    )
            if not ok:
                self.logger.warning(
                    "shm: 探针 {} 全部符号失败，最后错误: {}".format(
                        fn_name, last_error
                    )
                )

        if attached == 0:
            raise RuntimeError(
                "Failed to attach any shm kprobe/kretprobe; "
                "no SHM symbols available on this kernel"
            )
        self.logger.info("shm: 成功附加 {} 个探针".format(attached))

    def should_collect(self, key, value):
        # type: (Any, Any) -> bool
        """判断是否应该收集数据"""
        # 目标shmid过滤
        if self.target_shmids:
            if key.shmid not in self.target_shmids:
                return False

        # 目标进程过滤（空列表 = 全部）
        if not self._ptm.should_include_comm(getattr(key, "comm", b"")):
            return False

        return True
