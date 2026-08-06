#!/usr/bin/env python
# encoding: utf-8
"""
用户态函数监控器（ufunc）

BCC attach_uprobe / attach_uretprobe，统计聚合模式。
默认 enabled: false。符号/函数列表由运维提供（D26），禁止臆造交易符号。
"""

import os

try:
    from pathlib import Path
except ImportError:
    from ..utils.py2_compat import Path

try:
    from typing import Dict, List, Any, Optional
except ImportError:
    from ..utils.py2_compat import Dict, List, Any, Optional

from .base import BaseMonitor
from ..utils.monitor_data_utils import MonitorDataUtils
from ..utils.decorators import register_monitor
from ..utils.process_target_manager import ProcessTargetManager, decode_comm
from ..utils.config_validator import ConfigValidator


@register_monitor("ufunc")
class UfuncMonitor(BaseMonitor):
    """用户态函数调用统计监控器"""

    CONFIG_SCHEMA = {
        "target_processes": {
            "type": list,
            "required": False,
            "default": [],
            "item_type": str,
        },
        "targets": {
            "type": list,
            "required": False,
            "default": [],
        },
        "probe_limit": {
            "type": int,
            "required": False,
            "min": 1,
            "max": 256,
            "default": 32,
        },
        "resolve_from_pid": {
            "type": bool,
            "required": False,
            "default": True,
        },
    }

    CSV_COLUMNS = [
        ("comm", "comm"),
        ("func_id", "func_id"),
        ("func_name", "func_name"),
        ("tgid", "tgid"),
        ("count", "count"),
        ("avg_latency_us", "avg_latency_us"),
        ("max_latency_us", "max_latency_us"),
    ]

    CONSOLE_FORMAT = (
        "{:<16} {:>6} {:<24} {:>8} {:>8} {:>10.1f} {:>10.1f}",
        [
            "comm",
            "func_id",
            "func_name",
            "tgid",
            "count",
            "avg_latency_us",
            "max_latency_us",
        ],
        ["COMM", "FID", "FUNC", "TGID", "COUNT", "AVG_US", "MAX_US"],
    )

    def _validate_requirements(self):
        # type: () -> None
        """检查 BCC 是否具备 uprobe API；不可用时记状态，load 软失败。"""
        self._uprobe_available = True
        try:
            from bcc import BPF as _BPF  # noqa: F401
            # MockBPF / real BCC both should expose attach_uprobe after our conftest
            if not hasattr(_BPF, "attach_uprobe") and not callable(
                getattr(_BPF, "__init__", None)
            ):
                self._uprobe_available = False
        except Exception:
            # bcc 已在 conftest 注入；真实环境缺失则软失败
            pass

    def _initialize(self, config):
        # type: (Dict[str, Any]) -> None
        self.target_processes = list(config.get("target_processes") or [])
        self.targets = list(config.get("targets") or [])
        self.probe_limit = int(config.get("probe_limit") or 32)
        self.resolve_from_pid = bool(config.get("resolve_from_pid", True))
        self._ptm = ProcessTargetManager(self.target_processes, self.logger)
        self._pid_filter_enabled = bool(self._ptm.targets_nonempty)
        self._func_id_to_name = {}  # type: Dict[int, str]
        self._attach_specs = []  # type: List[Dict[str, Any]]
        self.attached_count = 0
        self.waiting_for_process = False
        self.uprobe_unavailable = False
        self._build_attach_specs()

    def _build_attach_specs(self):
        # type: () -> None
        """从配置构建 attach 规格（占位符号，运维填写）。"""
        specs = []
        func_id = 0
        for target in self.targets:
            if not isinstance(target, dict):
                continue
            binary = target.get("binary") or ""
            symbols = target.get("symbols") or []
            for sym in symbols:
                if func_id >= self.probe_limit:
                    break
                if isinstance(sym, dict):
                    name = sym.get("name") or ""
                    retprobe = bool(sym.get("retprobe", False))
                else:
                    name = str(sym)
                    retprobe = False
                if not name:
                    continue
                specs.append({
                    "func_id": func_id,
                    "name": name,
                    "binary": binary,
                    "retprobe": retprobe,
                })
                self._func_id_to_name[func_id] = name
                func_id += 1
            if func_id >= self.probe_limit:
                break
        self._attach_specs = specs

    def _pid_filter_targets_nonempty(self):
        # type: () -> bool
        return bool(getattr(self, "_pid_filter_enabled", False))

    def get_extra_cflags(self):
        # type: () -> List[str]
        if self._pid_filter_targets_nonempty():
            return ["-DENABLE_PID_FILTER=1"]
        return []

    def get_ebpf_code(self):
        # type: () -> str
        template_code = super(UfuncMonitor, self).get_ebpf_code()
        probe_functions = ""
        for spec in self._attach_specs:
            fid = spec["func_id"]
            if spec.get("retprobe"):
                probe_functions += """
int trace_ufunc_entry_{fid}(struct pt_regs *ctx) {{
    ufunc_entry_store({fid});
    return 0;
}}
int trace_ufunc_ret_{fid}(struct pt_regs *ctx) {{
    ufunc_ret_update({fid});
    return 0;
}}
""".format(fid=fid)
            else:
                probe_functions += """
int trace_ufunc_entry_{fid}(struct pt_regs *ctx) {{
    ufunc_entry_count_only({fid});
    return 0;
}}
""".format(fid=fid)
        return template_code.replace("PROBE_FUNCTIONS", probe_functions)

    def _resolve_attach_specs(self):
        # type: () -> List[Dict[str, Any]]
        """解析可 attach 的 specs（binary 存在）。"""
        # 重建 from config if empty (retry after operator filled / process appeared)
        if not self._attach_specs:
            self._build_attach_specs()
        resolved = []
        for spec in self._attach_specs:
            binary = spec.get("binary") or ""
            if not binary and self.resolve_from_pid:
                binary = self._resolve_binary_from_pid() or ""
            if not binary or not os.path.isfile(binary):
                continue
            s = dict(spec)
            s["binary"] = binary
            resolved.append(s)
        return resolved

    def load_ebpf_program(self):
        # type: () -> bool
        """
        软失败 / 软等待（设计 4.3.2）：
        - 无 binary / 进程时返回 True、attached_count=0、waiting_for_process=True，
          由 _on_collect_tick 周期性重试 resolve+attach；
        - 不因短暂无进程而让 eBPFMonitor 永久跳过本监控器。
        """
        if not self.enabled:
            return False

        resolved = self._resolve_attach_specs()
        if not resolved:
            # 无有效 binary：进入 soft-wait（仍算 load 成功，便于 run 循环重试）
            self.waiting_for_process = True
            self.attached_count = 0
            self.logger.warning(
                "ufunc: waiting_for_process (no valid binary yet); "
                "will retry each interval"
            )
            return True

        self._attach_specs = resolved
        self.waiting_for_process = False
        ok = super(UfuncMonitor, self).load_ebpf_program()
        if not ok:
            # attach 全失败：仍可 soft-wait 重试（除非 uprobe 完全不可用）
            if self.uprobe_unavailable:
                return False
            self.waiting_for_process = True
            self.attached_count = 0
            return True
        return True

    def _retry_load_attach(self):
        # type: () -> None
        """waiting_for_process 时每周期重试 resolve + load/attach。"""
        if self.attached_count > 0 and self.bpf is not None:
            self.waiting_for_process = False
            return
        resolved = self._resolve_attach_specs()
        if not resolved:
            return
        self._attach_specs = resolved
        self.logger.info("ufunc: retrying load/attach after waiting_for_process")
        # 若已有 bpf，先 cleanup 再重建（符号/路径可能变化）
        if self.bpf is not None:
            try:
                self.bpf.cleanup()
            except Exception:
                pass
            self.bpf = None
            self._cleaned_up = False
        try:
            ok = super(UfuncMonitor, self).load_ebpf_program()
            if ok and self.attached_count > 0:
                self.waiting_for_process = False
                self.logger.info(
                    "ufunc: attach succeeded after wait (count={})".format(
                        self.attached_count
                    )
                )
        except Exception as e:
            self.logger.warning("ufunc: retry load/attach failed: {}".format(e))

    def _resolve_binary_from_pid(self):
        # type: () -> Optional[str]
        self._ptm.refresh()
        pids = self._ptm.get_pids()
        for pid in pids:
            exe = "/proc/{}/exe".format(pid)
            try:
                return os.readlink(exe)
            except (OSError, IOError):
                continue
        return None

    def _sync_pid_allow(self):
        # type: () -> None
        if self._pid_filter_targets_nonempty() and self.bpf is not None:
            self._ptm.refresh()
            self._ptm.sync_pid_allow_map(self.bpf, "pid_allow")

    def _on_collect_tick(self):
        # type: () -> None
        """运行时 pid_allow 刷新 + soft-wait 重试 attach。"""
        if self.waiting_for_process or self.attached_count == 0:
            self._retry_load_attach()
        self._sync_pid_allow()

    def _configure_ebpf_program(self):
        # type: () -> None
        if self.bpf is None:
            return
        self._sync_pid_allow()

        attached = 0
        for spec in self._attach_specs:
            binary = spec["binary"]
            name = spec["name"]
            fid = spec["func_id"]
            try:
                self.bpf.attach_uprobe(
                    name=binary,
                    sym=name,
                    fn_name="trace_ufunc_entry_{}".format(fid),
                    pid=-1,
                )
                if spec.get("retprobe"):
                    self.bpf.attach_uretprobe(
                        name=binary,
                        sym=name,
                        fn_name="trace_ufunc_ret_{}".format(fid),
                        pid=-1,
                    )
                attached += 1
                self.logger.debug("ufunc attached {} on {}".format(name, binary))
            except Exception as e:
                self.logger.warning(
                    "ufunc attach failed {}@{}: {}".format(name, binary, e)
                )
        self.attached_count = attached
        if attached == 0:
            # soft-wait：不 raise，让 load 返回 True 并在 tick 重试
            self.waiting_for_process = True
            self.uprobe_unavailable = False
            self.logger.warning("ufunc: 0 probes attached; waiting_for_process")
            return

    def _normalize_stat_row(self, stat_data, record_type):
        # type: (Dict[str, Any], str) -> Dict[str, Any]
        out = dict(stat_data)
        out["comm"] = decode_comm(out.get("comm", ""))
        fid = int(out.get("func_id") or 0)
        out["func_id"] = fid
        out["func_name"] = self._func_id_to_name.get(fid, "unknown_{}".format(fid))
        out["tgid"] = int(out.get("tgid") or 0)
        count = int(out.get("count") or 0)
        total_ns = int(out.get("total_ns") or 0)
        max_ns = int(out.get("max_ns") or 0)
        out["count"] = count
        out["avg_latency_us"] = MonitorDataUtils.calc_avg_latency_us(total_ns, count)
        out["max_latency_us"] = MonitorDataUtils.calc_max_latency_us(max_ns)
        return out

    def should_collect(self, key, value):
        # type: (Any, Any) -> bool
        return self._ptm.should_include_comm(getattr(key, "comm", b""))

    def get_health(self):
        # type: () -> Dict[str, Any]
        h = super(UfuncMonitor, self).get_health()
        h["waiting_for_process"] = getattr(self, "waiting_for_process", False)
        h["uprobe_unavailable"] = getattr(self, "uprobe_unavailable", False)
        h["attached_count"] = getattr(self, "attached_count", 0)
        return h
