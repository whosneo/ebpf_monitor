#!/usr/bin/env python
# encoding: utf-8
"""
按进程名目标管理器（ProcessTargetManager）

统一进程名 → PID 集合解析，以及 BPF pid_allow map 的写新后删旧同步。
空目标列表语义：允许全部（用户态 should_include_* 返回 True；调用方不得启用内核过滤）。
"""

import os
import time

try:
    from typing import Any, Dict, List, Optional, Set
except ImportError:
    from .py2_compat import Any, Dict, List, Optional, Set  # type: ignore


# 内核 TASK_COMM_LEN 为 16，comm 最多 15 有效字符 + NUL
COMM_MAX_LEN = 15


def truncate_comm(name):
    # type: (Any) -> str
    """将配置进程名截断到内核 comm 匹配长度。"""
    if name is None:
        return ""
    if isinstance(name, bytes):
        name = name.decode("utf-8", errors="replace")
    s = str(name).rstrip("\x00").strip()
    if len(s) > COMM_MAX_LEN:
        return s[:COMM_MAX_LEN]
    return s


def decode_comm(comm):
    # type: (Any) -> str
    """解码 BPF/key 中的 comm 字段为 str。"""
    if isinstance(comm, bytes):
        return comm.decode("utf-8", errors="replace").rstrip("\x00")
    if comm is None:
        return ""
    return str(comm).rstrip("\x00")


class ProcessTargetManager(object):
    """按进程名维护 PID 集合，并同步 pid_allow map。"""

    def __init__(self, process_names, logger, match_mode="comm", refresh_interval_s=5.0):
        # type: (List[str], Any, str, float) -> None
        self.logger = logger
        self.match_mode = match_mode or "comm"
        self.refresh_interval_s = float(refresh_interval_s)
        names = process_names or []
        self._target_comms = set()  # type: Set[str]
        for n in names:
            t = truncate_comm(n)
            if t:
                self._target_comms.add(t)
        self._pids = set()  # type: Set[int]
        self._last_refresh = 0.0  # type: float
        if self._target_comms:
            self.refresh()

    @property
    def targets_nonempty(self):
        # type: () -> bool
        return bool(self._target_comms)

    def get_target_comms(self):
        # type: () -> List[str]
        return list(self._target_comms)

    def should_include_comm(self, comm):
        # type: (Any) -> bool
        """空目标列表 → True（全部允许）。"""
        if not self._target_comms:
            return True
        return truncate_comm(decode_comm(comm)) in self._target_comms

    def should_include_pid(self, pid):
        # type: (int) -> bool
        if not self._target_comms:
            return True
        self._maybe_refresh()
        return int(pid) in self._pids

    def get_pids(self):
        # type: () -> List[int]
        self._maybe_refresh()
        return list(self._pids)

    def _maybe_refresh(self):
        # type: () -> None
        now = time.time()
        if now - self._last_refresh >= self.refresh_interval_s:
            self.refresh()

    def refresh(self):
        # type: () -> None
        """扫描 /proc，更新 self._pids。"""
        self._last_refresh = time.time()
        if not self._target_comms:
            self._pids = set()
            return
        pids = set()  # type: Set[int]
        try:
            for entry in os.listdir("/proc"):
                if not entry.isdigit():
                    continue
                pid = int(entry)
                try:
                    if self.match_mode == "cmdline_basename":
                        path = "/proc/{}/cmdline".format(pid)
                        with open(path, "rb") as f:
                            raw = f.read()
                        if not raw:
                            continue
                        first = raw.split(b"\x00")[0]
                        base = os.path.basename(first.decode("utf-8", errors="replace"))
                        name = truncate_comm(base)
                    else:
                        path = "/proc/{}/comm".format(pid)
                        with open(path, "rb") as f:
                            name = truncate_comm(f.read())
                    if name in self._target_comms:
                        pids.add(pid)
                except (IOError, OSError, ValueError):
                    continue
        except (IOError, OSError) as e:
            if self.logger:
                self.logger.warning("ProcessTargetManager refresh failed: {}".format(e))
        self._pids = pids

    def sync_pid_allow_map(self, bpf, map_name="pid_allow"):
        # type: (Any, str) -> None
        """
        写新后删旧同步 pid_allow（禁止 clear-first）。

        1. 对每个 pid in new_set: map[pid] = 1
        2. 枚举现有 keys；对 key not in new_set: delete
        3. 禁止先清空再写
        """
        if bpf is None:
            return
        self._maybe_refresh()
        new_set = set(self._pids) if self._target_comms else set()
        try:
            table = bpf.get_table(map_name)
        except Exception as e:
            if self.logger:
                self.logger.error("sync_pid_allow_map get_table({}): {}".format(map_name, e))
            return

        # 1) 先写入新 PID
        for pid in new_set:
            try:
                # BCC map 通常支持 __setitem__；同时尝试 update
                key = self._as_key(table, pid)
                val = self._as_val(table, 1)
                if hasattr(table, "update"):
                    try:
                        table.update(key, val)
                        continue
                    except Exception:
                        pass
                table[key] = val
            except Exception as e:
                if self.logger:
                    self.logger.debug("pid_allow update {}: {}".format(pid, e))

        # 2) 再删除过期 PID
        try:
            existing = list(table.keys())
        except Exception:
            existing = []
        for key in existing:
            try:
                pid = int(key.value) if hasattr(key, "value") else int(key)
            except Exception:
                try:
                    pid = int(key)
                except Exception:
                    continue
            if pid not in new_set:
                try:
                    if hasattr(table, "items") and hasattr(table, "__delitem__"):
                        del table[key]
                    elif hasattr(table, "pop"):
                        table.pop(key)
                    else:
                        del table[key]
                except Exception:
                    try:
                        table.delete(key)
                    except Exception:
                        pass

    @staticmethod
    def _as_key(table, pid):
        # type: (Any, int) -> Any
        """尽量构造与 table.Key 兼容的 key。"""
        Key = getattr(table, "Key", None)
        if Key is not None:
            try:
                k = Key()
                if hasattr(k, "value"):
                    k.value = pid
                    return k
            except Exception:
                pass
        return pid

    @staticmethod
    def _as_val(table, value):
        # type: (Any, int) -> Any
        Leaf = getattr(table, "Leaf", None)
        if Leaf is not None:
            try:
                v = Leaf()
                if hasattr(v, "value"):
                    v.value = value
                    return v
            except Exception:
                pass
        return value


def sync_pid_allow_write_then_delete(table, new_pids, ops_log=None):
    # type: (Any, Set[int], Optional[List[str]]) -> List[str]
    """
    纯算法辅助：对 mock map 执行写新后删旧，记录操作序。

    ops_log 追加 "update:<pid>" / "delete:<pid>"。
    用于单测验证禁止先清空再写入。
    """
    if ops_log is None:
        ops_log = []
    new_set = set(int(p) for p in new_pids)
    # 先写新
    for pid in sorted(new_set):
        table[pid] = 1
        ops_log.append("update:{}".format(pid))
    # 再删旧
    for key in list(table.keys()):
        pid = int(key)
        if pid not in new_set:
            del table[key]
            ops_log.append("delete:{}".format(pid))
    return ops_log
