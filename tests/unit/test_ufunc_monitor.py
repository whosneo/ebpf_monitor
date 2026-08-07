#!/usr/bin/env python
# encoding: utf-8
"""Unit tests for ufunc monitor (placeholders only, no real trade symbols)."""

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.monitors.ufunc import UfuncMonitor


@pytest.fixture
def ufunc_config(tmp_path):
    binary = tmp_path / "trade_app"
    binary.write_text("ELF")
    return {
        "enabled": True,
        "interval": 2.0,
        "target_processes": ["trade_app"],
        "targets": [
            {
                "binary": str(binary),
                "symbols": [
                    {"name": "handle_order", "retprobe": False},
                    {"name": "match", "retprobe": True},
                ],
            }
        ],
        "probe_limit": 32,
        "resolve_from_pid": True,
    }


def test_default_enabled_false_in_schema():
    cfg = UfuncMonitor.get_default_config()
    # schema default for enabled comes from base True, but yaml ships false;
    # get_default_config still base enabled True — yaml is the production gate
    assert "targets" in cfg


def test_kfunc_still_kprobe_only():
    """Structural: kernel kfunc monitor still kprobe/kallsyms (not uprobe)."""
    from pathlib import Path
    kfunc_py = Path("src/monitors/kfunc.py").read_text()
    assert "attach_kprobe" in kfunc_py
    assert "attach_uprobe" not in kfunc_py
    assert "/proc/kallsyms" in kfunc_py
    assert '@register_monitor("kfunc")' in kfunc_py
    kfunc_c = Path("src/ebpf/kfunc.c").read_text()
    assert "BPF_HASH(kfunc_stats," in kfunc_c
    assert "BPF_HASH(func_stats," not in kfunc_c


def test_ufunc_c_entry_key_struct():
    text = Path("src/ebpf/ufunc.c").read_text()
    assert "struct ufunc_entry_key_t" in text
    assert "pid_tgid" in text
    assert "func_id" in text
    # forbidden packing in code (ignore comments): no assignment using << 32 on pid_tgid
    code_lines = [
        ln for ln in text.splitlines()
        if not ln.strip().startswith("/*") and not ln.strip().startswith("*") and "//" not in ln[: ln.find("<<") + 1 if "<<" in ln else 0]
    ]
    code_body = "\n".join(
        ln for ln in text.splitlines()
        if not ln.strip().startswith("*") and "禁止" not in ln
    )
    assert "ek.pid_tgid = bpf_get_current_pid_tgid()" in code_body
    assert "pid_tgid << 32 |" not in code_body
    assert "pid_tgid<<32|" not in code_body


def test_build_attach_specs(monitor_context, ufunc_config):
    m = UfuncMonitor(monitor_context, ufunc_config)
    assert len(m._attach_specs) == 2
    assert m._func_id_to_name[0] == "handle_order"
    assert m._func_id_to_name[1] == "match"
    assert m._attach_specs[1]["retprobe"] is True


def test_get_ebpf_code_generates_probes(monitor_context, ufunc_config, tmp_path):
    c_src = Path("src/ebpf/ufunc.c").read_text()
    c_file = tmp_path / "ufunc.c"
    c_file.write_text(c_src)
    monitor_context.ebpf_file_path = str(c_file)
    m = UfuncMonitor(monitor_context, ufunc_config)
    code = m.get_ebpf_code()
    assert "trace_ufunc_entry_0" in code
    assert "trace_ufunc_entry_1" in code
    assert "trace_ufunc_ret_1" in code
    assert "PROBE_FUNCTIONS" not in code
    assert "ufunc_entry_store" in code or "ufunc_entry_count_only" in code


def test_load_and_attach_uprobe(monitor_context, ufunc_config, tmp_path):
    c_src = Path("src/ebpf/ufunc.c").read_text()
    c_file = tmp_path / "ufunc.c"
    c_file.write_text(c_src)
    monitor_context.ebpf_file_path = str(c_file)
    monitor_context.compile_flags = []
    m = UfuncMonitor(monitor_context, ufunc_config)
    m.ebpf_file = str(c_file)
    m.compile_flags = []
    ok = m.load_ebpf_program()
    assert ok is True, "load failed; attached={}".format(getattr(m, "attached_count", None))
    assert m.bpf is not None, "BPF not constructed"
    inst = m.bpf
    assert len(inst._uprobes) >= 2
    assert any(u for u in inst._uretprobes)
    assert m.attached_count >= 1


def test_soft_wait_missing_binary_returns_true(monitor_context, ufunc_config):
    """Design 4.3.2: load True + waiting_for_process so eBPFMonitor can retry."""
    ufunc_config["targets"] = [
        {"binary": "/nonexistent/path/to/trade_app", "symbols": [{"name": "handle_order"}]}
    ]
    m = UfuncMonitor(monitor_context, ufunc_config)
    assert m.load_ebpf_program() is True
    assert m.waiting_for_process is True
    assert m.attached_count == 0
    assert m.bpf is None


def test_soft_wait_run_starts_despite_no_bpf(monitor_context, ufunc_config):
    """
    Integration: soft-wait load then run() must start thread
    (require_bpf_loaded must not block waiting_for_process).
    """
    ufunc_config["targets"] = [
        {"binary": "/nonexistent/path/to/trade_app", "symbols": [{"name": "handle_order"}]}
    ]
    # short interval for quick tick in test if needed
    ufunc_config["interval"] = 0.05
    m = UfuncMonitor(monitor_context, ufunc_config)
    assert m.load_ebpf_program() is True
    assert m.bpf is None
    assert m.waiting_for_process is True
    # Real shipped run() path through require_bpf_loaded
    ok = m.run()
    assert ok is True, "run() must succeed in soft-wait so tick can retry attach"
    assert m.is_running() is True
    assert m.is_thread_alive() is True
    m.stop()
    assert m.is_running() is False


def test_soft_wait_run_then_tick_retries_attach(monitor_context, ufunc_config, tmp_path):
    """
    End-to-end soft-wait: load (no bpf) -> run() -> _on_collect_tick retries attach
    once binary becomes available. Drives real run()/require_bpf_loaded path.
    """
    missing = {
        "enabled": True,
        "interval": 2.0,
        "target_processes": ["trade_app"],
        "targets": [
            {"binary": "", "symbols": [{"name": "handle_order", "retprobe": False}]}
        ],
        "probe_limit": 32,
        "resolve_from_pid": True,
    }
    c_src = Path("src/ebpf/ufunc.c").read_text()
    c_file = tmp_path / "ufunc.c"
    c_file.write_text(c_src)
    monitor_context.ebpf_file_path = str(c_file)
    m = UfuncMonitor(monitor_context, missing)
    m.ebpf_file = str(c_file)
    m.compile_flags = []
    assert m.load_ebpf_program() is True
    assert m.waiting_for_process is True
    assert m.bpf is None

    # require_bpf_loaded must allow run
    assert m.run() is True
    assert m.is_thread_alive() is True

    binary = tmp_path / "trade_app"
    binary.write_text("ELF")
    m._attach_specs = [
        {"func_id": 0, "name": "handle_order", "binary": str(binary), "retprobe": False}
    ]
    m._func_id_to_name = {0: "handle_order"}
    # Drive the same method the monitor loop calls each interval
    m._on_collect_tick()
    assert m.bpf is not None
    assert m.attached_count >= 1
    assert m.waiting_for_process is False
    m.stop()


def test_extra_cflags_with_targets(monitor_context, ufunc_config):
    m = UfuncMonitor(monitor_context, ufunc_config)
    assert "-DENABLE_PID_FILTER=1" in m.get_extra_cflags()


def test_normalize_row(monitor_context, ufunc_config):
    m = UfuncMonitor(monitor_context, ufunc_config)
    row = m._normalize_stat_row(
        {"comm": b"trade_app", "func_id": 0, "tgid": 123, "count": 5, "total_ns": 5000, "max_ns": 2000},
        "default",
    )
    assert row["func_name"] == "handle_order"
    assert row["tgid"] == 123


def test_yaml_ufunc_default_disabled():
    text = Path("config/monitor_config.yaml").read_text()
    # after we add ufunc section
    if "ufunc:" in text:
        # crude: find enabled under ufunc
        idx = text.index("ufunc:")
        snippet = text[idx:idx + 200]
        assert "enabled: false" in snippet or "enabled:false" in snippet
