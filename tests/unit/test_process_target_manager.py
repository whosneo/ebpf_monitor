#!/usr/bin/env python
# encoding: utf-8
"""Unit tests for ProcessTargetManager and pid_allow resync ordering."""

from unittest.mock import MagicMock

from src.utils.process_target_manager import (
    ProcessTargetManager,
    truncate_comm,
    sync_pid_allow_write_then_delete,
)


def test_empty_targets_allow_all():
    ptm = ProcessTargetManager([], MagicMock())
    assert ptm.should_include_comm("anything") is True
    assert ptm.should_include_pid(1) is True
    assert ptm.targets_nonempty is False


def test_nonempty_filters_comm():
    ptm = ProcessTargetManager(["trade_app", "zmb"], MagicMock())
    assert ptm.should_include_comm("trade_app") is True
    assert ptm.should_include_comm("other") is False


def test_truncate_comm_15():
    long_name = "a" * 20
    assert len(truncate_comm(long_name)) == 15


def test_sync_write_then_delete_order():
    table = {1: 1, 2: 1, 99: 1}
    ops = []
    sync_pid_allow_write_then_delete(table, {2, 3}, ops)
    # must not clear-first: first ops should be updates, not mass delete of all
    assert ops[0].startswith("update:")
    assert "update:2" in ops
    assert "update:3" in ops
    assert "delete:1" in ops
    assert "delete:99" in ops
    assert 1 not in table
    assert 99 not in table
    assert table[2] == 1
    assert table[3] == 1
    # never empty-then-write pattern: no "clear" ops
    assert not any(o == "clear" for o in ops)
    # first operation is not deleting everything
    assert not ops[0].startswith("delete:")


def test_sync_pid_allow_map_uses_write_then_delete():
    """Drive ProcessTargetManager.sync_pid_allow_map against a mock table."""
    ptm = ProcessTargetManager(["no_such_proc_xyz"], MagicMock())
    # force pids
    ptm._pids = {10, 20}
    ptm._last_refresh = 1e18  # skip refresh

    class Tbl(dict):
        def keys(self):
            return list(dict.keys(self))

        def update(self, k, v):
            self[k] = v

        def pop(self, k):
            return dict.pop(self, k)

    tbl = Tbl({5: 1, 10: 1})
    bpf = MagicMock()
    bpf.get_table.return_value = tbl
    ptm.sync_pid_allow_map(bpf, "pid_allow")
    assert 10 in tbl
    assert 20 in tbl
    assert 5 not in tbl
