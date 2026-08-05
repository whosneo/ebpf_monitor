#!/usr/bin/env python
# encoding: utf-8
"""Tests for monitor registry and discovery."""

import pytest

from src.utils.decorators import register_monitor, MONITOR_REGISTRY
from src.monitors.base import BaseMonitor


@register_monitor("test_reg")
class RegProbeMonitor(BaseMonitor):
    pass


def test_registry_has_registered():
    assert "test_reg" in MONITOR_REGISTRY
    assert MONITOR_REGISTRY["test_reg"] is RegProbeMonitor


def test_get_monitor_type():
    assert RegProbeMonitor.get_monitor_type() == "test_reg"
