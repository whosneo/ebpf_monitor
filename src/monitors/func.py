#!/usr/bin/env python
# encoding: utf-8
"""
内核函数监控器

监控指定模式的内核函数调用。
"""

# 标准库导入
import re

# 兼容性导入
try:
    from pathlib import Path
except ImportError:
    from ..utils.py2_compat import Path
try:
    from typing import Dict, List, Any
except ImportError:
    from ..utils.py2_compat import Dict, List, Any

# 本地模块导入
from .base import BaseMonitor
from ..utils.decorators import register_monitor


@register_monitor("func")
class FuncMonitor(BaseMonitor):
    """内核函数监控器"""

    # 配置模式定义
    # patterns: 内核函数名匹配模式列表，支持通配符*和?
    # probe_limit: 最大探针数量限制，防止匹配过多函数影响系统性能
    CONFIG_SCHEMA = {
        "patterns": {
            "type": list,
            "required": True,
            "min_length": 1,
            "item_type": str,
            "default": ["vfs_*"],  # 默认匹配VFS层函数（虚拟文件系统）
        },
        "probe_limit": {
            "type": int,
            "required": True,
            "min": 1,
            "max": 100,
            "default": 10,  # 默认最多附加10个探针
        }
    }

    def _validate_requirements(self):
        """验证内核函数监控要求"""
        if not Path("/proc/kallsyms").exists():
            raise RuntimeError("/proc/kallsyms 不可用，无法获取内核函数列表")

    def _initialize(self, config):
        # type: (Dict[str, Any]) -> None
        """初始化内核函数监控器"""
        # 查找匹配的函数（配置字段已由基类自动赋值）
        self.matched_functions = self._find_matching_functions()  # type: Dict[int, str]

    def _find_matching_functions(self):
        # type: () -> Dict[int, str]
        """查找匹配模式的内核函数"""
        matched = {}  # type: Dict[int, str]
        func_id = 0

        k_all_syms_path = "/proc/kallsyms"
        # 读取可用的内核函数列表
        with open(k_all_syms_path, "r") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 3:
                    # 格式: address type name [module]
                    symbol_type, symbol_name = parts[1], parts[2]

                    # 只关注内核函数 (type "T" 或 "t")
                    if symbol_type.lower() == "t":
                        # 检查是否匹配任何模式
                        for pattern in self.patterns:
                            if self._match_pattern(symbol_name, pattern):
                                matched[func_id] = symbol_name
                                func_id += 1
                                break

                    # 限制匹配数量
                    if len(matched) >= self.probe_limit:
                        break

        self.logger.info("找到 {} 个匹配的函数，模式: {}".format(len(matched), self.patterns))
        self.logger.debug("匹配的函数: {}".format(matched))
        return matched

    def _match_pattern(self, symbol_name, pattern):
        # type: (str, str) -> bool
        """检查符号名是否匹配模式"""
        # 将shell风格的通配符转换为正则表达式
        regex_pattern = "^{}$".format(pattern.replace("*", ".*").replace("?", "."))
        try:
            return bool(re.match(regex_pattern, symbol_name))
        except re.error:
            return False

    def get_ebpf_code(self):
        # type: () -> str
        """基于模板生成动态eBPF程序"""
        if not self.matched_functions:
            raise RuntimeError("没有匹配的函数")

        template_code = super(FuncMonitor, self).get_ebpf_code()

        # 生成探针函数代码
        probe_functions = ""
        for func_id in self.matched_functions.keys():
            probe_functions += '''
int trace_func_{func_id} (struct pt_regs *ctx) {{
    update_func_stats(ctx, {func_id});
    return 0;
}}
'''.format(func_id=func_id)
        # 替换占位符
        ebpf_code = template_code.replace("PROBE_FUNCTIONS", probe_functions)
        return ebpf_code

    def _configure_ebpf_program(self):
        """配置eBPF程序"""
        # 附加探针
        attached_count = 0
        for func_id, func_name in self.matched_functions.items():
            try:
                self.bpf.attach_kprobe(event=func_name, fn_name="trace_func_{}".format(func_id))
                attached_count += 1
                self.logger.debug("成功附加探针到函数 {}".format(func_name))
            except Exception as e:
                self.logger.warning("无法附加探针到函数 {}: {}".format(func_name, e))

        if attached_count == 0:
            raise RuntimeError("没有成功附加任何探针")

        self.logger.info("成功附加 {} 个函数探针".format(attached_count))

    # ==================== 格式化方法实现 ====================

    def _resolve_func_name(self, func_id):
        # type: (int) -> str
        """根据func_id解析函数名（需访问实例属性 matched_functions）"""
        return self.matched_functions.get(func_id, "unknown_{}".format(func_id))

    CSV_COLUMNS = [
        ("comm", "comm"),
        ("func_name", "func_id", _resolve_func_name),
        ("count", "count"),
    ]

    CONSOLE_FORMAT = (
        "{:<16} {:<32} {:>}",
        ["comm", ("func_id", _resolve_func_name), "count"],
        ["COMM", "FUNC", "COUNT"],
    )
