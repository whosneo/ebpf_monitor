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
from ..utils.py2_compat import compat_super


@register_monitor("func")
class FuncMonitor(BaseMonitor):
    """内核函数监控器"""

    @classmethod
    def get_default_monitor_config(cls):
        # type: () -> Dict[str, Any]
        """获取func监控器默认配置"""
        return {
            "patterns": ["vfs_*"],  # 匹配模式
            "probe_limit": 10  # 最大探针数量
        }

    @classmethod
    def validate_monitor_config(cls, config):
        # type: (Dict[str, Any]) -> None
        """
        验证func监控器配置
        
        Args:
            config: 监控器配置字典
            
        Raises:
            ValueError: 配置验证失败时抛出
        """
        if config.get("patterns") is None:
            raise ValueError("func监控配置中缺少必需字段: patterns")
        if not isinstance(config.get("patterns"), list):
            raise ValueError("patterns 必须为列表，当前类型: {}".format(type(config.get("patterns")).__name__))
        if len(config.get("patterns")) == 0:
            raise ValueError("patterns 列表不能为空")
        if config.get("probe_limit") is None:
            raise ValueError("func监控配置中缺少必需字段: probe_limit")
        if not isinstance(config.get("probe_limit"), int):
            raise ValueError("probe_limit 必须为整数，当前类型: {}".format(type(config.get("probe_limit")).__name__))
        if config.get("probe_limit") < 1:
            raise ValueError("probe_limit 必须大于等于 1，当前值: {}".format(config.get("probe_limit")))
        if config.get("probe_limit") > 100:
            raise ValueError("probe_limit 必须小于等于 100，当前值: {}".format(config.get("probe_limit")))

    def _validate_requirements(self):
        """验证内核函数监控要求"""
        if not Path("/proc/kallsyms").exists():
            raise RuntimeError("/proc/kallsyms 不可用，无法获取内核函数列表")

    def _initialize(self, config):
        # type: (Dict[str, Any]) -> None
        """初始化内核函数监控器"""
        # 应用配置
        self.patterns = config.get("patterns")  # type: List[str]
        self.probe_limit = config.get("probe_limit")  # type: int

        # 查找匹配的函数
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

    def _get_ebpf_code(self):
        # type: () -> str
        """基于模板生成动态eBPF程序"""
        if not self.matched_functions:
            raise RuntimeError("没有匹配的函数")

        template_code = compat_super(FuncMonitor, self)._get_ebpf_code()

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

    def monitor_csv_header(self):
        # type: () -> List[str]
        """获取CSV头部字段"""
        return ["comm", "func_name", "count"]

    def monitor_csv_data(self, data):
        # type: (Dict[str, Any]) -> Dict[str, Any]
        """将事件数据格式化为CSV行数据"""
        # 处理字节字符串
        return {
            "comm": data["comm"],
            "func_name": self.matched_functions.get(data["func_id"], "unknown_{}".format(data["func_id"])),
            "count": data["count"]
        }

    def monitor_console_header(self):
        # type: () -> str
        """获取控制台输出的表头"""
        return "{:<16} {:<32} {}".format("COMMAND", "FUNCTION", "COUNT")

    def monitor_console_data(self, data):
        # type: (Dict[str, Any]) -> str
        """将事件数据格式化为控制台输出"""
        return "{:<16} {:<32} {}".format(
            data["comm"],
            self.matched_functions.get(data["func_id"], "unknown_{}".format(data["func_id"])),
            data["count"]
        )
