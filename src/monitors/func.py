#!/usr/bin/env python3
# encoding: utf-8
"""
内核函数监控器

监控指定模式的内核函数调用。
"""

import ctypes as ct
import re
from pathlib import Path
from typing import Dict, List, Any

from .base import BaseEvent, BaseMonitor
from ..utils.data_processor import DataProcessor
from ..utils.decorators import register_monitor


class FuncEvent(BaseEvent):
    """内核函数调用事件"""
    _fields_ = [
        ("pid", ct.c_uint32),  # 进程ID
        ("ppid", ct.c_uint32),  # 父进程ID
        ("uid", ct.c_uint32),  # 用户ID
        ("func_id", ct.c_uint32),  # 函数ID
        ("comm", ct.c_char * 16),  # 进程名
    ]


@register_monitor("func")
class FuncMonitor(BaseMonitor):
    """内核函数监控器"""
    EVENT_TYPE: type = FuncEvent

    @classmethod
    def get_default_config(cls) -> Dict[str, Any]:
        """获取func监控器默认配置"""
        return {
            "enabled": True,
            "patterns": ["vfs_*"],  # 匹配模式
            "probe_limit": 10  # 最大探针数量
        }

    @classmethod
    def validate_monitor_config(cls, config: Dict[str, Any]):
        """验证func监控器配置"""
        assert config.get("patterns") is not None, "patterns不能为空"
        assert isinstance(config.get("patterns"), list), "patterns必须为列表"
        assert len(config.get("patterns")) > 0, "patterns列表不能为空"
        assert config.get("probe_limit") is not None, "probe_limit不能为空"
        assert isinstance(config.get("probe_limit"), int), "probe_limit必须为整数"
        assert config.get("probe_limit") >= 1, "probe_limit必须大于等于1"
        assert config.get("probe_limit") <= 100, "probe_limit必须小于等于100"

    def _validate_requirements(self):
        """验证内核函数监控要求"""
        if not Path("/proc/kallsyms").exists():
            raise RuntimeError("/proc/kallsyms 不可用，无法获取内核函数列表")

    def _initialize(self, config: Dict[str, Any]):
        """初始化内核函数监控器"""
        # 应用配置
        self.enabled: bool = config.get("enabled")
        self.patterns: List[str] = config.get("patterns")
        self.probe_limit: int = config.get("probe_limit")

        # 查找匹配的函数
        self.matched_functions: Dict[int, str] = self._find_matching_functions()

    def _find_matching_functions(self) -> Dict[int, str]:
        """查找匹配模式的内核函数"""
        matched: Dict[int, str] = {}
        func_id = 0

        k_all_syms_path = "/proc/kallsyms"
        # 读取可用的内核函数列表
        with open(k_all_syms_path, 'r') as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 3:
                    # 格式: address type name [module]
                    symbol_type, symbol_name = parts[1], parts[2]

                    # 只关注内核函数 (type 'T' 或 't')
                    if symbol_type.lower() == 't':
                        # 检查是否匹配任何模式
                        for pattern in self.patterns:
                            if self._match_pattern(symbol_name, pattern):
                                matched[func_id] = symbol_name
                                func_id += 1
                                break

                    # 限制匹配数量
                    if len(matched) >= self.probe_limit:
                        break

        self.logger.info(f"找到 {len(matched)} 个匹配的函数，模式: {self.patterns}")
        self.logger.debug(f"匹配的函数: {matched}")
        return matched

    @staticmethod
    def _match_pattern(symbol_name: str, pattern: str) -> bool:
        """检查符号名是否匹配模式"""
        # 将shell风格的通配符转换为正则表达式
        regex_pattern = f"^{pattern.replace('*', '.*').replace('?', '.')}$"
        try:
            return bool(re.match(regex_pattern, symbol_name))
        except re.error:
            return False

    def _get_ebpf_code(self) -> str:
        """基于模板生成动态eBPF程序"""
        if not self.matched_functions:
            raise RuntimeError("没有匹配的函数")

        # 读取eBPF模板文件
        try:
            with open(self.ebpf_file, 'r', encoding='utf-8') as f:
                template_code = f.read()
        except Exception as e:
            raise RuntimeError(f"读取eBPF模板文件失败: {e}")

        # 生成探针函数代码
        probe_functions = ""
        for func_id in self.matched_functions.keys():
            probe_functions += f'''
int trace_func_{func_id}(struct pt_regs *ctx) {{
    submit_func_event(ctx, {func_id});
    return 0;
}}
'''
        # 替换占位符
        ebpf_code = template_code.replace("PROBE_FUNCTIONS", probe_functions)
        return ebpf_code

    def _configure_ebpf_program(self):
        """配置eBPF程序"""
        # 附加探针
        attached_count = 0
        for func_id, func_name in self.matched_functions.items():
            try:
                self.bpf.attach_kprobe(event=func_name, fn_name=f"trace_func_{func_id}")
                attached_count += 1
                self.logger.debug(f"成功附加探针到函数 {func_name}")
            except Exception as e:
                self.logger.warning(f"无法附加探针到函数 {func_name}: {e}")

        if attached_count == 0:
            raise RuntimeError("没有成功附加任何探针")

        self.logger.info(f"成功附加 {attached_count} 个函数探针")

    # ==================== 格式化方法实现 ====================

    def get_csv_header(self) -> List[str]:
        """获取CSV头部字段"""
        return ['timestamp', 'time_str', 'pid', 'ppid', 'uid', 'comm', 'func_name']

    def format_for_csv(self, event_data: FuncEvent) -> Dict[str, Any]:
        """将事件数据格式化为CSV行数据"""
        timestamp = self._convert_timestamp(event_data)
        time_str = DataProcessor.format_timestamp(timestamp)

        # 处理字节字符串
        comm = DataProcessor.decode_bytes(event_data.comm)
        func_name = self.matched_functions.get(event_data.func_id, f"unknown_{event_data.func_id}")

        values = [timestamp, time_str, event_data.pid, event_data.ppid, event_data.uid, comm, func_name]

        return dict(zip(self.get_csv_header(), values))

    def get_console_header(self) -> str:
        """获取控制台输出的表头"""
        return f"{'TIME':<22} {'PID':<8} {'PPID':<8} {'UID':<6} {'COMMAND':<16} {'FUNCTION'}"

    def format_for_console(self, event_data: FuncEvent) -> str:
        """将事件数据格式化为控制台输出"""
        absolute_timestamp = self._convert_timestamp(event_data)
        time_prefix = f"[{DataProcessor.format_timestamp(absolute_timestamp)}]"

        # 处理字节字符串
        comm = DataProcessor.decode_bytes(event_data.comm)
        func_name = self.matched_functions.get(event_data.func_id, f"unknown_{event_data.func_id}")

        return f"{time_prefix:<22} {event_data.pid:<8} {event_data.ppid:<8} {event_data.uid:<6} {comm:<16} {func_name}"


if __name__ == "__main__":
    """测试模式"""
    import sys
    import time
    from ..utils.application_context import ApplicationContext

    context = ApplicationContext()

    logger = context.get_logger("FuncMonitor")
    logger.info("内核函数监控测试模式")

    monitor = FuncMonitor(context, FuncMonitor.get_default_config())

    output_controller = context.output_controller
    output_controller.register_monitor("func", monitor)

    if not monitor.load_ebpf_program():
        logger.error("eBPF程序加载失败")
        sys.exit(1)

    output_controller.start()

    if not monitor.run():
        logger.error("内核函数监控启动失败")
        sys.exit(1)

    logger.info("内核函数监控已启动")
    logger.info("按 Ctrl+C 停止监控")

    try:
        while monitor.is_running():
            time.sleep(1)
    except KeyboardInterrupt:
        print()
        logger.info("用户中断，正在停止监控...")
    finally:
        monitor.stop()
        output_controller.stop()
        output_controller.unregister_monitor("func")
        monitor.cleanup()
        output_controller.cleanup()
