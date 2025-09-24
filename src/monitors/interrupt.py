#!/usr/bin/env python3
# encoding: utf-8
"""
中断监控器

负责加载和管理中断监控eBPF程序，收集硬件中断和软中断性能数据。
支持按CPU核心统计、中断延迟测量和绑核进程的中断亲和性分析。
"""

import ctypes as ct
from typing import Dict, List, Any

import psutil

from .base import BaseEvent, BaseMonitor
from ..utils.data_processor import DataProcessor
from ..utils.decorators import register_monitor


class InterruptEvent(BaseEvent):
    """中断事件"""
    _fields_ = [
        ("pid", ct.c_uint32),  # 进程ID
        ("tid", ct.c_uint32),  # 线程ID
        ("irq_num", ct.c_uint32),  # 中断号
        ("irq_type", ct.c_uint32),  # 中断类型
        ("duration_ns", ct.c_uint64),  # 持续时间(纳秒)
        ("cpu", ct.c_uint32),  # CPU编号
        ("softirq_vec", ct.c_uint32),  # 软中断向量
        ("comm", ct.c_char * 16),  # 进程名
        ("irq_name", ct.c_char * 16),  # 中断名称（与C代码保持一致）
    ]

    @property
    def irq_type_str(self) -> str:
        """获取中断类型字符串"""
        types = []
        if self.irq_type & InterruptMonitor.IRQ_TYPE_HARDWARE:
            types.append("HARDWARE")
        if self.irq_type & InterruptMonitor.IRQ_TYPE_SOFTWARE:
            types.append("SOFTWARE")
        if self.irq_type & InterruptMonitor.IRQ_TYPE_TIMER:
            types.append("TIMER")
        if self.irq_type & InterruptMonitor.IRQ_TYPE_NETWORK:
            types.append("NETWORK")
        if self.irq_type & InterruptMonitor.IRQ_TYPE_BLOCK:
            types.append("BLOCK")
        if self.irq_type & InterruptMonitor.IRQ_TYPE_MIGRATE:
            types.append("MIGRATE")
        if self.irq_type & InterruptMonitor.IRQ_TYPE_AFFINITY:
            types.append("AFFINITY")
        return "|".join(types) if types else "UNKNOWN"

    @property
    def duration_us(self) -> float:
        """获取中断持续时间（微秒）"""
        return self.duration_ns / 1000.0

    @property
    def duration_ms(self) -> float:
        """获取中断持续时间（毫秒）"""
        return self.duration_ns / 1000000.0


@register_monitor("interrupt")
class InterruptMonitor(BaseMonitor):
    """中断监控器"""
    EVENT_TYPE: type = InterruptEvent

    REQUIRED_TRACEPOINTS: List[str] = [
        'irq:irq_handler_entry',
        'irq:irq_handler_exit',
        'irq:softirq_entry',
        'irq:softirq_exit',
        'sched:sched_migrate_task'  # 可选：进程迁移监控
    ]

    # 软中断类型映射 - 与内核tracepoint格式保持一致
    SOFTIRQ_NAMES = {
        0: "HI",
        1: "TIMER",
        2: "NET_TX",
        3: "NET_RX",
        4: "BLOCK",
        5: "IRQ_POLL",
        6: "TASKLET",
        7: "SCHED",
        8: "HRTIMER",
        9: "RCU"
    }

    # 中断类型常量
    IRQ_TYPE_HARDWARE = 0x1
    IRQ_TYPE_SOFTWARE = 0x2
    IRQ_TYPE_TIMER = 0x4
    IRQ_TYPE_NETWORK = 0x8
    IRQ_TYPE_BLOCK = 0x10
    IRQ_TYPE_MIGRATE = 0x4000
    IRQ_TYPE_AFFINITY = 0x8000

    @classmethod
    def get_default_config(cls) -> Dict[str, Any]:
        """获取默认配置"""
        return {
            "enabled": True,
            "monitor_hardware": True,
            "monitor_software": True,
            "monitor_timer": True,
            "monitor_network": True,
            "monitor_block": True,
            "monitor_migration": False  # 默认不监控进程迁移
        }

    @classmethod
    def validate_monitor_config(cls, config: Dict[str, Any]):
        """验证中断监控器配置"""
        assert config.get("monitor_hardware") is not None, "monitor_hardware不能为空"
        assert isinstance(config.get("monitor_hardware"), bool), "monitor_hardware必须为布尔值"

        assert config.get("monitor_software") is not None, "monitor_software不能为空"
        assert isinstance(config.get("monitor_software"), bool), "monitor_software必须为布尔值"

        assert config.get("monitor_timer") is not None, "monitor_timer不能为空"
        assert isinstance(config.get("monitor_timer"), bool), "monitor_timer必须为布尔值"

        assert config.get("monitor_network") is not None, "monitor_network不能为空"
        assert isinstance(config.get("monitor_network"), bool), "monitor_network必须为布尔值"

        assert config.get("monitor_block") is not None, "monitor_block不能为空"
        assert isinstance(config.get("monitor_block"), bool), "monitor_block必须为布尔值"

        assert config.get("monitor_migration") is not None, "monitor_migration不能为空"
        assert isinstance(config.get("monitor_migration"), bool), "monitor_migration必须为布尔值"

    def _initialize(self, config: Dict[str, Any]):
        """初始化中断监控器"""
        self.enabled = config.get("enabled")
        # CPU信息
        self.cpu_count = psutil.cpu_count()

        # 监控配置
        self.monitor_hardware = config.get("monitor_hardware")
        self.monitor_software = config.get("monitor_software")
        self.monitor_timer = config.get("monitor_timer")
        self.monitor_network = config.get("monitor_network")
        self.monitor_block = config.get("monitor_block")
        self.monitor_migration = config.get("monitor_migration")

    def _should_handle_event(self, event: InterruptEvent) -> bool:
        """检查是否应该处理事件"""
        if self.monitor_hardware and event.irq_type & self.IRQ_TYPE_HARDWARE:
            return True
        if self.monitor_software and event.irq_type & self.IRQ_TYPE_SOFTWARE:
            return True
        if self.monitor_timer and event.irq_type & self.IRQ_TYPE_TIMER:
            return True
        if self.monitor_network and event.irq_type & self.IRQ_TYPE_NETWORK:
            return True
        if self.monitor_block and event.irq_type & self.IRQ_TYPE_BLOCK:
            return True
        if self.monitor_migration and event.irq_type & self.IRQ_TYPE_MIGRATE:
            return True
        return False

    # ==================== 格式化方法实现 ====================

    def get_csv_header(self) -> List[str]:
        """获取CSV头部字段"""
        return ['timestamp', 'time_str', 'irq_num', 'irq_type', 'irq_type_str', 'irq_name', 'comm', 'pid', 'tid', 'duration_ns', 'duration_us', 'cpu', 'softirq_vec', 'orig_cpu', 'dest_cpu']

    def format_for_csv(self, event_data: InterruptEvent) -> Dict[str, Any]:
        """将事件数据格式化为CSV行数据"""
        timestamp = self._convert_timestamp(event_data)
        time_str = DataProcessor.format_timestamp(timestamp)
        
        # 处理字节字符串
        comm = DataProcessor.decode_bytes(event_data.comm)
        irq_name = DataProcessor.decode_bytes(event_data.irq_name)
        
        # 处理迁移事件的特殊字段映射
        if event_data.irq_type & self.IRQ_TYPE_MIGRATE:
            orig_cpu = event_data.irq_num      # 迁移事件中irq_num存储原CPU
            dest_cpu = event_data.softirq_vec  # 迁移事件中softirq_vec存储目标CPU
        else:
            orig_cpu = None
            dest_cpu = None
        
        values = [timestamp, time_str, event_data.irq_num, event_data.irq_type, event_data.irq_type_str, irq_name, comm, event_data.pid, event_data.tid, event_data.duration_ns, event_data.duration_us, event_data.cpu, event_data.softirq_vec, orig_cpu, dest_cpu]
        
        return dict(zip(self.get_csv_header(), values))

    def get_console_header(self) -> str:
        """获取控制台输出的表头"""
        return f"{'TIME':<22} {'IRQ_TYPE':<8} {'IRQ':<4} {'DURATION':<10} {'CPU':<3} {'PID':<8} {'COMM':<16} {'NAME/INFO'}"

    def format_for_console(self, event_data: InterruptEvent) -> str:
        """将事件数据格式化为控制台输出"""
        timestamp = self._convert_timestamp(event_data)
        time_str = f"[{DataProcessor.format_timestamp(timestamp)}]"

        # 处理字节字符串
        comm = DataProcessor.decode_bytes(event_data.comm)
        irq_name = DataProcessor.decode_bytes(event_data.irq_name)

        # 中断类型解释 - 基于主要类型标志
        if event_data.irq_type & self.IRQ_TYPE_HARDWARE:
            irq_type_str = 'HARD'
        elif event_data.irq_type & self.IRQ_TYPE_SOFTWARE:
            if event_data.irq_type & self.IRQ_TYPE_TIMER:
                irq_type_str = 'TIMER'
            elif event_data.irq_type & self.IRQ_TYPE_NETWORK:
                irq_type_str = 'NETWORK'
            elif event_data.irq_type & self.IRQ_TYPE_BLOCK:
                irq_type_str = 'BLOCK'
            else:
                irq_type_str = 'SOFT'
        elif event_data.irq_type & self.IRQ_TYPE_MIGRATE:
            irq_type_str = 'MIGRATE'
        else:
            irq_type_str = f'TYPE_{event_data.irq_type:X}'

        # 根据中断类型调整显示信息
        if event_data.irq_type & self.IRQ_TYPE_MIGRATE:
            # 进程迁移：显示 CPU迁移信息
            orig_cpu = event_data.irq_num      # 原CPU
            dest_cpu = event_data.softirq_vec  # 目标CPU
            info_str = f"{irq_name} {orig_cpu}→{dest_cpu}"
            duration_str = "-"
        else:
            # 普通中断：显示中断名称
            info_str = irq_name
            duration_str = f"{event_data.duration_us:.2f}μs"
        
        return f"{time_str:<22} {irq_type_str:<8} {event_data.irq_num:<4} {duration_str:<10} {event_data.cpu:<3} {event_data.pid:<8} {comm:<16} {info_str}"


if __name__ == '__main__':
    """测试模式"""
    import sys
    import time
    from ..utils.application_context import ApplicationContext

    context = ApplicationContext()

    logger = context.get_logger("InterruptMonitor")
    logger.info("中断监控测试模式")

    monitor = InterruptMonitor(context, InterruptMonitor.get_default_config())

    output_controller = context.output_controller
    output_controller.register_monitor("interrupt", monitor)

    if not monitor.load_ebpf_program():
        logger.error("eBPF程序加载失败")
        sys.exit(1)

    output_controller.start()

    if not monitor.run():
        logger.error("中断监控启动失败")
        sys.exit(1)

    logger.info("中断监控已启动")
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
        output_controller.unregister_monitor("interrupt")
        monitor.cleanup()
        output_controller.cleanup()
