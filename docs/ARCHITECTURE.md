# eBPF 系统监控工具架构设计文档

## 概述

本文档详细描述了 eBPF 系统监控工具的架构设计，包括系统整体架构、核心组件设计、数据流向、扩展机制等方面。该工具采用现代化的依赖注入架构，基于 eBPF 技术实现对 Linux 系统的深度监控，具有低开销、高精度、可扩展的特点。

## 设计目标

### 功能目标
- 提供多维度的系统性能监控能力
- 支持实时数据采集和处理
- 具备良好的可扩展性和可配置性
- 支持生产环境长期稳定运行

### 性能目标
- 监控开销控制在 5% 以下
- 支持高频事件处理（>10K events/sec）
- 内存占用控制在合理范围内
- 优化并发性能，减少锁竞争

### 可用性目标
- 支持长期稳定运行
- 具备完善的错误处理和恢复机制
- 提供友好的配置和使用接口
- 支持守护进程模式

## 系统架构

### 整体架构

系统采用分层架构设计，从用户空间到内核空间分为六个主要层次：

```
┌──────────────────────────────────────────────────────────────┐
│                     应用层 (Application)                     │
│                  main.py + 命令行接口                        │
└──────────────────────────────────────────────────────────────┘
┌──────────────────────────────────────────────────────────────┐
│                     控制层 (Control)                         │
│                   eBPFMonitor (主控制器)                     │
└──────────────────────────────────────────────────────────────┘
┌──────────────────────────────────────────────────────────────┐
│                     上下文层 (Context)                       │
│              ApplicationContext (依赖注入容器)               │
└──────────────────────────────────────────────────────────────┘
┌──────────────────────────────────────────────────────────────┐
│                     管理层 (Management)                      │
│  ConfigManager | LogManager | MonitorRegistry               │
│  OutputController | CapabilityChecker | DaemonManager       │
└──────────────────────────────────────────────────────────────┘
┌──────────────────────────────────────────────────────────────┐
│                     监控层 (Monitor)                         │
│    BaseMonitor → ExecMonitor (可扩展其他监控器)              │
└──────────────────────────────────────────────────────────────┘
┌──────────────────────────────────────────────────────────────┐
│                     内核层 (Kernel)                          │
│              eBPF Programs (C) + BPF Maps                   │
└──────────────────────────────────────────────────────────────┘
```

### 核心设计原则

1. **依赖注入原则**：通过 ApplicationContext 管理组件生命周期，替代传统单例模式
2. **单一职责原则**：每个组件负责明确的功能领域
3. **开闭原则**：对扩展开放，对修改关闭
4. **分层锁机制**：使用细粒度锁替代全局锁，优化并发性能
5. **配置驱动**：通过配置文件控制系统行为

### 架构优势

**依赖注入架构**
- 提高代码可测试性和可维护性
- 支持组件的动态替换和扩展
- 避免传统单例模式的全局状态问题

**分层锁机制**
- 减少锁竞争，提高并发性能
- 避免死锁风险
- 支持细粒度的性能优化

## 核心组件详解

### ApplicationContext（应用上下文）

**设计特点**
- 依赖注入容器，管理所有组件的生命周期
- 替代传统单例模式，提高可测试性
- 采用分层锁机制确保线程安全

**核心职责**
- 组件的创建、注册和注销
- 依赖关系的管理和注入
- 组件生命周期的控制

**关键方法**
```python
class ApplicationContext:
    def get_component(name: str) -> Optional[Any]     # 获取组件
    def get_capability_checker() -> CapabilityChecker # 获取兼容性检查器
    def get_monitor_registry() -> MonitorRegistry     # 获取监控器注册表
    def get_ebpf_monitor() -> eBPFMonitor            # 获取eBPF监控器
    def cleanup()                                    # 清理资源
```

### eBPFMonitor（主控制器）

**设计特点**
- 主控制器，协调所有监控器的工作
- 支持选择性启用监控器
- 统一状态管理锁优化并发性能

**核心职责**
- 监控器实例的创建和管理
- 系统启动、停止和清理
- 全局状态的维护
- 监控器状态跟踪

**状态管理设计**
```python
class eBPFMonitor:
    state_lock: threading.RLock       # 统一状态管理锁
    monitor_status: Dict[str, MonitorStatus]  # 监控器状态
```

**关键方法**
```python
class eBPFMonitor:
    def load() -> bool                              # 加载监控器
    def start() -> bool                             # 启动监控
    def stop() -> bool                              # 停止监控
    def cleanup()                                   # 清理资源
    def is_running() -> bool                        # 检查运行状态
```

### 管理层组件

**ConfigManager（配置管理器）**
- 负责 YAML 配置文件的解析和验证
- 提供类型安全的配置访问接口
- 支持配置错误的详细报告
- 采用单例模式确保配置一致性

**LogManager（日志管理器）**
- 统一的日志记录接口
- 支持多种输出目标（控制台、文件）
- 动态日志级别调整
- 采用单例模式确保日志一致性

**MonitorRegistry（监控器注册表）**
- 自动发现和注册监控器模块
- 维护监控器的元信息和状态
- 支持动态监控器加载
- 基于装饰器的自动注册机制

**OutputController（输出控制器）**
- 统一的数据输出管理
- 支持缓冲区和批量处理
- 根据监控器数量自动调整输出模式（单监控器支持控制台输出）
- 分层锁机制优化并发输出
- 支持聚合统计数据的高效输出

**MonitorFactory（监控器工厂）**
- 负责创建监控器实例
- 统一的监控器初始化流程
- 依赖注入支持

**MonitorContext（监控器上下文）**
- 为监控器提供统一的上下文环境
- 管理监控器的配置和依赖

**CapabilityChecker（兼容性检查器）**
- 内核版本和eBPF支持检测
- 系统兼容性验证
- 编译标志生成
- 运行环境验证

**DaemonManager（守护进程管理器）**
- 传统Unix守护进程功能
- PID文件管理
- 信号处理
- 优雅关闭机制

### 监控层设计

**BaseMonitor（监控器基类）**

定义了所有监控器的标准接口和生命周期：

```python
class BaseMonitor(ABC):
    @abstractmethod
    def load_ebpf_program() -> bool         # 加载eBPF程序
    
    @abstractmethod
    def run() -> bool                       # 启动监控
    
    @abstractmethod
    def stop()                              # 停止监控
    
    @abstractmethod
    def get_csv_header() -> List[str]       # CSV头部定义
    
    @abstractmethod
    def format_for_csv(event) -> Dict       # CSV格式化
    
    @abstractmethod
    def format_for_console(event) -> str    # 控制台格式化
```

**监控器注册机制**
```python
@register_monitor("exec")
class ExecMonitor(BaseMonitor):
    EVENT_TYPE = ExecEvent
    REQUIRED_TRACEPOINTS = [
        "syscalls:sys_enter_execve",
        "syscalls:sys_exit_execve"
    ]
```

**具体监控器实现**
- **ExecMonitor**：使用 kprobe 动态探针机制，单条记录模式，记录每次进程执行，兼容老内核
- **FuncMonitor**：使用 kprobe 动态探针，聚合统计模式，支持函数名列表配置
- **SyscallMonitor**：使用 raw_syscalls tracepoint，聚合统计模式，支持智能分类和错误率统计
- **BIOMonitor**：使用 block tracepoint 监控块设备I/O，聚合统计模式，支持延迟和吞吐量测量
- **OpenMonitor**：使用 syscalls tracepoint 监控文件打开操作，聚合统计模式，支持错误率分析
- **InterruptMonitor**：使用 irq/softirq tracepoint 监控硬件和软件中断，聚合统计模式，支持CPU分析
- **PageFaultMonitor**：使用 exceptions tracepoint 监控页面错误，聚合统计模式，支持NUMA节点分析
- **ContextSwitchMonitor**：使用 sched tracepoint 监控进程调度，聚合统计模式，支持切换次数统计

## eBPF 程序设计

### eBPF 程序架构

每个监控器对应一个 eBPF C 程序，负责在内核空间进行数据采集：

**ExecMonitor eBPF程序结构**
```c
// 事件数据结构定义
struct exec_event {
    u32 uid;                     // 用户 ID
    u32 pid;                     // 进程 ID
    char comm[TASK_COMM_LEN];    // 进程名
    char filename[MAX_PATH_LEN]; // 可执行文件路径
};

// BPF 映射定义
BPF_PERF_OUTPUT(exec_events);    // 事件输出管道

// kprobe探针函数
int trace_execve_entry(struct pt_regs *ctx) {
    struct exec_event event = {};
    event.uid = bpf_get_current_uid_gid() & 0xffffffff;
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // 获取filename参数（支持多种内核版本）
    const char *filename_ptr = (const char *)PT_REGS_PARM1(ctx);
    if (filename_ptr) {
        bpf_probe_read_str(&event.filename, sizeof(event.filename), filename_ptr);
    }
    
    // 提交事件到用户态
    exec_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
```

**设计特点**
- 使用 BCC 框架简化开发
- 采用 kprobe 机制确保兼容性（支持老内核）
- 自动尝试多种内核版本的execve符号名称
- 简化的事件结构减少开销
- 单次提交模式，实时性高

### 内核交互机制

**Kprobe 机制**
- 动态探针技术，可附加到任意内核函数
- 兼容性好，支持老内核（如3.10）
- 灵活性高，可访问函数参数和返回值
- 用于ExecMonitor等需要兼容老内核的场景

**Tracepoint 机制**
- 稳定的内核 ABI 接口
- 性能开销较低
- 适用于大部分系统调用和事件监控
- 提供丰富的上下文信息

**BPF Maps**
- 内核与用户空间数据交换
- 支持多种映射类型
- 提供高效的数据缓存
- 支持原子操作

## 数据流向设计

### 事件处理流程

系统支持两种数据处理模式：

**单条记录模式**（如ExecMonitor）：
```
内核事件触发 → eBPF程序捕获 → BPF映射缓存 → Python事件回调 → 
监控器处理 → 数据格式化 → 输出控制器 → CSV文件/控制台输出
```

**聚合统计模式**（大部分监控器）：
```
内核事件触发 → eBPF程序捕获 → BPF映射聚合 → 定时器触发 → 
Python读取统计 → 监控器格式化 → 输出控制器 → CSV文件/控制台输出
```

**详细流程说明**：

**单条记录模式**：
1. **事件触发**：系统调用 execve 在内核中发生
2. **eBPF捕获**：eBPF程序通过 tracepoint 捕获事件
3. **数据缓存**：事件数据存储在 BPF_HASH 中进行缓存
4. **用户空间回调**：Python程序通过 perf_buffer 接收事件
5. **监控器处理**：ExecMonitor 对事件进行解析和处理
6. **数据格式化**：将事件数据格式化为 CSV 或控制台格式
7. **输出控制**：根据配置输出到文件或控制台

**聚合统计模式**：
1. **事件触发**：系统调用在内核中发生
2. **eBPF聚合**：eBPF程序在内核空间进行统计聚合（使用BPF_HASH）
3. **定时器触发**：用户空间定时器（默认2秒）触发统计读取
4. **读取统计**：Python程序读取BPF映射中的聚合数据
5. **监控器格式化**：监控器将统计数据格式化
6. **清空映射**：读取后清空BPF映射，准备下一周期
7. **输出控制**：批量输出到文件或控制台

### 线程模型

系统采用多线程设计确保高性能：

```
主线程：负责系统初始化、配置管理、用户交互
监控线程：每个监控器运行在独立线程中处理事件
输出线程：专门的输出线程处理数据写入
```

### 并发控制

**锁机制**
- `state_lock`：eBPFMonitor统一状态管理锁
- `monitor_locks`：每个监控器的缓冲区锁
- `csv_locks`：每个CSV文件的写入锁
- `console_lock`：控制台输出锁
- `stats_lock`：监控器统计信息更新锁

## 扩展机制

### 监控器扩展

添加新监控器的步骤：

1. **创建 eBPF 程序**
```c
// src/ebpf/custom.c
struct custom_event {
    u64 timestamp;
    // 自定义字段
};

BPF_PERF_OUTPUT(custom_events);

TRACEPOINT_PROBE(custom, event_name) {
    // 监控逻辑
    return 0;
}
```

2. **实现 Python 监控器**
```python
# src/monitors/custom.py
@register_monitor("custom")
class CustomMonitor(BaseMonitor):
    EVENT_TYPE = CustomEvent
    
    def get_csv_header(self):
        return ['timestamp', 'custom_field']
    
    def format_for_csv(self, event_data):
        return {
            'timestamp': self._convert_timestamp(event_data),
            'custom_field': event_data.custom_field
        }
```

3. **添加配置支持**
```yaml
# config/monitor_config.yaml
monitors:
  custom:
    enabled: true
    custom_option: value
```

### 配置扩展

系统支持灵活的配置扩展：
- 新监控器自动配置发现
- 配置验证和错误处理
- 运行时配置更新

## 性能和安全考虑

### 性能优化

**内核空间优化**
- 使用高效的 BPF 映射类型
- 内核空间聚合减少用户空间开销
- 避免复杂的内核空间计算
- 优化数据结构大小

**用户空间优化**
- 缓冲区批量处理
- 多线程并发处理
- 统一状态锁减少竞争
- 智能输出模式切换
- 聚合统计模式减少数据量90%以上

**I/O 优化**
- 批量文件写入
- 异步日志记录
- 缓冲区大小调优
- 定期刷新机制

### 安全设计

**权限控制**
- 要求 root 权限运行
- 严格的文件路径验证
- 防止路径遍历攻击

**资源隔离**
- 所有文件限制在项目目录内
- 内存使用限制
- CPU 使用率控制

**错误处理**
- 完善的异常处理机制
- 优雅的降级策略
- 详细的错误日志记录

## 配置系统设计

### 配置类型系统

使用 dataclass 实现类型安全的配置系统：

```python
@dataclass
class AppConfig(ValidatedConfig):
    name: str = "ebpf_monitor"
    version: str = "1.0.0"
    debug: bool = False
    
    @classmethod
    def validate(cls, config: Dict[str, Any]) -> 'AppConfig':
        # 配置验证逻辑
        return cls(**config)
```

### 动态配置发现

监控器配置通过 `MonitorsConfig` 自动发现：
- 扫描已注册的监控器
- 合并默认配置和用户配置
- 验证配置的完整性和正确性

## 聚合统计模式设计

### 设计原理

大部分监控器采用聚合统计模式，在内核空间进行数据聚合，用户空间定期读取统计结果。

**核心优势**：
- 数据量减少90%以上
- 减少用户空间处理开销
- 提供丰富的统计指标
- 降低存储空间需求

### 实现机制

**内核空间聚合**：
```c
// 使用BPF_HASH存储聚合数据
BPF_HASH(stats, struct key_t, struct value_t, 10240);

// 事件处理时更新统计
TRACEPOINT_PROBE(category, event) {
    struct key_t key = {...};
    struct value_t *value = stats.lookup(&key);
    if (value) {
        value->count++;
        value->total += size;
        // 更新其他统计字段
    } else {
        struct value_t new_value = {...};
        stats.update(&key, &new_value);
    }
    return 0;
}
```

**用户空间定时读取**：
```python
def stats_timer_callback():
    # 读取BPF映射中的所有统计数据
    for key, value in bpf_map.items():
        # 格式化并输出
        self.output_stats(key, value)
    # 清空映射，准备下一周期
    bpf_map.clear()
```

### 统计字段设计

根据监控器类型，统计字段包括：
- **计数类**：count（操作次数）、error_count（错误次数）
- **延迟类**：avg_latency、min_latency、max_latency
- **吞吐量类**：total_bytes、throughput_mbps
- **比率类**：error_rate（错误率）

### 配置参数

- `interval`：统计周期（秒），默认2秒
- `min_count`：最小计数过滤，减少输出数据量
- `min_latency_us`：最小延迟过滤
- `min_switches`：最小切换次数过滤

## 数据分析工具架构

### 工具概述

项目提供了专门的数据分析工具（`analysis/analyzer.py`），用于分析eBPF监控系统采集的性能数据。

### 核心组件

**EBPFAnalyzer**
- 主分析类，支持所有监控器类型的数据分析
- 自动加载和清理数据
- 生成格式化的分析报告

**数据处理工具**（`data_utils.py`）
- 提供数据读取和清理函数
- 支持多种容错策略
- 处理时间戳和格式转换

**数据预处理脚本**（`preprocess_data.sh`）
- 按日期分割大文件
- 自动清理空文件
- 高效的bash实现

### 分析流程

```
原始CSV文件 → 数据预处理（可选） → 按日期加载 → 数据清理 → 
多维度统计分析 → 格式化输出 → 生成报告
```

### 分析维度

每个监控器支持的分析维度：
- **EXEC**：执行次数、文件统计、进程统计、用户统计
- **BIO**：I/O类型、数据量、吞吐量、进程统计
- **FUNC**：函数调用次数、进程-函数交叉统计
- **OPEN**：打开次数、错误率、文件统计、进程统计
- **SYSCALL**：调用次数、分类统计、错误率、进程统计
- **INTERRUPT**：中断次数、类型统计、CPU分布
- **PAGE_FAULT**：错误次数、类型统计、CPU分布、NUMA分布

### 性能优化

- 使用pandas进行高效数据处理
- 支持增量分析（按日期）
- 自动内存管理和清理
- 多种容错策略

## 总结

本架构设计通过现代化的依赖注入、统一状态锁机制和模块化设计，实现了一个高性能、可扩展的 eBPF 监控系统。核心特点包括：

1. **现代化架构**：依赖注入替代单例模式，提高可测试性
2. **高性能**：基于 eBPF 技术和聚合统计模式，监控开销极低
3. **聚合统计**：内核空间聚合，数据量减少90%以上
4. **可扩展性**：支持动态监控器注册和配置发现
5. **稳定性**：完善的错误处理和恢复机制
6. **安全性**：严格的权限控制和资源隔离
7. **生产就绪**：支持守护进程模式和长期稳定运行
8. **数据分析**：完整的数据分析工具链

该架构为系统性能监控提供了一个坚实的基础，能够满足生产环境的各种监控需求，同时为未来的功能扩展留下了充足的空间。