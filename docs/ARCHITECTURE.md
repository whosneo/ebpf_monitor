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
- 支持目标进程和用户过滤
- 分层锁架构优化并发性能

**核心职责**
- 监控器实例的创建和管理
- 目标进程和用户的管理
- 系统启动、停止和清理
- 全局状态的维护

**分层锁设计**
```python
class eBPFMonitor:
    target_lock: threading.RLock      # 目标进程/用户管理锁
    status_lock: threading.RLock      # 监控器状态管理锁
    stats_lock: threading.Lock        # 统计信息更新锁
```

**关键方法**
```python
class eBPFMonitor:
    def load() -> bool                              # 加载监控器
    def start() -> bool                             # 启动监控
    def stop() -> bool                              # 停止监控
    def add_target_processes(names: List[str])      # 添加目标进程
    def add_target_users(names: List[str])          # 添加目标用户
    def cleanup()                                   # 清理资源
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
- 根据监控器数量自动调整输出模式
- 分层锁机制优化并发输出

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
- **ExecMonitor**：使用 syscalls tracepoint 机制，支持目标过滤和参数解析
- **FuncMonitor**：使用 kprobe 动态探针，支持通配符模式匹配和动态代码生成
- **SyscallMonitor**：使用 raw_syscalls tracepoint，支持智能分类和性能阈值

## eBPF 程序设计

### eBPF 程序架构

每个监控器对应一个 eBPF C 程序，负责在内核空间进行数据采集：

**ExecMonitor eBPF程序结构**
```c
// 事件数据结构定义
struct exec_event {
    u64 timestamp;             // 时间戳 (纳秒)
    char comm[TASK_COMM_LEN];  // 进程名
    u32 uid;                   // 用户 ID
    u32 pid;                   // 进程 ID
    u32 ppid;                  // 父进程 ID
    int ret;                   // 返回值（出口）
    char argv[ARGSIZE];        // 参数字符串（入口）
};

// BPF 映射定义
BPF_PERF_OUTPUT(exec_events);              // 事件输出管道
BPF_HASH(target_pids, u32, u8, 1024);      // 目标进程PID映射
BPF_HASH(target_uids, u32, u8, 1024);      // 目标用户ID映射
BPF_HASH(exec_info, u64, struct exec_event, 1024); // 事件缓存

// 探针函数
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    // 入口事件处理逻辑
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_execve) {
    // 出口事件处理逻辑
    return 0;
}
```

**设计特点**
- 使用 BCC 框架简化开发
- 采用 tracepoint 机制确保稳定性
- 支持目标过滤减少开销
- 优化的参数解析避免验证器限制
- 双重 fork 监控模式确保完整性

### 内核交互机制

**Tracepoint 机制**
- 稳定的内核 ABI 接口
- 性能开销较低
- 适用于系统调用监控
- 提供丰富的上下文信息

**BPF Maps**
- 内核与用户空间数据交换
- 支持多种映射类型
- 提供高效的数据缓存
- 支持原子操作

## 数据流向设计

### 事件处理流程

系统的核心数据流向如下：

```
内核事件触发 → eBPF程序捕获 → BPF映射缓存 → Python事件回调 → 
监控器处理 → 数据格式化 → 输出控制器 → CSV文件/控制台输出
```

**详细流程说明**：

1. **事件触发**：系统调用 execve 在内核中发生
2. **eBPF捕获**：eBPF程序通过 tracepoint 捕获事件
3. **数据缓存**：事件数据存储在 BPF_HASH 中进行缓存
4. **用户空间回调**：Python程序通过 perf_buffer 接收事件
5. **监控器处理**：ExecMonitor 对事件进行解析和处理
6. **数据格式化**：将事件数据格式化为 CSV 或控制台格式
7. **输出控制**：根据配置输出到文件或控制台

### 线程模型

系统采用多线程设计确保高性能：

```
主线程：负责系统初始化、配置管理、用户交互
监控线程：每个监控器运行在独立线程中处理事件
输出线程：专门的输出线程处理数据写入
```

### 并发控制

**分层锁机制**
- `target_lock`：目标进程/用户管理锁
- `status_lock`：监控器状态管理锁
- `stats_lock`：统计信息更新锁
- `monitor_locks`：每个监控器的缓冲区锁
- `csv_locks`：每个CSV文件的写入锁
- `console_lock`：控制台输出锁

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
- 实现目标过滤减少事件数量
- 避免复杂的内核空间计算
- 优化参数解析逻辑

**用户空间优化**
- 缓冲区批量处理
- 多线程并发处理
- 分层锁减少竞争
- 智能输出模式切换

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

## 总结

本架构设计通过现代化的依赖注入、分层锁机制和模块化设计，实现了一个高性能、可扩展的 eBPF 监控系统。核心特点包括：

1. **现代化架构**：依赖注入替代单例模式，提高可测试性
2. **高性能**：基于 eBPF 技术和分层锁机制，监控开销极低
3. **可扩展性**：支持动态监控器注册和配置发现
4. **稳定性**：完善的错误处理和恢复机制
5. **安全性**：严格的权限控制和资源隔离
6. **生产就绪**：支持守护进程模式和长期稳定运行

该架构为系统性能监控提供了一个坚实的基础，能够满足生产环境的各种监控需求，同时为未来的功能扩展留下了充足的空间。