# eBPF 系统监控工具

基于 eBPF 技术的现代化系统监控解决方案，提供低开销、高精度的实时系统监控能力。采用依赖注入架构设计，支持多种监控器和灵活的输出控制。

## 🎯 项目概述

本工具通过 eBPF 技术深入内核空间，实现对 Linux 系统的实时监控。采用 Python 用户空间程序结合 C 语言 eBPF 内核程序，提供高效的数据收集和处理能力。

### 核心优势
- **低开销监控**：基于 eBPF 技术，对系统性能影响极小
- **实时数据**：支持实时事件收集和数据输出
- **模块化设计**：监控器自动注册机制，易于扩展
- **配置驱动**：通过 YAML 配置文件灵活控制行为
- **多输出格式**：支持控制台显示和 CSV 文件存储
- **生产就绪**：采用依赖注入和分层锁机制，确保稳定性

## 🛠 系统要求

**运行环境**
- Linux 内核版本 >= 4.1（推荐 4.18+）
- Python 3.7+
- root 权限

**硬件要求**
- CPU：2 核心以上
- 内存：2GB 以上
- 存储：1GB 可用空间

**依赖包**
- `python3-bpfcc`：BCC Python 绑定
- `bpfcc-tools`：BCC 工具集
- `kernel-devel/linux-headers`：内核开发包
- `python3-yaml`：YAML 配置解析
- `python3-psutil`：系统信息获取

## 🚀 快速开始

### 1. 环境检查与安装

**CentOS/RHEL 系列：**
```bash
# 安装依赖
sudo yum install python3-bpfcc bpfcc-tools kernel-devel-$(uname -r)
sudo yum install python3-yaml python3-psutil
```

**Ubuntu/Debian 系列：**
```bash
# 安装依赖
sudo apt update
sudo apt install python3-bpfcc bpfcc-tools linux-headers-$(uname -r)
sudo apt install python3-yaml python3-psutil
```

### 2. 基本使用

```bash
# 进入项目目录
cd ebpf

# 默认启动（所有监控器）
sudo python3 main.py

# 启动特定监控器
sudo python3 main.py -m exec,func,syscall

# 监控特定进程
sudo python3 main.py -p nginx,mysql,redis

# 监控特定用户
sudo python3 main.py -u root,www-data

# 详细输出模式
sudo python3 main.py --verbose
```

### 3. 守护进程模式

```bash
# 后台运行
sudo python3 main.py --daemon

# 查看守护进程状态
sudo python3 main.py --daemon-status

# 停止守护进程
sudo python3 main.py --daemon-stop
```

## 📁 项目结构

```
ebpf/
├── main.py                         # 程序主入口
├── src/                            # 源代码目录
│   ├── ebpf_monitor.py            # 主监控器类
│   ├── monitors/                   # 监控器模块
│   │   ├── base.py                # 监控器基类
│   │   ├── exec.py                # 进程执行监控
│   │   ├── func.py                # 内核函数监控
│   │   └── syscall.py             # 系统调用监控
│   ├── ebpf/                      # eBPF 内核程序
│   │   ├── exec.c                 # 进程执行监控 eBPF 程序
│   │   ├── func.c                 # 内核函数监控 eBPF 程序
│   │   └── syscall.c              # 系统调用监控 eBPF 程序
│   └── utils/                     # 工具模块
│       ├── application_context.py # 应用上下文（依赖注入）
│       ├── config_manager.py      # 配置管理器
│       ├── configs.py             # 配置数据类
│       ├── log_manager.py         # 日志管理器
│       ├── monitor_registry.py    # 监控器注册表
│       ├── capability_checker.py  # 系统兼容性检查
│       ├── output_controller.py   # 输出控制器
│       ├── data_processor.py      # 数据处理工具
│       ├── daemon_manager.py      # 守护进程管理
│       └── decorators.py          # 装饰器定义
├── config/                        # 配置文件
│   └── monitor_config.yaml        # 主配置文件
├── docs/                          # 文档目录
│   ├── ARCHITECTURE.md            # 架构设计文档
│   └── USER_GUIDE.md              # 用户使用指南
├── logs/                          # 日志文件目录
├── output/                        # 监控数据输出目录
└── temp/                          # 临时文件目录
```

## 🏗 架构设计

### 依赖注入架构

系统采用现代化的依赖注入架构，通过 `ApplicationContext` 管理组件生命周期：

```
┌─────────────────────────────────────────────────────────┐
│                    应用层 (Application)                  │
│                main.py + 命令行接口                      │
└─────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────┐
│                    控制层 (Control)                      │
│               eBPFMonitor (主控制器)                     │
└─────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────┐
│                   上下文层 (Context)                     │
│              ApplicationContext (依赖注入)               │
└─────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────┐
│                   管理层 (Management)                    │
│  ConfigManager | LogManager | MonitorRegistry           │
│  OutputController | CapabilityChecker | DaemonManager   │
└─────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────┐
│                   监控层 (Monitor)                       │
│    BaseMonitor → ExecMonitor (可扩展其他监控器)          │
└─────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────┐
│                   内核层 (Kernel)                        │
│              eBPF Programs (C 语言)                     │
└─────────────────────────────────────────────────────────┘
```

### 核心组件

**ApplicationContext**
- 依赖注入容器，管理所有组件的生命周期
- 替代传统单例模式，提高可测试性
- 采用分层锁机制确保线程安全

**eBPFMonitor**
- 主控制器，协调所有监控器的工作
- 支持目标进程和用户过滤
- 分层锁架构优化并发性能

**监控器系统**
- 基于 `@register_monitor` 装饰器自动注册
- 继承 `BaseMonitor` 抽象基类
- 支持运行时动态发现和加载

**输出控制**
- 智能输出模式：单监控器（控制台+文件），多监控器（仅文件）
- 缓冲区和批处理优化性能
- 分层锁机制避免输出竞争

### 数据流向

```
内核事件触发 → eBPF程序捕获 → BPF映射缓存 → Python事件回调 → 
监控器处理 → 数据格式化 → 输出控制器 → CSV文件/控制台输出
```

## 📊 监控功能

### 当前支持的监控器

| 监控器 | 功能描述 | eBPF机制 | 输出字段 |
|-------|---------|---------|----------|
| **exec** | 进程执行监控 | syscalls tracepoint | 时间戳、进程名、UID、PID、PPID、返回值、命令参数 |
| **func** | 内核函数监控 | kprobe | 时间戳、进程信息、函数名 |
| **syscall** | 系统调用监控 | raw_syscalls tracepoint | 系统调用号、分类、持续时间、返回值、错误状态 |

### 监控器详细说明

**ExecMonitor（进程执行监控）**
- **机制**：使用 `syscalls:sys_enter_execve` 和 `syscalls:sys_exit_execve` tracepoint
- **特点**：捕获进程执行完整信息，包括命令行参数（最多4个）
- **应用场景**：进程启动监控、安全审计、性能分析

**FuncMonitor（内核函数监控）**
- **机制**：使用 kprobe 动态探针技术
- **特点**：支持通配符模式匹配（如 `vfs_*`），动态生成探针，可配置探针数量限制
- **应用场景**：内核开发调试、性能热点分析、函数调用跟踪
- **配置示例**：
  ```yaml
  func:
    enabled: true
    patterns: ["vfs_*", "sys_*"]  # 监控VFS和系统调用相关函数
    probe_limit: 10               # 最多10个探针
  ```

**SyscallMonitor（系统调用监控）**
- **机制**：使用 `raw_syscalls:sys_enter` 和 `raw_syscalls:sys_exit` tracepoint
- **特点**：智能分类（文件IO、网络、内存、进程、信号、时间），支持性能阈值和采样策略
- **应用场景**：系统调用性能分析、异常检测、资源使用监控
- **配置示例**：
  ```yaml
  syscall:
    enabled: true
    sampling_strategy: "intelligent"
    monitor_categories:
      file_io: true
      network: true
      memory: true
      process: true
      signal: false
      time: false
    performance_thresholds:
      file_io_ms: 1.0
      network_ms: 5.0
      memory_ms: 0.5
      process_ms: 10.0
      default_us: 100
  ```

## ⚙️ 配置管理

### 配置文件结构

`config/monitor_config.yaml` 包含四个主要部分：

```yaml
# 应用配置
app:
  name: ebpf_monitor
  version: 1.0.0
  debug: true
  environment: development

# 日志配置
logging:
  level: DEBUG
  formatters:
    detailed:
      format: '%(asctime)s [%(levelname)s] %(name)s:%(lineno)d %(message)s'
  handlers:
    console:
      class: logging.StreamHandler
      formatter: simple
    file:
      class: logging.handlers.TimedRotatingFileHandler
      formatter: detailed
      filename: monitor.log
      when: D
      interval: 1
      backupCount: 365

# 输出控制器配置
output:
  buffer_size: 2000        # 事件缓冲区大小
  flush_interval: 2.0      # 刷新间隔（秒）
  csv_delimiter: ","       # CSV分隔符
  include_header: true     # 是否包含表头

# 监控器配置
monitors:
  exec:
    enabled: true
  
  func:
    enabled: true
    patterns: ["vfs_*"]          # 匹配模式
    probe_limit: 10              # 最大探针数量
  
  syscall:
    enabled: true
    sampling_strategy: "intelligent"
    high_priority_syscalls: [0, 1, 2, 3, 9, 57, 59]
    monitor_categories:
      file_io: true
      network: true
      memory: true
      process: true
      signal: false
      time: false
    performance_thresholds:
      file_io_ms: 1.0
      network_ms: 5.0
      memory_ms: 0.5
      process_ms: 10.0
      default_us: 100
    max_events_per_second: 1000
    show_errors_only: false
```

### 配置特点

- **动态配置发现**：监控器配置通过 `MonitorsConfig` 自动发现
- **类型安全验证**：使用 dataclass 确保配置类型正确
- **默认值支持**：每个监控器提供合理的默认配置
- **错误处理**：详细的配置验证和错误报告

## 📄 输出数据格式

### CSV 文件输出

监控数据按监控器类型分别存储为 CSV 文件，文件名格式为 `{监控器}_{时间戳}.csv`：

```
output/
├── exec_20250924_143045.csv      # 进程执行监控数据
├── func_20250924_143045.csv      # 内核函数监控数据
└── syscall_20250924_143045.csv   # 系统调用监控数据
```

**ExecMonitor CSV 数据示例**：
```csv
timestamp,time_str,comm,uid,pid,ppid,ret,argv
1726123845.123,[2025-09-12 14:30:45.123],nginx,0,1234,1,0,"nginx -g daemon off;"
1726123845.234,[2025-09-12 14:30:45.234],mysql,999,5678,1,0,"mysqld --defaults-file=/etc/mysql/my.cnf"
```

**FuncMonitor CSV 数据示例**：
```csv
timestamp,time_str,pid,ppid,uid,comm,func_name
1726123845.345,[2025-09-12 14:30:45.345],1234,1,0,nginx,vfs_read
1726123845.456,[2025-09-12 14:30:45.456],5678,1,999,mysql,vfs_write
```

**SyscallMonitor CSV 数据示例**：
```csv
timestamp,time_str,monitor_type,pid,tid,cpu,comm,syscall_nr,syscall_name,category,ret_val,error_name,duration_ns,duration_us,duration_ms,is_error,is_slow_call
1726123845.123,[2025-09-12 14:30:45.123],syscall,1234,1234,2,nginx,2,open,file_io,3,SUCCESS,15000,15.0,0.015,false,false
```

### 控制台实时输出

当只启动单个监控器时，支持控制台实时显示：

```
TIME                   COMM             UID    PID      PPID     RET  ARGS
[2025-09-12 14:30:45]  nginx            0      1234     1        0    nginx -g daemon off;
[2025-09-12 14:30:46]  mysql            999    5678     1        0    mysqld --defaults-file=/etc/mysql/my.cnf
```

## 🔧 开发和扩展

### 添加新监控器

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

## 🐛 故障排除

### 常见问题

**1. 权限错误**
```bash
# 错误：Permission denied
# 解决：使用 root 权限
sudo python3 main.py
```

**2. eBPF 不支持**
```bash
# 检查内核版本
uname -r

# 检查 eBPF 支持
ls /sys/fs/bpf/

# 检查内核配置
zcat /proc/config.gz | grep CONFIG_BPF
```

**3. 依赖包缺失**
```bash
# CentOS/RHEL
sudo yum install python3-bpfcc bpfcc-tools

# Ubuntu/Debian
sudo apt install python3-bpfcc bpfcc-tools
```

### 调试方法

**启用详细日志**
```bash
sudo python3 main.py --verbose
```

**查看日志**
```bash
# 实时查看
tail -f logs/monitor.log

# 查看错误
grep ERROR logs/monitor.log
```

## ⚡ 性能优化

### 配置调优

**缓冲区优化**
```yaml
output:
  buffer_size: 4000        # 增大缓冲区
  flush_interval: 5.0      # 调整刷新间隔
```

**监控器选择**
```bash
# 只启用必要的监控器
sudo python3 main.py -m exec

# 针对特定目标
sudo python3 main.py -p nginx,mysql
```

## 📚 相关文档

- [架构设计文档](docs/ARCHITECTURE.md) - 详细的系统架构和设计原理
- [用户使用指南](docs/USER_GUIDE.md) - 完整的安装配置和使用说明

## 🤝 贡献

欢迎提交 Issue 和 Pull Request 来改进本项目。

## 💡 技术支持

遇到问题时请按以下步骤排查：

1. 查看 [故障排除](#🐛-故障排除) 章节
2. 检查运行日志：`tail -f logs/monitor.log`
3. 在 GitHub Issues 中提交问题报告

---

**重要提示**：本工具需要 root 权限运行，请在安全可控的环境中使用。所有监控数据仅存储在项目目录内，不会影响系统其他部分。