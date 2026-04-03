# eBPF 系统监控工具

[![Python Version](https://img.shields.io/badge/python-2.7%2B-blue)](https://www.python.org/)
[![Python Version](https://img.shields.io/badge/python-3.7%2B-blue)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Linux-orange)](https://www.kernel.org/)
[![Kernel](https://img.shields.io/badge/kernel-3.10%2B-orange)](https://www.kernel.org/)

基于 eBPF 技术的现代化系统监控解决方案，提供低开销、高精度的实时系统监控能力。采用依赖注入架构设计，支持 8 种监控器（进程执行、文件打开、块I/O、系统调用、内核函数、中断、页面错误、上下文切换）和灵活的输出控制。

## 🎯 项目概述

本工具通过 eBPF 技术深入 Linux 内核空间，实现对系统的高效实时监控。采用 Python 用户空间程序结合 C 语言 eBPF 内核程序，提供高效的数据收集和处理能力。

### 核心优势
- **低开销监控**：基于 eBPF 技术，对系统性能影响极小（<1% CPU）
- **实时数据**：支持实时事件收集和数据输出（毫秒级延迟）
- **模块化设计**：监控器自动注册机制，易于扩展
- **配置驱动**：通过 YAML 配置文件灵活控制行为
- **多输出格式**：支持控制台显示和 CSV 文件存储
- **生产就绪**：采用依赖注入和分层锁机制，确保稳定性
- **数据分析**：内置强大的数据分析工具，支持多维度统计
- **双模式输出**：单条记录模式（exec）和聚合统计模式（其他监控器），数据量减少 90%+

## 🛠 系统要求

**运行环境**
- Linux 内核版本 >= 3.10（推荐 4.18+）
- Python 2.7+ 或 Python 3.7+（完全兼容 Python 2.7）
- root 权限或 CAP_BPF 能力

**硬件要求**
- CPU：2 核心以上（推荐 4 核心）
- 内存：2GB 以上（推荐 4GB）
- 存储：1GB 可用空间

**依赖包**
- `python3-bpfcc`：BCC Python 绑定
- `bpfcc-tools`：BCC 工具集
- `kernel-devel/linux-headers`：内核开发包
- `python3-yaml`：YAML 配置解析
- `python3-psutil`：系统信息获取

**Python 依赖**
```
pandas>=1.0.0
PyYAML>=3.13
bcc>=0.18.0
psutil>=5.4.0
```

## 🚀 快速开始

### 1. 环境检查与安装

**CentOS/RHEL 系列：**
```bash
# 安装依赖
sudo yum install python3-bpfcc bpfcc-tools kernel-devel-$(uname -r)
sudo yum install python3-pip python3-yaml python3-psutil
pip3 install -r requirements.txt
```

**Ubuntu/Debian 系列：**
```bash
# 安装依赖
sudo apt update
sudo apt install python3-bpfcc bpfcc-tools linux-headers-$(uname -r)
sudo apt install python3-pip python3-yaml python3-psutil
pip3 install -r requirements.txt
```

### 2. 基本使用

```bash
# 进入项目目录
cd ebpf

# 默认启动（所有已启用的监控器）
sudo python3 main.py

# 启动特定监控器
sudo python3 main.py -m exec

# 启动多个监控器
sudo python3 main.py -m exec,func,syscall,bio

# 详细输出模式
sudo python3 main.py --verbose

# 查看版本信息
python3 main.py -V

# 查看帮助
python3 main.py --help
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

### 4. 数据分析

```bash
# 进入分析目录
cd analysis

# 分析指定日期的数据
python3 analyzer.py --date 20251121

# 分析特定类型的监控数据
python3 analyzer.py --date 20251121 --type bio
```

## 📁 项目结构

```
ebpf/
├── main.py                        # 程序主入口
├── requirements.txt               # Python 依赖
├── README.md                      # 项目说明文档
├── package.sh                     # 打包脚本
├── src/                           # 源代码目录
│   ├── ebpf_monitor.py            # 主监控器类
│   ├── monitors/                  # 监控器模块
│   │   ├── base.py                # 监控器基类
│   │   ├── exec.py                # 进程执行监控
│   │   ├── func.py                # 内核函数监控
│   │   ├── syscall.py             # 系统调用监控
│   │   ├── bio.py                 # 块I/O操作监控
│   │   ├── open.py                # 文件打开监控
│   │   ├── interrupt.py           # 中断监控
│   │   ├── page_fault.py          # 页面错误监控
│   │   └── context_switch.py      # 上下文切换监控
│   ├── ebpf/                      # eBPF 内核程序
│   │   ├── exec.c                 # 进程执行监控 eBPF 程序
│   │   ├── func.c                 # 内核函数监控 eBPF 程序
│   │   ├── syscall.c              # 系统调用监控 eBPF 程序
│   │   ├── bio.c                  # 块I/O操作监控 eBPF 程序
│   │   ├── open.c                 # 文件打开监控 eBPF 程序
│   │   ├── interrupt.c            # 中断监控 eBPF 程序
│   │   ├── page_fault.c           # 页面错误监控 eBPF 程序
│   │   └── context_switch.c       # 上下文切换监控 eBPF 程序
│   └── utils/                     # 工具模块
│       ├── application_context.py # 应用上下文（依赖注入）
│       ├── config_manager.py      # 配置管理器
│       ├── config_validator.py    # 配置验证器
│       ├── configs.py             # 配置数据类
│       ├── monitors_config.py     # 监控器配置
│       ├── log_manager.py         # 日志管理器
│       ├── monitor_registry.py    # 监控器注册表
│       ├── monitor_factory.py     # 监控器工厂
│       ├── monitor_context.py     # 监控器上下文
│       ├── monitor_data_utils.py  # 监控数据工具
│       ├── capability_checker.py  # 系统兼容性检查
│       ├── output_controller.py   # 输出控制器
│       ├── console_writer.py      # 控制台输出
│       ├── csv_writer.py          # CSV 输出
│       ├── data_processor.py      # 数据处理工具
│       ├── daemon_manager.py      # 守护进程管理
│       ├── decorators.py          # 装饰器定义
│       └── py2_compat.py          # Python 2兼容性支持
├── config/                        # 配置文件
│   └── monitor_config.yaml        # 主配置文件
├── docs/                          # 文档目录
│   ├── ARCHITECTURE.md            # 架构设计文档
│   └── USER_GUIDE.md              # 用户使用指南
├── analysis/                      # 数据分析工具
│   ├── analyzer.py                # 主分析程序
│   ├── data_utils.py              # 数据处理工具
│   ├── preprocess_data.sh         # 数据预处理脚本
│   ├── requirements.txt           # 分析工具依赖
│   ├── README.md                  # 分析工具文档
│   ├── USAGE.md                   # 使用说明
│   ├── daily_data/                # 预处理后的每日数据
│   └── reports/                   # 生成的分析报告
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
│                main.py + 命令行接口                       │
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
│  MonitorFactory | MonitorContext                        │
└─────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────┐
│                   监控层 (Monitor)                       │
│    BaseMonitor → ExecMonitor, BioMonitor, ...           │
└─────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────┐
│                   内核层 (Kernel)                        │
│              eBPF Programs (C 语言)                      │
└─────────────────────────────────────────────────────────┘
```

### 核心组件

**ApplicationContext**
- 依赖注入容器，管理所有组件的生命周期
- 替代传统单例模式，提高可测试性
- 采用分层锁机制确保线程安全

**eBPFMonitor**
- 主控制器，协调所有监控器的工作
- 支持多监控器并发运行
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

### 数据输出模式

系统采用**两种输出模式**，根据监控器类型自动选择：

| 模式 | 监控器 | 特点 |
|------|--------|------|
| **单条记录模式** | exec | 每个事件生成一条记录，实时输出 |
| **聚合统计模式** | bio, open, syscall, func, interrupt, page_fault, context_switch | 按时间间隔聚合统计数据，数据量减少 90%+ |

**聚合统计优势**：
- **高效聚合**：按配置的时间间隔（默认 2 秒）聚合统计数据
- **数据量小**：相比单条记录模式，数据量减少 90% 以上
- **统计丰富**：包含 count、error_rate、avg_latency 等统计指标
- **便于分析**：预聚合的数据可直接用于性能分析

### 当前支持的监控器

| 监控器 | 功能描述 | eBPF机制 | 输出模式 | 配置选项 |
|-------|---------|---------|---------|----------|
| **exec** | 进程执行监控 | kprobe | 单条记录 | enabled |
| **open** | 文件打开监控 | tracepoint | 聚合统计 | enabled, interval, min_count, show_errors_only |
| **bio** | 块 I/O 操作监控 | tracepoint | 聚合统计 | enabled, interval, min_latency_us |
| **syscall** | 系统调用监控 | tracepoint | 聚合统计 | enabled, interval, monitor_categories, show_errors_only |
| **func** | 内核函数监控 | kprobe | 聚合统计 | enabled, interval, patterns, probe_limit |
| **interrupt** | 中断监控 | tracepoint | 聚合统计 | enabled, interval |
| **page_fault** | 页面错误监控 | tracepoint | 聚合统计 | enabled, interval |
| **context_switch** | 上下文切换监控 | tracepoint | 聚合统计 | enabled, interval, min_switches |

### 监控器详细说明

**ExecMonitor（进程执行监控）**
- **机制**：使用 kprobe 动态探针，附加到 `__x64_sys_execve`/`sys_execve` 等内核符号
- **特点**：兼容老内核（如 RHEL 7/内核 3.10），捕获进程执行信息，单条记录模式
- **应用场景**：进程启动监控、安全审计、性能分析
- **兼容性**：支持多种内核版本，自动尝试不同的 execve 符号名称

**FuncMonitor（内核函数监控）**
- **机制**：使用 kprobe 动态探针技术
- **特点**：支持函数名列表配置（支持通配符如 `vfs_*`），动态生成探针，聚合统计模式
- **应用场景**：内核开发调试、性能热点分析、函数调用跟踪
- **配置示例**：
  ```yaml
  func:
    enabled: true
    interval: 2
    patterns: ["vfs_read", "sys_*"]  # 函数名列表
    probe_limit: 10                      # 最大探针数量
  ```
- **注意**：patterns 支持通配符（如 `vfs_*`），会从 `/proc/kallsyms` 中查找匹配的函数

**SyscallMonitor（系统调用监控）**
- **机制**：使用 `raw_syscalls:sys_enter` 和 `raw_syscalls:sys_exit` tracepoint
- **特点**：智能分类（文件IO、网络、内存、进程、IPC等），聚合统计模式，支持错误率分析
- **应用场景**：系统调用性能分析、异常检测、资源使用监控
- **配置示例**：
  ```yaml
  syscall:
    enabled: true
    interval: 2
    monitor_categories:
      file_io: true
      network: true
      memory: true
      process: true
      ipc: true
    show_errors_only: false
  ```

**BIOMonitor（块I/O操作监控）**
- **机制**：使用 `block:block_rq_issue` 和 `block:block_rq_complete` tracepoint
- **特点**：监控块设备层 IO，测量延迟和吞吐量，聚合统计模式，过滤 Page Cache 命中
- **应用场景**：存储性能分析、I/O 瓶颈定位、磁盘性能评估
- **配置示例**：
  ```yaml
  bio:
    enabled: true
    interval: 2
    min_latency_us: 0   # 最小延迟过滤（微秒）
  ```

**OpenMonitor（文件打开监控）**
- **机制**：使用 `syscalls:sys_enter/exit_open/openat` tracepoint
- **特点**：监控文件访问模式、权限和操作状态，聚合统计模式，支持错误率分析
- **应用场景**：文件访问审计、权限分析、安全监控
- **配置示例**：
  ```yaml
  open:
    enabled: true
    interval: 2
    min_count: 1               # 最小访问次数过滤
    show_errors_only: false    # 是否只显示有错误的操作
  ```

**InterruptMonitor（中断监控）**
- **机制**：使用 `irq:irq_handler_entry` 和 `irq:softirq_entry` tracepoint
- **特点**：区分硬件/软件中断，聚合统计模式，支持 CPU 亲和性分析
- **应用场景**：系统性能调优、中断负载均衡、CPU 热点分析
- **配置示例**：
  ```yaml
  interrupt:
    enabled: true
    interval: 2
  ```

**PageFaultMonitor（页面错误监控）**
- **机制**：使用 `exceptions:page_fault_user` tracepoint
- **特点**：监控用户空间页面错误，区分主要/次要错误，聚合统计模式，支持 NUMA 节点分析
- **应用场景**：内存性能分析、内存压力监控、应用优化
- **配置示例**：
  ```yaml
  page_fault:
    enabled: true
    interval: 2                # 统计周期（秒）
  ```

**ContextSwitchMonitor（上下文切换监控）**
- **机制**：使用 `sched:sched_switch` tracepoint
- **特点**：监控进程/线程上下文切换，分析 CPU 调度性能，支持统计聚合
- **应用场景**：CPU 调度分析、性能优化、延迟诊断、负载均衡分析
- **配置示例**：
  ```yaml
  context_switch:
    enabled: true
    interval: 2              # 统计周期（秒）
    min_switches: 10         # 最小切换次数过滤
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
  buffer_size: 5000            # 事件缓冲区大小
  batch_size: 1000             # 批处理大小
  large_batch_threshold: 500   # 大批次阈值
  flush_interval: 2.0          # 刷新间隔（秒）
  output_thread_sleep: 0.1     # 输出线程休眠时间（秒）
  csv_delimiter: ","           # CSV分隔符
  include_header: true         # 是否包含表头

# 监控器配置
monitors:
  exec:
    enabled: true
  
  func:
    enabled: true
    interval: 2
    patterns: ["vfs_read", "vfs_write"]  # 匹配模式
    probe_limit: 10                      # 最大探针数量
  
  syscall:
    enabled: true
    interval: 2
    monitor_categories:
      file_io: true
      network: true
      memory: true
      process: true
      signal: false
      time: false
      ipc: true
    show_errors_only: false
  
  bio:
    enabled: true
    interval: 2
    min_latency_us: 0                    # 最小延迟过滤（微秒）
  
  open:
    enabled: true
    interval: 2
    min_count: 1                         # 最小访问次数过滤
    show_errors_only: false
  
  interrupt:
    enabled: true
    interval: 2
  
  page_fault:
    enabled: true
    interval: 2
  
  context_switch:
    enabled: true
    interval: 2
    min_switches: 10                     # 最小切换次数过滤
```

### 配置特点

- **动态配置发现**：监控器配置通过 `MonitorsConfig` 自动发现
- **类型安全验证**：使用配置类确保配置类型正确
- **默认值支持**：每个监控器提供合理的默认配置
- **错误处理**：详细的配置验证和错误报告

### Python 2.7 兼容性说明

本项目完全兼容 Python 2.7，采用以下兼容性策略：

- **类型注解**：使用注释形式的类型提示（`# type: ...`），不影响 Python 2.7 运行
- **pathlib**：提供 Python 2.7 兼容的 Path 实现（`src/utils/py2_compat.py`）
- **字符串格式化**：统一使用 `.format()` 方法而非 f-string
- **异常处理**：兼容 Python 2.7 的异常类型（如使用 `IOError` 而非 `FileNotFoundError`）
- **字典操作**：使用 `.items()` 而非 `.iteritems()`
- **导入处理**：所有 Python 3 特性都有 Python 2.7 降级方案

**推荐使用 Python 3.7+ 以获得更好的性能和类型检查支持，但 Python 2.7 环境下也能正常运行。**

## 📄 输出数据格式

### CSV 文件输出

监控数据按监控器类型分别存储为 CSV 文件，文件名格式为 `{监控器}_{时间戳}.csv`：

```
output/
├── exec_20251121_143045.csv           # 进程执行监控数据
├── func_20251121_143045.csv           # 内核函数监控数据
├── syscall_20251121_143045.csv        # 系统调用监控数据
├── bio_20251121_143045.csv            # 块I/O操作监控数据
├── open_20251121_143045.csv           # 文件打开监控数据
├── interrupt_20251121_143045.csv      # 中断监控数据
├── page_fault_20251121_143045.csv     # 页面错误监控数据
└── context_switch_20251121_143045.csv # 上下文切换监控数据
```

### 聚合统计格式

大部分监控器采用聚合统计格式输出，按配置的时间间隔（默认 2 秒）汇总数据：

**优势**：
- 数据量减少 90% 以上
- 包含丰富的统计指标（count、error_rate、avg_latency 等）
- 便于直接进行性能分析
- 减少存储空间需求

**ExecMonitor CSV 数据示例**（单条记录模式）：
```csv
timestamp,time_str,uid,pid,comm,filename
1732176700.123,[2025-11-21 14:30:00.123],0,1234,bash,/usr/bin/ls
1732176700.234,[2025-11-21 14:30:00.234],1000,5678,python3,/usr/bin/python3
```

**FuncMonitor CSV 数据示例**（聚合统计模式）：
```csv
timestamp,time_str,comm,func_name,count
1732176700.000,[2025-11-21 14:30:00.000],nginx,vfs_read,1250
1732176700.000,[2025-11-21 14:30:00.000],nginx,vfs_write,856
```

**SyscallMonitor CSV 数据示例**（聚合统计模式）：
```csv
timestamp,time_str,monitor_type,comm,syscall_nr,syscall_name,category,count,error_count,error_rate
1732176700.000,[2025-11-21 14:30:00.000],syscall,nginx,0,read,file_io,1250,5,0.004
1732176700.000,[2025-11-21 14:30:00.000],nginx,1,write,file_io,856,2,0.002
```

**BIOMonitor CSV 数据示例**（聚合统计模式）：
```csv
timestamp,time_str,comm,io_type,io_type_str,count,total_bytes,size_mb,avg_latency_us,min_latency_us,max_latency_us,throughput_mbps
1732176700.000,[2025-11-21 14:30:00.000],mysqld,0,READ,1250,5242880,5.00,125.5,10.2,2500.8,40.0
1732176700.000,[2025-11-21 14:30:00.000],mysqld,1,WRITE,856,3538944,3.38,256.3,15.6,5000.2,13.2
```

**OpenMonitor CSV 数据示例**（聚合统计模式）：
```csv
timestamp,time_str,comm,operation,filename,count,errors,error_rate,avg_lat_us,min_lat_us,max_lat_us,flags
1732176700.000,[2025-11-21 14:30:00.000],nginx,OPENAT,/var/log/nginx/access.log,125,0,0.000,45.2,12.5,250.8,WR|CLO
1732176700.000,[2025-11-21 14:30:00.000],mysqld,OPEN,/var/lib/mysql/data.db,85,2,0.024,125.6,25.3,1500.2,RD|WR
```

**InterruptMonitor CSV 数据示例**（聚合统计模式）：
```csv
timestamp,time_str,comm,irq_type,irq_type_str,cpu,count
1732176700.000,[2025-11-21 14:30:00.000],swapper/0,1,TIMER,0,2500
1732176700.000,[2025-11-21 14:30:00.000],ksoftirqd/1,2,NET_RX,1,1250
```

**PageFaultMonitor CSV 数据示例**（聚合统计模式）：
```csv
timestamp,time_str,comm,fault_type,fault_type_str,cpu,numa_node,count
1732176700.000,[2025-11-21 14:30:00.000],nginx,1,MINOR,2,0,1250
1732176700.000,[2025-11-21 14:30:00.000],mysqld,2,MAJOR,1,0,85
```

**ContextSwitchMonitor CSV 数据示例**（聚合统计模式）：
```csv
timestamp,time_str,prev_comm,next_comm,cpu,count
1732176700.000,[2025-11-21 14:30:00.000],nginx,swapper/0,2,125
1732176700.000,[2025-11-21 14:30:00.000],swapper/0,nginx,2,125
```

### 控制台实时输出

当只启动单个监控器时，支持控制台实时显示。输出格式因监控器类型而异：

**ExecMonitor 控制台输出**：
```
TIME                   UID    PID      COMM             FILENAME
[2025-11-21 14:30:00]  0      1234     bash             /usr/bin/ls
[2025-11-21 14:30:01]  1000   5678     python3          /usr/bin/python3
```

**聚合统计监控器控制台输出**（以 FuncMonitor 为例）：
```
TIME                   COMM             FUNC_NAME        COUNT
[2025-11-21 14:30:00]  nginx            vfs_read         1250
[2025-11-21 14:30:00]  nginx            vfs_write        856
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

# 安装 Python 依赖
pip3 install -r requirements.txt
```

**4. 内核头文件缺失**
```bash
# CentOS/RHEL
sudo yum install kernel-devel-$(uname -r)

# Ubuntu/Debian
sudo apt install linux-headers-$(uname -r)
```

**5. 监控器加载失败**
```bash
# 查看详细错误日志
tail -f logs/monitor.log

# 检查可用监控器
python3 main.py --help
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

# 查看特定组件日志
grep "eBPFMonitor" logs/monitor.log
```

**检查系统状态**
```bash
# 检查进程状态
ps aux | grep python3

# 检查系统资源
top
free -h
df -h
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
```

## 📊 数据分析

项目提供了强大的数据分析工具，用于分析 eBPF 监控系统采集的性能数据。

### 分析工具特性

- **支持所有监控器类型**：exec, bio, func, open, syscall, interrupt, page_fault
- **聚合统计分析**：针对聚合统计格式优化，分析速度快
- **多维度统计**：提供 Top 排名、百分比、交叉分析等
- **数据预处理**：自动分割大文件，按日期组织数据
- **可视化报告**：生成格式化的文本分析报告

### 快速使用

```bash
# 进入分析目录
cd analysis

# 预处理数据（可选，将大文件按日期分割）
./preprocess_data.sh

# 分析指定日期的所有数据
python3 analyzer.py --date 20251121

# 分析特定类型的数据
python3 analyzer.py --date 20251121 --type bio

# 查看帮助
python3 analyzer.py --help
```

### 分析示例输出

```
================================================================================
BIO (块I/O) 监控数据分析 - 20251121
================================================================================

总I/O操作数: 12,345
总数据量: 1,234.56 MB (1,294,967,296 bytes)

按I/O类型统计:
  READ                   8,234次 (66.70%) |   800.50 MB | 平均延迟:   1,234.56 μs
  WRITE                  3,456次 (28.00%) |   400.25 MB | 平均延迟:   2,345.67 μs
  ...

按进程统计 (Top 15):
    1. mysqld                  5,678次 (46.00%) |   567.89 MB
    2. nginx                   3,456次 (28.00%) |   345.67 MB
    ...
```

详细使用说明请参考 [分析工具文档](analysis/README.md)。

## 📚 相关文档

- [架构设计文档](docs/ARCHITECTURE.md) - 详细的系统架构和设计原理
- [用户使用指南](docs/USER_GUIDE.md) - 完整的安装配置和使用说明
- [数据分析工具](analysis/README.md) - 数据分析工具使用指南

---

**重要提示**：本工具需要 root 权限运行，请在安全可控的环境中使用。所有监控数据仅存储在项目目录内，不会影响系统其他部分。
