# eBPF 系统监控工具用户指南

## 简介

eBPF 系统监控工具是一个基于 eBPF 技术的现代化系统性能监控解决方案。它能够在极低的系统开销下，对 Linux 系统进行深度的实时监控，帮助用户了解系统的运行状况、发现性能瓶颈、诊断系统问题。

### 核心特性

**监控能力**
- 进程生命周期监控：进程创建、执行、退出
- 内核函数调用监控：支持通配符模式匹配的函数跟踪
- 系统调用监控：智能分类、性能阈值和采样策略
- I/O 操作监控：读写性能分析、延迟和吞吐量测量
- 文件操作监控：文件打开、访问权限和状态分析
- 中断监控：硬件中断和软中断延迟测量、CPU亲和性分析
- 页面错误监控：内存访问模式分析、主要/次要页面错误统计

**技术优势**
- 基于 eBPF 内核技术，监控开销极低
- 依赖注入架构，支持按需启用监控器
- 实时数据处理和输出
- 支持多种输出格式（CSV、控制台）
- 完善的配置管理和错误处理
- 支持守护进程模式

## 系统要求

### 硬件要求
- CPU：2 核心以上（推荐 4 核心）
- 内存：2GB 以上（推荐 4GB）
- 存储：1GB 可用空间
- 架构：x86_64 或 aarch64

### 软件要求

**操作系统支持**
- CentOS/RHEL 7.0+（内核 >= 3.10.0）
- Ubuntu 18.04+（内核 >= 4.15.0）
- Debian 9+（内核 >= 4.9.0）
- 其他主流 Linux 发行版

**运行环境**
- Python 3.7 及以上版本
- root 权限或 sudo 权限
- 内核 eBPF 支持（CONFIG_BPF=y）

**依赖包**
- `python3-bpfcc`：BCC Python 绑定
- `bpfcc-tools`：BCC 工具集
- `kernel-devel/linux-headers`：内核开发包
- `python3-yaml`：YAML 配置解析
- `python3-psutil`：系统信息获取

## 安装指南

### 环境检查

在安装之前，请先检查系统环境：

```bash
# 检查内核版本
uname -r

# 检查 eBPF 支持
ls /sys/fs/bpf/

# 检查权限
whoami

# 检查 Python 版本
python3 --version
```

### 依赖安装

**CentOS/RHEL 系列**
```bash
# 安装 BCC 工具和 Python 绑定
sudo yum install python3-bpfcc bpfcc-tools

# 安装内核开发包
sudo yum install kernel-devel-$(uname -r)

# 安装 Python 依赖
sudo yum install python3-pip python3-yaml python3-psutil
```

**Ubuntu/Debian 系列**
```bash
# 更新包索引
sudo apt update

# 安装 BCC 工具和 Python 绑定
sudo apt install python3-bpfcc bpfcc-tools

# 安装内核头文件
sudo apt install linux-headers-$(uname -r)

# 安装 Python 依赖
sudo apt install python3-pip python3-yaml python3-psutil
```

### 获取项目

```bash
# 下载或克隆项目到本地
cd /opt
sudo git clone <repository-url> ebpf-monitor
cd ebpf-monitor

# 或者解压项目包
sudo tar -xzf ebpf-monitor.tar.gz
cd ebpf-monitor
```

## 基本使用

### 快速启动

**默认启动**
```bash
# 使用默认配置启动所有可用监控器
sudo python3 main.py

# 查看帮助信息
python3 main.py --help
```

**选择监控器**
```bash
# 启动特定监控器
sudo python3 main.py -m exec

# 启动多个监控器
sudo python3 main.py -m exec,func,syscall

# 查看可用监控器列表
sudo python3 main.py --help
```

**详细模式**
```bash
# 启用详细日志输出
sudo python3 main.py --verbose

# 查看日志
tail -f logs/monitor.log
```

### 守护进程模式

```bash
# 后台运行
sudo python3 main.py --daemon

# 查看守护进程状态
sudo python3 main.py --daemon-status

# 停止守护进程
sudo python3 main.py --daemon-stop
```

### 查看输出数据

**实时查看日志**
```bash
# 查看运行日志
tail -f logs/monitor.log

# 查看错误日志
grep ERROR logs/monitor.log

# 查看特定级别日志
grep -E "(ERROR|WARNING)" logs/monitor.log
```

**查看监控数据**
```bash
# 查看生成的CSV文件
ls -la output/

# 查看具体监控器的输出
head output/exec_*.csv
tail -f output/exec_*.csv

# 查看CSV文件内容
cat output/exec_20250924_143045.csv
```

## 监控器说明

### 当前支持的监控器

| 监控器 | 功能描述 | 监控对象 | 主要输出字段 |
|-------|---------|---------|-------------|
| **exec** | 进程执行监控 | execve系统调用 | 用户ID、进程ID、进程名、可执行文件路径 |
| **func** | 内核函数监控 | 指定内核函数 | 进程信息、函数名、调用次数 |
| **syscall** | 系统调用监控 | 所有系统调用 | 系统调用号、分类、调用次数、错误状态 |
| **bio** | 块I/O操作监控 | 块设备I/O | I/O类型、数据量、延迟、吞吐量 |
| **open** | 文件打开监控 | open/openat系统调用 | 文件路径、打开标志、错误率、延迟 |
| **interrupt** | 中断监控 | irq/softirq事件 | 中断号、类型、次数、CPU |
| **page_fault** | 页面错误监控 | 内存页面错误事件 | 错误类型、次数、CPU、NUMA节点 |
| **context_switch** | 上下文切换监控 | 进程调度事件 | 进程切换、CPU、切换次数 |

### 监控器详细说明

**ExecMonitor（进程执行监控）**
- **功能描述**：监控系统中所有进程的执行事件
- **监控机制**：使用 kprobe 动态探针，附加到 `__x64_sys_execve`/`sys_execve` 等内核符号
- **特点**：兼容老内核（如RHEL 7/内核3.10），捕获execve系统调用，记录进程执行信息（单条记录模式）
- **输出字段**：时间戳、用户ID、进程ID、进程名、可执行文件路径
- **输出模式**：单条记录（每次execve调用生成一条记录）
- **兼容性**：自动尝试多种内核版本的execve符号名称（`__x64_sys_execve`、`__ia32_sys_execve`、`sys_execve`）

**FuncMonitor（内核函数监控）**
- **功能描述**：监控指定模式的内核函数调用
- **监控机制**：使用 kprobe 动态探针技术
- **特点**：支持指定函数名列表，动态生成探针，可配置探针数量限制，聚合统计模式
- **输出字段**：时间戳、进程名、函数名、调用次数
- **输出模式**：聚合统计（按配置间隔汇总）
- **配置示例**：
  ```yaml
  func:
    enabled: true
    interval: 2
    patterns: ["vfs_read", "vfs_write"]
    probe_limit: 10
  ```

**SyscallMonitor（系统调用监控）**
- **功能描述**：监控系统调用执行情况，分析调用模式和错误状态
- **监控机制**：使用 `raw_syscalls:sys_enter` 和 `raw_syscalls:sys_exit` tracepoint
- **特点**：智能分类（文件IO、网络、内存、进程、IPC等），聚合统计模式，支持错误率分析
- **输出字段**：时间戳、进程名、系统调用号、系统调用名、分类、调用次数、错误次数、错误率
- **输出模式**：聚合统计（按配置间隔汇总）
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
- **功能描述**：监控系统中的块设备I/O操作
- **监控机制**：使用 `block:block_rq_issue` 和 `block:block_rq_complete` tracepoint
- **特点**：测量I/O延迟和吞吐量，聚合统计模式，支持延迟过滤
- **输出字段**：时间戳、进程名、I/O类型、操作次数、总字节数、数据量(MB)、平均延迟、最小/最大延迟、吞吐量
- **输出模式**：聚合统计（按配置间隔汇总）
- **配置示例**：
  ```yaml
  bio:
    enabled: true
    interval: 2
    min_latency_us: 0  # 最小延迟过滤（微秒）
  ```

**OpenMonitor（文件打开监控）**
- **功能描述**：监控系统中的文件打开操作
- **监控机制**：使用 `syscalls:sys_enter/exit_open/openat` tracepoint
- **特点**：监控文件访问模式、权限和操作状态，聚合统计模式，支持错误率分析
- **输出字段**：时间戳、进程名、操作类型、文件路径、打开次数、错误次数、错误率、平均/最小/最大延迟、打开标志
- **输出模式**：聚合统计（按配置间隔汇总）
- **配置示例**：
  ```yaml
  open:
    enabled: true
    interval: 2
    min_count: 1
    show_errors_only: false
  ```

**InterruptMonitor（中断监控）**
- **功能描述**：监控系统中的硬件中断和软中断
- **监控机制**：使用 `irq:irq_handler_entry` 和 `irq:softirq_entry` tracepoint
- **特点**：区分硬件/软件中断，聚合统计模式，支持CPU亲和性分析
- **输出字段**：时间戳、进程名、中断类型、中断类型字符串、CPU编号、中断次数
- **输出模式**：聚合统计（按配置间隔汇总）
- **配置示例**：
  ```yaml
  interrupt:
    enabled: true
    interval: 2
  ```

**PageFaultMonitor（页面错误监控）**
- **功能描述**：监控系统中的页面错误事件
- **监控机制**：使用 `exceptions:page_fault_user` tracepoint
- **特点**：区分主要/次要页面错误，聚合统计模式，支持NUMA节点分析
- **输出字段**：时间戳、进程名、错误类型、错误类型字符串、CPU编号、NUMA节点、错误次数
- **输出模式**：聚合统计（按配置间隔汇总）
- **配置示例**：
  ```yaml
  page_fault:
    enabled: true
    interval: 2
  ```

**ContextSwitchMonitor（上下文切换监控）**
- **功能描述**：监控系统中的进程上下文切换
- **监控机制**：使用 `sched:sched_switch` tracepoint
- **特点**：监控进程调度，聚合统计模式，支持最小切换次数过滤
- **输出字段**：时间戳、前一进程名、后一进程名、CPU编号、切换次数
- **输出模式**：聚合统计（按配置间隔汇总）
- **应用场景**：CPU调度分析、性能优化、负载均衡分析
- **配置示例**：
  ```yaml
  context_switch:
    enabled: true
    interval: 2
    min_switches: 10
  ```

**使用示例**
```bash
# 监控所有进程执行
sudo python3 main.py -m exec

# 监控内核函数
sudo python3 main.py -m func

# 监控系统调用
sudo python3 main.py -m syscall

# 监控块I/O操作
sudo python3 main.py -m bio

# 监控文件打开操作
sudo python3 main.py -m open

# 监控中断
sudo python3 main.py -m interrupt

# 监控页面错误
sudo python3 main.py -m page_fault

# 监控上下文切换
sudo python3 main.py -m context_switch

# 同时启动多个监控器
sudo python3 main.py -m exec,func,syscall,bio,open,interrupt,page_fault,context_switch

# 启动所有已启用的监控器（默认）
sudo python3 main.py
```

## 配置管理

### 配置文件

主配置文件位于 `config/monitor_config.yaml`，包含以下主要部分：

**应用配置**
```yaml
app:
  name: ebpf_monitor
  version: 1.0.0
  description: eBPF Monitor for Linux
  author: bwyu
  email: bwyu@czce.com.cn
  environment: development  # development 或 production
  debug: true
```

**日志配置**
```yaml
logging:
  level: DEBUG              # DEBUG, INFO, WARNING, ERROR
  formatters:
    detailed:
      format: '%(asctime)s [%(levelname)s] %(name)s:%(lineno)d %(message)s'
    simple:
      format: '%(levelname)s: %(message)s'
  handlers:
    console:
      class: logging.StreamHandler
      formatter: simple
      stream: ext://sys.stdout
    file:
      class: logging.handlers.TimedRotatingFileHandler
      formatter: detailed
      filename: monitor.log
      when: D                # 按天轮转
      interval: 1
      backupCount: 365       # 保留365天
```

**输出配置**
```yaml
output:
  buffer_size: 2000          # 事件缓冲区大小
  flush_interval: 2.0        # 刷新间隔（秒）
  csv_delimiter: ","         # CSV分隔符
  include_header: true       # 是否包含表头
```

**监控器配置**
```yaml
monitors:
  exec:
    enabled: true
  
  func:
    enabled: true
    interval: 2
    patterns: ["vfs_read", "vfs_write"]
    probe_limit: 10
  
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
  
  bio:
    enabled: true
    interval: 2
    min_latency_us: 0
  
  open:
    enabled: true
    interval: 2
    min_count: 1
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
    min_switches: 10
```

### 配置选项说明

**通用选项**
- `enabled`: 是否启用该监控器
- `interval`: 统计周期（秒），适用于聚合统计模式的监控器
- `show_errors_only`: 是否只显示有错误的操作

**监控器特定选项**
- `patterns`: 函数名列表（FuncMonitor）
- `probe_limit`: 最大探针数量（FuncMonitor）
- `monitor_categories`: 监控的系统调用分类（SyscallMonitor）
- `min_latency_us`: 最小延迟过滤（BIOMonitor）
- `min_count`: 最小访问次数过滤（OpenMonitor）
- `min_switches`: 最小切换次数过滤（ContextSwitchMonitor）

**性能调优选项**
- `buffer_size`: 事件缓冲区大小（在output配置中）
- `flush_interval`: 数据刷新间隔（在output配置中）
- `interval`: 统计周期，较大的值可以减少数据量

## 输出数据格式

### CSV 文件格式

监控数据以 CSV 格式存储，文件名格式为 `{监控器}_{时间戳}.csv`：

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

### 数据输出模式

系统支持两种输出模式：

1. **单条记录模式**：每个事件生成一条记录（如ExecMonitor）
2. **聚合统计模式**：按配置间隔汇总统计（大部分监控器）

聚合统计模式的优势：
- 数据量减少90%以上
- 包含丰富的统计指标（count、error_rate、avg_latency等）
- 便于直接进行性能分析

**ExecMonitor CSV 数据示例**（单条记录模式）
```csv
timestamp,time_str,uid,pid,comm,filename
1732176700.123,[2025-11-21 14:30:00.123],0,1234,bash,/usr/bin/ls
1732176700.234,[2025-11-21 14:30:00.234],1000,5678,python3,/usr/bin/python3
```

**FuncMonitor CSV 数据示例**（聚合统计模式）
```csv
timestamp,time_str,comm,func_name,count
1732176700.000,[2025-11-21 14:30:00.000],nginx,vfs_read,1250
1732176700.000,[2025-11-21 14:30:00.000],nginx,vfs_write,856
```

### 控制台输出

当只启动单个监控器时，支持控制台实时显示。输出格式因监控器类型而异：

**ExecMonitor 控制台输出**（单条记录模式）：
```
TIME                   UID    PID      COMM             FILENAME
[2025-11-21 14:30:00]  0      1234     bash             /usr/bin/ls
[2025-11-21 14:30:01]  1000   5678     python3          /usr/bin/python3
```

**聚合统计监控器控制台输出**（以FuncMonitor为例）：
```
TIME                   COMM             FUNC_NAME        COUNT
[2025-11-21 14:30:00]  nginx            vfs_read         1250
[2025-11-21 14:30:00]  nginx            vfs_write        856
[2025-11-21 14:30:02]  mysqld           vfs_read         2340
```

### 数据分析

项目提供了专门的数据分析工具，支持对监控数据进行深度分析。

**使用分析工具**
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

**手动分析 CSV 数据**
```bash
# 统计进程执行次数
cut -d',' -f5 output/exec_*.csv | sort | uniq -c | sort -nr

# 查看最常执行的文件
cut -d',' -f6 output/exec_*.csv | sort | uniq -c | sort -nr | head -20

# 查看特定时间段的数据
awk -F',' '$1 >= 1732176700 && $1 <= 1732176900' output/exec_*.csv
```

详细使用说明请参考 [分析工具文档](../analysis/README.md)。

## 故障排除

### 常见问题

**1. 权限错误**
```bash
# 错误信息：Permission denied
# 原因：没有root权限
# 解决方案：
sudo python3 main.py
```

**2. eBPF 不支持**
```bash
# 错误信息：eBPF not supported
# 检查内核版本
uname -r

# 检查 eBPF 支持
ls /sys/fs/bpf/

# 检查内核配置
zcat /proc/config.gz | grep CONFIG_BPF
# 或者
grep CONFIG_BPF /boot/config-$(uname -r)
```

**3. 依赖包缺失**
```bash
# 错误信息：ModuleNotFoundError: No module named 'bpfcc'
# 解决方案：
# CentOS/RHEL
sudo yum install python3-bpfcc bpfcc-tools

# Ubuntu/Debian
sudo apt install python3-bpfcc bpfcc-tools
```

**4. 内核头文件缺失**
```bash
# 错误信息：fatal error: linux/kconfig.h: No such file or directory
# 解决方案：
# CentOS/RHEL
sudo yum install kernel-devel-$(uname -r)

# Ubuntu/Debian
sudo apt install linux-headers-$(uname -r)
```

**5. 配置文件错误**
```bash
# 错误信息：yaml.scanner.ScannerError
# 验证配置文件语法
python3 -c "import yaml; yaml.safe_load(open('config/monitor_config.yaml'))"

# 检查配置文件格式
cat -A config/monitor_config.yaml
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

# 查看警告
grep WARNING logs/monitor.log

# 查看特定组件日志
grep "eBPFMonitor" logs/monitor.log
```

**检查系统状态**
```bash
# 检查系统资源
top
htop

# 检查磁盘空间
df -h

# 检查内存使用
free -h

# 检查进程状态
ps aux | grep python3
```

**手动测试**
```bash
# 测试单个监控器
sudo python3 -c "
from src.utils.application_context import ApplicationContext
from src.monitors.exec import ExecMonitor

context = ApplicationContext()
monitor = ExecMonitor(context, {'enabled': True})
print('Monitor created successfully')
"
```

## 性能优化

### 配置调优

**缓冲区优化**
```yaml
output:
  buffer_size: 5000        # 增大缓冲区减少IO
  flush_interval: 5.0      # 调整刷新间隔
  batch_size: 2000         # 增大批处理大小
```

**统计周期调整**
```yaml
monitors:
  func:
    interval: 5            # 增大统计周期减少数据量
  syscall:
    interval: 5
  bio:
    interval: 5
```

**日志级别调整**
```yaml
logging:
  level: INFO              # 生产环境建议使用INFO级别
```

**监控器选择**
```bash
# 只启用必要的监控器
sudo python3 main.py -m exec,bio

# 通过配置文件禁用不需要的监控器
# 编辑 config/monitor_config.yaml，设置 enabled: false
```

### 系统优化

**资源限制**
- 只启用必要的监控器
- 调整缓冲区大小平衡内存和性能
- 合理设置统计周期和刷新间隔
- 使用过滤选项减少数据量（如min_count、min_switches等）

**生产环境建议**
- 使用配置文件而非命令行参数
- 定期清理输出文件
- 监控系统资源使用情况
- 使用守护进程模式
- 使用聚合统计模式减少数据量
- 定期运行数据分析工具

**文件管理**
```bash
# 定期清理旧的输出文件
find output/ -name "*.csv" -mtime +7 -delete

# 压缩历史日志
gzip logs/monitor.log.*
```

## 生产环境部署

### 监控和告警

```bash
# 监控脚本示例
#!/bin/bash
# check_ebpf_monitor.sh

PID_FILE="/opt/ebpf-monitor/temp/monitor.pid"
LOG_FILE="/opt/ebpf-monitor/logs/monitor.log"

if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if ps -p "$PID" > /dev/null 2>&1; then
        echo "eBPF Monitor is running (PID: $PID)"
        exit 0
    else
        echo "eBPF Monitor PID file exists but process is not running"
        exit 1
    fi
else
    echo "eBPF Monitor is not running"
    exit 1
fi
```

## 总结

eBPF 系统监控工具提供了强大的系统监控能力，通过合理的配置和使用，可以帮助用户：

- 深入了解系统运行状况
- 快速定位性能瓶颈
- 分析系统行为模式
- 诊断系统问题
- 支持生产环境长期运行

### 最佳实践

1. **环境准备**：确保内核版本和依赖包满足要求
2. **配置优化**：根据实际需求调整缓冲区和刷新间隔
3. **目标过滤**：使用进程和用户过滤减少数据量
4. **资源管理**：定期清理输出文件和日志
5. **监控告警**：设置服务监控和异常告警
6. **性能调优**：根据系统负载调整配置参数

更多详细信息请参考：
- [架构设计文档](ARCHITECTURE.md) - 系统架构和设计原理
- [项目主页](../README.md) - 项目概述和快速开始指南