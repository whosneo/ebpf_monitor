# eBPF 数据分析工具

一个简单实用的eBPF监控数据分析工具，用于分析和对比不同系统的性能表现。

## 功能特性

- **数据分割**: 将大型监控数据文件按日期分割成小文件
- **性能分析**: 分析系统调用、I/O、进程执行等关键性能指标
- **系统对比**: 对比不同日期或不同系统的性能差异
- **可视化报告**: 生成图表和HTML报告
- **异常检测**: 自动识别性能异常和瓶颈

## 安装依赖

```bash
cd analysis
pip3 install -r requirements.txt
```

## 使用方法

### 1. 数据分割

首先需要将output目录中的大文件按日期分割：

```bash
# 使用bash脚本快速分割
./split_data.sh 2025-10-20 2025-10-25

# 指定自定义目录
./split_data.sh -o /path/to/output -d /path/to/daily_data 2025-10-20 2025-10-25

# 详细输出模式
./split_data.sh -v 2025-10-20 2025-10-25
```

**bash脚本优势**：
- 🚀 **速度极快**：使用grep直接过滤，无需加载到内存
- 💾 **内存占用几乎为0**：不受文件大小限制
- 🛠 **简单可靠**：不会因为数据格式问题崩溃
- 📊 **处理能力强**：可以处理TB级数据文件
- ⚡ **无需Python依赖**：纯bash + grep，系统自带
- 🧹 **自动清理**：自动删除只有表头的空文件

### 2. 查看可用日期

```bash
python3 analyzer.py --list-dates
```

### 3. 分析单日数据

```bash
# 分析指定日期的所有监控器数据
python3 analyzer.py --analyze 20251021

# 只分析特定监控器
python3 analyzer.py --analyze 20251021 --monitors syscall io exec

# 详细分析exec数据（包含filename、可执行文件、命令等分布）
python3 analyzer.py --analyze-exec 20251021

# 详细分析open数据（包含filename、命令、操作类型等分布）
python3 analyzer.py --analyze-open 20251021

# 详细分析func数据（包含函数名、命令、用户等分布）
python3 analyzer.py --analyze-func 20251021

# 详细分析interrupt数据（包含中断类型、持续时间、CPU分布等）
python3 analyzer.py --analyze-interrupt 20251021

# 详细分析io数据（包含I/O类型、性能、文件描述符等分布）
python3 analyzer.py --analyze-io 20251021

# 详细分析page_fault数据（包含错误类型、地址、CPU分布等）
python3 analyzer.py --analyze-page-fault 20251021

# 详细分析syscall数据（包含系统调用、类别、性能、错误等分布）
python3 analyzer.py --analyze-syscall 20251021
```

### 4. 对比多日数据

```bash
# 对比多个日期的性能
python3 analyzer.py --compare 20251021 20251022 20251023

# 分析日期范围
python3 analyzer.py --date-range 20251021 20251025
```

### 5. 生成可视化报告

```bash
# 生成完整的可视化报告
python3 -c "
from analyzer import EBPFAnalyzer
from visualizer import EBPFVisualizer

analyzer = EBPFAnalyzer()
visualizer = EBPFVisualizer()

# 对比分析
results = analyzer.compare_systems(['20250925', '20251021'])

# 生成图表
image_paths = visualizer.create_dashboard(results)

# 生成HTML报告
report_path = visualizer.generate_html_report(results, image_paths)
print(f'报告已生成: {report_path}')
"
```

## 命令行参数

### 基础功能
- `--analyze DATE`: 分析指定日期的数据 (YYYYMMDD格式)
- `--compare DATE1 DATE2 ...`: 对比多个日期的数据
- `--date-range START END`: 分析日期范围内的数据
- `--list-dates`: 列出可用的日期

### 详细分析功能
- `--analyze-exec DATE`: 详细分析exec数据
- `--analyze-open DATE`: 详细分析open数据
- `--analyze-func DATE`: 详细分析func数据
- `--analyze-interrupt DATE`: 详细分析interrupt数据
- `--analyze-io DATE`: 详细分析io数据
- `--analyze-page-fault DATE`: 详细分析page_fault数据
- `--analyze-syscall DATE`: 详细分析syscall数据

### 其他选项
- `--monitors TYPE1 TYPE2 ...`: 指定监控器类型
- `--output-dir DIR`: 指定output目录路径 (默认: ../output)
- `--daily-dir DIR`: 指定日数据目录路径 (默认: ./daily_data)
- `--verbose`: 详细输出

## 详细分析功能说明

### EXEC 监控器分析
- **filename分析**: 统计不同filename的出现次数
- **可执行文件分析**: 分析argv中的可执行文件路径分布
- **命令分析**: 统计不同命令的执行频率
- **用户分析**: 按用户ID统计执行次数
- **失败分析**: 分析执行失败的情况和原因

### OPEN 监控器分析
- **filename分析**: 最常访问的文件、文件扩展名分布、目录访问统计
- **命令分析**: 最活跃的文件访问命令
- **操作类型分析**: OPEN/OPENAT等操作类型分布
- **用户分析**: 各用户的文件访问统计
- **失败分析**: 文件访问失败的统计和分析
- **权限分析**: 文件访问标志位分析

### FUNC 监控器分析
- **函数分析**: 最常调用的内核函数、VFS/SYS函数分类统计
- **命令分析**: 最活跃的函数调用命令
- **用户分析**: 各用户的函数调用统计

### INTERRUPT 监控器分析
- **中断类型分析**: 硬件/软件中断类型分布
- **中断名称分析**: 最频繁的中断名称统计
- **持续时间分析**: 中断处理时间的统计分析
- **CPU分析**: 各CPU核心的中断分布
- **命令分析**: 触发中断最多的命令

### IO 监控器分析
- **I/O类型分析**: READ/WRITE操作分布
- **性能分析**: 吞吐量和延迟统计
- **文件描述符分析**: 最活跃的文件描述符
- **数据大小分析**: I/O操作的数据量统计
- **命令分析**: I/O最活跃的命令
- **错误分析**: I/O错误统计

### PAGE_FAULT 监控器分析
- **错误类型分析**: 页面错误类型分布
- **错误分类统计**: Major/Minor/Write/User错误统计
- **地址分析**: 页面错误的地址范围分析
- **命令分析**: 产生页面错误最多的命令
- **CPU分析**: 各CPU核心的页面错误分布

### SYSCALL 监控器分析
- **系统调用分析**: 最常用的系统调用统计
- **类别分析**: 系统调用按功能分类统计
- **性能分析**: 系统调用执行时间统计
- **错误分析**: 系统调用错误类型和频率
- **慢调用分析**: 执行时间超长的系统调用
- **命令分析**: 系统调用最活跃的命令

## 支持的监控器类型

- `exec`: 进程执行监控
- `syscall`: 系统调用监控
- `io`: I/O操作监控
- `interrupt`: 中断监控
- `func`: 内核函数监控
- `open`: 文件打开监控
- `page_fault`: 页面错误监控

## 输出文件

### 日数据文件
分割后的数据存储在 `daily_data/` 目录中，文件命名格式：
```
exec_20251021.csv
syscall_20251021.csv
io_20251021.csv
...
```

### 分析报告
生成的报告和图表存储在 `reports/` 目录中：
- PNG图表文件
- HTML分析报告

## 性能指标说明

### 系统调用 (syscall)
- `total_calls`: 总调用次数
- `avg_duration_ms`: 平均持续时间(毫秒)
- `max_duration_ms`: 最大持续时间(毫秒)
- `error_rate`: 错误率
- `slow_calls`: 慢调用次数

### I/O操作 (io)
- `total_operations`: 总操作次数
- `avg_throughput_mbps`: 平均吞吐量(MB/s)
- `avg_duration_us`: 平均持续时间(微秒)
- `read_operations`: 读操作次数
- `write_operations`: 写操作次数

### 进程执行 (exec)
- `total_processes`: 总进程数
- `unique_commands`: 唯一命令数
- `failed_executions`: 失败执行次数

### 中断 (interrupt)
- `total_interrupts`: 总中断次数
- `avg_duration_us`: 平均持续时间(微秒)
- `hardware_interrupts`: 硬件中断次数
- `software_interrupts`: 软件中断次数

### 页面错误 (page_fault)
- `total_faults`: 总页面错误次数
- `major_faults`: 主要页面错误次数
- `minor_faults`: 次要页面错误次数
- `write_faults`: 写错误次数

## 数据质量处理

工具自动处理以下数据质量问题：

### 文件读取层面
- **多种编码支持**：自动尝试UTF-8, GBK, GB2312, Latin1等编码
- **CSV格式问题**：处理引号嵌套、字段分隔符问题
- **多策略读取**：标准读取 → 无引号模式 → 严格CSV → 宽松模式 → 手动解析
- **容错处理**：跳过格式错误行，继续处理其他数据

### 数据清理层面
- **时间戳处理**：自动转换和验证时间戳格式
- **数值类型转换**：安全转换数值列，处理无效值
- **布尔值处理**：智能识别True/False/1/0等格式
- **字符串清理**：移除多余引号、处理转义字符
- **空值处理**：移除完全空的行和无效数据

### 错误恢复能力
- **分块读取**：大文件分块处理，避免内存溢出
- **手动解析**：当所有标准方法失败时，使用自定义CSV解析器
- **字段对齐**：自动处理字段数量不匹配问题
- **继续处理**：单个文件失败不影响其他文件的处理

## 示例工作流

```bash
# 1. 分割数据（推荐使用bash脚本）
./split_data.sh 2025-10-20 2025-10-25

# 2. 查看可用日期
python3 analyzer.py --list-dates

# 3. 分析单日性能
python3 analyzer.py --analyze 20251021 --verbose

# 4. 对比多日性能
python3 analyzer.py --compare 20251021 20251022 20251023

# 5. 生成可视化报告 (需要在Python中执行)
```

## 大文件处理优化

### 超大文件处理策略

当处理超过1亿行的数据文件时，推荐使用以下策略：

#### 方法一：Bash脚本处理（推荐）

```bash
# 分批处理，快速高效
./split_data.sh 2025-10-01 2025-10-07
./split_data.sh 2025-10-08 2025-10-14
./split_data.sh 2025-10-15 2025-10-21

# 处理整月数据
./split_data.sh 2025-10-01 2025-10-31
```

**Bash脚本特点**：
- 🚀 使用grep直接过滤，速度极快
- 💾 内存占用几乎为0
- 🛠 简单可靠，不会因为数据格式问题崩溃
- 📊 可以处理任意大小的文件

### 处理能力

| 文件大小 | Bash脚本处理时间 |
|---------|-----------------|
| **小文件** (<1GB) | ✅ 秒级处理 |
| **中等文件** (1GB-10GB) | ✅ 分钟级处理 |
| **大文件** (10GB-100GB) | ✅ 十分钟级处理 |
| **超大文件** (>100GB) | ✅ 小时级处理 |

## 注意事项

1. 确保有足够的磁盘空间存储分割后的数据
2. 大文件分割可能需要较长时间，请耐心等待
3. bash脚本不会检查重复数据，以提高处理速度
4. 脚本会自动删除只有表头的空文件，保持输出目录整洁
5. 可视化功能需要图形界面支持
6. 建议在分析前先备份原始数据

## 故障排除

### 常见问题

**1. 数据格式错误**
```
Error tokenizing data. C error: EOF inside string starting at row ...
```
解决方法：
- 工具会自动尝试多种读取策略（标准读取 → 无引号模式 → 手动解析）
- 使用 `--verbose` 查看详细的处理过程
- 工具会跳过格式错误的行，继续处理其他数据

**2. 编码错误**
- 工具会自动尝试多种编码格式（UTF-8, GBK, GB2312, Latin1）
- 如果仍有问题，检查原始文件的编码

**3. 内存不足**
- 工具使用分块读取，理论上可以处理任意大小的文件
- 推荐使用bash脚本进行数据分割，内存占用几乎为0

**4. 图表显示问题**
- 确保安装了matplotlib和seaborn
- 在服务器环境中可能需要设置DISPLAY变量

**5. 数据文件不存在**
- 检查output目录路径是否正确
- 确保eBPF监控工具已经生成了数据文件
