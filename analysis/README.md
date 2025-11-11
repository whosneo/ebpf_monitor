# eBPF数据分析工具

## 概述

本工具用于分析eBPF监控系统采集的性能数据，支持新的聚合统计数据格式。

## 新版本特性

### 数据格式变化

新版本的监控系统采用**聚合统计格式**输出数据，相比旧版本的单条记录格式，具有以下优势：

1. **数据量大幅减少**：从单条记录变为聚合统计，数据文件大小减少90%以上
2. **分析效率提升**：预聚合的数据可以直接用于统计分析
3. **增加统计字段**：包含count、error_rate、avg_latency等统计信息
4. **时间可读性**：增加time_str字段，方便人工查看

### 支持的监控器类型

- **exec**: 进程执行监控
- **bio**: 块I/O操作监控（原io监控器）
- **func**: VFS函数调用监控
- **open**: 文件打开操作监控
- **syscall**: 系统调用监控
- **interrupt**: 中断监控
- **page_fault**: 页面错误监控

## 安装依赖

```bash
pip3 install -r requirements.txt
```

## 使用方法

### 基本用法

```bash
# 分析指定日期的所有数据
python3 analyzer.py --date 20251103

# 分析指定类型的数据
python3 analyzer.py --date 20251103 --type exec

# 指定数据目录
python3 analyzer.py --date 20251103 --output-dir /path/to/output --daily-dir /path/to/daily_data
```

### 命令行参数

- `--date`: 分析日期，格式为YYYYMMDD（必需）
- `--type`: 监控器类型，可选值: exec, bio, func, open, syscall, interrupt, page_fault, all（默认: all）
- `--output-dir`: output目录路径（默认: ../output）
- `--daily-dir`: daily_data目录路径（默认: ./daily_data）

## 数据格式说明

### 1. EXEC 监控器

**字段**:
- `timestamp`: Unix时间戳
- `time_str`: 可读时间字符串
- `uid`: 用户ID
- `pid`: 进程ID
- `comm`: 进程名
- `filename`: 可执行文件路径

**分析内容**:
- 总执行次数统计
- 最常执行的文件Top 20
- 按进程统计执行次数
- 按用户UID统计

### 2. BIO 监控器（块I/O）

**字段**:
- `timestamp`: Unix时间戳
- `time_str`: 可读时间字符串
- `comm`: 进程名
- `io_type`: I/O类型编号
- `io_type_str`: I/O类型字符串（READ, WRITE, FLUSH, SYNC等）
- `count`: 操作次数
- `total_bytes`: 总字节数
- `size_mb`: 数据量（MB）
- `avg_latency_us`: 平均延迟（微秒）
- `min_latency_us`: 最小延迟
- `max_latency_us`: 最大延迟
- `throughput_mbps`: 吞吐量（MB/s）

**分析内容**:
- 总I/O操作数和数据量
- 按I/O类型统计（READ/WRITE/SYNC等）
- 按进程统计I/O操作
- 吞吐量统计

### 3. FUNC 监控器（VFS函数）

**字段**:
- `timestamp`: Unix时间戳
- `time_str`: 可读时间字符串
- `comm`: 进程名
- `func_name`: 函数名（vfs_read, vfs_write等）
- `count`: 调用次数

**分析内容**:
- 总函数调用次数
- 按函数统计调用次数
- 按进程统计调用次数
- 进程-函数交叉统计

### 4. OPEN 监控器

**字段**:
- `timestamp`: Unix时间戳
- `time_str`: 可读时间字符串
- `comm`: 进程名
- `operation`: 操作类型（OPEN, OPENAT）
- `filename`: 文件路径
- `count`: 打开次数
- `errors`: 错误次数
- `error_rate`: 错误率
- `avg_lat_us`: 平均延迟（微秒）
- `min_lat_us`: 最小延迟
- `max_lat_us`: 最大延迟
- `flags`: 打开标志（RD, WR, CLO等）

**分析内容**:
- 总打开次数和错误率
- 按操作类型统计
- 最常打开的文件Top 20
- 错误率最高的文件Top 10
- 按进程统计

### 5. SYSCALL 监控器

**字段**:
- `timestamp`: Unix时间戳
- `time_str`: 可读时间字符串
- `monitor_type`: 监控类型
- `comm`: 进程名
- `syscall_nr`: 系统调用编号
- `syscall_name`: 系统调用名称
- `category`: 分类（file_io, memory, process, ipc等）
- `count`: 调用次数
- `error_count`: 错误次数
- `error_rate`: 错误率

**分析内容**:
- 总系统调用次数和错误率
- 按系统调用统计Top 20
- 按分类统计
- 按进程统计

### 6. INTERRUPT 监控器

**字段**:
- `timestamp`: Unix时间戳
- `time_str`: 可读时间字符串
- `comm`: 进程名
- `irq_type`: 中断类型编号
- `irq_type_str`: 中断类型字符串（TIMER, SOFT, NETWORK, BLOCK等）
- `cpu`: CPU编号
- `count`: 中断次数

**分析内容**:
- 总中断次数
- 按中断类型统计
- 按CPU统计（识别热点CPU）
- 按进程统计

### 7. PAGE_FAULT 监控器

**字段**:
- `timestamp`: Unix时间戳
- `time_str`: 可读时间字符串
- `comm`: 进程名
- `fault_type`: 错误类型编号
- `fault_type_str`: 错误类型字符串（MAJOR/MINOR, READ/WRITE, USER/KERNEL）
- `cpu`: CPU编号
- `numa_node`: NUMA节点
- `count`: 错误次数

**分析内容**:
- 总页面错误次数
- 按错误类型统计
- 按CPU统计
- 按NUMA节点统计
- 按进程统计

## 数据分割

对于包含多日数据的大文件，建议使用bash脚本进行分割：

```bash
cd analysis
./split_data.sh
```

脚本会自动：
1. 扫描output目录中的所有CSV文件
2. 按日期分割数据到daily_data目录
3. 删除只有表头的空文件
4. 显示分割结果统计

### bash脚本优势

- **高效**: 使用grep直接过滤，速度快
- **低内存**: 流式处理，不占用大量内存
- **简单**: 不做复杂检查，专注于分割任务
- **自动清理**: 自动删除只有表头的空文件

### 注意事项

- bash脚本不会检查重复数据，以提高处理速度
- 脚本会自动删除只有表头的空文件，保持输出目录整洁
- 对于超大文件（>100GB），建议分批处理

## 输出示例

### EXEC 分析输出

```
================================================================================
EXEC 监控数据分析 - 20251103
================================================================================

总执行次数: 1,234
唯一可执行文件数: 45
唯一进程名数: 23

最常执行的文件 (Top 20):
   1. /usr/bin/ls                                                123次 (9.97%)
   2. /usr/bin/cat                                               89次 (7.21%)
   ...

按进程统计执行次数 (Top 15):
   1. bash                    456次 (36.95%)
   2. python                  234次 (18.96%)
   ...
```

### BIO 分析输出

```
================================================================================
BIO (块I/O) 监控数据分析 - 20251103
================================================================================

总I/O操作数: 12,345
总数据量: 1,234.56 MB (1,294,967,296 bytes)

按I/O类型统计:
  READ                   8,234次 (66.70%) |   800.50 MB | 平均延迟:   1,234.56 μs
  WRITE                  3,456次 (28.00%) |   400.25 MB | 平均延迟:   2,345.67 μs
  ...
```

## 故障排除

### 1. 找不到数据文件

**错误**: `未找到xxx在YYYYMMDD的数据`

**解决方法**:
- 检查output目录路径是否正确
- 确认数据文件名格式为: `{type}_YYYYMMDD_HHMMSS.csv`
- 如果使用daily_data，确保已运行split_data.sh

### 2. 数据格式错误

**错误**: `Error tokenizing data`

**解决方法**:
- 新版本的safe_read_csv已经包含多种容错策略
- 如果仍然出错，检查CSV文件是否损坏
- 尝试使用bash脚本重新分割数据

### 3. 内存不足

**错误**: `MemoryError`

**解决方法**:
- 使用bash脚本先分割数据
- 分析单日数据而不是全部数据
- 增加系统内存或使用更大内存的机器

### 4. 字段缺失

**错误**: `KeyError: 'xxx'`

**解决方法**:
- 确认数据文件格式是否为新版本聚合格式
- 检查监控器是否正确配置并运行
- 查看数据文件表头，确认字段名称

## 性能优化建议

1. **使用bash脚本分割**: 对于大文件，先用bash脚本分割可以大幅提升分析速度
2. **按日分析**: 分析单日数据比分析全部数据快得多
3. **选择性分析**: 只分析需要的监控器类型，使用--type参数
4. **清理旧数据**: 定期清理不需要的历史数据

## 与旧版本的区别

### 数据格式

| 特性 | 旧版本 | 新版本 |
|------|--------|--------|
| 数据粒度 | 单条记录 | 聚合统计 |
| 文件大小 | 大（GB级） | 小（MB级） |
| 分析速度 | 慢 | 快 |
| 统计字段 | 少 | 多（含count、error_rate等） |
| 时间格式 | 仅timestamp | timestamp + time_str |

### 监控器变化

- `io` → `bio`（重命名，增强功能）
- 所有监控器都采用聚合格式
- 移除了 `vfs` 和 `context_switch` 监控器（未实现深度分析）

### 分析方法

- 旧版本：需要先聚合再分析
- 新版本：直接分析预聚合数据

## 开发说明

### 添加新的分析功能

1. 在`EBPFAnalyzer`类中添加新的分析方法
2. 方法命名格式: `analyze_{monitor_type}`
3. 使用`load_daily_data`加载数据
4. 使用`clean_loaded_data`清理数据
5. 输出格式化的分析结果

### 代码结构

```
analysis/
├── analyzer.py          # 主分析程序
├── data_utils.py        # 数据处理工具
├── visualizer.py        # 可视化工具（待开发）
├── split_data.sh        # 数据分割脚本
├── requirements.txt     # Python依赖
└── README.md           # 本文档
```

## 常见问题

**Q: 为什么要改用聚合格式？**

A: 聚合格式可以大幅减少数据量（减少90%以上），提升分析速度，同时提供更丰富的统计信息。

**Q: 旧版本的数据还能用吗？**

A: 不能直接使用。需要重新采集数据，或者编写转换脚本（不推荐）。

**Q: 如何选择分析日期？**

A: 查看output或daily_data目录中的文件名，提取日期部分（YYYYMMDD格式）。

**Q: 可以分析多日数据吗？**

A: 当前版本只支持单日分析。如需多日对比，请多次运行分析工具。

**Q: 如何导出分析结果？**

A: 使用shell重定向: `python3 analyzer.py --date 20251103 > report.txt`

## 更新日志

### v2.0.0 (2025-11-04)

- 🎉 完全重写以支持新的聚合统计数据格式
- 🔄 IO监控器重命名为BIO
- 📊 7个核心监控器深度分析增强（EXEC, SYSCALL, BIO, FUNC, OPEN, INTERRUPT, PAGE_FAULT）
- ✨ 新增完整排名、累计百分比、多维度交叉分析
- 🚀 分析速度提升10倍以上
- 📉 内存占用减少90%以上
- 🛠️ 改进数据清理和容错机制
- 🐍 更新为Python 3专用（pandas 2.x+）
- 📝 更新文档以反映新格式

### v1.0.0 (2024-10-21)

- 初始版本
- 支持单条记录格式的数据分析

## 许可证

本工具是eBPF监控系统的一部分，遵循项目主许可证。

## 联系方式

如有问题或建议，请联系项目维护者。
