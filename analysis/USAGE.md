# eBPF 数据分析工具使用指南

## 目录结构

```
analysis/
├── daily_data/          # 预处理后的数据（按主机名分目录）
│   ├── server1/
│   │   ├── exec_20251103.csv
│   │   ├── bio_20251103.csv
│   │   └── ...
│   ├── server2/
│   │   └── ...
│   └── server3/
│       └── ...
├── reports/             # 分析报告（按主机名分目录）
│   ├── server1/
│   │   ├── exec_20251103.txt
│   │   ├── bio_20251103.txt
│   │   └── ...
│   ├── server2/
│   │   └── ...
│   ├── compare_exec_20251103.txt      # 横向对比报告
│   ├── compare_bio_20251103.txt
│   └── ...
├── preprocess_data.sh   # 数据预处理脚本
└── analyzer.py          # 数据分析工具
```

## 工作流程

### 步骤1：数据预处理

在**每台服务器**上运行预处理脚本，将原始output数据按日期分割：

```bash
# 预处理单个日期
./preprocess_data.sh 2025-11-03

# 预处理日期范围
./preprocess_data.sh 2025-11-01 2025-11-03

# 指定自定义目录
./preprocess_data.sh -o /path/to/output -d /path/to/daily_data 2025-11-03

# 详细输出模式
./preprocess_data.sh -v 2025-11-03
```

**输出示例：**
```
[INFO] 开始数据分割...
[INFO] 日期范围: 2025-11-03 到 2025-11-03
[INFO] 输入目录: ../output
[INFO] 主机名: server1
[INFO] 输出目录: ./daily_data/server1
[INFO] 找到 9 个CSV文件
[INFO] 处理 exec 监控器数据...
[INFO] 完成处理 exec: 处理了 1234 行数据
...
[INFO] 最终生成的日文件 (server1):
  exec_20251103.csv: 1234 行数据
  bio_20251103.csv: 5678 行数据
  ...
```

预处理后的数据会保存在 `daily_data/主机名/` 目录下。

### 步骤2：单机分析

在**每台服务器**上运行分析工具：

```bash
# 分析所有监控器（使用当前主机名）
python3 analyzer.py --date 20251103

# 分析指定监控器
python3 analyzer.py --date 20251103 --type exec
python3 analyzer.py --date 20251103 --type bio

# 指定主机名（如果需要分析其他服务器的数据）
python3 analyzer.py --date 20251103 --hostname server2

# 指定自定义目录
python3 analyzer.py --date 20251103 \
    --daily-dir /path/to/daily_data \
    --reports-dir /path/to/reports
```

**输出示例：**
```
2025-11-03 10:30:45 - INFO - 加载数据: ./daily_data/server1/exec_20251103.csv
2025-11-03 10:30:46 - INFO - exec 数据清理: 1234 -> 1230 行
2025-11-03 10:30:47 - INFO - 分析报告已保存: ./reports/server1/exec_20251103.txt

================================================================================
EXEC 监控数据分析 - 20251103
================================================================================

总执行次数: 1,230
唯一可执行文件数: 45
唯一进程名数: 23

最常执行的文件 (Top 20):
   1. /usr/bin/bash                                         450次 (36.59%)
   2. /usr/bin/python3                                      230次 (18.70%)
   ...
```

分析报告会保存在 `reports/主机名/监控器_YYYYMMDD.txt`。

### 步骤3：横向对比（多服务器）

将所有服务器的 `daily_data` 目录收集到一台机器上，然后运行对比分析：

```bash
# 对比2台服务器的所有监控器
python3 analyzer.py --date 20251103 \
    --compare \
    --servers server1 server2

# 对比3台服务器的指定监控器
python3 analyzer.py --date 20251103 \
    --compare \
    --servers server1 server2 server3 \
    --type exec

# 对比所有监控器
python3 analyzer.py --date 20251103 \
    --compare \
    --servers CBD-ME-3-B CBD-TStream-9 JSZX-TStream-9 \
    --type all
```

**输出示例：**
```
2025-11-03 10:35:00 - INFO - 加载 server1 数据: 1230 行
2025-11-03 10:35:01 - INFO - 加载 server2 数据: 2340 行
2025-11-03 10:35:02 - INFO - 对比报告已保存: ./reports/compare_exec_20251103.txt

====================================================================================================
服务器横向对比分析 - EXEC - 20251103
====================================================================================================

对比服务器: server1, server2

====================================================================================================
EXEC 监控对比
====================================================================================================

基本统计对比:
服务器                      总执行次数        唯一文件数        唯一进程数
----------------------------------------------------------------------
server1                          1,230              45              23
server2                          2,340              67              34

最常执行文件 Top 10 对比:

server1:
   1. /usr/bin/bash                                         450次
   2. /usr/bin/python3                                      230次
   ...

server2:
   1. /usr/bin/bash                                         890次
   2. /usr/bin/ls                                           340次
   ...
```

对比报告会保存在 `reports/compare_监控器_YYYYMMDD.txt`（注意：不在子目录中）。

## 命令行参数详解

### preprocess_data.sh

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `日期` | 处理日期（YYYY-MM-DD格式），必需 | - |
| `结束日期` | 可选，日期范围的结束日期 | 等于开始日期 |
| `-o, --output-dir` | 原始数据目录 | `../output` |
| `-d, --daily-dir` | 预处理数据输出目录 | `./daily_data` |
| `-v, --verbose` | 详细输出模式 | false |
| `-h, --help` | 显示帮助信息 | - |

### analyzer.py

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--date` | 分析日期（YYYYMMDD格式），必需 | - |
| `--type` | 监控器类型 | `all` |
| `--daily-dir` | 预处理数据目录 | `./daily_data` |
| `--reports-dir` | 报告输出目录 | `./reports` |
| `--hostname` | 指定主机名 | 当前主机名 |
| `--compare` | 启用横向对比模式 | false |
| `--servers` | 对比模式下的服务器列表 | - |

**监控器类型选项：**
- `exec` - 进程执行监控
- `bio` - 块I/O监控
- `func` - VFS函数调用监控
- `open` - 文件打开监控
- `syscall` - 系统调用监控
- `interrupt` - 中断监控
- `page_fault` - 页面错误监控
- `all` - 所有监控器

## 实际应用场景

### 场景1：日常单机分析

```bash
# 在服务器上
cd /path/to/ebpf/analysis

# 1. 预处理今天的数据
./preprocess_data.sh $(date +%Y-%m-%d)

# 2. 分析所有监控器
python3 analyzer.py --date $(date +%Y%m%d)

# 3. 查看报告
ls -lh reports/$(hostname)/
cat reports/$(hostname)/exec_$(date +%Y%m%d).txt
```

### 场景2：多服务器对比分析

```bash
# 在各个服务器上预处理数据
# server1:
./preprocess_data.sh 2025-11-03

# server2:
./preprocess_data.sh 2025-11-03

# server3:
./preprocess_data.sh 2025-11-03

# 将所有服务器的daily_data目录复制到一台机器
# 在分析机器上：
rsync -avz server1:/path/to/analysis/daily_data/server1/ ./daily_data/server1/
rsync -avz server2:/path/to/analysis/daily_data/server2/ ./daily_data/server2/
rsync -avz server3:/path/to/analysis/daily_data/server3/ ./daily_data/server3/

# 执行横向对比
python3 analyzer.py --date 20251103 \
    --compare \
    --servers server1 server2 server3

# 查看对比报告
ls -lh reports/compare_*.txt
cat reports/compare_exec_20251103.txt
```

### 场景3：历史数据批量分析

```bash
# 预处理一周的数据
./preprocess_data.sh 2025-10-28 2025-11-03

# 分析每一天
for date in 20251028 20251029 20251030 20251031 20251101 20251102 20251103; do
    echo "分析 $date ..."
    python3 analyzer.py --date $date
done

# 查看所有报告
ls -lh reports/$(hostname)/
```

## 注意事项

1. **主机名一致性**：确保各服务器的hostname设置正确且唯一，因为目录结构依赖hostname
2. **数据同步**：横向对比前，确保所有服务器的daily_data已同步到分析机器
3. **磁盘空间**：预处理会生成新文件，确保有足够磁盘空间
4. **日期格式**：
   - preprocess_data.sh 使用 `YYYY-MM-DD` 格式
   - analyzer.py 使用 `YYYYMMDD` 格式（无分隔符）
5. **权限**：preprocess_data.sh 需要执行权限：`chmod +x preprocess_data.sh`

## 故障排除

### 问题1：找不到数据文件

```
WARNING - 未找到exec在20251103的数据，请先运行preprocess_data.sh预处理数据
```

**解决方案：**
- 确认已运行 `preprocess_data.sh` 预处理数据
- 检查 `daily_data/主机名/` 目录是否存在对应的CSV文件
- 确认日期格式正确

### 问题2：对比模式需要至少2个服务器

```
ERROR - 对比模式需要至少2个服务器hostname（使用 --servers server1 server2 ...）
```

**解决方案：**
- 使用 `--servers` 参数指定至少2个服务器hostname
- 确保这些服务器的数据已存在于 `daily_data/` 目录中

### 问题3：主机名不匹配

如果主机名与实际不符，可以手动指定：

```bash
python3 analyzer.py --date 20251103 --hostname correct-hostname
```

## 输出报告示例

### 单机报告

文件：`reports/server1/exec_20251103.txt`

```
================================================================================
EXEC 监控数据分析 - 20251103
================================================================================

总执行次数: 1,230
唯一可执行文件数: 45
唯一进程名数: 23

最常执行的文件 (Top 20):
   1. /usr/bin/bash                                         450次 (36.59%)
   2. /usr/bin/python3                                      230次 (18.70%)
   ...

按进程统计执行次数 (Top 15):
   1. bash                  450次 (36.59%)
   2. python3               230次 (18.70%)
   ...

按用户UID统计:
  root                450次 (36.59%)
  uid=1000            780次 (63.41%)
```

### 横向对比报告

文件：`reports/compare_exec_20251103.txt`

```
====================================================================================================
服务器横向对比分析 - EXEC - 20251103
====================================================================================================

对比服务器: server1, server2, server3

====================================================================================================
EXEC 监控对比
====================================================================================================

基本统计对比:
服务器                      总执行次数        唯一文件数        唯一进程数
----------------------------------------------------------------------
server1                          1,230              45              23
server2                          2,340              67              34
server3                            890              32              18

最常执行文件 Top 10 对比:

server1:
   1. /usr/bin/bash                                         450次
   2. /usr/bin/python3                                      230次
   ...

server2:
   1. /usr/bin/bash                                         890次
   2. /usr/bin/ls                                           340次
   ...

server3:
   1. /usr/bin/bash                                         320次
   2. /usr/bin/grep                                         180次
   ...
```

## 高级用法

### 自动化脚本示例

创建 `daily_analysis.sh`：

```bash
#!/bin/bash

DATE=$(date +%Y-%m-%d)
DATE_COMPACT=$(date +%Y%m%d)
HOSTNAME=$(hostname)

echo "开始每日分析 - $DATE ($HOSTNAME)"

# 1. 预处理数据
echo "步骤1: 预处理数据..."
./preprocess_data.sh $DATE

# 2. 执行分析
echo "步骤2: 执行分析..."
python3 analyzer.py --date $DATE_COMPACT

# 3. 生成摘要
echo "步骤3: 生成摘要..."
echo "分析完成 - $DATE" > reports/$HOSTNAME/summary_$DATE_COMPACT.txt
echo "报告文件：" >> reports/$HOSTNAME/summary_$DATE_COMPACT.txt
ls -lh reports/$HOSTNAME/*_$DATE_COMPACT.txt >> reports/$HOSTNAME/summary_$DATE_COMPACT.txt

echo "完成！报告保存在 reports/$HOSTNAME/"
```

使用cron定时执行：

```bash
# 每天凌晨1点执行
0 1 * * * cd /path/to/ebpf/analysis && ./daily_analysis.sh >> logs/analysis.log 2>&1
```

## 总结

这套工具提供了完整的eBPF数据分析流程：

1. **数据预处理**：按主机名和日期组织数据
2. **单机分析**：深入分析单台服务器的性能指标
3. **横向对比**：对比多台服务器的性能差异

通过合理使用这些功能，可以快速定位性能问题、发现系统差异、优化资源配置。

