#!/bin/bash

# eBPF数据预处理脚本
# 使用grep按日期范围快速分割数据文件

set -e

# 默认配置
OUTPUT_DIR="../output"
DAILY_DATA_DIR="./daily_data"
VERBOSE=false
HOSTNAME=""
MONITOR_TYPE=""  # 指定监控器类型，为空表示处理所有类型

# 检测操作系统类型
OS_TYPE=$(uname)
if [ "$OS_TYPE" = "Darwin" ]; then
    log_debug "检测到 macOS 系统" 2>/dev/null || true
elif [ "$OS_TYPE" = "Linux" ]; then
    log_debug "检测到 Linux 系统" 2>/dev/null || true
else
    log_debug "检测到未知系统: $OS_TYPE" 2>/dev/null || true
fi

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 打印帮助信息
show_help() {
    echo "eBPF数据预处理脚本"
    echo ""
    echo "用法: $0 [选项] <日期> [结束日期]"
    echo ""
    echo "参数:"
    echo "  日期              处理日期 (YYYY-MM-DD 格式)"
    echo "  结束日期          可选，结束日期 (YYYY-MM-DD 格式)"
    echo "                    如果不提供，则只处理单个日期"
    echo ""
    echo "选项:"
    echo "  -o, --output-dir DIR     指定output目录 (默认: ../output)"
    echo "  -d, --daily-dir DIR      指定输出目录 (默认: ./daily_data)"
    echo "  --hostname NAME          指定主机名 (默认: 自动检测output目录下的主机)"
    echo "  -t, --type TYPE          指定监控器类型 (如: open, exec, bio等，默认: 全部)"
    echo "  -v, --verbose            详细输出"
    echo "  -h, --help               显示此帮助信息"
    echo ""
    echo "功能:"
    echo "  - 使用grep按日期快速过滤数据"
    echo "  - 自动删除只有表头的空文件"
    echo "  - 支持处理TB级大文件"
    echo "  - 内存占用几乎为0"
    echo ""
    echo "示例:"
    echo "  $0 2025-11-03                              # 处理单个日期"
    echo "  $0 2025-10-20 2025-10-25                   # 处理日期范围"
    echo "  $0 --hostname CBD-ME-3-B 2025-11-03        # 指定主机处理"
    echo "  $0 -t open --hostname CBD-TStream-9 2025-11-07  # 只处理open类型"
    echo "  $0 -v -o /path/to/output 2025-11-03        # 详细输出"
    echo ""
}

# 日志函数
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_debug() {
    if [ "$VERBOSE" = true ]; then
        echo -e "${BLUE}[DEBUG]${NC} $1"
    fi
}

# 将日期格式从YYYY-MM-DD转换为YYYYMMDD
date_to_compact() {
    echo "$1" | sed 's/-//g'
}

# 将日期格式从YYYYMMDD转换为YYYY-MM-DD
compact_to_date() {
    local date_str="$1"
    echo "${date_str:0:4}-${date_str:4:2}-${date_str:6:2}"
}

# 验证日期格式
validate_date() {
    local date_str="$1"
    
    # 根据操作系统类型使用不同的date命令
    if [ "$OS_TYPE" = "Darwin" ]; then
        # macOS (BSD date)
        if ! date -j -f "%Y-%m-%d" "$date_str" >/dev/null 2>&1; then
            log_error "无效的日期格式: $date_str (应为 YYYY-MM-DD)"
            return 1
        fi
    else
        # Linux (GNU date)
        if ! date -d "$date_str" >/dev/null 2>&1; then
            log_error "无效的日期格式: $date_str (应为 YYYY-MM-DD)"
            return 1
        fi
    fi
    
    return 0
}

# 生成日期范围内的所有日期
generate_date_range() {
    local start_date="$1"
    local end_date="$2"
    local current_date="$start_date"
    
    while [ "$current_date" != "$end_date" ]; do
        echo "$current_date"
        
        # 根据操作系统类型使用不同的date命令
        if [ "$OS_TYPE" = "Darwin" ]; then
            # macOS (BSD date)
            current_date=$(date -j -v+1d -f "%Y-%m-%d" "$current_date" +%Y-%m-%d)
        else
            # Linux (GNU date)
            current_date=$(date -d "$current_date + 1 day" +%Y-%m-%d)
        fi
    done
    echo "$end_date"  # 包含结束日期
}

# open数据特殊处理：路径归类 + 字段精简
process_open_line() {
    # 路径归类（多个模式）+ 字段精简（只保留前8个字段）
    # 使用-E选项支持扩展正则表达式（兼容macOS和Linux）
    sed -E \
        -e 's|/home/czce/ats/zmb/topic/[0-9]+/[0-9]{20}\.|/home/czce/ats/zmb/topic/[TOPIC_ID]/*.|g' \
        -e 's|/home/czce/ats/zmb/topic/[0-9]+|/home/czce/ats/zmb/topic/[TOPIC_ID]|g' \
        -e 's|/proc/[0-9]+/|/proc/[PID]/|g' \
        -e 's|/proc/self/task/[0-9]+/|/proc/self/task/[PID]/|g' \
        -e 's|,[0-9]+/cmdline|,[PID]/cmdline|g' \
        -e 's|,[0-9]+/stat|,[PID]/stat|g' \
        -e 's|/proc/irq/[0-9]+/|/proc/irq/[N]/|g' \
        -e 's|/var/lib/NetworkManager/timestamps\.[a-zA-Z0-9]+|/var/lib/NetworkManager/timestamps.*|g' \
        -e 's|/usr/local/lib/systemd/system/session-[0-9]+|/usr/local/lib/systemd/system/session-[N]|g' \
        -e 's|/usr/lib/systemd/system/session-[0-9]+|/usr/lib/systemd/system/session-[N]|g' \
        -e 's|/run/systemd/users/\.#[a-zA-Z0-9]+|/run/systemd/users/.#*|g' \
        -e 's|/run/systemd/sessions/\.#[a-zA-Z0-9]+|/run/systemd/sessions/.#*|g' \
        -e 's|/run/systemd/sessions/[0-9]+\.ref|/run/systemd/sessions/[N].ref|g' \
        -e 's|/run/systemd/generator/session-[0-9]+|/run/systemd/generator/session-[N]|g' \
        -e 's|/run/systemd/generator.late/session-[0-9]+|/run/systemd/generator.late/session-[N]|g' \
        -e 's|/etc/systemd/system/session-[0-9]+|/etc/systemd/system/session-[N]|g' \
        -e 's|/sys/fs/cgroup/pids/user\.slice/user-[0-9]+\.slice/session-[0-9]+\.scope|/sys/fs/cgroup/pids/user.slice/user-[UID].slice/session-[N].scope|g' \
        -e 's|/sys/devices/system/cpu/cpu[0-9]+/cpufreq|/sys/devices/system/cpu/cpu[N]/cpufreq|g' | \
    awk -F',' 'BEGIN {OFS=","} {print $1,$2,$3,$4,$5,$6,$7,$8}'
}

# 处理单个文件
process_file() {
    local input_file="$1"
    local monitor_type="$2"
    local start_date="$3"
    local end_date="$4"
    
    log_debug "处理文件: $input_file"
    
    # 检查文件是否存在
    if [ ! -f "$input_file" ]; then
        log_warn "文件不存在: $input_file"
        return 1
    fi
    
    # 获取文件头
    local header=$(head -n 1 "$input_file")
    if [ -z "$header" ]; then
        log_warn "文件为空: $input_file"
        return 1
    fi
    
    # 检查是否有timestamp列
    if ! echo "$header" | grep -q "timestamp"; then
        log_warn "文件没有timestamp列: $input_file"
        return 1
    fi
    
    local processed_lines=0
    
    log_info "开始处理 $monitor_type 文件: $(basename "$input_file")"
    
    # 生成日期范围
    local dates=($(generate_date_range "$start_date" "$end_date"))
    
    # 为每个日期创建输出文件并写入头部
    local output_files=()
    for date in "${dates[@]}"; do
        local compact_date=$(date_to_compact "$date")
        local output_file="$DAILY_DATA_DIR/$HOSTNAME/${monitor_type}_${compact_date}.csv"
        output_files+=("$output_file")
        
        # 如果文件不存在，创建并写入头部
        if [ ! -f "$output_file" ]; then
            # open类型需要精简表头
            if [ "$monitor_type" = "open" ]; then
                echo "$header" | awk -F',' 'BEGIN {OFS=","} {print $1,$2,$3,$4,$5,$6,$7,$8}' > "$output_file"
            else
                echo "$header" > "$output_file"
            fi
            log_debug "创建输出文件: $output_file"
        fi
    done
    
    # 使用grep按日期过滤数据
    for date in "${dates[@]}"; do
        local compact_date=$(date_to_compact "$date")
        local output_file="$DAILY_DATA_DIR/$HOSTNAME/${monitor_type}_${compact_date}.csv"
        
        # 构建grep模式 - 匹配日期格式 YYYY-MM-DD
        local grep_pattern="$date"
        
        # open类型需要特殊处理：边过滤边替换边精简
        if [ "$monitor_type" = "open" ]; then
            local filtered_lines=$(tail -n +2 "$input_file" | grep "$grep_pattern" | process_open_line | tee -a "$output_file" | wc -l)
        else
            # 其他类型正常处理
            local filtered_lines=$(tail -n +2 "$input_file" | grep "$grep_pattern" | tee -a "$output_file" | wc -l)
        fi
        
        if [ "$filtered_lines" -gt 0 ]; then
            log_debug "日期 $date: 写入 $filtered_lines 行到 $output_file"
            processed_lines=$((processed_lines + filtered_lines))
        fi
    done
    
    log_info "完成处理 $monitor_type: 处理了 $processed_lines 行数据"
    return 0
}

# 主处理函数
main() {
    # 解析命令行参数
    while [[ $# -gt 0 ]]; do
        case $1 in
            -o|--output-dir)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -d|--daily-dir)
                DAILY_DATA_DIR="$2"
                shift 2
                ;;
            --hostname)
                HOSTNAME="$2"
                shift 2
                ;;
            -t|--type)
                MONITOR_TYPE="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            -*)
                log_error "未知选项: $1"
                show_help
                exit 1
                ;;
            *)
                break
                ;;
        esac
    done
    
    # 检查参数数量（支持1个或2个日期参数）
    if [ $# -eq 0 ] || [ $# -gt 2 ]; then
        log_error "需要提供1个或2个日期参数"
        show_help
        exit 1
    fi
    
    local start_date="$1"
    local end_date="${2:-$1}"  # 如果没有第二个参数，使用第一个参数作为结束日期
    
    # 验证日期格式
    if ! validate_date "$start_date" || ! validate_date "$end_date"; then
        exit 1
    fi
    
    # 检查日期顺序
    if [ "$start_date" \> "$end_date" ]; then
        log_error "开始日期不能晚于结束日期"
        exit 1
    fi
    
    # 检查输入目录
    if [ ! -d "$OUTPUT_DIR" ]; then
        log_error "输入目录不存在: $OUTPUT_DIR"
        exit 1
    fi
    
    # 处理主机名
    if [ -z "$HOSTNAME" ]; then
        # 自动检测output目录下的主机目录
        local host_dirs=($(find "$OUTPUT_DIR" -mindepth 1 -maxdepth 1 -type d -exec basename {} \;))
        
        if [ ${#host_dirs[@]} -eq 0 ]; then
            log_error "在 $OUTPUT_DIR 中未找到主机目录"
            exit 1
        elif [ ${#host_dirs[@]} -eq 1 ]; then
            HOSTNAME="${host_dirs[0]}"
            log_info "自动检测到主机: $HOSTNAME"
        else
            log_error "发现多个主机目录，请使用 --hostname 参数指定:"
            for host in "${host_dirs[@]}"; do
                echo "  - $host"
            done
            exit 1
        fi
    fi
    
    # 检查主机目录是否存在
    if [ ! -d "$OUTPUT_DIR/$HOSTNAME" ]; then
        log_error "主机目录不存在: $OUTPUT_DIR/$HOSTNAME"
        exit 1
    fi
    
    log_info "开始数据分割..."
    log_info "日期范围: $start_date 到 $end_date"
    log_info "输入目录: $OUTPUT_DIR/$HOSTNAME"
    log_info "主机名: $HOSTNAME"
    log_info "输出目录: $DAILY_DATA_DIR/$HOSTNAME"
    if [ -n "$MONITOR_TYPE" ]; then
        log_info "监控器类型: $MONITOR_TYPE"
    fi
    
    # 创建输出目录（按主机名分目录）
    mkdir -p "$DAILY_DATA_DIR/$HOSTNAME"
    
    # 构建文件匹配模式 - 按类型和日期范围智能筛选
    local dates=($(generate_date_range "$start_date" "$end_date"))
    local csv_files=()
    
    # 构建文件名模式
    local file_pattern="${MONITOR_TYPE:-*}_*"
    
    # 按日期查找匹配的文件
    for date in "${dates[@]}"; do
        local compact_date=$(date_to_compact "$date")
        local date_files=($(find "$OUTPUT_DIR/$HOSTNAME" -name "${file_pattern}${compact_date}*.csv" -type f 2>/dev/null | sort))
        csv_files+=("${date_files[@]}")
    done
    
    if [ ${#csv_files[@]} -eq 0 ]; then
        if [ -n "$MONITOR_TYPE" ]; then
            log_warn "未找到 $MONITOR_TYPE 类型在日期范围 $start_date 到 $end_date 的CSV文件"
        else
            log_warn "未找到日期范围 $start_date 到 $end_date 的CSV文件"
        fi
        exit 1
    fi
    
    if [ -n "$MONITOR_TYPE" ]; then
        log_info "找到 ${#csv_files[@]} 个匹配的 $MONITOR_TYPE 文件"
    else
        log_info "找到 ${#csv_files[@]} 个匹配日期范围的文件"
    fi
    
    # 统计信息
    local total_files=0
    local processed_files=0
    local failed_files=0
    
    # 直接处理所有文件
    for file in "${csv_files[@]}"; do
        local basename=$(basename "$file")
        local monitor_type=""
        
        # 提取监控器类型
        if [[ $basename =~ ^(exec|syscall|bio|interrupt|func|open|page_fault|context_switch)_ ]]; then
            monitor_type="${BASH_REMATCH[1]}"
            
            # 如果指定了监控器类型，只处理该类型
            if [ -n "$MONITOR_TYPE" ] && [ "$monitor_type" != "$MONITOR_TYPE" ]; then
                log_debug "跳过文件（类型不匹配）: $basename"
                continue
            fi
            
            total_files=$((total_files + 1))
            
            if process_file "$file" "$monitor_type" "$start_date" "$end_date"; then
                processed_files=$((processed_files + 1))
            else
                failed_files=$((failed_files + 1))
            fi
        else
            log_debug "跳过文件（无法识别监控器类型）: $basename"
        fi
    done
    
    # 输出统计信息
    echo ""
    log_info "数据分割完成!"
    log_info "总文件数: $total_files"
    log_info "成功处理: $processed_files"
    log_info "处理失败: $failed_files"
    
    # 清理空文件（只有表头的文件）
    echo ""
    log_info "清理空文件..."
    local empty_files=0
    local output_files=($(find "$DAILY_DATA_DIR/$HOSTNAME" -name "*.csv" -type f | sort))
    
    for file in "${output_files[@]}"; do
        local line_count=$(wc -l < "$file")
        if [ "$line_count" -le 1 ]; then
            log_debug "删除空文件: $(basename "$file")"
            rm "$file"
            empty_files=$((empty_files + 1))
        fi
    done
    
    if [ "$empty_files" -gt 0 ]; then
        log_info "删除了 $empty_files 个空文件"
    fi
    
    # 显示本次处理生成的文件
    echo ""
    log_info "本次处理生成的文件 ($HOSTNAME):"
    
    # 生成日期范围
    local dates=($(generate_date_range "$start_date" "$end_date"))
    local found_files=0
    
    for date in "${dates[@]}"; do
        local compact_date=$(date_to_compact "$date")
        
        # 如果指定了监控器类型，只显示该类型
        if [ -n "$MONITOR_TYPE" ]; then
            local file_path="$DAILY_DATA_DIR/$HOSTNAME/${MONITOR_TYPE}_${compact_date}.csv"
            if [ -f "$file_path" ]; then
                local line_count=$(wc -l < "$file_path")
                if [ "$line_count" -gt 1 ]; then
                    echo "  $(basename "$file_path"): $((line_count - 1)) 行数据"
                    found_files=$((found_files + 1))
                fi
            fi
        else
            # 显示该日期的所有类型文件
            local date_files=($(find "$DAILY_DATA_DIR/$HOSTNAME" -name "*_${compact_date}.csv" -type f | sort))
            for file in "${date_files[@]}"; do
                local line_count=$(wc -l < "$file")
                if [ "$line_count" -gt 1 ]; then
                    echo "  $(basename "$file"): $((line_count - 1)) 行数据"
                    found_files=$((found_files + 1))
                fi
            done
        fi
    done
    
    if [ "$found_files" -eq 0 ]; then
        log_warn "没有生成任何包含数据的文件"
    fi
}

# 执行主函数
main "$@"
