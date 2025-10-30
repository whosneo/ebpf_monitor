#!/bin/bash

# eBPF数据分割脚本
# 使用grep按日期范围快速分割数据文件

set -e

# 默认配置
OUTPUT_DIR="../output"
DAILY_DATA_DIR="./daily_data"
VERBOSE=false

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 打印帮助信息
show_help() {
    echo "eBPF数据分割脚本"
    echo ""
    echo "用法: $0 [选项] <开始日期> <结束日期>"
    echo ""
    echo "参数:"
    echo "  开始日期          开始日期 (YYYY-MM-DD 格式)"
    echo "  结束日期          结束日期 (YYYY-MM-DD 格式)"
    echo ""
    echo "选项:"
    echo "  -o, --output-dir DIR     指定output目录 (默认: ../output)"
    echo "  -d, --daily-dir DIR      指定输出目录 (默认: ./daily_data)"
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
    echo "  $0 2025-10-20 2025-10-25"
    echo "  $0 -v -o /path/to/output 2025-10-20 2025-10-25"
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
    if ! date -d "$date_str" >/dev/null 2>&1; then
        log_error "无效的日期格式: $date_str (应为 YYYY-MM-DD)"
        return 1
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
        current_date=$(date -d "$current_date + 1 day" +%Y-%m-%d)
    done
    echo "$end_date"  # 包含结束日期
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
    local total_lines=$(wc -l < "$input_file")
    
    log_info "开始处理 $monitor_type 文件: $(basename "$input_file") ($total_lines 行)"
    
    # 生成日期范围
    local dates=($(generate_date_range "$start_date" "$end_date"))
    
    # 为每个日期创建输出文件并写入头部
    local output_files=()
    for date in "${dates[@]}"; do
        local compact_date=$(date_to_compact "$date")
        local output_file="$DAILY_DATA_DIR/${monitor_type}_${compact_date}.csv"
        output_files+=("$output_file")
        
        # 如果文件不存在，创建并写入头部
        if [ ! -f "$output_file" ]; then
            echo "$header" > "$output_file"
            log_debug "创建输出文件: $output_file"
        fi
    done
    
    # 使用grep按日期过滤数据
    for date in "${dates[@]}"; do
        local compact_date=$(date_to_compact "$date")
        local output_file="$DAILY_DATA_DIR/${monitor_type}_${compact_date}.csv"
        
        # 构建grep模式 - 匹配日期格式 YYYY-MM-DD
        local grep_pattern="$date"
        
        # 过滤数据并追加到输出文件（跳过头部行）
        local filtered_lines=$(tail -n +2 "$input_file" | grep "$grep_pattern" | wc -l)
        
        if [ "$filtered_lines" -gt 0 ]; then
            tail -n +2 "$input_file" | grep "$grep_pattern" >> "$output_file"
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
    
    # 检查参数数量
    if [ $# -ne 2 ]; then
        log_error "需要提供开始日期和结束日期"
        show_help
        exit 1
    fi
    
    local start_date="$1"
    local end_date="$2"
    
    # 验证日期格式
    if ! validate_date "$start_date" || ! validate_date "$end_date"; then
        exit 1
    fi
    
    # 检查日期顺序
    if [ "$start_date" \> "$end_date" ]; then
        log_error "开始日期不能晚于结束日期"
        exit 1
    fi
    
    log_info "开始数据分割..."
    log_info "日期范围: $start_date 到 $end_date"
    log_info "输入目录: $OUTPUT_DIR"
    log_info "输出目录: $DAILY_DATA_DIR"
    
    # 创建输出目录
    mkdir -p "$DAILY_DATA_DIR"
    
    # 检查输入目录
    if [ ! -d "$OUTPUT_DIR" ]; then
        log_error "输入目录不存在: $OUTPUT_DIR"
        exit 1
    fi
    
    # 查找所有CSV文件
    local csv_files=($(find "$OUTPUT_DIR" -name "*.csv" -type f))
    
    if [ ${#csv_files[@]} -eq 0 ]; then
        log_warn "在 $OUTPUT_DIR 中未找到CSV文件"
        exit 1
    fi
    
    log_info "找到 ${#csv_files[@]} 个CSV文件"
    
    # 统计信息
    local total_files=0
    local processed_files=0
    local failed_files=0
    
    # 按监控器类型分组处理文件
    declare -A monitor_files
    
    for file in "${csv_files[@]}"; do
        local basename=$(basename "$file")
        local monitor_type=""
        
        # 提取监控器类型
        if [[ $basename =~ ^(exec|syscall|io|interrupt|func|open|page_fault)_ ]]; then
            monitor_type="${BASH_REMATCH[1]}"
            monitor_files["$monitor_type"]+="$file "
        else
            log_debug "跳过文件（无法识别监控器类型）: $basename"
        fi
    done
    
    # 处理每种监控器类型的文件
    for monitor_type in "${!monitor_files[@]}"; do
        log_info "处理 $monitor_type 监控器数据..."
        
        local files_array=(${monitor_files[$monitor_type]})
        for file in "${files_array[@]}"; do
            total_files=$((total_files + 1))
            if process_file "$file" "$monitor_type" "$start_date" "$end_date"; then
                processed_files=$((processed_files + 1))
            else
                failed_files=$((failed_files + 1))
            fi
        done
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
    local output_files=($(find "$DAILY_DATA_DIR" -name "*.csv" -type f | sort))
    
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
    
    # 显示最终生成的文件
    output_files=($(find "$DAILY_DATA_DIR" -name "*.csv" -type f | sort))
    if [ ${#output_files[@]} -gt 0 ]; then
        echo ""
        log_info "最终生成的日文件:"
        for file in "${output_files[@]}"; do
            local line_count=$(wc -l < "$file")
            echo "  $(basename "$file"): $((line_count - 1)) 行数据"
        done
    else
        log_warn "没有生成任何包含数据的文件"
    fi
}

# 执行主函数
main "$@"
