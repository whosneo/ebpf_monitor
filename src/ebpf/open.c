/* eBPF open_monitor 程序 - 基于统计模式的文件打开监控
 * 
 * 设计特点：
 * 1. 统计模式：在内核态按多维度累积文件打开统计，避免高频操作导致的数据丢失
 * 2. 定期输出：Python端定时读取统计数据并输出（默认5秒周期）
 * 3. 保留路径：统计维度包含完整文件路径，便于识别热点文件
 * 4. 延迟统计：记录文件打开操作的延迟（min/avg/max）
 * 
 * 使用的Tracepoint：
 * - syscalls:sys_enter_open: 监控传统open系统调用入口
 * - syscalls:sys_exit_open: 监控传统open系统调用出口
 * - syscalls:sys_enter_openat: 监控现代openat系统调用入口
 * - syscalls:sys_exit_openat: 监控现代openat系统调用出口
 * 
 * 统计维度说明：
 * - comm: 进程名（识别哪些进程打开文件）
 * - operation: 操作类型（OPEN vs OPENAT）
 * - filename: 文件路径（识别热点文件）
 * 
 * 统计指标：
 * - count: 打开次数
 * - error_count: 错误次数（返回值 < 0）
 * - total_latency_ns: 总延迟（纳秒）
 * - min_latency_ns: 最小延迟
 * - max_latency_ns: 最大延迟
 * - flags_summary: 标志位汇总（位或运算）
 * 
 * 性能优化：
 * - 使用原子操作(__sync_fetch_and_add)保证并发安全
 * - min/max使用简单比较(非原子)，避免CAS操作的兼容性问题
 * - 兼容内核3.10+（使用lookup+update模式）
 * - Hash Map大小：open_stats=10240, open_entry_times=1024
 * 
 * 兼容性支持：
 * - 支持内核版本：3.10+（CentOS 7）到最新内核
 * - 用户空间字符串读取：使用 bpf_probe_read 确保最大兼容性
 * 
 * 过滤机制：
 * - 默认监控所有进程和用户
 * - 自动过滤内核线程（PID=0）
 */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

#define MAX_PATH_LEN 256    // 文件名最大长度

/* 操作类型定义 */
#define OP_OPEN    0
#define OP_OPENAT  1

/* 统计Key：(进程名, 操作类型, 文件路径)
 * 注意：comm[16] + u32 + filename[256]会有填充字节，必须用__builtin_memset清零
 */
struct open_stats_key_t {
    char comm[TASK_COMM_LEN];      // 进程名 (16字节)
    u32 operation;                 // 操作类型：OP_OPEN or OP_OPENAT
    char filename[MAX_PATH_LEN];   // 文件路径 (256字节)
};

/* 统计Value */
struct open_stats_value_t {
    u64 count;                     // 打开次数
    u64 error_count;               // 错误次数
    u64 total_latency_ns;          // 总延迟（纳秒）
    u64 min_latency_ns;            // 最小延迟
    u64 max_latency_ns;            // 最大延迟
    u32 flags_summary;             // 标志位汇总（位或运算）
};

/* 临时存储结构（用于计算延迟） */
struct open_entry_info_t {
    u64 start_ts;                  // 开始时间戳
    char comm[TASK_COMM_LEN];      // 进程名
    u32 operation;                 // 操作类型
    char filename[MAX_PATH_LEN];   // 文件路径
    u32 flags;                     // 打开标志
};

/* BPF映射 */
BPF_HASH(open_stats, struct open_stats_key_t, struct open_stats_value_t, 10240);  // 文件打开统计
BPF_HASH(open_entry_times, u64, struct open_entry_info_t, 1024);                  // 临时存储（pid_tgid -> 入口信息）
BPF_PERCPU_ARRAY(open_key_heap, struct open_stats_key_t, 1);                      // Per-CPU临时Key存储（避免栈溢出）

/* 辅助函数：安全读取用户空间字符串
 * 
 * 兼容性说明：
 * - 使用 bpf_probe_read 以兼容旧内核（3.10+）
 * - 这是最通用的读取函数，所有内核版本都支持
 * - 在启用 SMAP/SMEP 的新内核上仍然可用（BPF 上下文允许）
 * - 虽然较新内核推荐使用 bpf_probe_read_user_str，但为了最大兼容性选择此函数
 */
static inline int read_user_filename(char *dest, const char __user *src) {
    __builtin_memset(dest, 0, MAX_PATH_LEN);
    
    // 使用 bpf_probe_read 兼容 3.10+ 所有内核版本
    int ret = bpf_probe_read(dest, MAX_PATH_LEN - 1, src);
    if (ret < 0) {
        // 读取失败，标记为未知
        __builtin_memcpy(dest, "N/A", 3);
        return -1;
    }
    
    // 确保字符串以null结尾（防御性编程）
    dest[MAX_PATH_LEN - 1] = '\0';
    return 0;
}

/* 统计更新函数：更新文件打开统计
 * 
 * 注意：为避免超出BPF栈限制（512字节），此函数接收已构造好的Key指针
 */
static inline void update_open_stats(
    struct open_stats_key_t *key,
    u32 flags,
    u64 latency_ns,
    bool is_error
) {
    // 查找或初始化统计（兼容3.10内核，使用lookup+update模式）
    struct open_stats_value_t *value = open_stats.lookup(key);
    if (!value) {
        // 不存在，创建新条目
        struct open_stats_value_t new_val = {};
        new_val.count = 1;
        new_val.error_count = is_error ? 1 : 0;
        new_val.total_latency_ns = latency_ns;
        new_val.min_latency_ns = latency_ns;
        new_val.max_latency_ns = latency_ns;
        new_val.flags_summary = flags;
        open_stats.update(key, &new_val);
    } else {
        // 已存在，原子更新计数和累加值
        __sync_fetch_and_add(&value->count, 1);
        if (is_error) {
            __sync_fetch_and_add(&value->error_count, 1);
        }
        __sync_fetch_and_add(&value->total_latency_ns, latency_ns);
        
        // 更新min（简单比较，在并发时可能不完全准确，但足够接近）
        if (latency_ns < value->min_latency_ns) {
            value->min_latency_ns = latency_ns;
        }
        
        // 更新max（简单比较，在并发时可能不完全准确，但足够接近）
        if (latency_ns > value->max_latency_ns) {
            value->max_latency_ns = latency_ns;
        }
        
        // 位或运算汇总flags
        value->flags_summary |= flags;
    }
}

// # cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_open/format
// name: sys_enter_open
// ID: 610
// format:
// 	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
// 	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
// 	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
// 	field:int common_pid;	offset:4;	size:4;	signed:1;

// 	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
// 	field:const char * filename;	offset:16;	size:8;	signed:0;
// 	field:int flags;	offset:24;	size:8;	signed:0;
// 	field:umode_t mode;	offset:32;	size:8;	signed:0;

// print fmt: "filename: 0x%08lx, flags: 0x%08lx, mode: 0x%08lx", ((unsigned long)(REC->filename)), ((unsigned long)(REC->flags)), ((unsigned long)(REC->mode))

/* Tracepoint：文件打开入口 (open) */
TRACEPOINT_PROBE(syscalls, sys_enter_open) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    if (pid == 0) { //进程过滤，过滤内核线程
        return 0;
    }

    // 记录开始时间和参数
    struct open_entry_info_t info = {};
    info.start_ts = bpf_ktime_get_ns();
    info.operation = OP_OPEN;
    info.flags = args->flags;
    bpf_get_current_comm(&info.comm, sizeof(info.comm));

    // 读取文件名
    read_user_filename(info.filename, args->filename);

    open_entry_times.update(&pid_tgid, &info);
    return 0;
}

// # cat /sys/kernel/debug/tracing/events/syscalls/sys_exit_open/format
// name: sys_exit_open
// ID: 609
// format:
// 	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
// 	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
// 	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
// 	field:int common_pid;	offset:4;	size:4;	signed:1;

// 	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
// 	field:long ret;	offset:16;	size:8;	signed:1;

// print fmt: "0x%lx", REC->ret

/* Tracepoint：文件打开出口 (open) */
TRACEPOINT_PROBE(syscalls, sys_exit_open) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    if (pid == 0) { // 进程过滤，过滤内核线程
        return 0;
    }

    // 查找对应的入口信息
    struct open_entry_info_t *info = open_entry_times.lookup(&pid_tgid);
    if (!info) {
        return 0;
    }

    // 计算延迟
    u64 end_ts = bpf_ktime_get_ns();
    u64 latency_ns = end_ts - info->start_ts;
    
    // 判断是否错误
    s32 ret = args->ret;
    bool is_error = (ret < 0);

    // 使用per-cpu数组避免栈溢出（Key结构太大：276字节）
    int zero = 0;
    struct open_stats_key_t *key = open_key_heap.lookup(&zero);
    if (!key) {
        open_entry_times.delete(&pid_tgid);
        return 0;
    }
    
    // 构造统计Key
    __builtin_memset(key, 0, sizeof(*key));  // 显式清零，包括填充字节
    __builtin_memcpy(key->comm, info->comm, TASK_COMM_LEN);
    key->operation = info->operation;
    __builtin_memcpy(key->filename, info->filename, MAX_PATH_LEN);

    // 更新统计
    update_open_stats(key, info->flags, latency_ns, is_error);

    // 清理临时记录
    open_entry_times.delete(&pid_tgid);
    return 0;
}

// # cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format
// name: sys_enter_openat
// ID: 608
// format:
// 	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
// 	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
// 	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
// 	field:int common_pid;	offset:4;	size:4;	signed:1;

// 	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
// 	field:int dfd;	offset:16;	size:8;	signed:0;
// 	field:const char * filename;	offset:24;	size:8;	signed:0;
// 	field:int flags;	offset:32;	size:8;	signed:0;
// 	field:umode_t mode;	offset:40;	size:8;	signed:0;

// print fmt: "dfd: 0x%08lx, filename: 0x%08lx, flags: 0x%08lx, mode: 0x%08lx", ((unsigned long)(REC->dfd)), ((unsigned long)(REC->filename)), ((unsigned long)(REC->flags)), ((unsigned long)(REC->mode))

/* Tracepoint：文件打开入口 (openat) */
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    if (pid == 0) { //进程过滤，过滤内核线程
        return 0;
    }


    // 记录开始时间和参数
    struct open_entry_info_t info = {};
    info.start_ts = bpf_ktime_get_ns();
    info.operation = OP_OPENAT;
    info.flags = args->flags;
    bpf_get_current_comm(&info.comm, sizeof(info.comm));

    // 读取文件名
    read_user_filename(info.filename, args->filename);

    open_entry_times.update(&pid_tgid, &info);
    return 0;
}

// # cat /sys/kernel/debug/tracing/events/syscalls/sys_exit_openat/format
// name: sys_exit_openat
// ID: 607
// format:
// 	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
// 	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
// 	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
// 	field:int common_pid;	offset:4;	size:4;	signed:1;

// 	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
// 	field:long ret;	offset:16;	size:8;	signed:1;

// print fmt: "0x%lx", REC->ret

/* Tracepoint：文件打开出口 (openat) */
TRACEPOINT_PROBE(syscalls, sys_exit_openat) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    if (pid == 0) { // 进程过滤，过滤内核线程
        return 0;
    }

    // 查找对应的入口信息
    struct open_entry_info_t *info = open_entry_times.lookup(&pid_tgid);
    if (!info) {
        return 0;
    }

    // 计算延迟
    u64 end_ts = bpf_ktime_get_ns();
    u64 latency_ns = end_ts - info->start_ts;
    
    // 判断是否错误
    s32 ret = args->ret;
    bool is_error = (ret < 0);

    // 使用per-cpu数组避免栈溢出（Key结构太大：276字节）
    int zero = 0;
    struct open_stats_key_t *key = open_key_heap.lookup(&zero);
    if (!key) {
        open_entry_times.delete(&pid_tgid);
        return 0;
    }
    
    // 构造统计Key
    __builtin_memset(key, 0, sizeof(*key));  // 显式清零，包括填充字节
    __builtin_memcpy(key->comm, info->comm, TASK_COMM_LEN);
    key->operation = info->operation;
    __builtin_memcpy(key->filename, info->filename, MAX_PATH_LEN);

    // 更新统计
    update_open_stats(key, info->flags, latency_ns, is_error);

    // 清理临时记录
    open_entry_times.delete(&pid_tgid);
    return 0;
}
