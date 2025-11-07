/* eBPF syscall_monitor 程序 - 基于统计模式的系统调用监控
 * 
 * 设计特点：
 * 1. 统计模式：在内核态按多维度累积系统调用次数和错误次数，避免高频调用导致的事件丢失
 * 2. 定期输出：Python端定时读取统计数据并输出（默认1秒周期）
 * 3. 全覆盖：监控所有系统调用，无采样丢失
 * 4. 错误统计：分别记录成功和失败的调用次数，便于问题诊断
 * 
 * 采用raw_syscalls Tracepoint机制：
 * - raw_syscalls:sys_exit: 监控系统调用出口（统计点）
 * 
 * 统计维度：
 * - syscall_stats: (进程名, 系统调用号) -> (调用次数, 错误次数)
 *   用途：分析哪些进程调用了哪些系统调用，成功率如何
 * 
 * 性能优化：
 * - 使用原子操作(__sync_fetch_and_add)保证并发安全
 * - 兼容内核3.10+（使用lookup+update模式）
 * - Hash Map大小：syscall_stats=10240（约330KB内存）
 */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

/* 统计 Key：(进程名, 系统调用号)
 * 注意：comm[16] + u32会有填充字节，必须用__builtin_memset清零
 */
struct stats_key_t {
    char comm[TASK_COMM_LEN];      // 进程名 (16字节)
    u32 syscall_nr;                // 系统调用号
};

/* 统计 Value：(调用次数, 错误次数) */
struct stats_value_t {
    u64 count;                     // 总调用次数
    u64 error_count;               // 错误调用次数（返回值 < 0）
};

/* BPF映射 */
BPF_HASH(syscall_stats, struct stats_key_t, struct stats_value_t, 10240);  // 系统调用统计 (进程名, 系统调用号)

/* 统计更新函数：更新系统调用统计 (进程名, 系统调用号) */
static inline void update_syscall_stats(u32 syscall_nr, s64 ret_val) {
    struct stats_key_t key = {};
    __builtin_memset(&key, 0, sizeof(key));  // 显式清零，包括填充字节
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
    key.syscall_nr = syscall_nr;
    
    struct stats_value_t *val = syscall_stats.lookup(&key);
    if (val) {
        // 已存在，原子增加计数
        __sync_fetch_and_add(&val->count, 1);
        if (ret_val < 0) {
            __sync_fetch_and_add(&val->error_count, 1);
        }
    } else {
        // 首次出现，创建新条目
        struct stats_value_t new_val = {0};
        new_val.count = 1;
        new_val.error_count = (ret_val < 0) ? 1 : 0;
        syscall_stats.update(&key, &new_val);
    }
}

// # cat /sys/kernel/debug/tracing/events/raw_syscalls/sys_exit/format
// name: sys_exit
// ID: 21
// format:
// 	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
// 	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
// 	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
// 	field:int common_pid;	offset:4;	size:4;	signed:1;

// 	field:long id;	offset:8;	size:8;	signed:1;
// 	field:long ret;	offset:16;	size:8;	signed:1;

// print fmt: "NR %ld = %ld", REC->id, REC->ret

// Tracepoint: raw_syscalls:sys_exit - 监控系统调用出口（统计点）
TRACEPOINT_PROBE(raw_syscalls, sys_exit) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    // 过滤掉内核线程（PID 0）
    if (pid == 0) {
        return 0;
    }

    // 获取系统调用号和返回值
    u32 syscall_nr = 0;
    s64 ret_val = 0;
    if (args) {
        if (args->id >= 0) {
            syscall_nr = (u32)args->id;
        }
        ret_val = (s64)args->ret;
    }
    
    // 更新统计表
    update_syscall_stats(syscall_nr, ret_val);
    
    return 0;
}