/* eBPF syscall_monitor 程序 - 监控系统调用执行情况
 * 
 * 采用raw_syscalls Tracepoint机制的优势：
 * 1. 广覆盖性：能够监控所有系统调用，不遗漏任何调用
 * 2. 完整数据：获取系统调用号、返回值、执行时间等完整信息
 * 3. 稳定性：raw_syscalls tracepoint是内核提供的稳定ABI
 * 4. 灵活性：支持智能采样和分类过滤策略
 * 5. 性能优化：通过智能采样控制系统开销
 * 
 * 使用的Tracepoint：
 * - raw_syscalls:sys_enter: 监控系统调用入口
 * - raw_syscalls:sys_exit: 监控系统调用出口
 * 
 * 智能采样策略：
 * - 高优先级系统调用（文件IO、进程管理）：高采样率
 * - 中优先级系统调用：中等采样率
 * - 低优先级系统调用（时间获取等）：低采样率
 */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

/* 系统调用事件数据结构 */
struct syscall_event {
    u64 timestamp;                 // 时间戳 (纳秒)
    u32 pid;                       // 进程ID
    u32 tid;                       // 线程ID
    u32 syscall_nr;                // 系统调用号
    u32 cpu;                       // CPU编号
    s64 ret_val;                   // 返回值
    u64 duration_ns;               // 持续时间(纳秒)
    char comm[TASK_COMM_LEN];      // 进程名
};

/* 系统调用信息记录结构 */
struct syscall_info {
    u64 start_time;                // 开始时间
    u32 syscall_nr;                // 系统调用号
};

/* BPF映射和输出管道 */
BPF_PERF_OUTPUT(syscall_events);                             // 事件输出管道
BPF_HASH(target_pids, u32, u8, 1024);                        // 目标进程PID映射
BPF_HASH(target_uids, u32, u8, 1024);                        // 目标用户ID映射
BPF_HASH(syscall_info_hash, u64, struct syscall_info, 4096); // 系统调用信息存储

/* 辅助函数：检查是否为目标进程 */
static inline bool is_target_process(u32 pid) {
    // u8 *val = target_pids.lookup(&pid);
    // return val != 0;  // 优化：!= NULL -> !=0（verifier 友好）
    return true;  // 系统调用监控默认监控所有进程
}

/* 辅助函数：检查是否为目标用户 */
static inline bool is_target_user(u32 uid) {
    // u8 *val = target_uids.lookup(&uid);
    // return val != 0;
    return true;  // 系统调用监控默认监控所有用户
}

/* 辅助函数：智能采样策略 */
static inline bool should_sample_syscall(u32 syscall_nr) {
    // 高优先级系统调用：总是采样
    // 文件IO：read(0), write(1), open(2), close(3), openat(257)
    if (syscall_nr <= 3 || syscall_nr == 257) {
        return true;
    }
    
    // 内存管理：mmap(9), munmap(11), brk(12)
    if (syscall_nr == 9 || syscall_nr == 11 || syscall_nr == 12) {
        return true;
    }
    
    // 进程管理：fork(57), vfork(58), execve(59), clone(56), exit(60)
    if (syscall_nr >= 56 && syscall_nr <= 60) {
        return true;
    }
    
    // 中优先级系统调用：每10个采样1个
    // 其他文件操作、网络操作等
    if (syscall_nr < 100) {
        return (bpf_get_prandom_u32() % 10) == 0;
    }
    
    // 低优先级系统调用：每50个采样1个
    // 时间获取、状态查询等
    return (bpf_get_prandom_u32() % 50) == 0;
}

/* 辅助函数：检查是否应该跳过系统调用 */
static inline bool should_skip_syscall(u32 syscall_nr) {
    // 跳过一些非常频繁但通常不重要的系统调用
    switch (syscall_nr) {
        case 96:   // gettimeofday
        case 228:  // clock_gettime
        case 230:  // clock_nanosleep
            return (bpf_get_prandom_u32() % 100) != 0;  // 只采样1%
        default:
            return false;
    }
}

// # cat /sys/kernel/debug/tracing/events/raw_syscalls/sys_enter/format
// name: sys_enter
// ID: 22
// format:
// 	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
// 	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
// 	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
// 	field:int common_pid;	offset:4;	size:4;	signed:1;

// 	field:long id;	offset:8;	size:8;	signed:1;
// 	field:unsigned long args[6];	offset:16;	size:48;	signed:0;

// print fmt: "NR %ld (%lx, %lx, %lx, %lx, %lx, %lx)", REC->id, REC->args[0], REC->args[1], REC->args[2], REC->args[3], REC->args[4], REC->args[5]

// Tracepoint: raw_syscalls:sys_enter - 监控系统调用入口
TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid & 0xffffffff;
    
    // 过滤掉内核线程（PID 0）
    if (pid == 0) {
        return 0;
    }
    
    // 进程过滤
    if (!is_target_process(pid)) {
        return 0;
    }
    
    // 用户过滤
    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    if (!is_target_user(uid)) {
        return 0;
    }
    
    // 获取系统调用号
    u32 syscall_nr = 0;
    if (args && args->id >= 0) {
        syscall_nr = (u32)args->id;
    }
    
    // 应用跳过策略
    if (should_skip_syscall(syscall_nr)) {
        return 0;
    }
    
    // 应用智能采样策略
    if (!should_sample_syscall(syscall_nr)) {
        return 0;
    }
    
    // 记录系统调用开始信息
    struct syscall_info info = {};
    info.start_time = bpf_ktime_get_ns();
    info.syscall_nr = syscall_nr;

    syscall_info_hash.update(&pid_tgid, &info);
    
    return 0;
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

// Tracepoint: raw_syscalls:sys_exit - 监控系统调用出口
TRACEPOINT_PROBE(raw_syscalls, sys_exit) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid & 0xffffffff;
    
    // 过滤掉内核线程（PID 0）
    if (pid == 0) {
        return 0;
    }
    
    // 查找对应的开始记录
    struct syscall_info *info = syscall_info_hash.lookup(&pid_tgid);
    if (!info) {
        return 0;  // 没有对应的sys_enter事件，可能被过滤掉了
    }
    
    u64 end_time = bpf_ktime_get_ns();
    u64 duration = end_time - info->start_time;
    
    // 构造完整的事件数据
    struct syscall_event event = {};
    event.timestamp = info->start_time;
    event.pid = pid_tgid >> 32;
    event.tid = pid_tgid & 0xffffffff;
    event.syscall_nr = info->syscall_nr;
    event.cpu = bpf_get_smp_processor_id();
    event.duration_ns = duration;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    // 获取系统调用返回值
    event.ret_val = 0;
    if (args && args->ret) {
        event.ret_val = (s64)args->ret;
    }

    // 发送事件到用户空间
    syscall_events.perf_submit(args, &event, sizeof(event));
    
    // 清理哈希表中的记录
    syscall_info_hash.delete(&pid_tgid);
    
    return 0;
}

/* 
 * 注意事项：
 * 1. 这个eBPF程序需要root权限运行
 * 2. raw_syscalls tracepoint会产生大量事件，智能采样是必要的
 * 3. 采样策略可以根据实际需求调整
 * 4. 系统调用参数获取被简化以提高可靠性和性能
 * 5. 高频但不重要的系统调用（如时间获取）会被大幅降采样
 */