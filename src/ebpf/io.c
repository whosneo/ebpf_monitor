/* eBPF io_monitor 程序 - 监控系统IO操作
 * 
 * 采用Syscalls Tracepoint机制的优势：
 * 1. 精确性：直接监控read/write系统调用的入口和出口
 * 2. 完整参数：能够获取IO大小、文件描述符等信息
 * 3. 稳定性：syscalls tracepoint是内核提供的稳定ABI
 * 4. 性能：相比kprobe，tracepoint开销更小
 * 5. 时序准确：能够精确测量IO操作的执行时间
 * 
 * 使用的Tracepoint：
 * - syscalls:sys_enter_read: 监控读操作入口
 * - syscalls:sys_exit_read: 监控读操作出口
 * - syscalls:sys_enter_write: 监控写操作入口
 * - syscalls:sys_exit_write: 监控写操作出口
 */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

/* IO类型定义 */
#define IO_TYPE_READ     1
#define IO_TYPE_WRITE    2

/* IO事件数据结构 */
struct io_event {
    u64 timestamp;             // 时间戳 (纳秒)
    u32 pid;                   // 进程 ID
    u32 tid;                   // 线程 ID
    u32 fd;                    // 文件描述符
    u32 io_type;               // IO类型 (READ/WRITE)
    u64 size;                  // IO大小
    u64 duration_ns;           // 持续时间(纳秒)
    s64 ret_val;               // 返回值
    u32 cpu;                   // CPU编号
    char comm[TASK_COMM_LEN];  // 进程名
};

/* IO时序记录结构 */
struct io_info {
    u64 start_time;
    u32 io_type;
    u32 fd;
    u64 size;
};

/* BPF映射和输出管道 */
BPF_PERF_OUTPUT(io_events);                        // 事件输出管道
BPF_HASH(target_pids, u32, u8, 1024);              // 目标进程PID映射
BPF_HASH(target_uids, u32, u8, 1024);              // 目标用户ID映射
BPF_HASH(io_info_hash, u64, struct io_info, 1024);   // IO开始时间

/* 辅助函数：检查是否为目标进程 */
static inline bool is_target_process(u32 pid) {
    // u8 *val = target_pids.lookup(&pid);
    // return val != 0;  // 优化：!= NULL -> !=0（verifier 友好）
    return true;  // IO监控默认监控所有进程
}

/* 辅助函数：检查是否为目标用户 */
static inline bool is_target_user(u32 uid) {
    // u8 *val = target_uids.lookup(&uid);
    // return val != 0;
    return true;  // IO监控默认监控所有用户
}

/* 辅助函数：初始化基础事件数据 */
static inline void init_io_event(struct io_event *event) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid >> 32;
    event->tid = pid_tgid & 0xffffffff;
    event->cpu = bpf_get_smp_processor_id();
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
}

// # cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_read/format
// name: sys_enter_read
// ID: 664
// format:
// 	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
// 	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
// 	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
// 	field:int common_pid;	offset:4;	size:4;	signed:1;

// 	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
// 	field:unsigned int fd;	offset:16;	size:8;	signed:0;
// 	field:char * buf;	offset:24;	size:8;	signed:0;
// 	field:size_t count;	offset:32;	size:8;	signed:0;

// print fmt: "fd: 0x%08lx, buf: 0x%08lx, count: 0x%08lx", ((unsigned long)(REC->fd)), ((unsigned long)(REC->buf)), ((unsigned long)(REC->count))

/* Tracepoint：读操作入口 */
TRACEPOINT_PROBE(syscalls, sys_enter_read) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    if (!is_target_process(pid)) {
        return 0;
    }

    u64 uid_gid = bpf_get_current_uid_gid();
    u32 uid = uid_gid & 0xffffffff;
    if (!is_target_user(uid)) {
        return 0;
    }

    // 记录开始时间 - 使用pid_tgid作为key
    struct io_info info = {};
    info.start_time = bpf_ktime_get_ns();
    info.io_type = IO_TYPE_READ;
    info.fd = args->fd;
    info.size = args->count;

    io_info_hash.update(&pid_tgid, &info);
    return 0;
}

// # cat /sys/kernel/debug/tracing/events/syscalls/sys_exit_read/format
// name: sys_exit_read
// ID: 663
// format:
// 	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
// 	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
// 	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
// 	field:int common_pid;	offset:4;	size:4;	signed:1;

// 	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
// 	field:long ret;	offset:16;	size:8;	signed:1;

// print fmt: "0x%lx", REC->ret

/* Tracepoint：读操作出口 */
TRACEPOINT_PROBE(syscalls, sys_exit_read) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 end_ts = bpf_ktime_get_ns();
    s64 ret_val = args->ret;
    
    // 查找对应的开始时间 - 使用pid_tgid作为key
    struct io_info *info = io_info_hash.lookup(&pid_tgid);
    if (!info || info->io_type != IO_TYPE_READ) {
        return 0;
    }
    
    u64 duration = end_ts - info->start_time;
    
    // 创建IO事件
    struct io_event event = {};
    init_io_event(&event);
    
    event.timestamp = info->start_time;
    event.fd = info->fd;
    event.io_type = IO_TYPE_READ;
    event.size = info->size;
    event.duration_ns = duration;
    event.ret_val = ret_val;
    
    // 提交事件
    io_events.perf_submit(args, &event, sizeof(event));
    
    // 清理开始时间
    io_info_hash.delete(&pid_tgid);
    return 0;
}

// # cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_write/format
// name: sys_enter_write
// ID: 662
// format:
// 	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
// 	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
// 	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
// 	field:int common_pid;	offset:4;	size:4;	signed:1;

// 	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
// 	field:unsigned int fd;	offset:16;	size:8;	signed:0;
// 	field:const char * buf;	offset:24;	size:8;	signed:0;
// 	field:size_t count;	offset:32;	size:8;	signed:0;

// print fmt: "fd: 0x%08lx, buf: 0x%08lx, count: 0x%08lx", ((unsigned long)(REC->fd)), ((unsigned long)(REC->buf)), ((unsigned long)(REC->count))

/* Tracepoint：写操作入口 */
TRACEPOINT_PROBE(syscalls, sys_enter_write) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    if (!is_target_process(pid)) {
        return 0;
    }
    
    u64 uid_gid = bpf_get_current_uid_gid();
    u32 uid = uid_gid & 0xffffffff;
    if (!is_target_user(uid)) {
        return 0;
    }

    // 记录开始时间 - 使用pid_tgid作为key
    struct io_info info = {};
    info.start_time = bpf_ktime_get_ns();
    info.io_type = IO_TYPE_WRITE;
    info.fd = args->fd;
    info.size = args->count;
    
    io_info_hash.update(&pid_tgid, &info);
    return 0;
}

// # cat /sys/kernel/debug/tracing/events/syscalls/sys_exit_write/format
// name: sys_exit_write
// ID: 661
// format:
// 	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
// 	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
// 	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
// 	field:int common_pid;	offset:4;	size:4;	signed:1;

// 	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
// 	field:long ret;	offset:16;	size:8;	signed:1;

// print fmt: "0x%lx", REC->ret

/* Tracepoint：写操作出口 */
TRACEPOINT_PROBE(syscalls, sys_exit_write) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 end_ts = bpf_ktime_get_ns();
    s64 ret_val = args->ret;
    
    // 查找对应的开始时间 - 使用pid_tgid作为key
    struct io_info *info = io_info_hash.lookup(&pid_tgid);
    if (!info || info->io_type != IO_TYPE_WRITE) {
        return 0;
    }
    
    u64 duration = end_ts - info->start_time;
    
    // 创建IO事件
    struct io_event event = {};
    init_io_event(&event);
    
    event.timestamp = info->start_time;
    event.fd = info->fd;
    event.io_type = IO_TYPE_WRITE;
    event.size = info->size;
    event.duration_ns = duration;
    event.ret_val = ret_val;
    
    // 提交事件
    io_events.perf_submit(args, &event, sizeof(event));
    
    // 清理开始时间
    io_info_hash.delete(&pid_tgid);
    return 0;
}