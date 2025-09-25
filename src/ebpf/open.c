/* eBPF open_monitor 程序 - 监控文件打开操作
 * 
 * 采用Syscalls Tracepoint机制的优势：
 * 1. 精确性：直接监控openat系统调用的入口和出口
 * 2. 完整参数：能够获取文件路径、打开标志、权限等信息
 * 3. 稳定性：syscalls tracepoint是内核提供的稳定ABI
 * 4. 性能：相比kprobe，tracepoint开销更小
 * 5. 时序准确：能够精确测量文件打开操作的执行时间
 * 
 * 使用的Tracepoint：
 * - syscalls:sys_enter_open: 监控传统open系统调用入口
 * - syscalls:sys_exit_open: 监控传统open系统调用出口
 * - syscalls:sys_enter_openat: 监控现代openat系统调用入口
 * - syscalls:sys_exit_openat: 监控现代openat系统调用出口
 */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

#define MAX_FILENAME 256    // 文件名最大长度

/* 事件类型枚举 */
enum event_type {
    EVENT_OPEN,
    EVENT_OPENAT
};

/* 文件打开事件数据结构 */
struct open_event {
    u64 timestamp;             // 时间戳 (纳秒)
    u32 pid;                   // 进程 ID
    u32 tid;                   // 线程 ID
    u32 uid;                   // 用户 ID
    int flags;                 // 打开标志
    int mode;                  // 文件权限
    s32 ret;                   // 返回值（文件描述符或错误码）
    u32 cpu;                   // CPU编号
    enum event_type type;      // 事件类型
    char comm[TASK_COMM_LEN];  // 进程名
    char filename[MAX_FILENAME]; // 文件路径
};

/* 文件打开信息记录结构 */
struct open_info {
    u64 timestamp;
    int flags;
    int mode;
    char filename[MAX_FILENAME];
};

/* BPF映射和输出管道 */
BPF_PERF_OUTPUT(open_events);                      // 事件输出管道
BPF_HASH(target_pids, u32, u8, 1024);              // 目标进程PID映射
BPF_HASH(target_uids, u32, u8, 1024);              // 目标用户ID映射
BPF_HASH(open_info_hash, u64, struct open_info, 1024);   // 开始时间

/* 辅助函数：检查是否为目标进程 */
static inline bool is_target_process(u32 pid) {
    // u8 *val = target_pids.lookup(&pid);
    // return val != 0;  // 优化：!= NULL -> !=0（verifier 友好）
    return true;  // open监控默认监控所有进程
}

/* 辅助函数：检查是否为目标用户 */
static inline bool is_target_user(u32 uid) {
    // u8 *val = target_uids.lookup(&uid);
    // return val != 0;
    return true;  // open监控默认监控所有用户
}

/* 辅助函数：初始化基础事件数据 */
static inline void init_open_event(struct open_event *event) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid >> 32;
    event->tid = pid_tgid & 0xffffffff;
    event->cpu = bpf_get_smp_processor_id();
    u64 uid_gid = bpf_get_current_uid_gid();
    event->uid = uid_gid & 0xffffffff;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
}

/* 辅助函数：安全读取用户空间字符串 */
static inline int read_user_filename(char *dest, const char __user *src) {
    __builtin_memset(dest, 0, MAX_FILENAME);
    // 使用bpf_probe_read替代bpf_probe_read_user_str以兼容旧内核
    int ret = bpf_probe_read(dest, MAX_FILENAME - 1, src);
    if (ret < 0) {
        __builtin_memcpy(dest, "<unknown>", 10);
        return -1;
    }
    // 确保字符串以null结尾
    dest[MAX_FILENAME - 1] = '\0';
    return 0;
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
    u32 tid = pid_tgid & 0xffffffff;
    if (!is_target_process(pid)) { //进程过滤
        return 0;
    }
    if (pid == 0) { // 过滤内核线程
        return 0;
    }

    u64 uid_gid = bpf_get_current_uid_gid();
    u32 uid = uid_gid & 0xffffffff;
    if (!is_target_user(uid)) {
        return 0;
    }

    // 记录开始时间和参数
    struct open_info info = {};
    info.timestamp = bpf_ktime_get_ns();
    info.flags = args->flags;
    info.mode = args->mode;

    // 读取文件名
    if (args->filename) {
        read_user_filename(info.filename, args->filename);
    }

    open_info_hash.update(&pid_tgid, &info);
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
    if (!is_target_process(pid)) { // 进程过滤
        return 0;
    }
    if (pid == 0) { // 过滤内核线程
        return 0;
    }

    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    if (!is_target_user(uid)) { // 用户过滤
        return 0;
    }

    // 查找对应的事件
    struct open_info *info = open_info_hash.lookup(&pid_tgid);
    if (!info) {
        return 0;
    }

    // 创建文件打开事件
    struct open_event event = {};
    init_open_event(&event);

    event.timestamp = info->timestamp;
    event.flags = info->flags;
    event.mode = info->mode;
    event.ret = args->ret;
    event.type = EVENT_OPEN;
    __builtin_memcpy(event.filename, info->filename, MAX_FILENAME);

    // 提交事件
    open_events.perf_submit(args, &event, sizeof(event));

    // 清理事件
    open_info_hash.delete(&pid_tgid);
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
    u32 tid = pid_tgid & 0xffffffff;
    if (!is_target_process(pid)) { //进程过滤
        return 0;
    }
    if (pid == 0) { // 过滤内核线程
        return 0;
    }

    u64 uid_gid = bpf_get_current_uid_gid();
    u32 uid = uid_gid & 0xffffffff;
    u32 gid = uid_gid >> 32;
    if (!is_target_user(uid)) { //用户过滤
        return 0;
    }

    // 记录开始时间和参数
    struct open_info info = {};
    info.timestamp = bpf_ktime_get_ns();
    info.flags = args->flags;
    info.mode = args->mode;

    // 读取文件名
    if (args->filename) {
        read_user_filename(info.filename, args->filename);
    }

    open_info_hash.update(&pid_tgid, &info);
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
    if (!is_target_process(pid)) { // 进程过滤
        return 0;
    }
    if (pid == 0) { // 过滤内核线程
        return 0;
    }

    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    if (!is_target_user(uid)) { // 用户过滤
        return 0;
    }

    // 查找对应的事件
    struct open_info *info = open_info_hash.lookup(&pid_tgid);
    if (!info) {
        return 0;
    }

    // 创建文件打开事件
    struct open_event event = {};
    init_open_event(&event);

    event.timestamp = info->timestamp;
    event.flags = info->flags;
    event.mode = info->mode;
    event.ret = args->ret;
    event.type = EVENT_OPENAT;
    __builtin_memcpy(event.filename, info->filename, MAX_FILENAME);

    // 提交事件
    open_events.perf_submit(args, &event, sizeof(event));

    // 清理事件
    open_info_hash.delete(&pid_tgid);
    return 0;
}
