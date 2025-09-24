/* eBPF exec_monitor 程序 - 使用syscalls tracepoint监控execve系统调用
 * 
 * 采用Syscalls Tracepoint机制的优势：
 * 1. 精确性：直接监控execve系统调用的入口和出口，获取准确的调用信息
 * 2. 完整参数：能够在系统调用入口获取完整的execve参数信息
 * 3. 稳定性：syscalls tracepoint是内核提供的稳定ABI
 * 4. 性能：相比kprobe，tracepoint开销更小，对系统性能影响更小
 * 5. 时序准确：能够精确测量execve系统调用的执行时间
 * 
 * 使用的Tracepoint：
 * - syscalls:sys_enter_execve: 监控execve系统调用入口
 * - syscalls:sys_exit_execve: 监控execve系统调用出口
 */
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

#define ARGSIZE  256            // 参数字符串最大长度

struct exec_event {
    u64 timestamp;             // 时间戳 (纳秒)
    char comm[TASK_COMM_LEN];  // 进程名
    u32 uid;                   // 用户 ID
    u32 pid;                   // 进程 ID
    u32 ppid;                  // 父进程 ID
    int ret;                   // 返回值（出口）
    char argv[ARGSIZE];        // 参数字符串（入口）
};

BPF_HASH(exec_info, u64, struct exec_event, 1024);

/* BPF映射和输出管道 */
BPF_PERF_OUTPUT(exec_events);              // 事件输出管道
BPF_HASH(target_pids, u32, u8, 1024);      // 目标进程PID映射
BPF_HASH(target_uids, u32, u8, 1024);      // 目标用户ID映射

/* 辅助函数：检查是否为目标进程 */
static inline bool is_target_process(u32 pid) {
    // u8 *val = target_pids.lookup(&pid);
    // return val != 0;  // 优化：!= NULL -> !=0（verifier 友好）
    return true;
}

/* 辅助函数：检查是否为目标用户 */
static inline bool is_target_user(u32 uid) {
    // u8 *val = target_uids.lookup(&uid);
    // return val != 0;
    return true;
}

/* 公共：获取 ppid */
static inline void get_ppid(u32 *ppid) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task && task->real_parent) {
        bpf_probe_read_kernel(ppid, sizeof(u32), &task->real_parent->tgid);
    } else {
        *ppid = 0;
    }
}

// # cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/format
// name: sys_enter_execve
// ID: 684
// format:
// 	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
// 	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
// 	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
// 	field:int common_pid;	offset:4;	size:4;	signed:1;

// 	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
// 	field:const char * filename;	offset:16;	size:8;	signed:0;
// 	field:const char *const * argv;	offset:24;	size:8;	signed:0;
// 	field:const char *const * envp;	offset:32;	size:8;	signed:0;

// print fmt: "filename: 0x%08lx, argv: 0x%08lx, envp: 0x%08lx", ((unsigned long)(REC->filename)), ((unsigned long)(REC->argv)), ((unsigned long)(REC->envp))

/* 入口：syscalls:sys_enter_execve */
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
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

    struct exec_event event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.uid = uid;
    event.pid = pid;
    get_ppid(&event.ppid);

    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    // 读取argv参数（最多4个参数）
    event.argv[0] = '\0';
    int argv_len = 0;

    // 尝试获取argv参数 - 手动展开循环避免验证器限制
    if (args->argv) {
        char **argv_ptr = (char **)args->argv;
        char temp_arg[16] = {0};  // 减少缓冲区大小
        
        // 手动展开前4个参数的读取
        #define READ_ARG(idx) do { \
            if (argv_len >= ARGSIZE - 20) break; \
            char *arg_ptr; \
            if (bpf_probe_read_user(&arg_ptr, sizeof(arg_ptr), (void *)(argv_ptr + idx)) != 0 || !arg_ptr) break; \
            if (idx > 0 && argv_len < ARGSIZE - 2) event.argv[argv_len++] = ' '; \
            __builtin_memset(temp_arg, 0, sizeof(temp_arg)); \
            if (bpf_probe_read_user_str(temp_arg, sizeof(temp_arg), arg_ptr) > 0) { \
                for (int j = 0; j < 15 && temp_arg[j] != '\0' && argv_len < ARGSIZE - 1; j++) { \
                    event.argv[argv_len++] = temp_arg[j]; \
                } \
            } \
        } while(0)
        
        READ_ARG(0);
        READ_ARG(1);
        READ_ARG(2);
        READ_ARG(3);
        
        #undef READ_ARG
    }
    event.argv[argv_len] = '\0';  // null 结尾

    exec_info.update(&pid_tgid, &event);
    return 0;
}

// # cat /sys/kernel/debug/tracing/events/syscalls/sys_exit_execve/format
// name: sys_exit_execve
// ID: 683
// format:
//         field:unsigned short common_type;       offset:0;       size:2; signed:0;
//         field:unsigned char common_flags;       offset:2;       size:1; signed:0;
//         field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
//         field:int common_pid;   offset:4;       size:4; signed:1;

//         field:int __syscall_nr; offset:8;       size:4; signed:1;
//         field:long ret; offset:16;      size:8; signed:1;

// print fmt: "0x%lx", REC->ret

/* 出口：syscalls:sys_exit_execve */
TRACEPOINT_PROBE(syscalls, sys_exit_execve) {
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

    struct exec_event *event = exec_info.lookup(&pid_tgid);
    if (!event) {
        return 0;
    }

    event->ret = args->ret;
    exec_events.perf_submit(args, event, sizeof(*event));
    exec_info.delete(&pid_tgid);
    return 0;
}
