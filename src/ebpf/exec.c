/* eBPF exec_monitor 程序 - 使用kprobe监控execve系统调用（老内核兼容版本）
 * 
 * 采用kprobe机制的优势：
 * 1. 兼容性：支持老内核（如RHEL 7 / 内核3.10），无需syscalls tracepoint
 * 2. 稳定性：kprobe是成熟稳定的内核功能
 * 3. 功能完整：能够获取execve的完整参数信息
 * 
 * 使用的探测点：
 * - kprobe:sys_execve: 监控execve系统调用入口
 * - kretprobe:sys_execve: 监控execve系统调用返回
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

/* 公共：获取 ppid - 兼容旧内核版本 */
static inline void get_ppid(u32 *ppid) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task) {
        // 先读取real_parent指针
        struct task_struct *parent;
        if (bpf_probe_read(&parent, sizeof(parent), &task->real_parent) == 0 && parent) {
            // 再读取父进程的tgid
            bpf_probe_read(ppid, sizeof(u32), &parent->tgid);
        } else {
            *ppid = 0;
        }
    } else {
        *ppid = 0;
    }
}

/* 入口：kprobe:sys_execve */
int trace_execve_entry(struct pt_regs *ctx) {
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

    // 从寄存器获取execve参数：PT_REGS_PARM1=filename, PT_REGS_PARM2=argv
    const char *const *argv = (const char *const *)PT_REGS_PARM2(ctx);
    if (argv) {
        char **argv_ptr = (char **)argv;
        char temp_arg[16] = {0};  // 减少缓冲区大小

        // 手动展开前4个参数的读取
        #define READ_ARG(idx) do { \
            if (argv_len >= ARGSIZE - 20) break; \
            char *arg_ptr; \
            if (bpf_probe_read(&arg_ptr, sizeof(arg_ptr), (void *)(argv_ptr + idx)) != 0 || !arg_ptr) break; \
            if (idx > 0 && argv_len < ARGSIZE - 2) event.argv[argv_len++] = ' '; \
            __builtin_memset(temp_arg, 0, sizeof(temp_arg)); \
            if (bpf_probe_read(temp_arg, sizeof(temp_arg) - 1, arg_ptr) == 0) { \
                temp_arg[sizeof(temp_arg) - 1] = '\0'; \
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

/* 出口：kretprobe:sys_execve */
int trace_execve_return(struct pt_regs *ctx) {
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

    event->ret = PT_REGS_RC(ctx);
    exec_events.perf_submit(ctx, event, sizeof(*event));
    exec_info.delete(&pid_tgid);
    return 0;
}
