/* eBPF exec_monitor 程序 - 使用kprobe监控execve系统调用（老内核兼容版本）
 * 
 * 采用kprobe机制的优势：
 * 1. 兼容性：支持老内核（如RHEL 7 / 内核3.10），无需syscalls tracepoint
 * 2. 稳定性：kprobe是成熟稳定的内核功能
 * 3. 功能完整：能够获取execve的完整参数信息
 * 
 * 使用的探测点：
 * - kprobe:sys_execve/__x64_sys_execve: 监控execve系统调用入口
 */
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

#define MAX_PATH_LEN  256        // 文件路径最大长度

struct exec_event {
    u32 uid;                     // 用户 ID
    u32 pid;                     // 进程 ID
    char comm[TASK_COMM_LEN];    // 进程名
    char filename[MAX_PATH_LEN]; // 文件路径
};

/* BPF映射和输出管道 */
BPF_PERF_OUTPUT(exec_events);              // 事件输出管道

/* 入口：kprobe:sys_execve/__x64_sys_execve */
int trace_execve_entry(struct pt_regs *ctx) {
    struct exec_event event = {};
    event.uid = bpf_get_current_uid_gid() & 0xffffffff;
    event.pid = bpf_get_current_pid_tgid() >> 32;

    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    // 获取filename参数
    // 注意：4.17+ 内核使用 __x64_sys_execve 等包装器，参数在 pt_regs 中
    // 旧内核使用 sys_execve，参数直接在寄存器中
    const char *filename_ptr = NULL;
    
#ifdef KERNEL_VERSION_4_17_PLUS
    // 4.17+ 内核：参数被包装在 pt_regs 结构中
    // __x64_sys_execve(const struct pt_regs *regs)
    // 实际参数在 regs->di (filename), regs->si (argv), regs->dx (envp)
    struct pt_regs *real_regs = (struct pt_regs *)PT_REGS_PARM1(ctx);
    bpf_probe_read(&filename_ptr, sizeof(filename_ptr), &real_regs->di);
#else
    // 旧内核：参数直接在寄存器中
    // sys_execve(const char *filename, ...)
    filename_ptr = (const char *)PT_REGS_PARM1(ctx);
#endif

    if (filename_ptr) {
        bpf_probe_read_str(&event.filename, sizeof(event.filename), filename_ptr);
    } else {
        event.filename[0] = '\0';
    }

    // 提交事件到用户态
    exec_events.perf_submit(ctx, &event, sizeof(event));

    return 0;
}
