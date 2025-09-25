/* eBPF func 程序模板 - 基于BCC funccount模式的实时函数监控
 * 
 * 设计特点：
 * 1. 模板化：使用占位符，由Python代码动态替换
 * 2. 实时性：每次函数调用都输出事件，而不是统计计数
 * 3. 轻量级：只记录基本的调用信息
 * 4. 灵活性：支持任意内核函数监控
 * 
 * 占位符说明：
 * - PROBE_FUNCTIONS: 动态生成的探针函数代码
 */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct func_event {
    u64 timestamp;             // 时间戳 (纳秒)
    u32 pid;                   // 进程 ID
    u32 ppid;                  // 父进程 ID
    u32 uid;                   // 用户 ID
    u32 func_id;               // 函数ID（用于标识具体函数）
    char comm[TASK_COMM_LEN];  // 进程名
};

/* BPF映射和输出管道 */
BPF_PERF_OUTPUT(func_events);              // 事件输出管道
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
    if (task) {
        // RHEL 7兼容：使用bpf_probe_read替代bpf_probe_read_kernel
        // 分两步读取以满足eBPF验证器要求
        struct task_struct *parent = NULL;
        if (bpf_probe_read(&parent, sizeof(parent), &task->real_parent) == 0 && parent) {
            bpf_probe_read(ppid, sizeof(u32), &parent->tgid);
        } else {
            *ppid = 0;
        }
    } else {
        *ppid = 0;
    }
}

// 通用事件提交函数
static inline void submit_func_event(struct pt_regs *ctx, u32 func_id) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!is_target_process(pid)) {
        return;
    }

    u64 uid_gid = bpf_get_current_uid_gid();
    u32 uid = uid_gid & 0xffffffff;
    if (!is_target_user(uid)) {
        return;
    }

    struct func_event event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.pid = pid;
    event.uid = uid;
    event.func_id = func_id;
    get_ppid(&event.ppid);

    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    func_events.perf_submit(ctx, &event, sizeof(event));
}

// ============================================================================
// 动态生成的探针函数将在此处插入
// ============================================================================

PROBE_FUNCTIONS
