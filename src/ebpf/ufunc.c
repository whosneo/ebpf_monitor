/* eBPF ufunc 程序模板 - 用户态函数调用统计（BCC uprobe/uretprobe）
 *
 * 设计特点：
 * 1. 统计模式：内核态按 (comm, func_id, tgid) 聚合
 * 2. entry key：struct { u64 pid_tgid; u32 func_id; u32 _pad } — 禁止 pid_tgid<<32|func_id
 * 3. PROBE_FUNCTIONS 占位由 Python 动态替换
 */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct ufunc_stats_key_t {
    char comm[TASK_COMM_LEN];
    u32 func_id;
    u32 tgid;
};

struct ufunc_stats_value_t {
    u64 count;
    u64 total_ns;
    u64 max_ns;
};

/* entry 配对 key：原样存放 bpf_get_current_pid_tgid()，禁止移位打包 */
struct ufunc_entry_key_t {
    u64 pid_tgid;
    u32 func_id;
    u32 _pad;
};

BPF_HASH(ufunc_stats, struct ufunc_stats_key_t, struct ufunc_stats_value_t, 10240);
BPF_HASH(ufunc_entry, struct ufunc_entry_key_t, u64, 10240);

/* Optional PID whitelist */
BPF_HASH(pid_allow, u32, u8, 1024);

static inline int allow_current(void) {
#ifdef ENABLE_PID_FILTER
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u8 *p = pid_allow.lookup(&pid);
    if (!p)
        return 0;
    return 1;
#else
    return 1;
#endif
}

static inline void ufunc_count_entry(u32 func_id) {
    if (!allow_current())
        return;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32;

    struct ufunc_stats_key_t sk = {};
    __builtin_memset(&sk, 0, sizeof(sk));
    bpf_get_current_comm(&sk.comm, sizeof(sk.comm));
    sk.func_id = func_id;
    sk.tgid = tgid;

    struct ufunc_stats_value_t *val = ufunc_stats.lookup(&sk);
    if (!val) {
        struct ufunc_stats_value_t zero = {};
        ufunc_stats.update(&sk, &zero);
        val = ufunc_stats.lookup(&sk);
        if (!val)
            return;
    }
    __sync_fetch_and_add(&val->count, 1);
}

static inline void ufunc_entry_store(u32 func_id) {
    if (!allow_current())
        return;
    struct ufunc_entry_key_t ek = {};
    __builtin_memset(&ek, 0, sizeof(ek));
    ek.pid_tgid = bpf_get_current_pid_tgid(); /* 不得再移位 */
    ek.func_id = func_id;
    u64 ts = bpf_ktime_get_ns();
    ufunc_entry.update(&ek, &ts);
    ufunc_count_entry(func_id);
}

static inline void ufunc_ret_update(u32 func_id) {
    if (!allow_current())
        return;
    struct ufunc_entry_key_t ek = {};
    __builtin_memset(&ek, 0, sizeof(ek));
    ek.pid_tgid = bpf_get_current_pid_tgid();
    ek.func_id = func_id;
    u64 *start = ufunc_entry.lookup(&ek);
    if (!start)
        return; /* count 已在 entry 更新；latency 丢失 */
    u64 latency = bpf_ktime_get_ns() - *start;
    ufunc_entry.delete(&ek);

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32;
    struct ufunc_stats_key_t sk = {};
    __builtin_memset(&sk, 0, sizeof(sk));
    bpf_get_current_comm(&sk.comm, sizeof(sk.comm));
    sk.func_id = func_id;
    sk.tgid = tgid;

    struct ufunc_stats_value_t *val = ufunc_stats.lookup(&sk);
    if (!val)
        return;
    __sync_fetch_and_add(&val->total_ns, latency);
    if (latency > val->max_ns)
        val->max_ns = latency;
}

/* count-only entry (no retprobe pairing) */
static inline void ufunc_entry_count_only(u32 func_id) {
    ufunc_count_entry(func_id);
}

// ============================================================================
// 动态生成的探针函数将在此处插入
// ============================================================================

PROBE_FUNCTIONS
