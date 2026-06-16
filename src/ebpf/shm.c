/* eBPF shm_monitor 程序 - 基于统计模式的共享内存通信监控
 *
 * 设计特点：
 * 1. 统计模式：在内核态按多维度累积共享内存操作统计
 * 2. 定期输出：Python端定时读取统计数据并输出（默认2秒周期）
 * 3. 深度监控：捕获shmget/shmat/shmdt/shmctl系统调用，分析内存访问模式
 *
 * 监控维度：
 * - shm_stats: (shmid, 进程名) -> (访问次数, 操作耗时统计)
 * - shm_segments: shmid -> (操作次数) 跟踪活跃内存段
 *
 * 使用的Kprobe：
 * - shmget: 创建/获取共享内存段
 * - shmat: 附加到进程地址空间
 * - shmdt: 从进程分离
 * - shmctl: 控制操作
 *
 * 统计指标：
 * - count: 操作次数
 * - total_ns: 总操作耗时（纳秒）
 * - min_ns: 最小操作耗时
 * - max_ns: 最大操作耗时
 * - err_count: 错误次数（返回值<0）
 *
 * 性能优化：
 * - 使用原子操作(__sync_fetch_and_add)保证并发安全
 * - 兼容内核3.10+（使用lookup+update模式）
 * - Hash Map大小：10240
 */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/ipc.h>
#include <linux/shm.h>

/* 操作类型常量 */
#define SHMOP_GET   1   /* shmget */
#define SHMOP_AT    2   /* shmat */
#define SHMOP_DT    3   /* shmdt */
#define SHMOP_CTL   4   /* shmctl */

/* 统计Key：(shmid, 进程名)
 * 注意：u32 + comm[16]会有填充字节，必须用__builtin_memset清零
 */
struct shm_stats_key_t {
    u32 shmid;                  /* 共享内存ID */
    char comm[TASK_COMM_LEN];  /* 进程名 (16字节) */
};

/* 统计Value */
struct shm_stats_value_t {
    u64 count;         /* 操作次数 */
    u64 total_ns;      /* 总操作耗时（纳秒） */
    u64 min_ns;        /* 最小操作耗时 */
    u64 max_ns;        /* 最大操作耗时 */
    u64 err_count;     /* 错误次数 */
};

/* 段统计Key：shmid */
struct shm_seg_key_t {
    u32 shmid;
};

/* 段统计Value */
struct shm_seg_value_t {
    u64 op_count;      /* 总操作次数 */
    u64 attach_count;  /* 附加次数（shmat成功） */
    u64 detach_count;  /* 分离次数（shmdt成功） */
};

/* 临时存储，用于计算操作耗时 */
struct shm_start_info_t {
    u64 start_ts;              /* 开始时间戳 */
    char comm[TASK_COMM_LEN];  /* 进程名 */
    u32 shmid;                 /* 共享内存ID */
    u32 op_type;               /* 操作类型 */
};

/* BPF映射 */
BPF_HASH(shm_stats, struct shm_stats_key_t, struct shm_stats_value_t, 10240);
BPF_HASH(shm_segments, u32, struct shm_seg_value_t, 10240);
BPF_HASH(shm_start_ts, u64, struct shm_start_info_t, 10240);

/* 统计更新函数 */
static inline void update_shm_stats(u32 shmid, char *comm, u64 ns, int ret) {
    struct shm_stats_key_t key = {};
    __builtin_memset(&key, 0, sizeof(key));
    key.shmid = shmid;
    bpf_probe_read(&key.comm, sizeof(key.comm), comm);

    /* lookup→update→lookup模式，兼容3.10内核 */
    struct shm_stats_value_t *val = shm_stats.lookup(&key);
    if (!val) {
        struct shm_stats_value_t zero = {};
        shm_stats.update(&key, &zero);
        val = shm_stats.lookup(&key);
        if (!val) {
            return;
        }
    }

    __sync_fetch_and_add(&val->count, 1);
    if (ret < 0) {
        __sync_fetch_and_add(&val->err_count, 1);
    }

    if (ns > 0) {
        __sync_fetch_and_add(&val->total_ns, ns);
        if (ns < val->min_ns || val->min_ns == 0) {
            val->min_ns = ns;
        }
        if (ns > val->max_ns) {
            val->max_ns = ns;
        }
    }
}

/* 段统计更新函数 */
static inline void update_shm_segment(u32 shmid, int op_type, int ret) {
    struct shm_seg_value_t *seg = shm_segments.lookup(&shmid);
    if (!seg) {
        struct shm_seg_value_t zero = {};
        shm_segments.update(&shmid, &zero);
        seg = shm_segments.lookup(&shmid);
        if (!seg) {
            return;
        }
    }

    __sync_fetch_and_add(&seg->op_count, 1);

    if (op_type == SHMOP_AT && ret >= 0) {
        __sync_fetch_and_add(&seg->attach_count, 1);
    } else if (op_type == SHMOP_DT && ret >= 0) {
        __sync_fetch_and_add(&seg->detach_count, 1);
    }
}

/* ==================== Kprobe处理函数 ==================== */

/* Kprobe: shmget - 创建/获取共享内存段
 * 参数: (int shmflg, size_t size, int shmflg)
 * 返回: shmid (成功) 或 <0 (失败)
 */
int kprobe__shmget(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    if (pid == 0) return 0;

    /* 记录开始时间 */
    struct shm_start_info_t info = {};
    info.start_ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&info.comm, sizeof(info.comm));
    info.op_type = SHMOP_GET;
    info.shmid = 0;  /* shmget返回后才知道shmid */

    u64 key = pid_tgid;
    shm_start_ts.update(&key, &info);

    return 0;
}

/* Kretprobe: shmget返回 - 获取shmid */
int kretprobe__shmget(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    if (pid == 0) return 0;

    u64 key = pid_tgid;
    struct shm_start_info_t *info = shm_start_ts.lookup(&key);
    if (!info) return 0;

    u64 latency_ns = bpf_ktime_get_ns() - info->start_ts;
    s64 ret = PT_REGS_RC(ctx);

    /* shmid >= 0 表示成功，< 0 表示错误 */
    u32 shmid = 0;
    if (ret >= 0) {
        shmid = (u32)ret;
    }

    char comm[TASK_COMM_LEN] = {};
    bpf_probe_read(&comm, sizeof(comm), info->comm);

    update_shm_stats(shmid, comm, latency_ns, (int)ret);
    if (ret >= 0) {
        update_shm_segment(shmid, SHMOP_GET, (int)ret);
    }

    shm_start_ts.delete(&key);
    return 0;
}

/* Kprobe: shmat - 附加到进程地址空间
 * 参数: (int shmid, const void __user *shmaddr, int shmflg)
 * 返回: attach地址 (成功) 或 <0 (失败)
 */
int kprobe__shmat(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    if (pid == 0) return 0;

    int shmid = (int)PT_REGS_PARM1(ctx);

    struct shm_start_info_t info = {};
    info.start_ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&info.comm, sizeof(info.comm));
    info.op_type = SHMOP_AT;
    info.shmid = (u32)shmid;

    u64 key = pid_tgid;
    shm_start_ts.update(&key, &info);

    return 0;
}

/* Kretprobe: shmat返回 */
int kretprobe__shmat(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    if (pid == 0) return 0;

    u64 key = pid_tgid;
    struct shm_start_info_t *info = shm_start_ts.lookup(&key);
    if (!info) return 0;

    u64 latency_ns = bpf_ktime_get_ns() - info->start_ts;
    s64 ret = PT_REGS_RC(ctx);

    char comm[TASK_COMM_LEN] = {};
    bpf_probe_read(&comm, sizeof(comm), info->comm);

    update_shm_stats(info->shmid, comm, latency_ns, (int)ret);
    update_shm_segment(info->shmid, SHMOP_AT, (int)ret);

    shm_start_ts.delete(&key);
    return 0;
}

/* Kprobe: shmdt - 从进程分离
 * 参数: (const void __user *shmaddr)
 * 返回: 0 (成功) 或 <0 (失败)
 */
int kprobe__shmdt(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    if (pid == 0) return 0;

    /* shmdt不直接提供shmid，使用pid作为临时key */
    struct shm_start_info_t info = {};
    info.start_ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&info.comm, sizeof(info.comm));
    info.op_type = SHMOP_DT;
    info.shmid = 0;  /* shmdt不直接提供shmid */

    u64 key = pid_tgid;
    shm_start_ts.update(&key, &info);

    return 0;
}

/* Kretprobe: shmdt返回 */
int kretprobe__shmdt(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    if (pid == 0) return 0;

    u64 key = pid_tgid;
    struct shm_start_info_t *info = shm_start_ts.lookup(&key);
    if (!info) return 0;

    u64 latency_ns = bpf_ktime_get_ns() - info->start_ts;
    s64 ret = PT_REGS_RC(ctx);

    char comm[TASK_COMM_LEN] = {};
    bpf_probe_read(&comm, sizeof(comm), info->comm);

    /* shmdt没有shmid参数，使用shmid=0 */
    update_shm_stats(0, comm, latency_ns, (int)ret);

    shm_start_ts.delete(&key);
    return 0;
}

/* Kprobe: shmctl - 控制操作
 * 参数: (int cmd, struct shmid_ds __user *buf, int pid)
 * 返回: 0 (成功) 或 <0 (失败)
 */
int kprobe__shmctl(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    if (pid == 0) return 0;

    int shmid = (int)PT_REGS_PARM1(ctx);

    struct shm_start_info_t info = {};
    info.start_ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&info.comm, sizeof(info.comm));
    info.op_type = SHMOP_CTL;
    info.shmid = (u32)shmid;

    u64 key = pid_tgid;
    shm_start_ts.update(&key, &info);

    return 0;
}

/* Kretprobe: shmctl返回 */
int kretprobe__shmctl(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    if (pid == 0) return 0;

    u64 key = pid_tgid;
    struct shm_start_info_t *info = shm_start_ts.lookup(&key);
    if (!info) return 0;

    u64 latency_ns = bpf_ktime_get_ns() - info->start_ts;
    s64 ret = PT_REGS_RC(ctx);

    char comm[TASK_COMM_LEN] = {};
    bpf_probe_read(&comm, sizeof(comm), info->comm);

    update_shm_stats(info->shmid, comm, latency_ns, (int)ret);

    shm_start_ts.delete(&key);
    return 0;
}
