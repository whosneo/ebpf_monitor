/* eBPF process_trade_monitor 程序 - 基于统计模式的交易进程级监控
 *
 * 设计特点：
 * 1. 统计模式：在内核态按多维度累积交易进程的系统调用和IPC统计
 * 2. 定期输出：Python端定时读取统计数据并输出（默认2秒周期）
 * 3. 角色识别：区分ZMB/ZME进程，提供交易特定的性能指标
 *
 * 监控维度：
 * - trade_syscall_stats: (进程名, 系统调用分类) -> (次数, 错误次数, 延迟统计)
 * - trade_ipc_stats: (进程名, IPC类型) -> (次数, 延迟统计)
 *
 * 使用的Tracepoint：
 * - raw_syscalls:sys_enter: 系统调用入口（记录开始时间）
 * - raw_syscalls:sys_exit: 系统调用出口（计算延迟，更新统计）
 *
 * 统计指标：
 * - count: 系统调用次数
 * - error_count: 错误次数（返回值<0）
 * - total_ns: 总延迟（纳秒）
 * - min_ns: 最小延迟
 * - max_ns: 最大延迟
 *
 * 性能优化：
 * - 使用原子操作(__sync_fetch_and_add)保证并发安全
 * - 兼容内核3.10+（使用lookup+update模式）
 * - Hash Map大小：10240
 */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

/* 系统调用分类常量（与Python层SyscallCategory保持一致） */
#define SCAT_FILE_IO    1
#define SCAT_NETWORK    2
#define SCAT_MEMORY     3
#define SCAT_PROCESS    4
#define SCAT_IPC        5
#define SCAT_TIME       6
#define SCAT_SIGNAL     7
#define SCAT_OTHER      0

/* 统计Key：(进程名, 系统调用分类)
 * 注意：comm[16] + u32会有填充字节，必须用__builtin_memset清零
 */
struct trade_stats_key_t {
    char comm[TASK_COMM_LEN];      /* 进程名 (16字节) */
    u32 syscall_category;           /* 系统调用分类 */
};

/* 统计Value */
struct trade_stats_value_t {
    u64 count;             /* 调用次数 */
    u64 error_count;       /* 错误次数 */
    u64 total_ns;          /* 总延迟（纳秒） */
    u64 min_ns;            /* 最小延迟 */
    u64 max_ns;            /* 最大延迟 */
};

/* IPC统计Key：(进程名, IPC类型) */
struct trade_ipc_key_t {
    char comm[TASK_COMM_LEN];
    u32 ipc_type;                  /* IPC类型: 1=pipe, 2=shm, 3=futex, 4=msg */
};

/* IPC统计Value */
struct trade_ipc_value_t {
    u64 count;
    u64 total_ns;
};

/* 临时存储，用于计算系统调用延迟 */
struct syscall_start_info_t {
    u64 start_ts;
    u64 syscall_nr;
};

/* BPF映射 */
BPF_HASH(trade_syscall_stats, struct trade_stats_key_t, struct trade_stats_value_t, 10240);
BPF_HASH(trade_ipc_stats, struct trade_ipc_key_t, struct trade_ipc_value_t, 10240);
BPF_HASH(trade_syscall_start, u64, struct syscall_start_info_t, 10240);

/* 系统调用分类函数 */
static inline u32 classify_syscall(u64 nr) {
    switch (nr) {
        /* 文件IO */
        case 0: case 1: case 2: case 3: case 4: case 5: case 6: case 7:
        case 8: case 16: case 17: case 18: case 19: case 20: case 21:
        case 32: case 33: case 40: case 72: case 73: case 74: case 75:
        case 76: case 77: case 78: case 79: case 80: case 81: case 82:
        case 83: case 84: case 85: case 86: case 87: case 88: case 89:
        case 90: case 91: case 92: case 93: case 94: case 133: case 137:
        case 138: case 161: case 165: case 166: case 217: case 257: case 258:
        case 259: case 260: case 261: case 262: case 263: case 264: case 265:
        case 266: case 267: case 268: case 269: case 270: case 271: case 275:
        case 276: case 277: case 278: case 280: case 285: case 291: case 292:
        case 294: case 306: case 316: case 322: case 323:
            return SCAT_FILE_IO;

        /* 网络 */
        case 41: case 42: case 43: case 44: case 45: case 46: case 47:
        case 48: case 49: case 50: case 51: case 52: case 53: case 54:
        case 55: case 288: case 299: case 307:
            return SCAT_NETWORK;

        /* 内存 */
        case 9: case 10: case 11: case 12: case 25: case 26: case 27:
        case 28: case 149: case 150: case 151: case 152: case 279: case 319:
        case 29: case 30: case 31: case 67:
            return SCAT_MEMORY;

        /* 进程 */
        case 24: case 39: case 56: case 57: case 58: case 59: case 60:
        case 61: case 95: case 101: case 102: case 104: case 105: case 106:
        case 107: case 108: case 109: case 110: case 111: case 112: case 113:
        case 114: case 115: case 116: case 117: case 118: case 119: case 120:
        case 125: case 126: case 155: case 157: case 158: case 186: case 231:
        case 247: case 272: case 273: case 274: case 318: case 321:
            return SCAT_PROCESS;

        /* IPC */
        case 22: case 293: case 64: case 65: case 66: case 220:
        case 68: case 69: case 70: case 71: case 284: case 290: case 202: case 240:
            return SCAT_IPC;

        /* 时间 */
        case 35: case 36: case 37: case 38: case 96: case 201:
        case 222: case 223: case 224: case 226: case 227: case 228:
        case 229: case 230: case 283: case 286: case 287:
            return SCAT_TIME;

        /* 信号 */
        case 13: case 14: case 15: case 34: case 62: case 127:
        case 128: case 129: case 130: case 131: case 200: case 234:
        case 282: case 289:
            return SCAT_SIGNAL;

        default:
            return SCAT_OTHER;
    }
}

/* IPC类型分类函数 */
static inline u32 classify_ipc(u64 nr) {
    switch (nr) {
        case 22: case 293:         /* pipe, pipe2 */
            return 1;
        case 29: case 30: case 31: case 67:  /* shmget, shmat, shmctl, shmdt */
            return 2;
        case 202: case 240:        /* futex */
            return 3;
        case 68: case 69: case 70: case 71:  /* msgget, msgsnd, msgrcv, msgctl */
            return 4;
        default:
            return 0;
    }
}

/* 统计更新函数 */
static inline void update_trade_stats(u32 category, s64 ret_val, u64 latency_ns) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));

    struct trade_stats_key_t key = {};
    __builtin_memset(&key, 0, sizeof(key));
    __builtin_memcpy(key.comm, comm, TASK_COMM_LEN);
    key.syscall_category = category;

    /* lookup→update→lookup模式，兼容3.10内核 */
    struct trade_stats_value_t *val = trade_syscall_stats.lookup(&key);
    if (!val) {
        struct trade_stats_value_t zero = {};
        trade_syscall_stats.update(&key, &zero);
        val = trade_syscall_stats.lookup(&key);
        if (!val) {
            return;
        }
    }

    __sync_fetch_and_add(&val->count, 1);
    if (ret_val < 0) {
        __sync_fetch_and_add(&val->error_count, 1);
    }

    if (latency_ns > 0) {
        __sync_fetch_and_add(&val->total_ns, latency_ns);
        if (latency_ns < val->min_ns || val->min_ns == 0) {
            val->min_ns = latency_ns;
        }
        if (latency_ns > val->max_ns) {
            val->max_ns = latency_ns;
        }
    }
}

/* IPC统计更新函数 */
static inline void update_ipc_stats(u32 ipc_type, u64 latency_ns) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));

    struct trade_ipc_key_t key = {};
    __builtin_memset(&key, 0, sizeof(key));
    __builtin_memcpy(key.comm, comm, TASK_COMM_LEN);
    key.ipc_type = ipc_type;

    struct trade_ipc_value_t *val = trade_ipc_stats.lookup(&key);
    if (!val) {
        struct trade_ipc_value_t zero = {};
        trade_ipc_stats.update(&key, &zero);
        val = trade_ipc_stats.lookup(&key);
        if (!val) {
            return;
        }
    }

    __sync_fetch_and_add(&val->count, 1);
    if (latency_ns > 0) {
        __sync_fetch_and_add(&val->total_ns, latency_ns);
    }
}

/* ==================== Tracepoint处理函数 ==================== */

/* Tracepoint: raw_syscalls:sys_enter - 系统调用入口 */
TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    if (pid == 0) return 0;

    u64 syscall_nr = 0;
    if (args) {
        syscall_nr = args->id;
    }

    /* 记录开始时间 */
    struct syscall_start_info_t info = {};
    info.start_ts = bpf_ktime_get_ns();
    info.syscall_nr = syscall_nr;
    trade_syscall_start.update(&pid_tgid, &info);

    return 0;
}

/* Tracepoint: raw_syscalls:sys_exit - 系统调用出口 */
TRACEPOINT_PROBE(raw_syscalls, sys_exit) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    if (pid == 0) return 0;

    /* 查找开始时间 */
    struct syscall_start_info_t *start = trade_syscall_start.lookup(&pid_tgid);
    if (!start) return 0;

    u64 latency_ns = bpf_ktime_get_ns() - start->start_ts;
    u64 syscall_nr = start->syscall_nr;

    /* 过滤异常值（>10秒） */
    if (latency_ns > 10000000000ULL) {
        latency_ns = 0;
    }

    s64 ret_val = 0;
    if (args) {
        ret_val = args->ret;
    }

    /* 获取系统调用分类 */
    u32 category = classify_syscall(syscall_nr);

    /* 更新分类统计 */
    update_trade_stats(category, ret_val, latency_ns);

    /* 更新IPC统计（如果适用） */
    u32 ipc_type = classify_ipc(syscall_nr);
    if (ipc_type > 0) {
        update_ipc_stats(ipc_type, latency_ns);
    }

    /* 清理临时数据 */
    trade_syscall_start.delete(&pid_tgid);

    return 0;
}
