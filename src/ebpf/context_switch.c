/* eBPF context_switch_monitor 程序 - 监控进程上下文切换
 * 
 * 功能：统计各进程的上下文切换情况
 * 模式：统计聚合模式（定期输出）
 * 
 * 监控维度：
 *   Key: (comm, cpu)
 *   Value: (switch_in_count, switch_out_count, voluntary_count, involuntary_count)
 * 
 * 切换类型：
 *   - Voluntary (自愿切换): 进程主动让出CPU（IO等待、sleep等）
 *   - Involuntary (非自愿切换): 进程被强制切换（时间片用尽、被抢占等）
 * 
 * 判断依据：
 *   - prev_state == TASK_RUNNING (0) → 非自愿切换
 *   - prev_state != TASK_RUNNING    → 自愿切换
 * 
 * Tracepoint: sched:sched_switch
 * 
 * 应用场景：
 *   - 识别高频切换的进程
 *   - 发现CPU调度瓶颈
 *   - 优化多线程应用
 *   - 诊断系统响应慢问题
 */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

/* 任务名称最大长度 */
#define TASK_COMM_LEN 16

/* TASK_RUNNING 已在 <linux/sched.h> 中定义，无需重复定义 */

/* ==================== 数据结构定义 ==================== */

/* 统计Key：进程级别 */
struct switch_key_t {
    char comm[TASK_COMM_LEN];  // 进程名
    u32 cpu;                   // CPU编号
};

/* 统计Value：切换统计 */
struct switch_value_t {
    u64 switch_in_count;       // 切换进来的次数
    u64 switch_out_count;      // 切换出去的次数
    u64 voluntary_count;       // 自愿切换次数
    u64 involuntary_count;     // 非自愿切换次数
};

/* ==================== BPF Maps ==================== */

/* 上下文切换统计表 */
BPF_HASH(context_switch_stats, struct switch_key_t, struct switch_value_t, 10240);

/* ==================== 辅助函数 ==================== */

/* 更新上下文切换统计 */
static inline void update_switch_stats(
    char *comm, 
    u32 cpu, 
    bool is_switch_out, 
    bool is_voluntary
) {
    // 初始化Key
    struct switch_key_t key = {};
    __builtin_memset(&key, 0, sizeof(key));
    
    // 设置Key字段（兼容3.10内核，使用bpf_probe_read）
    bpf_probe_read(&key.comm, sizeof(key.comm), comm);
    key.cpu = cpu;
    
    // 查找或初始化统计（兼容3.10内核，使用lookup+update模式）
    struct switch_value_t *value = context_switch_stats.lookup(&key);
    if (!value) {
        // 不存在，创建新条目
        struct switch_value_t zero = {};
        context_switch_stats.update(&key, &zero);
        value = context_switch_stats.lookup(&key);
        if (!value) {
            return;  // 更新失败
        }
    }
    
    // 原子更新计数
    if (is_switch_out) {
        __sync_fetch_and_add(&value->switch_out_count, 1);
    } else {
        __sync_fetch_and_add(&value->switch_in_count, 1);
    }
    
    // 更新自愿/非自愿计数
    if (is_voluntary) {
        __sync_fetch_and_add(&value->voluntary_count, 1);
    } else {
        __sync_fetch_and_add(&value->involuntary_count, 1);
    }
}

/* ==================== Tracepoint处理函数 ==================== */

// Tracepoint格式参考:
// # cat /sys/kernel/debug/tracing/events/sched/sched_switch/format
// name: sched_switch
// ID: 314
// format:
//         field:unsigned short common_type;       offset:0;       size:2; signed:0;
//         field:unsigned char common_flags;       offset:2;       size:1; signed:0;
//         field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
//         field:int common_pid;   offset:4;       size:4; signed:1;

//         field:char prev_comm[16];       offset:8;       size:16;        signed:1;
//         field:pid_t prev_pid;   offset:24;      size:4; signed:1;
//         field:int prev_prio;    offset:28;      size:4; signed:1;
//         field:long prev_state;  offset:32;      size:8; signed:1;
//         field:char next_comm[16];       offset:40;      size:16;        signed:1;
//         field:pid_t next_pid;   offset:56;      size:4; signed:1;
//         field:int next_prio;    offset:60;      size:4; signed:1;

// print fmt: "prev_comm=%s prev_pid=%d prev_prio=%d prev_state=%s%s ==> next_comm=%s next_pid=%d next_prio=%d", REC->prev_comm, REC->prev_pid, REC->prev_prio, (REC->prev_state & ((((0x0000 | 0x0001 | 0x0002 | 0x0004 | 0x0008 | 0x0010 | 0x0020 | 0x0040) + 1) << 1) - 1)) ? __print_flags(REC->prev_state & ((((0x0000 | 0x0001 | 0x0002 | 0x0004 | 0x0008 | 0x0010 | 0x0020 | 0x0040) + 1) << 1) - 1), "|", { 0x0001, "S" }, { 0x0002, "D" }, { 0x0004, "T" }, { 0x0008, "t" }, { 0x0010, "X" }, { 0x0020, "Z" }, { 0x0040, "P" }, { 0x0080, "I" }) : "R", REC->prev_state & (((0x0000 | 0x0001 | 0x0002 | 0x0004 | 0x0008 | 0x0010 | 0x0020 | 0x0040) + 1) << 1) ? "+" : "", REC->next_comm, REC->next_pid, REC->next_prio

TRACEPOINT_PROBE(sched, sched_switch) {
    // 获取CPU编号
    u32 cpu = bpf_get_smp_processor_id();
    
    long prev_state = args->prev_state;
    
    // 判断prev进程的切换类型
    // prev_state == TASK_RUNNING (0) 表示被抢占（非自愿）
    // prev_state != TASK_RUNNING 表示主动让出（自愿）
    bool prev_voluntary = (prev_state != TASK_RUNNING);
    
    // 更新prev进程的统计（切换出去）
    update_switch_stats((char *)args->prev_comm, cpu, true, prev_voluntary);
    
    // 更新next进程的统计（切换进来）
    // next进程切换进来不区分自愿/非自愿，统一计入involuntary
    // （因为next进程是被调度器选中的，不是主动的）
    update_switch_stats((char *)args->next_comm, cpu, false, false);
    
    return 0;
}

