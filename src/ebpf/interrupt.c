/* eBPF interrupt_monitor 程序 - 监控系统硬件中断和软中断
 * 
 * 采用Tracepoint机制的优势：
 * 1. 精确性：直接监控中断处理的入口和出口，获取准确的中断信息
 * 2. 完整数据：能够获取中断号、处理时间、CPU信息等完整数据
 * 3. 稳定性：tracepoint是内核提供的稳定ABI
 * 4. 性能：相比kprobe，tracepoint开销更小
 * 5. 时序准确：能够精确测量中断处理延迟
 * 
 * 使用的Tracepoint：
 * - irq:irq_handler_entry: 监控硬件中断入口
 * - irq:irq_handler_exit: 监控硬件中断出口
 * - irq:softirq_entry: 监控软中断入口
 * - irq:softirq_exit: 监控软中断出口
 * - sched:sched_migrate_task: 监控进程迁移（可选）
 */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/irq.h>
#include <linux/interrupt.h>

/* 中断类型定义 - 与Python代码保持一致 */
#define IRQ_TYPE_HARDWARE    0x1
#define IRQ_TYPE_SOFTWARE    0x2
#define IRQ_TYPE_TIMER       0x4
#define IRQ_TYPE_NETWORK     0x8
#define IRQ_TYPE_BLOCK       0x10
#define IRQ_TYPE_MIGRATE     0x4000
#define IRQ_TYPE_AFFINITY    0x8000

/* 中断事件数据结构 */
struct interrupt_event {
    u64 timestamp;             // 时间戳 (纳秒)
    u32 pid;                   // 进程 ID
    u32 tid;                   // 线程 ID
    u32 irq_num;               // 中断号
    u32 irq_type;              // 中断类型
    u64 duration_ns;           // 持续时间(纳秒)
    u32 cpu;                   // CPU编号
    u32 softirq_vec;           // 软中断向量
    char comm[TASK_COMM_LEN];  // 进程名
    char irq_name[16];         // 中断名称（简化为16字节）
};

/* 中断时序记录结构 */
struct irq_timing {
    u64 start_time;
    u32 irq_num;
    u32 cpu;
};

/* BPF映射和输出管道 */
BPF_PERF_OUTPUT(interrupt_events);                    // 事件输出管道
BPF_HASH(target_pids, u32, u8, 1024);                // 目标进程PID映射
BPF_HASH(target_uids, u32, u8, 1024);                // 目标用户ID映射
BPF_HASH(irq_start_times, u64, struct irq_timing, 1024);     // 硬件中断开始时间
BPF_HASH(softirq_start_times, u64, struct irq_timing, 1024); // 软中断开始时间

/* 辅助函数：检查是否为目标进程 */
static inline bool is_target_process(u32 pid) {
    // u8 *val = target_pids.lookup(&pid);
    // return val != 0;  // 优化：!= NULL -> !=0（verifier 友好）
    return true;  // 中断监控默认监控所有进程
}

/* 辅助函数：检查是否为目标用户 */
static inline bool is_target_user(u32 uid) {
    // u8 *val = target_uids.lookup(&uid);
    // return val != 0;
    return true;  // 中断监控默认监控所有用户
}

/* 辅助函数：生成中断唯一标识 */
static inline u64 make_irq_key(u32 irq_num, u32 cpu) {
    return ((u64)cpu << 32) | irq_num;
}

/* 辅助函数：生成软中断唯一标识 */
static inline u64 make_softirq_key(u32 vec, u32 cpu) {
    return ((u64)cpu << 32) | (0x80000000 | vec);
}

/* 辅助函数：获取软中断名称 */
static inline void get_softirq_name(u32 vec, char *name) {
    switch (vec) {
        case 0: // HI_SOFTIRQ
            __builtin_memcpy(name, "HI", 3);
            break;
        case 1: // TIMER_SOFTIRQ
            __builtin_memcpy(name, "TIMER", 6);
            break;
        case 2: // NET_TX_SOFTIRQ
            __builtin_memcpy(name, "NET_TX", 7);
            break;
        case 3: // NET_RX_SOFTIRQ
            __builtin_memcpy(name, "NET_RX", 7);
            break;
        case 4: // BLOCK_SOFTIRQ
            __builtin_memcpy(name, "BLOCK", 6);
            break;
        case 5: // IRQ_POLL_SOFTIRQ
            __builtin_memcpy(name, "IRQ_POLL", 9);
            break;
        case 6: // TASKLET_SOFTIRQ
            __builtin_memcpy(name, "TASKLET", 8);
            break;
        case 7: // SCHED_SOFTIRQ
            __builtin_memcpy(name, "SCHED", 6);
            break;
        case 8: // HRTIMER_SOFTIRQ
            __builtin_memcpy(name, "HRTIMER", 8);
            break;
        case 9: // RCU_SOFTIRQ
            __builtin_memcpy(name, "RCU", 4);
            break;
        default:
            __builtin_memcpy(name, "UNKNOWN", 8);
            break;
    }
}

/* 辅助函数：初始化基础事件数据 */
static inline void init_interrupt_event(struct interrupt_event *event) {
    event->timestamp = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid >> 32;
    event->tid = pid_tgid & 0xffffffff;
    event->cpu = bpf_get_smp_processor_id();
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
}

// # cat /sys/kernel/debug/tracing/events/irq/irq_handler_entry/format
// name: irq_handler_entry
// ID: 149
// format:
// 	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
// 	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
// 	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
// 	field:int common_pid;	offset:4;	size:4;	signed:1;

// 	field:int irq;	offset:8;	size:4;	signed:1;
// 	field:__data_loc char[] name;	offset:12;	size:4;	signed:1;

// print fmt: "irq=%d name=%s", REC->irq, __get_str(name)

/* Tracepoint：硬件中断入口 */
TRACEPOINT_PROBE(irq, irq_handler_entry) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!is_target_process(pid)) {
        return 0;
    }
    
    u64 uid_gid = bpf_get_current_uid_gid();
    u32 uid = uid_gid & 0xffffffff;
    if (!is_target_user(uid)) {
        return 0;
    }
    
    u32 irq_num = args->irq;
    u32 cpu = bpf_get_smp_processor_id();
    u64 key = make_irq_key(irq_num, cpu);
    u64 ts = bpf_ktime_get_ns();
    
    // 记录开始时间
    struct irq_timing timing = {};
    timing.start_time = ts;
    timing.irq_num = irq_num;
    timing.cpu = cpu;
    
    irq_start_times.update(&key, &timing);
    return 0;
}

// # cat /sys/kernel/debug/tracing/events/irq/irq_handler_exit/format
// name: irq_handler_exit
// ID: 148
// format:
// 	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
// 	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
// 	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
// 	field:int common_pid;	offset:4;	size:4;	signed:1;

// 	field:int irq;	offset:8;	size:4;	signed:1;
// 	field:int ret;	offset:12;	size:4;	signed:1;

// print fmt: "irq=%d ret=%s", REC->irq, REC->ret ? "handled" : "unhandled"

/* Tracepoint：硬件中断出口 */
TRACEPOINT_PROBE(irq, irq_handler_exit) {
    u32 irq_num = args->irq;
    u32 cpu = bpf_get_smp_processor_id();
    u64 key = make_irq_key(irq_num, cpu);
    u64 end_ts = bpf_ktime_get_ns();
    
    struct irq_timing *timing = irq_start_times.lookup(&key);
    if (!timing) {
        return 0;
    }
    
    u64 duration = end_ts - timing->start_time;
    
    // 创建中断事件
    struct interrupt_event event = {};
    init_interrupt_event(&event);
    
    event.irq_num = irq_num;
    event.irq_type = IRQ_TYPE_HARDWARE;
    event.duration_ns = duration;
    event.softirq_vec = 0;
    
    // 设置中断名称
    __builtin_memcpy(event.irq_name, "hw_irq", 7);
    
    // 提交事件
    interrupt_events.perf_submit(args, &event, sizeof(event));
    
    // 清理开始时间
    irq_start_times.delete(&key);
    return 0;
}

// # cat /sys/kernel/debug/tracing/events/irq/softirq_entry/format
// name: softirq_entry
// ID: 147
// format:
// 	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
// 	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
// 	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
// 	field:int common_pid;	offset:4;	size:4;	signed:1;

// 	field:unsigned int vec;	offset:8;	size:4;	signed:0;

// print fmt: "vec=%u [action=%s]", REC->vec, __print_symbolic(REC->vec, { 0, "HI" }, { 1, "TIMER" }, { 2, "NET_TX" }, { 3, "NET_RX" }, { 4, "BLOCK" }, { 5, "IRQ_POLL" }, { 6, "TASKLET" }, { 7, "SCHED" }, { 8, "HRTIMER" }, { 9, "RCU" })

/* Tracepoint：软中断入口 */
TRACEPOINT_PROBE(irq, softirq_entry) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!is_target_process(pid)) {
        return 0;
    }
    
    u64 uid_gid = bpf_get_current_uid_gid();
    u32 uid = uid_gid & 0xffffffff;
    if (!is_target_user(uid)) {
        return 0;
    }
    
    u32 vec = args->vec;
    u32 cpu = bpf_get_smp_processor_id();
    u64 key = make_softirq_key(vec, cpu);
    u64 ts = bpf_ktime_get_ns();
    
    // 记录开始时间
    struct irq_timing timing = {};
    timing.start_time = ts;
    timing.irq_num = vec;
    timing.cpu = cpu;
    
    softirq_start_times.update(&key, &timing);
    return 0;
}

// # cat /sys/kernel/debug/tracing/events/irq/softirq_exit/format
// name: softirq_exit
// ID: 146
// format:
// 	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
// 	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
// 	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
// 	field:int common_pid;	offset:4;	size:4;	signed:1;

// 	field:unsigned int vec;	offset:8;	size:4;	signed:0;

// print fmt: "vec=%u [action=%s]", REC->vec, __print_symbolic(REC->vec, { 0, "HI" }, { 1, "TIMER" }, { 2, "NET_TX" }, { 3, "NET_RX" }, { 4, "BLOCK" }, { 5, "IRQ_POLL" }, { 6, "TASKLET" }, { 7, "SCHED" }, { 8, "HRTIMER" }, { 9, "RCU" })

/* Tracepoint：软中断出口 */
TRACEPOINT_PROBE(irq, softirq_exit) {
    u32 vec = args->vec;
    u32 cpu = bpf_get_smp_processor_id();
    u64 key = make_softirq_key(vec, cpu);
    u64 end_ts = bpf_ktime_get_ns();
    
    struct irq_timing *timing = softirq_start_times.lookup(&key);
    if (!timing) {
        return 0;
    }
    
    u64 duration = end_ts - timing->start_time;
    
    // 创建软中断事件
    struct interrupt_event event = {};
    init_interrupt_event(&event);
    
    event.irq_num = 0;
    event.irq_type = IRQ_TYPE_SOFTWARE;
    event.duration_ns = duration;
    event.softirq_vec = vec;
    
    // 获取软中断名称
    get_softirq_name(vec, event.irq_name);
    
    // 设置特定软中断类型标志
    if (vec == 2 || vec == 3) {  // NET_TX_SOFTIRQ || NET_RX_SOFTIRQ
        event.irq_type |= IRQ_TYPE_NETWORK;
    } else if (vec == 1 || vec == 8) {  // TIMER_SOFTIRQ || HRTIMER_SOFTIRQ
        event.irq_type |= IRQ_TYPE_TIMER;
    } else if (vec == 4) {  // BLOCK_SOFTIRQ
        event.irq_type |= IRQ_TYPE_BLOCK;
    }
    
    // 提交事件
    interrupt_events.perf_submit(args, &event, sizeof(event));
    
    // 清理开始时间
    softirq_start_times.delete(&key);
    return 0;
}

// # cat /sys/kernel/debug/tracing/events/sched/sched_migrate_task/format
// name: sched_migrate_task
// ID: 311
// format:
// 	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
// 	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
// 	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
// 	field:int common_pid;	offset:4;	size:4;	signed:1;

// 	field:char comm[16];	offset:8;	size:16;	signed:1;
// 	field:pid_t pid;	offset:24;	size:4;	signed:1;
// 	field:int prio;	offset:28;	size:4;	signed:1;
// 	field:int orig_cpu;	offset:32;	size:4;	signed:1;
// 	field:int dest_cpu;	offset:36;	size:4;	signed:1;

// print fmt: "comm=%s pid=%d prio=%d orig_cpu=%d dest_cpu=%d", REC->comm, REC->pid, REC->prio, REC->orig_cpu, REC->dest_cpu

/* Tracepoint：进程迁移监控（可选） */
TRACEPOINT_PROBE(sched, sched_migrate_task) {
    u32 pid = args->pid;
    
    // 检查是否为目标进程
    if (!is_target_process(pid)) {
        return 0;
    }
    
    u64 uid_gid = bpf_get_current_uid_gid();
    u32 uid = uid_gid & 0xffffffff;
    if (!is_target_user(uid)) {
        return 0;
    }
    
    // 创建迁移事件
    struct interrupt_event event = {};
    init_interrupt_event(&event);
    
    event.pid = pid;
    event.irq_type = IRQ_TYPE_MIGRATE;
    event.irq_num = args->orig_cpu;      // 原CPU
    event.softirq_vec = args->dest_cpu;  // 目标CPU
    event.duration_ns = 0;
    
    __builtin_memcpy(event.irq_name, "migrate", 8);
    
    // 提交迁移事件
    interrupt_events.perf_submit(args, &event, sizeof(event));
    return 0;
}

