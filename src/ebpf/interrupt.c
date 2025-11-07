/* eBPF interrupt_monitor 程序 - 基于统计模式的中断监控
 * 
 * 设计特点：
 * 1. 统计模式：在内核态按多维度累积中断次数，避免高频中断导致的事件丢失
 * 2. 定期输出：Python端定时读取统计数据并输出（默认1秒周期）
 * 3. 单表全维度设计：统计 (进程名, 中断类型, CPU) 维度的中断次数
 * 4. 无延迟测量：只统计频率，不计算中断延迟，简化实现并提升性能
 * 
 * 使用的Tracepoint（只需exit，不需要entry）：
 * - irq:irq_handler_exit: 硬件中断出口（统计点）
 * - irq:softirq_exit: 软中断出口（统计点）
 * 
 * 统计维度：
 * - interrupt_stats: (进程名, 中断类型, CPU) -> 次数
 *   用途：分析哪些进程在哪些CPU上触发了何种类型的中断
 * 
 * 性能优化：
 * - 使用原子操作(__sync_fetch_and_add)保证并发安全
 * - 兼容内核3.10+（使用lookup+update模式）
 * - Hash Map大小：interrupt_stats=10240（约330KB内存）
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

/* 统计 Key：(进程名, 中断类型, CPU)
 * 注意：comm[16] + u32 + u32虽然没有填充，但为了一致性也显式清零
 */
struct stats_key_t {
    char comm[TASK_COMM_LEN];  // 进程名 (16字节)
    u32 irq_type;              // 中断类型
    u32 cpu;                   // CPU编号
};

/* 统计 Value（共用） */
struct stats_value_t {
    u64 count;  // 调用次数
};

/* BPF映射 */
BPF_HASH(interrupt_stats, struct stats_key_t, struct stats_value_t, 10240);  // 中断统计 (进程名, 中断类型, CPU)

/* 统计更新函数：更新中断统计 (进程名, 中断类型, CPU) */
static inline void update_interrupt_stats(u32 irq_type, u32 cpu) {
    struct stats_key_t key = {};
    __builtin_memset(&key, 0, sizeof(key));  // 显式清零，确保一致性
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
    key.irq_type = irq_type;
    key.cpu = cpu;
    
    struct stats_value_t *val = interrupt_stats.lookup(&key);
    if (val) {
        __sync_fetch_and_add(&val->count, 1);
    } else {
        struct stats_value_t new_val = {0};
        new_val.count = 1;
        interrupt_stats.update(&key, &new_val);
    }
}

// # cat /sys/kernel/debug/tracing/events/irq/irq_handler_exit/format
// name: irq_handler_exit
// ID: 148
// format:
//         field:unsigned short common_type;       offset:0;       size:2; signed:0;
//         field:unsigned char common_flags;       offset:2;       size:1; signed:0;
//         field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
//         field:int common_pid;   offset:4;       size:4; signed:1;

//         field:int irq;  offset:8;       size:4; signed:1;
//         field:int ret;  offset:12;      size:4; signed:1;

// print fmt: "irq=%d ret=%s", REC->irq, REC->ret ? "handled" : "unhandled"

/* Tracepoint：硬件中断出口（统计点） */
TRACEPOINT_PROBE(irq, irq_handler_exit) {
    u32 cpu = bpf_get_smp_processor_id();
    u32 irq_type = IRQ_TYPE_HARDWARE;
    
    // 更新统计表
    update_interrupt_stats(irq_type, cpu);
    
    return 0;
}

// # cat /sys/kernel/debug/tracing/events/irq/softirq_exit/format
// name: softirq_exit
// ID: 146
// format:
//         field:unsigned short common_type;       offset:0;       size:2; signed:0;
//         field:unsigned char common_flags;       offset:2;       size:1; signed:0;
//         field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
//         field:int common_pid;   offset:4;       size:4; signed:1;

//         field:unsigned int vec; offset:8;       size:4; signed:0;

// print fmt: "vec=%u [action=%s]", REC->vec, __print_symbolic(REC->vec, { 0, "HI" }, { 1, "TIMER" }, { 2, "NET_TX" }, { 3, "NET_RX" }, { 4, "BLOCK" }, { 5, "IRQ_POLL" }, { 6, "TASKLET" }, { 7, "SCHED" }, { 8, "HRTIMER" }, { 9, "RCU" })

/* Tracepoint：软中断出口（统计点） */
TRACEPOINT_PROBE(irq, softirq_exit) {
    u32 vec = args->vec;
    u32 cpu = bpf_get_smp_processor_id();
    u32 irq_type = IRQ_TYPE_SOFTWARE;
    
    // 设置特定软中断类型标志
    if (vec == 2 || vec == 3) {  // NET_TX_SOFTIRQ || NET_RX_SOFTIRQ
        irq_type |= IRQ_TYPE_NETWORK;
    } else if (vec == 1 || vec == 8) {  // TIMER_SOFTIRQ || HRTIMER_SOFTIRQ
        irq_type |= IRQ_TYPE_TIMER;
    } else if (vec == 4) {  // BLOCK_SOFTIRQ
        irq_type |= IRQ_TYPE_BLOCK;
    }
    
    // 更新统计表
    update_interrupt_stats(irq_type, cpu);
    
    return 0;
}
