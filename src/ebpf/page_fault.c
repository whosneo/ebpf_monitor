/* eBPF page_fault_monitor 程序 - 基于统计模式的页面错误监控
 * 
 * 设计特点：
 * 1. 统计模式：在内核态按多维度累积页面错误次数，避免高频事件导致的数据丢失
 * 2. 定期输出：Python端定时读取统计数据并输出（默认5秒周期）
 * 3. 统计维度：(进程名, 错误类型, CPU) -> 次数
 * 4. NUMA支持：Python端提供CPU到NUMA节点的映射分析
 * 
 * 使用的Tracepoint：
 * - exceptions:page_fault_user: 监控用户空间页面错误
 * - exceptions:page_fault_kernel: 监控内核空间页面错误
 * 
 * 统计维度说明：
 * - comm: 进程名（识别内存密集型进程）
 * - fault_type: 错误类型位掩码（MAJOR/MINOR/WRITE/USER，通过error_code解析）
 * - cpu: CPU编号（分析CPU和NUMA节点分布）
 * 
 * 错误类型检测能力：
 * ✅ MAJOR (0x2): 页面不在内存，需要从磁盘加载（error_code bit 0 = 0）
 * ✅ MINOR (0x1): 页面在内存，权限问题（error_code bit 0 = 1）
 * ✅ WRITE (0x4): 写访问导致的错误（error_code bit 1 = 1）
 * ✅ USER (0x8): 用户空间错误（error_code bit 2 = 1）
 * ❌ SHARED: 无法通过error_code检测，需要VMA查询
 * ❌ SWAP: 无法通过error_code检测，需要页表查询
 * 
 * 性能优化：
 * - 使用原子操作(__sync_fetch_and_add)保证并发安全
 * - 兼容内核3.10+（使用lookup+update模式）
 * - Hash Map大小：page_fault_stats=10240（约240KB内存）
 */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

/* 页面错误类型定义 - 与Python代码保持一致
 * 注意：只能通过error_code检测以下四种类型
 */
#define FAULT_TYPE_MINOR     0x1      // 次要页面错误（页面在内存，权限问题）
#define FAULT_TYPE_MAJOR     0x2      // 主要页面错误（页面不在内存，需要加载）
#define FAULT_TYPE_WRITE     0x4      // 写错误（写访问导致的错误）
#define FAULT_TYPE_USER      0x8      // 用户空间错误（用户模式访问）

/* 统计Key：(进程名, 错误类型, CPU)
 * 注意：comm[16] + u32 + u32虽然没有填充，但为了一致性也显式清零
 */
struct stats_key_t {
    char comm[TASK_COMM_LEN];  // 进程名 (16字节)
    u32 fault_type;            // 错误类型位掩码
    u32 cpu;                   // CPU编号
};

/* 统计Value */
struct stats_value_t {
    u64 count;  // 页面错误次数
};

/* BPF映射 */
BPF_HASH(page_fault_stats, struct stats_key_t, struct stats_value_t, 10240);  // 页面错误统计

/* 辅助函数：确定页面错误类型 */
static inline u32 determine_fault_type(unsigned long error_code, bool is_user_fault) {
    u32 fault_type = 0;
    
    // 基本错误类型判断
    // error_code bit 0: Present bit
    // - 1 = 页面存在但权限不足（保护错误，通常是次要错误）
    // - 0 = 页面不存在（需要分配/加载，通常是主要错误）
    if (error_code & 0x1) {
        fault_type |= FAULT_TYPE_MINOR;  // 页面存在，权限问题
    } else {
        fault_type |= FAULT_TYPE_MAJOR;  // 页面不存在，需要加载
    }
    
    // error_code bit 1: Write bit
    // - 1 = 写访问导致的错误
    // - 0 = 读访问导致的错误
    if (error_code & 0x2) {
        fault_type |= FAULT_TYPE_WRITE;
    }
    
    // error_code bit 2: User bit (但我们通过is_user_fault参数传递)
    // - 1 = 用户模式访问导致的错误
    // - 0 = 内核模式访问导致的错误
    if (is_user_fault) {
        fault_type |= FAULT_TYPE_USER;
    }
    
    return fault_type;
}

/* 统计更新函数：更新页面错误统计 */
static inline void update_page_fault_stats(u32 fault_type, u32 cpu) {
    struct stats_key_t key = {};
    __builtin_memset(&key, 0, sizeof(key));  // 显式清零，确保一致性
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
    key.fault_type = fault_type;
    key.cpu = cpu;
    
    // 兼容3.10内核：使用lookup + update模式
    struct stats_value_t *val = page_fault_stats.lookup(&key);
    if (val) {
        // 已存在，原子递增
        __sync_fetch_and_add(&val->count, 1);
    } else {
        // 不存在，创建新条目
        struct stats_value_t new_val = {.count = 1};
        page_fault_stats.update(&key, &new_val);
    }
}

// # cat /sys/kernel/debug/tracing/events/exceptions/page_fault_user/format
// name: page_fault_user
// ID: 119
// format:
// 	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
// 	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
// 	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
// 	field:int common_pid;	offset:4;	size:4;	signed:1;

// 	field:unsigned long address;	offset:8;	size:8;	signed:0;
// 	field:unsigned long ip;	offset:16;	size:8;	signed:0;
// 	field:unsigned long error_code;	offset:24;	size:8;	signed:0;

// print fmt: "address=%pf ip=%pf error_code=0x%lx", (void *)REC->address, (void *)REC->ip, REC->error_code

// Tracepoint: exceptions:page_fault_user - 监控用户空间页面错误
TRACEPOINT_PROBE(exceptions, page_fault_user) {
    // 确定错误类型并更新统计
    u32 fault_type = determine_fault_type(args->error_code, true);
    u32 cpu = bpf_get_smp_processor_id();
    
    update_page_fault_stats(fault_type, cpu);
    
    return 0;
}

// # cat /sys/kernel/debug/tracing/events/exceptions/page_fault_kernel/format
// name: page_fault_kernel
// ID: 118
// format:
// 	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
// 	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
// 	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
// 	field:int common_pid;	offset:4;	size:4;	signed:1;

// 	field:unsigned long address;	offset:8;	size:8;	signed:0;
// 	field:unsigned long ip;	offset:16;	size:8;	signed:0;
// 	field:unsigned long error_code;	offset:24;	size:8;	signed:0;

// print fmt: "address=%pf ip=%pf error_code=0x%lx", (void *)REC->address, (void *)REC->ip, REC->error_code

// Tracepoint: exceptions:page_fault_kernel - 监控内核空间页面错误
TRACEPOINT_PROBE(exceptions, page_fault_kernel) {
    // 确定错误类型并更新统计
    u32 fault_type = determine_fault_type(args->error_code, false);
    u32 cpu = bpf_get_smp_processor_id();
    
    update_page_fault_stats(fault_type, cpu);
    
    return 0;
}
