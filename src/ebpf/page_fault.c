/* eBPF page_fault_monitor 程序 - 监控系统页面错误事件
 * 
 * 采用纯Tracepoint机制的优势：
 * 1. 兼容性：使用exceptions tracepoint，避免内核符号依赖问题
 * 2. 稳定性：tracepoint是内核提供的稳定ABI
 * 3. 简洁性：无需复杂的状态管理和时间测量
 * 4. 可靠性：避免kprobe可能的兼容性问题
 * 5. 性能：最小的系统开销
 * 
 * 使用的Tracepoint：
 * - exceptions:page_fault_user: 监控用户空间页面错误
 * - exceptions:page_fault_kernel: 监控内核空间页面错误
 * 
 * 注意：此实现专注于页面错误的发生模式分析，不测量处理时间
 */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

/* 页面错误类型定义 - 与Python代码保持一致 */
#define FAULT_TYPE_MINOR     0x1      // 次要页面错误
#define FAULT_TYPE_MAJOR     0x2      // 主要页面错误
#define FAULT_TYPE_WRITE     0x4      // 写错误
#define FAULT_TYPE_USER      0x8      // 用户空间错误
#define FAULT_TYPE_SHARED    0x10     // 共享内存错误
#define FAULT_TYPE_SWAP      0x8000   // 交换页面错误

/* 页面错误事件数据结构 */
struct page_fault_event {
    u64 timestamp;                 // 时间戳 (纳秒)
    u32 pid;                       // 进程ID
    u32 tid;                       // 线程ID
    char comm[TASK_COMM_LEN];      // 进程名
    u64 address;                   // 内存地址
    u32 fault_type;                // 错误类型
    u32 cpu;                       // CPU编号
};

/* BPF映射和输出管道 */
BPF_PERF_OUTPUT(page_fault_events);                 // 事件输出管道
BPF_HASH(target_pids, u32, u8, 1024);               // 目标进程PID映射
BPF_HASH(target_uids, u32, u8, 1024);               // 目标用户ID映射

/* 辅助函数：检查是否为目标进程 */
static inline bool is_target_process(u32 pid) {
    // u8 *val = target_pids.lookup(&pid);
    // return val != 0;
    return true;  // 页面错误监控默认监控所有进程
}

/* 辅助函数：检查是否为目标用户 */
static inline bool is_target_user(u32 uid) {
    // u8 *val = target_uids.lookup(&uid);
    // return val != 0;
    return true;  // 页面错误监控默认监控所有用户
}

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

/* 辅助函数：初始化基础事件数据 */
static inline void init_page_fault_event(struct page_fault_event *event, bool is_user_fault, unsigned long address, unsigned long error_code) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    event->timestamp = bpf_ktime_get_ns();
    event->pid = pid_tgid >> 32;
    event->tid = pid_tgid & 0xffffffff;
    event->cpu = bpf_get_smp_processor_id();
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    event->address = address;
    event->fault_type = determine_fault_type(error_code, is_user_fault);
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
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    
    // 进程过滤
    if (!is_target_process(pid)) {
        return 0;
    }
    
    // 用户过滤
    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    if (!is_target_user(uid)) {
        return 0;
    }
    
    // 构造并发送事件
    struct page_fault_event event = {};
    init_page_fault_event(&event, true, args->address, args->error_code);
    
    page_fault_events.perf_submit(args, &event, sizeof(event));
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
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    
    // 进程过滤
    if (!is_target_process(pid)) {
        return 0;
    }
    
    // 构造并发送事件
    struct page_fault_event event = {};
    init_page_fault_event(&event, false, args->address, args->error_code);
    
    page_fault_events.perf_submit(args, &event, sizeof(event));
    return 0;
}

/* 
 * 注意事项：
 * 1. 这个eBPF程序需要root权限运行
 * 2. 完全基于tracepoint实现，避免kprobe兼容性问题
 * 3. 数据结构已简化，移除了无法获取的字段
 * 4. 专注于页面错误的发生模式和频率分析
 * 5. 提供最大的系统兼容性和稳定性
 */