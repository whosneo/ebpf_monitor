/* eBPF func 程序模板 - 基于统计模式的函数调用监控
 * 
 * 设计特点：
 * 1. 统计模式：在内核态按(进程名, 函数)维度累积调用次数
 * 2. 定期输出：Python端定时读取统计数据并输出
 * 3. 高性能：避免高频函数调用导致的事件丢失
 * 4. 聚合分析：同名进程自动聚合，便于应用级分析
 * 
 * 占位符说明：
 * - PROBE_FUNCTIONS: 动态生成的探针函数代码
 */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

/* 统计Key：按进程名和函数ID聚合
 * 注意：comm[16] + u32会有填充字节，必须用__builtin_memset清零
 */
struct stats_key_t {
    char comm[TASK_COMM_LEN];  // 进程名 (16字节)
    u32 func_id;               // 函数ID
};

/* 统计Value：调用次数 */
struct stats_value_t {
    u64 count;  // 调用计数
};

/* BPF映射和输出管道 */
BPF_HASH(func_stats, struct stats_key_t, struct stats_value_t, 10240);  // 函数调用统计

// 统计更新函数：累积函数调用次数
static inline void update_func_stats(struct pt_regs *ctx, u32 func_id) {
    // 构建统计key
    struct stats_key_t key = {};
    __builtin_memset(&key, 0, sizeof(key));  // 显式清零，包括填充字节
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
    key.func_id = func_id;

    // 查找或初始化统计value
    struct stats_value_t *val = func_stats.lookup(&key);
    if (val) {
        // 已存在，直接递增
        __sync_fetch_and_add(&val->count, 1);
    } else {
        // 不存在，初始化为1
        struct stats_value_t new_val = {0};
        new_val.count = 1;
        func_stats.update(&key, &new_val);
    }
}

// ============================================================================
// 动态生成的探针函数将在此处插入
// ============================================================================

PROBE_FUNCTIONS
