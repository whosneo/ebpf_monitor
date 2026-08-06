/* eBPF nic_monitor 程序 - 低延时网卡监控（统计聚合模式）
 *
 * 用途：ROADMAP Phase 2 验证 spike（SWIFT-2200N）
 * 设计目标：
 *   - 捕获收发包统计、字节、粗略路径延迟
 *   - 关注软件可见队列/缓冲行为（结合 collect_nic_metrics.py 获取硬件队列深度、ring、bql、softnet）
 *   - 低开销聚合（内核 map 累积）
 *   - 兼容 3.10+ 内核，使用 kprobe + lookup/update 模式
 *
 * 核心指标（文档计划）：
 *   - 硬件队列深度（主要通过 collect_nic_metrics 采集 ethtool/sysfs；eBPF 辅助软件视图）
 *   - 缓冲区数据（skb len 统计 + backlog 相关）
 *   - 网卡级延迟（收发路径粗略配对 ns）
 *
 * SWIFT-2200N（中科驭数，vendor 1f47）：
 *   - 标准 Linux 驱动 + Kernel Bypass 库。
 *   - 通用 net 探针可捕获标准路径流量。
 *   - Driver specific 符号（KPU/ring 管理）占位：需在真实硬件上 nm /proc/kallsyms 查找填充。
 *   - 建议并行运行：python analysis/collect_nic_metrics.py --product SWIFT-2200N
 *
 * 输出模式建议（spike 后决定）：
 *   - 优先统计聚合（BPF_HASH + 原子更新 + 定期 pop），数据量可控。
 *   - 高性能低延迟场景下事件模式风险高（丢包或 CPU 开销）。
 *
 * 统计维度：
 *   (comm, direction) -> count, total_bytes, latency stats, queue_events
 *
 * 使用的探针（通用，优先兼容）：
 *   - dev_hard_start_xmit / dev_queue_xmit （TX）
 *   - netif_rx / netif_receive_skb （RX 简化）
 *
 * 性能：
 *   - 原子操作
 *   - 过滤内核线程
 */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>

/* 方向常量 */
#define DIR_TX 1
#define DIR_RX 2

/* Key：进程 + 方向 */
struct nic_key_t {
    char comm[TASK_COMM_LEN];
    u32 direction;
};

/* Value：统计 */
struct nic_val_t {
    u64 count;
    u64 total_bytes;
    u64 total_ns;
    u64 min_ns;
    u64 max_ns;
    u64 queue_events;   /* 占位：高队列深度事件计数（软件侧估算或未来 driver probe） */
};

/* 延迟配对辅助：记录开始时间 + comm */
struct nic_ts_t {
    u64 start_ts;
    char comm[TASK_COMM_LEN];
};

/* BPF maps */
BPF_HASH(nic_stats, struct nic_key_t, struct nic_val_t, 10240);
BPF_HASH(nic_start_ts, u64, struct nic_ts_t, 10240);

/* 辅助更新统计 */
static inline void update_nic_stats(char *comm, u32 direction, u64 bytes, u64 latency_ns, u64 q_event) {
    struct nic_key_t key = {};
    __builtin_memset(&key, 0, sizeof(key));
    bpf_probe_read(&key.comm, sizeof(key.comm), comm);
    key.direction = direction;

    struct nic_val_t *val = nic_stats.lookup(&key);
    if (!val) {
        struct nic_val_t zero = {};
        nic_stats.update(&key, &zero);
        val = nic_stats.lookup(&key);
        if (!val) return;
    }

    __sync_fetch_and_add(&val->count, 1);
    __sync_fetch_and_add(&val->total_bytes, bytes);

    if (latency_ns > 0) {
        __sync_fetch_and_add(&val->total_ns, latency_ns);
        if (latency_ns < val->min_ns || val->min_ns == 0) {
            val->min_ns = latency_ns;
        }
        if (latency_ns > val->max_ns) {
            val->max_ns = latency_ns;
        }
    }

    if (q_event > 0) {
        __sync_fetch_and_add(&val->queue_events, q_event);
    }
}

/* ==================== TX 路径 ==================== */

/* kprobe: dev_hard_start_xmit （TX 硬件启动，网卡级接近点）
 * 兼容老内核常见符号。参数大致：(struct sk_buff *skb, struct net_device *dev)
 */
int kprobe__dev_hard_start_xmit(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    if (pid == 0) return 0;

    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    if (!skb) return 0;

    u64 ts = bpf_ktime_get_ns();
    u32 len = 0;
    bpf_probe_read(&len, sizeof(len), &skb->len);

    struct nic_ts_t info = {};
    info.start_ts = ts;
    bpf_get_current_comm(&info.comm, sizeof(info.comm));

    /* 简单 key 用 skb 指针或 len 相关；这里简化用地址近似配对 */
    u64 skb_key = (u64)(uintptr_t)skb;
    nic_start_ts.update(&skb_key, &info);

    /* 先记基本 TX 统计（延迟待 RX 或完成时补充） */
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    update_nic_stats(comm, DIR_TX, len, 0, 0);

    return 0;
}

/* 可选补充：__dev_queue_xmit 入口（队列深度相关）
 * 现代内核导出符号为 __dev_queue_xmit，裸名 dev_queue_xmit 常不可 trace。
 */
int kprobe____dev_queue_xmit(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    if (!skb) return 0;

    /* 占位：未来可读 dev->qdisc 或 ring 深度；目前仅做事件计数占位，后续可根据实际符号增强 */
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    update_nic_stats(comm, DIR_TX, 0, 0, 1); /* 记一次队列事件 */
    return 0;
}

/* ==================== RX 路径 ==================== */

/* kprobe: netif_rx （或 netif_receive_skb 简化版） */
int kprobe__netif_rx(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    if (pid == 0) return 0;

    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    if (!skb) return 0;

    u32 len = 0;
    bpf_probe_read(&len, sizeof(len), &skb->len);

    u64 latency_ns = 0;
    u64 skb_key = (u64)(uintptr_t)skb;
    struct nic_ts_t *tx_info = nic_start_ts.lookup(&skb_key);
    if (tx_info) {
        latency_ns = bpf_ktime_get_ns() - tx_info->start_ts;
        if (latency_ns > 10000000000ULL) latency_ns = 0; /* 过滤异常 */
        nic_start_ts.delete(&skb_key);
    }

    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));

    update_nic_stats(comm, DIR_RX, len, latency_ns, 0);

    return 0;
}

/* 额外：__napi_poll（内核导出名为 __napi_poll，裸名 napi_poll 常不可 trace） */
int kprobe____napi_poll(struct pt_regs *ctx) {
    /* 占位：未来 driver specific 或 napi 内部队列深度探针
     * SWIFT-2200N: 查找驱动中 napi 或 ring poll 函数名后添加
     */
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    /* 示例：记一次 poll 作为缓冲/队列活动 */
    update_nic_stats(comm, DIR_RX, 0, 0, 1);
    return 0;
}

/* 结束：Python 端定期 pop nic_stats 表获取数据。 */
