/* eBPF udp_monitor 程序 - 基于统计模式的UDP网络通信监控
 *
 * 设计特点：
 * 1. 统计模式：在内核态按多维度累积UDP收发统计，避免高频网络流量导致的数据丢失
 * 2. 定期输出：Python端定时读取统计数据并输出（默认2秒周期）
 * 3. 延迟计算：通过kprobe配对实现UDP收发延迟测量
 *
 * 监控维度：
 * - (进程名, 方向) -> (报文数, 总字节, 延迟统计)
 *
 * 使用的Kprobe：
 * - udp_sendmsg: UDP发送路径（兼容3.10-4.19）
 * - udp_rcv: UDP接收路径（兼容3.10-4.19）
 *
 * 统计指标：
 * - count: UDP报文数
 * - total_bytes: 总字节数
 * - total_ns: 总延迟（纳秒，收发配对计算）
 * - min_ns: 最小延迟
 * - max_ns: 最大延迟
 *
 * 性能优化：
 * - 使用原子操作(__sync_fetch_and_add)保证并发安全
 * - min/max使用简单比较(非原子)，避免CAS操作的兼容性问题
 * - 兼容内核3.10+（使用lookup+update模式）
 * - Hash Map大小：udp_stats=10240, udp_start_ts=10240
 */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <net/sock.h>
#include <net/inet_sock.h>

/* 方向常量 */
#define DIR_SEND 1
#define DIR_RECV 2

/* 统计Key：(进程名, 方向)
 * 注意：comm[16] + u32会有填充字节，必须用__builtin_memset清零
 */
struct udp_stats_key_t {
    char comm[TASK_COMM_LEN];  /* 进程名 (16字节) */
    u32 direction;             /* 方向: 1=发送, 2=接收 */
};

/* 统计Value */
struct udp_stats_value_t {
    u64 count;         /* 报文数 */
    u64 total_bytes;   /* 总字节数 */
    u64 total_ns;      /* 总延迟（纳秒） */
    u64 min_ns;        /* 最小延迟 */
    u64 max_ns;        /* 最大延迟 */
};

/* 延迟计算辅助结构 */
struct udp_msg_info_t {
    u64 start_ts;              /* 开始时间戳 */
    char comm[TASK_COMM_LEN];  /* 进程名 */
};

/* BPF映射 */
BPF_HASH(udp_stats, struct udp_stats_key_t, struct udp_stats_value_t, 10240);
BPF_HASH(udp_start_ts, u64, struct udp_msg_info_t, 10240);

/* 统计更新函数：更新UDP统计 */
static inline void update_udp_stats(char *comm, u32 direction, u64 bytes, u64 ns) {
    struct udp_stats_key_t key = {};
    __builtin_memset(&key, 0, sizeof(key));
    bpf_probe_read(&key.comm, sizeof(key.comm), comm);
    key.direction = direction;

    /* lookup→update→lookup模式，兼容3.10内核 */
    struct udp_stats_value_t *val = udp_stats.lookup(&key);
    if (!val) {
        struct udp_stats_value_t zero = {};
        udp_stats.update(&key, &zero);
        val = udp_stats.lookup(&key);
        if (!val) {
            return;
        }
    }

    __sync_fetch_and_add(&val->count, 1);
    __sync_fetch_and_add(&val->total_bytes, bytes);

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

/* ==================== Kprobe处理函数 ==================== */

/* Kprobe: udp_sendmsg - UDP发送路径
 * 兼容内核3.10-4.19
 * 参数: (struct sock *sk, struct msghdr *msg, size_t len)
 */
int kprobe__udp_sendmsg(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    /* 过滤内核线程 */
    if (pid == 0) return 0;

    /* 获取sock指针（第一个参数） */
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk) return 0;

    /* 获取字节数（第三个参数） */
    size_t len = (size_t)PT_REGS_PARM3(ctx);

    /* 读取源端口和地址 */
    u16 sport = 0;
    u32 saddr = 0;
    bpf_probe_read(&sport, sizeof(sport), &sk->__sk_common.skc_num);
    bpf_probe_read(&saddr, sizeof(saddr), &sk->__sk_common.skc_rcv_saddr);

    /* 构造消息Key用于延迟计算 */
    u64 msg_key = ((u64)saddr << 32) | (u64)sport;

    /* 记录发送信息 */
    struct udp_msg_info_t info = {};
    info.start_ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&info.comm, sizeof(info.comm));
    udp_start_ts.update(&msg_key, &info);

    /* 更新发送统计 */
    char *comm = info.comm;
    update_udp_stats(comm, DIR_SEND, len, 0);

    return 0;
}

/* Kprobe: udp_rcv - UDP接收路径
 * 兼容内核3.10-4.19
 * 参数: (struct sk_buff *skb)
 */
int kprobe__udp_rcv(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    /* 过滤内核线程 */
    if (pid == 0) return 0;

    /* 获取skb指针 */
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    if (!skb) return 0;

    /* 从skb中读取UDP头信息 */
    unsigned char *head = NULL;
    u16 headers = 0;
    bpf_probe_read(&head, sizeof(head), &skb->head);
    bpf_probe_read(&headers, sizeof(headers), &skb->transport_header);
    if (!head) return 0;

    /* 计算UDP头偏移 */
    unsigned char *udp_hdr = head + headers;

    /* 读取UDP头字段 */
    u16 uh_sport = 0;
    u16 uh_dport = 0;
    bpf_probe_read(&uh_sport, sizeof(uh_sport), udp_hdr);
    bpf_probe_read(&uh_dport, sizeof(uh_dport), udp_hdr + 2);

    /* 读取IP层信息 */
    unsigned char *net_hdr = head + headers - sizeof(struct iphdr) - sizeof(struct udphdr);
    u32 saddr = 0;
    u32 daddr = 0;
    bpf_probe_read(&saddr, sizeof(saddr), net_hdr + 12);
    bpf_probe_read(&daddr, sizeof(daddr), net_hdr + 16);

    /* 构造消息Key（与发送端匹配） */
    u64 msg_key = ((u64)saddr << 32) | (u64)uh_sport;

    /* 查找对应的发送记录计算延迟 */
    u64 latency_ns = 0;
    struct udp_msg_info_t *send_info = udp_start_ts.lookup(&msg_key);
    if (send_info) {
        latency_ns = bpf_ktime_get_ns() - send_info->start_ts;
        /* 过滤异常值（>10秒） */
        if (latency_ns > 10000000000ULL) {
            latency_ns = 0;
        }
        udp_start_ts.delete(&msg_key);
    }

    /* 获取当前进程信息 */
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));

    /* 计算数据长度 */
    u64 bytes = 0;
    u16 uh_len = 0;
    bpf_probe_read(&uh_len, sizeof(uh_len), udp_hdr + 4);
    if (uh_len >= 8) {
        bytes = uh_len - 8;
    }

    /* 更新接收统计 */
    update_udp_stats(comm, DIR_RECV, bytes, latency_ns);

    return 0;
}
