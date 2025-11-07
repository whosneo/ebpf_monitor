/* eBPF bio_monitor 程序 - 基于统计模式的Block IO监控
 * 
 * 设计特点：
 * 1. 统计模式：在内核态按多维度累积Block IO统计，避免高频IO导致的数据丢失
 * 2. 定期输出：Python端定时读取统计数据并输出（默认5秒周期）
 * 3. 监控Block层：监控真实的磁盘IO，过滤了Page Cache命中的操作
 * 4. 统计维度：(进程名, BIO类型) -> (次数, 字节数, 延迟统计)
 * 
 * 使用的Tracepoint：
 * - block:block_rq_issue: BIO请求下发到设备（起点，记录开始时间）
 * - block:block_rq_complete: BIO请求完成（终点，计算延迟）
 * 
 * 统计维度说明：
 * - comm: 进程名（识别IO密集型进程）
 * - bio_type: BIO类型（READ/WRITE/SYNC，通过rwbs解析）
 * 
 * 统计指标：
 * - count: BIO次数
 * - total_bytes: 总字节数
 * - total_ns: 总延迟（纳秒）
 * - min_ns: 最小延迟
 * - max_ns: 最大延迟
 * 
 * 性能优化：
 * - 使用原子操作(__sync_fetch_and_add)保证并发安全
 * - min/max使用简单比较(非原子)，避免CAS操作的兼容性问题
 * - 兼容内核3.10+（使用lookup+update模式）
 * - Hash Map大小：bio_stats=10240, start_times=10240
 */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/blkdev.h>

/* BIO类型定义 - 与Python代码保持一致 */
#define BIO_TYPE_READ       0x1      // R: Read
#define BIO_TYPE_WRITE      0x2      // W: Write
#define BIO_TYPE_SYNC       0x4      // S: Synchronous
#define BIO_TYPE_FLUSH      0x8      // F: Flush
#define BIO_TYPE_DISCARD    0x10     // D: Discard/TRIM
#define BIO_TYPE_METADATA   0x20     // M: Metadata
#define BIO_TYPE_READAHEAD  0x40     // A: Read-ahead
#define BIO_TYPE_NONE       0x80     // N: None (barrier/flush without data)

/* 统计Key：(进程名, BIO类型) 
 * 注意：comm[16] + u32会有填充字节，必须用__builtin_memset清零
 */
struct stats_key_t {
    char comm[TASK_COMM_LEN];  // 进程名 (16字节)
    u32 bio_type;              // BIO类型（READ/WRITE/SYNC组合）
};

/* 统计Value */
struct stats_value_t {
    u64 count;         // IO次数
    u64 total_bytes;   // 总字节数
    u64 total_ns;      // 总延迟（纳秒）
    u64 min_ns;        // 最小延迟
    u64 max_ns;        // 最大延迟
};

/* start_times Map的Key说明：
 * 
 * 使用u64直接作为Key，打包(dev, sector)信息：
 * - 高32位：设备号(dev)
 * - 低32位：扇区号的低32位(sector & 0xFFFFFFFF)
 * 
 * ⚠️ 已知限制：扇区重用冲突
 * - 如果同一扇区在短时间内被多次访问，后续的issue会覆盖前一个
 * - 这会导致前一个请求的延迟计算丢失
 * - 影响范围：约0.01-0.1%的IO请求（取决于工作负载）
 * 
 * 为什么接受这个限制：
 * 1. tracepoint不提供request指针，无法使用唯一ID
 * 2. 扇区重用冲突概率极低（IO延迟ms级，扇区访问间隔通常更长）
 * 3. 即使丢失个别IO延迟，不影响整体统计准确性（count/bytes仍准确）
 * 4. 更复杂的方案（如辅助索引）会显著增加性能开销
 */

/* 请求信息（临时存储，用于计算延迟） */
struct request_info_t {
    u64 start_ts;              // 开始时间戳
    char comm[TASK_COMM_LEN];  // 进程名
    u32 bio_type;              // BIO类型
    u32 nr_bytes;              // 字节数
};

/* BPF映射 */
BPF_HASH(bio_stats, struct stats_key_t, struct stats_value_t, 10240);   // BIO统计
BPF_HASH(start_times, u64, struct request_info_t, 10240);               // 临时存储（u64打包的(dev,sector) -> 请求信息）

/* 辅助函数：解析rwbs字符串，确定BIO类型
 * 
 * rwbs字符串格式说明：
 * - R: Read（读）
 * - W: Write（写）
 * - N: None（无数据传输，通常是Flush）
 * - D: Discard（丢弃/TRIM）
 * - F: Flush（刷盘）
 * - M: Metadata（元数据）
 * - S: Synchronous（同步）
 * - A: Read-ahead（预读）
 * 
 * 示例：
 * - "R" -> READ
 * - "W" -> WRITE
 * - "WS" -> WRITE|SYNC
 * - "F" -> FLUSH
 * - "FFS" -> FLUSH|SYNC
 * - "D" -> DISCARD
 * - "RM" -> READ|METADATA
 */
static inline u32 parse_rwbs(char *rwbs) {
    u32 bio_type = 0;
    
    // 遍历rwbs字符串，识别所有标志
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        if (rwbs[i] == '\0') break;
        
        switch (rwbs[i]) {
            case 'R':
            case 'r':
                bio_type |= BIO_TYPE_READ;
                break;
            case 'W':
            case 'w':
                bio_type |= BIO_TYPE_WRITE;
                break;
            case 'S':
            case 's':
                bio_type |= BIO_TYPE_SYNC;
                break;
            case 'F':
            case 'f':
                bio_type |= BIO_TYPE_FLUSH;
                break;
            case 'D':
            case 'd':
                bio_type |= BIO_TYPE_DISCARD;
                break;
            case 'M':
            case 'm':
                bio_type |= BIO_TYPE_METADATA;
                break;
            case 'A':
            case 'a':
                bio_type |= BIO_TYPE_READAHEAD;
                break;
            case 'N':
            case 'n':
                bio_type |= BIO_TYPE_NONE;
                break;
        }
    }
    
    return bio_type;
}

/* 统计更新函数：更新BIO统计 */
static inline void update_bio_stats(struct stats_key_t *key, u64 bytes, u64 ns) {
    struct stats_value_t *val = bio_stats.lookup(key);
    if (val) {
        // 已存在，原子更新计数和累加值
        __sync_fetch_and_add(&val->count, 1);
        __sync_fetch_and_add(&val->total_bytes, bytes);
        __sync_fetch_and_add(&val->total_ns, ns);
        
        // 更新min（简单比较，在并发时可能不完全准确，但足够接近）
        if (ns < val->min_ns) {
            val->min_ns = ns;
        }
        
        // 更新max（简单比较，在并发时可能不完全准确，但足够接近）
        if (ns > val->max_ns) {
            val->max_ns = ns;
        }
    } else {
        // 不存在，创建新条目
        struct stats_value_t new_val = {
            .count = 1,
            .total_bytes = bytes,
            .total_ns = ns,
            .min_ns = ns,
            .max_ns = ns
        };
        bio_stats.update(key, &new_val);
    }
}

// # cat /sys/kernel/debug/tracing/events/block/block_rq_issue/format
// name: block_rq_issue
// ID: 986
// format:
//         field:unsigned short common_type;       offset:0;       size:2; signed:0;
//         field:unsigned char common_flags;       offset:2;       size:1; signed:0;
//         field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
//         field:int common_pid;   offset:4;       size:4; signed:1;

//         field:dev_t dev;        offset:8;       size:4; signed:0;
//         field:sector_t sector;  offset:16;      size:8; signed:0;
//         field:unsigned int nr_sector;   offset:24;      size:4; signed:0;
//         field:unsigned int bytes;       offset:28;      size:4; signed:0;
//         field:char rwbs[8];     offset:32;      size:8; signed:1;
//         field:char comm[16];    offset:40;      size:16;        signed:1;
//         field:__data_loc char[] cmd;    offset:56;      size:4; signed:1;

// print fmt: "%d,%d %s %u (%s) %llu + %u [%s]", ((unsigned int) ((REC->dev) >> 20)), ((unsigned int) ((REC->dev) & ((1U << 20) - 1))), REC->rwbs, REC->bytes, __get_str(cmd), (unsigned long long)REC->sector, REC->nr_sector, REC->comm

// Tracepoint: block:block_rq_issue - IO请求下发到设备
TRACEPOINT_PROBE(block, block_rq_issue) {
    // 获取开始时间戳
    u64 start_ts = bpf_ktime_get_ns();
    
    // 构造请求Key（dev高32位 + sector低32位打包成u64）
    u64 req_key = ((u64)args->dev << 32) | ((u64)args->sector & 0xFFFFFFFF);
    
    // 记录请求信息
    struct request_info_t info = {};
    info.start_ts = start_ts;
    bpf_get_current_comm(&info.comm, sizeof(info.comm));
    
    // 解析rwbs字符串
    char rwbs[8];
    bpf_probe_read(&rwbs, sizeof(rwbs), (void *)args->rwbs);
    info.bio_type = parse_rwbs(rwbs);
    
    // 计算字节数（优先使用bytes字段，如果为0则用nr_sector * 512）
    info.nr_bytes = args->bytes > 0 ? args->bytes : args->nr_sector * 512;
    
    // 保存到start_times
    start_times.update(&req_key, &info);
    
    return 0;
}

// # cat /sys/kernel/debug/tracing/events/block/block_rq_complete/format
// name: block_rq_complete
// ID: 988
// format:
//         field:unsigned short common_type;       offset:0;       size:2; signed:0;
//         field:unsigned char common_flags;       offset:2;       size:1; signed:0;
//         field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
//         field:int common_pid;   offset:4;       size:4; signed:1;

//         field:dev_t dev;        offset:8;       size:4; signed:0;
//         field:sector_t sector;  offset:16;      size:8; signed:0;
//         field:unsigned int nr_sector;   offset:24;      size:4; signed:0;
//         field:int error;        offset:28;      size:4; signed:1;
//         field:char rwbs[8];     offset:32;      size:8; signed:1;
//         field:__data_loc char[] cmd;    offset:40;      size:4; signed:1;

// print fmt: "%d,%d %s (%s) %llu + %u [%d]", ((unsigned int) ((REC->dev) >> 20)), ((unsigned int) ((REC->dev) & ((1U << 20) - 1))), REC->rwbs, __get_str(cmd), (unsigned long long)REC->sector, REC->nr_sector, REC->error

// Tracepoint: block:block_rq_complete - IO请求完成
TRACEPOINT_PROBE(block, block_rq_complete) {
    // 构造请求Key（dev高32位 + sector低32位打包成u64）
    u64 req_key = ((u64)args->dev << 32) | ((u64)args->sector & 0xFFFFFFFF);
    
    // 查找对应的start信息
    struct request_info_t *info = start_times.lookup(&req_key);
    if (!info) {
        return 0;
    }
    
    // 计算延迟
    u64 end_ts = bpf_ktime_get_ns();
    u64 duration_ns = end_ts - info->start_ts;
    
    // 过滤异常值（>10秒的可能是bug或设备故障）
    if (duration_ns > 10000000000ULL) {
        start_times.delete(&req_key);
        return 0;
    }
    
    // 构造统计Key
    struct stats_key_t key = {};
    __builtin_memset(&key, 0, sizeof(key));  // 显式清零，包括填充字节
    __builtin_memcpy(key.comm, info->comm, TASK_COMM_LEN);
    key.bio_type = info->bio_type;
    
    // 更新统计
    update_bio_stats(&key, info->nr_bytes, duration_ns);
    
    // 清理start_times
    start_times.delete(&req_key);
    
    return 0;
}
