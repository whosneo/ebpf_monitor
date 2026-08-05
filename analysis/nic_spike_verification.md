# SWIFT-2200N 低延时网卡验证 Spike 报告（Phase 2）

**日期**：2026-07-03  
**型号**：SWIFT-2200N Pro（中科驭数 YUSUR，PCI vendor 1f47）  
**目标**：验证 eBPF 系统级全量监控在真实低延时网卡上的数据量与可行性。重点：延迟、硬件队列深度、缓冲区。

## 已完成的最小 spike 代码

- `src/ebpf/nic.c`（本目录同级）
  - 统计聚合模式（BPF_HASH nic_stats + 原子更新）
  - 通用探针：
    - kprobe__dev_hard_start_xmit / dev_queue_xmit （TX）
    - kprobe__netif_rx + kprobe__napi_poll （RX）
  - 维度：(comm, direction) -> count, bytes, latency (配对 ns), queue_events（软件侧占位）
  - 兼容 3.10+（lookup/update 模式）
  - 占位注释：SWIFT-2200N driver specific 符号待真实硬件填充

- 配套辅助工具（已就绪）：
  - `analysis/collect_nic_metrics.py --product SWIFT-2200N`
    - 采集 ring、channels、ethtool stats、sysfs queues/BQL/softnet_stat、PCI 识别
    - SWIFT_2200N_FOCUS_METRICS 已定义（重点 correlate 字段）

## 推荐输出模式

**强烈推荐：统计聚合模式（已实现）**

理由（基于设计与类似 udp 经验）：
- 低延时卡（<2us 路径）下每秒报文量可能极大（10G+ 线速、小包）。
- 事件模式（perf buffer）容易丢数据、CPU 抖动。
- 聚合后每 2s 输出一次，数据量大幅降低（90%+），适合 CSV/Prometheus。
- 队列深度/缓冲趋势适合定期采样。

如果 spike 实测显示特定指标需要更高分辨率，可在正式实现中增加混合模式（关键 spike 事件单独输出）。

## 如何在真实 SWIFT-2200N 硬件上运行验证

1. 确保环境：
   - 安装 SWIFT-2200N 驱动（中科驭数提供标准驱动）
   - 加载对应 iface（lspci -nn 应看到 1f47:xxxx）
   - python + bcc（或通过项目 venv）

2. 采集基线（硬件指标）：
   ```bash
   cd analysis
   python collect_nic_metrics.py --product SWIFT-2200N -i eth0,eth1 -o ./nic_metrics
   ```

3. 启动 spike 监控（临时使用）：
   - 当前使用完整框架时：待 nic.py 实现后 `sudo python main.py -m nic`
   - 快速验证（手动加载示例，后续替换为正式 monitor）：
     使用 bcc python 片段直接 attach nic.c 的 map 并定期 pop（见下文）。

4. 量化数据量：
   - 观察：
     - 每秒事件原始量（无聚合）
     - 聚合后每 interval 输出行数 / 大小
     - CPU 影响（top / perf）
     - 延迟影响（与已知交易路径对比）
   - 记录：`output/` CSV + nic_metrics json

5. Driver specific 增强（真实卡上）：
   ```bash
   # 加载驱动后
   grep -E 'yusur|kpu|swft|nic_poll|ring' /proc/kallsyms | head -20
   # 或 objdump -t /lib/modules/.../yusur_*.ko
   ```
   把发现的符号加到 nic.c 的 kprobe__ 中（e.g. kprobe__yusur_rx_poll）。

6. 产生输出：
   - CSV（nic_stats 表 pop）
   - 分析：用 analyzer 后续增强 + 手动对比 collect 结果

## 示例快速验证 Python 片段（spike 用，生产用正式 NicMonitor）

```python
# 临时 spike_harness.py （不依赖完整框架）
from bcc import BPF
import time, json

b = BPF(src_file="src/ebpf/nic.c")  # 或 text=...
stats = b.get_table("nic_stats")

print("Running NIC spike... Ctrl-C stop")
try:
    while True:
        time.sleep(2)
        data = []
        for k, v in stats.items():
            data.append({
                "comm": k.comm.decode('utf-8', 'replace').strip('\x00'),
                "dir": "TX" if k.direction == 1 else "RX",
                "count": v.count,
                "bytes": v.total_bytes,
                "avg_lat_us": (v.total_ns / v.count / 1000.0) if v.count > 0 else 0,
                "queue_events": v.queue_events,
            })
            # pop to clear
            stats.pop(k)
        if data:
            print(json.dumps(data, indent=2))
except KeyboardInterrupt:
    pass
```

运行：`python spike_harness.py` （需 root + bcc + nic.c 存在）

## 模拟 / 预期结果（虚拟环境观察 + 真实卡预期）

**虚拟/普通网卡环境**（当前测试，2026-07-03）：
- 包率低，聚合输出每周期 <10 行。
- queue_events 主要来自 dev_queue_xmit / napi 占位。
- 使用 `--product SWIFT-2200N` 运行 collect_nic_metrics 成功打标并采集 sysctl/softnet/queues 等（见 output 或终端输出）。真实 SWIFT-2200N 上 ring/channels/ethtool 将更丰富。

**SWIFT-2200N 真实交易环境预期**：
- 小包高频（行情/订单），单方向 count 可能每秒 10k~100k+。
- 聚合后输出仍可控（每周期几十~几百行）。
- latency 分布会非常低（us 级），P99 重要。
- queue depth / ring 需结合 collect_nic_metrics 看 ethtool current/max + BQL inflight。
- 若 bypass 路径存在，标准探针覆盖率需验证（可能只捕获 fallback 路径）。

**风险与观察点**：
- 旁路库导致部分流量不可见 → 需与用户态库日志或 vendor 指标交叉验证。
- 高频下 map 大小（当前 10240）是否够 → 必要时增大。
- CPU 影响 < 1-2% 目标。

## 结论与输入给后续阶段

- 模式推荐：**统计聚合**（默认 2s interval）。
- 最小代码已交付（nic.c）。
- 型号已更新 ROADMAP。
- 下一步（继续按序）：Phase 4 测试框架 + Phase 5 分析增强 → Phase 3 正式 NicMonitor（nic.py + 完善 nic.c + 配置集成）。

报告位置：analysis/nic_spike_verification.md
可附加真实运行的 nic_metrics_*.json / csv 作为证据。

**下一步行动**：在有 SWIFT-2200N 的服务器上执行以上步骤，补充实际量化数字到本报告。
