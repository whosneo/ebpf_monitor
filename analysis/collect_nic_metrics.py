#!/usr/bin/env python3
# encoding: utf-8
"""
高速网卡静态/半静态指标采集工具

采集 ethtool、sysfs、sysctl 中的网卡配置与计数器，用于与 eBPF 监控器
（interrupt、context_switch、syscall、udp 等）输出的系统性能指标做关联分析。

用法:
  python collect_nic_metrics.py
  python collect_nic_metrics.py -i eth0,eth1 -o ./nic_metrics
  python collect_nic_metrics.py --format json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Tuple


SYS_NET = "/sys/class/net"
PROC_SOFTNET = "/proc/net/softnet_stat"
ETHTOOL_BIN = shutil.which("ethtool") or "/sbin/ethtool"
YUSUR_VENDOR_ID = "1f47"

# PCI 登记名 -> 市场型号（SWIFT 无独立 PCI 名，需结合驱动/文档确认）
YUSUR_PCI_PRODUCT_MAP = {
    "1001": "FLEXFLOW-2200T",
    "3201": "FLEXFLOW-2200R",
    "4001": "CONFLUX-2200E",
    "5001": "CONFLUX-2200P",
    "6001": "CONFLUX-2200X",
    "3101": "FLEXFLOW-2100R",
}

# SWIFT-2200N 关联分析时建议重点关注的指标
SWIFT_2200N_FOCUS_METRICS = {
    "config": [
        "ethtool.ring.current.RX",
        "ethtool.ring.current.TX",
        "ethtool.channels.current",
        "ethtool.coalesce",
        "ethtool.pause",
        "mtu",
        "tx_queue_len",
        "sysctl_buffers.net.core.netdev_max_backlog",
        "sysctl_buffers.net.core.rmem_max",
        "sysctl_buffers.net.core.wmem_max",
    ],
    "runtime": [
        "statistics.rx_dropped",
        "statistics.rx_missed_errors",
        "statistics.rx_fifo_errors",
        "statistics.tx_dropped",
        "statistics.tx_fifo_errors",
        "softnet_stat.dropped",
        "softnet_stat.time_squeeze",
        "queues.tx.bql.inflight",
        "queues.tx.bql.stall_cnt",
    ],
    "correlate_with_ebpf": [
        "interrupt (NET_RX / NET_TX)",
        "context_switch",
        "udp (latency / throughput)",
        "syscall (network category)",
    ],
}


def read_text(path: str, default: str = "") -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read().strip()
    except OSError:
        return default


def read_int(path: str, default: int = 0) -> int:
    text = read_text(path, "")
    if not text:
        return default
    try:
        return int(text, 0)
    except ValueError:
        return default


def run_command(cmd: List[str]) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            check=False,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except OSError as exc:
        return 127, "", str(exc)


def list_interfaces(explicit: Optional[List[str]] = None) -> List[str]:
    if explicit:
        return explicit
    try:
        names = sorted(
            name
            for name in os.listdir(SYS_NET)
            if name != "lo" and os.path.isdir(os.path.join(SYS_NET, name))
        )
    except OSError:
        names = []
    return names


def parse_key_value_block(text: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        result[key.strip()] = value.strip()
    return result


def parse_ethtool_ring(text: str) -> Dict[str, Any]:
    data: Dict[str, Any] = {}
    current: Optional[str] = None
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("Pre-set maximums"):
            current = "max"
            data[current] = {}
            continue
        if line.startswith("Current hardware settings"):
            current = "current"
            data[current] = {}
            continue
        if current and ":" in line:
            key, value = line.split(":", 1)
            data[current][key.strip()] = _parse_ethtool_int(value.strip())
    return data


def _parse_ethtool_int(value: str) -> Any:
    lowered = value.lower()
    if lowered in ("n/a", "na", "not supported", "not available"):
        return None
    try:
        return int(value)
    except ValueError:
        return value


def parse_ethtool_channels(text: str) -> Dict[str, Any]:
    data: Dict[str, Any] = {}
    current: Optional[str] = None
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("Pre-set maximums"):
            current = "max"
            data[current] = {}
            continue
        if line.startswith("Current hardware settings"):
            current = "current"
            data[current] = {}
            continue
        if current and ":" in line:
            key, value = line.split(":", 1)
            data[current][key.strip()] = _parse_ethtool_int(value.strip())
    return data


def parse_ethtool_stats(text: str) -> Dict[str, int]:
    stats: Dict[str, int] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        try:
            stats[key] = int(value, 0)
        except ValueError:
            continue
    return stats


def parse_on_off_map(text: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("Features for"):
            continue
        parts = line.split(":", 1)
        if len(parts) != 2:
            continue
        key = parts[0].strip()
        value = parts[1].strip()
        if value in ("on", "off", "fixed"):
            result[key] = value
    return result


def collect_pci_devices() -> List[Dict[str, Any]]:
    rc, stdout, stderr = run_command(["lspci", "-nn"])
    if rc != 0:
        return [{"error": stderr or stdout or "lspci failed"}]

    devices: List[Dict[str, Any]] = []
    # e.g. "00:0a.0 Ethernet controller [0200]: Device 1f47:4001 (rev 10)"
    yusur_pattern = re.compile(
        r"^(\S+)\s+(.+?):\s+.*?\[{0}:([0-9a-fA-F]{{4}})\]".format(YUSUR_VENDOR_ID),
        re.IGNORECASE,
    )
    for line in stdout.splitlines():
        match = yusur_pattern.search(line)
        if not match:
            continue
        device_id = match.group(3).lower()
        devices.append({
            "pci_slot": match.group(1),
            "description": match.group(2),
            "vendor_id": YUSUR_VENDOR_ID,
            "device_id": device_id,
            "pci_name": line,
            "mapped_product": YUSUR_PCI_PRODUCT_MAP.get(device_id),
        })
    return devices


def collect_sysctl_buffers() -> Dict[str, Any]:
    keys = [
        "net.core.rmem_max",
        "net.core.wmem_max",
        "net.core.rmem_default",
        "net.core.wmem_default",
        "net.core.netdev_max_backlog",
        "net.core.netdev_budget",
        "net.core.netdev_budget_usecs",
        "net.core.somaxconn",
        "net.ipv4.tcp_rmem",
        "net.ipv4.tcp_wmem",
        "net.ipv4.udp_rmem_min",
        "net.ipv4.udp_wmem_min",
    ]
    result: Dict[str, Any] = {}
    for key in keys:
        proc_path = "/proc/sys/" + key.replace(".", "/")
        raw = read_text(proc_path, "")
        if not raw:
            continue
        parts = raw.split()
        if len(parts) > 1:
            result[key] = [int(part) for part in parts]
        else:
            try:
                result[key] = int(raw)
            except ValueError:
                result[key] = raw
    return result


def collect_softnet_stat() -> List[Dict[str, int]]:
    rows: List[Dict[str, int]] = []
    raw = read_text(PROC_SOFTNET, "")
    if not raw:
        return rows
    for cpu_idx, line in enumerate(raw.splitlines()):
        parts = [int(part, 16) for part in line.split()]
        if len(parts) < 4:
            continue
        entry = {
            "cpu": cpu_idx,
            "processed": parts[0],
            "dropped": parts[1],
            "time_squeeze": parts[2],
            "cpu_collision": parts[3],
        }
        if len(parts) >= 9:
            entry["received_rps"] = parts[8]
        if len(parts) >= 10:
            entry["flow_limit_count"] = parts[9]
        rows.append(entry)
    return rows


def collect_queue_metrics(iface: str) -> Dict[str, Any]:
    queues_root = os.path.join(SYS_NET, iface, "queues")
    result: Dict[str, Any] = {"rx": [], "tx": []}
    if not os.path.isdir(queues_root):
        return result

    for queue_name in sorted(os.listdir(queues_root)):
        queue_path = os.path.join(queues_root, queue_name)
        if not os.path.isdir(queue_path):
            continue
        entry: Dict[str, Any] = {"name": queue_name}
        if queue_name.startswith("rx-"):
            entry["rps_cpus"] = read_text(os.path.join(queue_path, "rps_cpus"), "")
            entry["rps_flow_cnt"] = read_int(os.path.join(queue_path, "rps_flow_cnt"))
            result["rx"].append(entry)
        elif queue_name.startswith("tx-"):
            entry["xps_cpus"] = read_text(os.path.join(queue_path, "xps_cpus"), "")
            entry["xps_rxqs"] = read_text(os.path.join(queue_path, "xps_rxqs"), "")
            entry["tx_maxrate"] = read_int(os.path.join(queue_path, "tx_maxrate"))
            bql_path = os.path.join(queue_path, "byte_queue_limits")
            if os.path.isdir(bql_path):
                entry["bql"] = {
                    "limit": read_int(os.path.join(bql_path, "limit")),
                    "limit_min": read_int(os.path.join(bql_path, "limit_min")),
                    "limit_max": read_int(os.path.join(bql_path, "limit_max")),
                    "inflight": read_int(os.path.join(bql_path, "inflight")),
                    "stall_cnt": read_int(os.path.join(bql_path, "stall_cnt")),
                    "stall_max": read_int(os.path.join(bql_path, "stall_max")),
                    "stall_thrs": read_int(os.path.join(bql_path, "stall_thrs")),
                    "hold_time": read_int(os.path.join(bql_path, "hold_time")),
                }
            result["tx"].append(entry)
    return result


def collect_interface_stats(iface: str) -> Dict[str, int]:
    stats_dir = os.path.join(SYS_NET, iface, "statistics")
    stats: Dict[str, int] = {}
    if not os.path.isdir(stats_dir):
        return stats
    for name in sorted(os.listdir(stats_dir)):
        value = read_int(os.path.join(stats_dir, name))
        stats[name] = value
    return stats


def collect_ethtool(iface: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    commands = {
        "driver": [ETHTOOL_BIN, "-i", iface],
        "link": [ETHTOOL_BIN, iface],
        "ring": [ETHTOOL_BIN, "-g", iface],
        "channels": [ETHTOOL_BIN, "-l", iface],
        "pause": [ETHTOOL_BIN, "-a", iface],
        "coalesce": [ETHTOOL_BIN, "-c", iface],
        "offload": [ETHTOOL_BIN, "-k", iface],
        "stats": [ETHTOOL_BIN, "-S", iface],
    }
    for name, cmd in commands.items():
        rc, stdout, stderr = run_command(cmd)
        if rc != 0:
            result[name] = {"supported": False, "error": stderr or stdout or "command failed"}
            continue
        if name == "ring":
            result[name] = {"supported": True, **parse_ethtool_ring(stdout)}
        elif name == "channels":
            result[name] = {"supported": True, **parse_ethtool_channels(stdout)}
        elif name == "stats":
            result[name] = {"supported": True, "counters": parse_ethtool_stats(stdout)}
        elif name == "offload":
            result[name] = {"supported": True, "features": parse_on_off_map(stdout)}
        else:
            result[name] = {"supported": True, **parse_key_value_block(stdout)}
    return result


def collect_interface(iface: str) -> Dict[str, Any]:
    iface_path = os.path.join(SYS_NET, iface)
    device_path = os.path.join(iface_path, "device")
    driver_name = ""
    if os.path.islink(device_path):
        driver_link = os.path.join(device_path, "driver")
        if os.path.islink(driver_link):
            driver_name = os.path.basename(os.readlink(driver_link))

    data: Dict[str, Any] = {
        "interface": iface,
        "driver": driver_name,
        "ifindex": read_int(os.path.join(iface_path, "ifindex")),
        "mtu": read_int(os.path.join(iface_path, "mtu")),
        "speed_mbps": read_int(os.path.join(iface_path, "speed")),
        "duplex": read_text(os.path.join(iface_path, "duplex")),
        "operstate": read_text(os.path.join(iface_path, "operstate")),
        "carrier": read_int(os.path.join(iface_path, "carrier")),
        "tx_queue_len": read_int(os.path.join(iface_path, "tx_queue_len")),
        "gro_flush_timeout": read_int(os.path.join(iface_path, "gro_flush_timeout")),
        "napi_defer_hard_irqs": read_int(os.path.join(iface_path, "napi_defer_hard_irqs")),
        "statistics": collect_interface_stats(iface),
        "queues": collect_queue_metrics(iface),
        "ethtool": collect_ethtool(iface),
    }
    return data


def flatten_record(record: Dict[str, Any], prefix: str = "") -> Dict[str, Any]:
    flat: Dict[str, Any] = {}
    for key, value in record.items():
        full_key = "{}.{}".format(prefix, key) if prefix else key
        if isinstance(value, dict):
            flat.update(flatten_record(value, full_key))
        elif isinstance(value, list):
            flat[full_key] = json.dumps(value, ensure_ascii=False)
        else:
            flat[full_key] = value
    return flat


def write_csv(path: str, rows: List[Dict[str, Any]]) -> None:
    if not rows:
        return
    columns: List[str] = []
    for row in rows:
        for key in row:
            if key not in columns:
                columns.append(key)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(",".join(columns) + "\n")
        for row in rows:
            values = []
            for col in columns:
                value = row.get(col, "")
                text = "" if value is None else str(value)
                if "," in text or '"' in text:
                    text = '"' + text.replace('"', '""') + '"'
                values.append(text)
            fh.write(",".join(values) + "\n")


def build_summary(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    summary: Dict[str, Any] = {
        "interfaces": len(snapshot.get("interfaces", [])),
        "supported_ring_buffer": 0,
        "supported_channels": 0,
        "total_rx_dropped": 0,
        "total_tx_dropped": 0,
        "softnet_dropped": sum(item.get("dropped", 0) for item in snapshot.get("softnet_stat", [])),
        "softnet_time_squeeze": sum(item.get("time_squeeze", 0) for item in snapshot.get("softnet_stat", [])),
    }
    for iface in snapshot.get("interfaces", []):
        stats = iface.get("statistics", {})
        summary["total_rx_dropped"] += stats.get("rx_dropped", 0)
        summary["total_tx_dropped"] += stats.get("tx_dropped", 0)
        ring = iface.get("ethtool", {}).get("ring", {})
        channels = iface.get("ethtool", {}).get("channels", {})
        if ring.get("supported"):
            summary["supported_ring_buffer"] += 1
        if channels.get("supported"):
            summary["supported_channels"] += 1
    return summary


def collect_snapshot(
    interfaces: Optional[List[str]] = None,
    product: str = "",
) -> Dict[str, Any]:
    timestamp = time.time()
    iface_names = list_interfaces(interfaces)
    pci_devices = collect_pci_devices()
    snapshot: Dict[str, Any] = {
        "timestamp": timestamp,
        "time_str": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp)),
        "hostname": socket.gethostname(),
        "kernel": read_text("/proc/sys/kernel/osrelease"),
        "product": product,
        "pci_devices": pci_devices,
        "sysctl_buffers": collect_sysctl_buffers(),
        "softnet_stat": collect_softnet_stat(),
        "interfaces": [collect_interface(name) for name in iface_names],
    }
    if product.upper().replace("_", "-") in ("SWIFT-2200N", "SWIFT2200N"):
        snapshot["focus_metrics"] = SWIFT_2200N_FOCUS_METRICS
    snapshot["summary"] = build_summary(snapshot)
    return snapshot


def print_human_report(snapshot: Dict[str, Any]) -> None:
    print("NIC metrics snapshot @ {} ({})".format(snapshot["time_str"], snapshot["hostname"]))
    print("Kernel: {}".format(snapshot.get("kernel", "unknown")))
    if snapshot.get("product"):
        print("Product: {}".format(snapshot["product"]))
    pci_devices = snapshot.get("pci_devices", [])
    if pci_devices and "error" not in pci_devices[0]:
        print("YUSUR PCI devices: {}".format(len(pci_devices)))
        for dev in pci_devices:
            mapped = dev.get("mapped_product") or "unknown"
            print("  {} device_id={} mapped={}".format(
                dev.get("pci_slot"), dev.get("device_id"), mapped))
    print()

    sysctl = snapshot.get("sysctl_buffers", {})
    if sysctl:
        print("== Kernel socket / netdev buffers ==")
        for key in sorted(sysctl):
            print("  {} = {}".format(key, sysctl[key]))
        print()

    softnet = snapshot.get("softnet_stat", [])
    if softnet:
        total_dropped = sum(item.get("dropped", 0) for item in softnet)
        total_squeeze = sum(item.get("time_squeeze", 0) for item in softnet)
        print("== softnet_stat ==")
        print("  CPUs: {}, dropped(total): {}, time_squeeze(total): {}".format(
            len(softnet), total_dropped, total_squeeze))
        print()

    for iface in snapshot.get("interfaces", []):
        print("== {} (driver: {}, speed: {} Mbps, mtu: {}) ==".format(
            iface["interface"],
            iface.get("driver") or "unknown",
            iface.get("speed_mbps"),
            iface.get("mtu"),
        ))
        print("  operstate={}, tx_queue_len={}, carrier={}".format(
            iface.get("operstate"), iface.get("tx_queue_len"), iface.get("carrier")))

        stats = iface.get("statistics", {})
        interesting = [
            "rx_packets", "tx_packets", "rx_bytes", "tx_bytes",
            "rx_dropped", "tx_dropped", "rx_missed_errors",
            "rx_fifo_errors", "tx_fifo_errors", "rx_over_errors",
        ]
        print("  netdev statistics:")
        for key in interesting:
            if key in stats:
                print("    {} = {}".format(key, stats[key]))

        ring = iface.get("ethtool", {}).get("ring", {})
        if ring.get("supported"):
            current = ring.get("current", {})
            maximum = ring.get("max", {})
            print("  ring buffers (current/max):")
            for key in sorted(set(list(current.keys()) + list(maximum.keys()))):
                print("    {} = {}/{}".format(key, current.get(key, "-"), maximum.get(key, "-")))
        else:
            print("  ring buffers: not supported ({})".format(
                ring.get("error", "unknown")))

        channels = iface.get("ethtool", {}).get("channels", {})
        if channels.get("supported"):
            current = channels.get("current", {})
            print("  channels (current): {}".format(current))
        else:
            print("  channels: not supported")

        coalesce = iface.get("ethtool", {}).get("coalesce", {})
        if coalesce.get("supported"):
            keys = [
                "rx-usecs", "tx-usecs", "rx-frames", "tx-frames",
                "pkt-rate-low", "pkt-rate-high",
            ]
            present = {k: coalesce[k] for k in keys if k in coalesce}
            if present:
                print("  coalesce: {}".format(present))

        tx_queues = iface.get("queues", {}).get("tx", [])
        if tx_queues:
            sample = tx_queues[0]
            bql = sample.get("bql")
            if bql:
                print("  BQL sample ({}): limit={} inflight={} stall_cnt={}".format(
                    sample.get("name"),
                    bql.get("limit"),
                    bql.get("inflight"),
                    bql.get("stall_cnt"),
                ))
        print()

    summary = snapshot.get("summary", {})
    print("== Summary ==")
    for key, value in sorted(summary.items()):
        print("  {} = {}".format(key, value))


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collect high-speed NIC metrics for correlation analysis")
    parser.add_argument(
        "-i", "--interfaces",
        default="",
        help="Comma-separated interface list. Default: all non-loopback interfaces.",
    )
    parser.add_argument(
        "-o", "--output-dir",
        default="",
        help="Directory to write snapshot files. Default: only print to stdout.",
    )
    parser.add_argument(
        "--format",
        choices=("human", "json"),
        default="human",
        help="Stdout format. Files are always written as JSON + CSV when --output-dir is set.",
    )
    parser.add_argument(
        "--product",
        default="",
        help="NIC product label for tagging output, e.g. SWIFT-2200N.",
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    explicit = [item.strip() for item in args.interfaces.split(",") if item.strip()] or None
    snapshot = collect_snapshot(explicit, product=args.product)

    if args.format == "json":
        print(json.dumps(snapshot, ensure_ascii=False, indent=2))
    else:
        print_human_report(snapshot)

    if args.output_dir:
        os.makedirs(args.output_dir, exist_ok=True)
        stamp = time.strftime("%Y%m%d_%H%M%S", time.localtime(snapshot["timestamp"]))
        json_path = os.path.join(args.output_dir, "nic_metrics_{}.json".format(stamp))
        csv_path = os.path.join(args.output_dir, "nic_metrics_{}.csv".format(stamp))
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump(snapshot, fh, ensure_ascii=False, indent=2)

        flat_rows = []
        for iface in snapshot.get("interfaces", []):
            row = {
                "timestamp": snapshot["timestamp"],
                "time_str": snapshot["time_str"],
                "hostname": snapshot["hostname"],
                "product": snapshot.get("product", ""),
            }
            row.update(flatten_record(iface))
            flat_rows.append(row)
        write_csv(csv_path, flat_rows)
        print("Saved: {}".format(json_path))
        print("Saved: {}".format(csv_path))

    return 0


if __name__ == "__main__":
    sys.exit(main())